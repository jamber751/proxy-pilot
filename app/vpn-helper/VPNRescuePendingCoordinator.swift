import Darwin
import Foundation

/// Pending-only orchestration. It never selects, retires, or modifies release
/// state. The system wrapper binds fixed protected storage and the caller's
/// held lifecycle lease; recovery arming/draining are trusted local callbacks.
/// Once exchange starts, failure is forward-only; callers must retain recovery
/// and retry the same pending edge, never swap back or cancel the journal.
enum VPNRescuePendingCoordinator {
    #if VPN_EXPLICIT_RESCUE && (VPN_RESCUE_SYSTEM_ENTRY || VPN_APPLICATION_DESTINATION_ROOT_TESTING)
    private enum Mode {
        #if VPN_RESCUE_SYSTEM_ENTRY
        case system
        #endif
        #if VPN_APPLICATION_DESTINATION_ROOT_TESTING
        case fixture(Int32)
        #endif
        var productionDestination: Bool {
            switch self {
            #if VPN_RESCUE_SYSTEM_ENTRY
            case .system: return true
            #endif
            #if VPN_APPLICATION_DESTINATION_ROOT_TESTING
            case .fixture: return false
            #endif
            }
        }
    }

    #if VPN_APPLICATION_DESTINATION_ROOT_TESTING
    static func testRun(context: VPNRescueJournalContext,
                        executor: VPNRescueExecutor,
                        inTrustedDirectory base: Int32, destination: Int32,
                        armCandidateRecovery: () throws -> Void,
                        drainPreviousService: () throws -> Void,
                        checkpoint: (String) throws -> Void = { _ in }) throws
        -> VPNApplicationDestinationExchange.Outcome {
        try perform(context: context, executor: executor, base: base, mode: .fixture(destination),
            armCandidateRecovery: armCandidateRecovery, drainPreviousService: drainPreviousService,
            checkpoint: checkpoint)
    }
    #endif

    #if VPN_RESCUE_SYSTEM_ENTRY
    static func runSystem(service: Int32, update: Int32, lease: VPNLifecycleLease,
                          context: VPNRescueJournalContext, executor: VPNRescueExecutor,
                          armCandidateRecovery: () throws -> Void,
                          drainPreviousService: () throws -> Void) throws
        -> VPNApplicationDestinationExchange.Outcome {
        guard getuid() == 0, geteuid() == 0 else { throw VPNRescueExecutorError.requiresRoot }
        try VPNDirectoryProvisioner.requireSystemDirectory(service)
        try VPNDirectoryProvisioner.requireSystemUpdateDirectory(update)
        var facts = stat()
        guard fstat(service, &facts) == 0,
              try context.checkedStorageIdentity(holding: lease)
                == (device: UInt64(facts.st_dev), inode: UInt64(facts.st_ino)) else {
            throw VPNRescueJournalContextError.mismatchedStorage
        }
        return try perform(context: context, executor: executor, base: update, mode: .system,
            armCandidateRecovery: armCandidateRecovery, drainPreviousService: drainPreviousService,
            checkpoint: { _ in })
    }
    #endif

    private static func perform(context: VPNRescueJournalContext, executor: VPNRescueExecutor,
                                base: Int32, mode: Mode,
                                armCandidateRecovery: () throws -> Void,
                                drainPreviousService: () throws -> Void,
                                checkpoint: (String) throws -> Void) throws
        -> VPNApplicationDestinationExchange.Outcome {
        func validate() throws {
            try context.validate()
            try executor.revalidate()
            guard executor.authorization.matchesSource(context.previous.release),
                  executor.authorization.matchesDestination(context.candidate.release),
                  executor.authorization.matchesTransition(context.transition) else {
                throw VPNApplicationDestinationExchangeError.invalidTransition
            }
        }
        try validate()
        let destination: Int32
        switch mode {
        #if VPN_RESCUE_SYSTEM_ENTRY
        case .system:
            destination = open("/Applications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        #endif
        #if VPN_APPLICATION_DESTINATION_ROOT_TESTING
        case .fixture(let directory): destination = fcntl(directory, F_DUPFD_CLOEXEC, 0)
        #endif
        }
        guard destination >= 0 else { throw VPNApplicationDestinationStageError.unsafeDestination }
        defer { close(destination) }

        // A137 may have stopped before preparing the destination stage. Only
        // the already-exchanged protected B/A layout authorizes completing it;
        // a finish token never performs the earlier protected namespace swap.
        let current = openat(base, "current", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let previous = openat(base, "candidate", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard current >= 0, previous >= 0 else {
            if current >= 0 { close(current) }
            if previous >= 0 { close(previous) }
            throw VPNApplicationDestinationExchangeError.invalidLayout
        }
        defer { close(current); close(previous) }
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: current)
        try VPNStagedApplication.requireExclusiveBundle(inTrustedDirectory: previous)
        let currentObservation = try VPNStagedApplication.inspect(inTrustedDirectory: current,
            release: context.candidate.release)
        let previousObservation = try VPNStagedApplication.inspect(inTrustedDirectory: previous,
            release: context.previous.release)
        let retainedExecutor = try VPNReplacementExecutor.inspectPrepared(
            inTrustedDirectory: base, release: context.previous.release)
        try retainedExecutor.revalidatePrepared()
        let installedPrevious = try? VPNStagedApplication.inspectInstalled(
            inApplicationsDirectory: destination, ownerUserID: 0,
            productionParent: mode.productionDestination, release: context.previous.release)
        let installedCandidate = try? VPNStagedApplication.inspectInstalled(
            inApplicationsDirectory: destination, ownerUserID: 0,
            productionParent: mode.productionDestination, release: context.candidate.release)
        guard (installedPrevious == nil) != (installedCandidate == nil) else {
            throw VPNApplicationDestinationExchangeError.invalidLayout
        }
        try validate()
        if installedPrevious != nil {
            switch mode {
            #if VPN_RESCUE_SYSTEM_ENTRY
            case .system:
                _ = try VPNApplicationDestinationStage.prepare(inTrustedDirectory: base,
                    release: context.candidate.release)
            #endif
            #if VPN_APPLICATION_DESTINATION_ROOT_TESTING
            case .fixture:
                _ = try VPNApplicationDestinationStage.testPrepare(inTrustedDirectory: base,
                    destination: destination, release: context.candidate.release)
            #endif
            }
        }
        // Installed B means a previous destination exchange committed: retain
        // stage A for the existing exchange primitive to verify on forward retry.
        try validate()
        try retainedExecutor.revalidatePrepared()
        try VPNStagedApplication.revalidate(currentObservation, inTrustedDirectory: current)
        try VPNStagedApplication.revalidate(previousObservation, inTrustedDirectory: previous)
        func authorizeMutation() throws {
            try validate()
            try armCandidateRecovery()
            try validate()
            try drainPreviousService()
            try validate()
        }
        // Existing primitives inspect all app slots before the callback and
        // independently revalidate them immediately before publication.
        let outcome: VPNApplicationDestinationExchange.Outcome
        switch mode {
        #if VPN_RESCUE_SYSTEM_ENTRY
        case .system:
            outcome = try VPNApplicationDestinationExchange.rescueExchange(
                inTrustedDirectory: base, previous: context.previous.release,
                previousOwnerUserID: context.ownerUserID, candidate: context.candidate.release,
                transition: context.transition, executor: executor,
                authorizeMutation: authorizeMutation, checkpoint: checkpoint)
        #endif
        #if VPN_APPLICATION_DESTINATION_ROOT_TESTING
        case .fixture(let destination):
            outcome = try VPNApplicationDestinationExchange.testRescueExchange(
                inTrustedDirectory: base, destination: destination,
                previous: context.previous.release, previousOwnerUserID: context.ownerUserID,
                candidate: context.candidate.release, transition: context.transition,
                executor: executor, authorizeMutation: authorizeMutation, checkpoint: checkpoint)
        #endif
        }
        try validate()
        return outcome
    }
    #endif
}
