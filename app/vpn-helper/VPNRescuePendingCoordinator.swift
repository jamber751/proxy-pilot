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
