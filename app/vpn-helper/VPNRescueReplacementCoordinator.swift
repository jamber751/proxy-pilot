import Darwin
import Foundation

#if VPN_RESCUE_PREPARATION && VPN_EXPLICIT_RESCUE && (VPN_RESCUE_SYSTEM_ENTRY || VPN_RESCUE_REPLACEMENT_COORDINATOR_TESTING)
/// Exact-edge replacement boundary. The caller retains the service lease;
/// existing primitives acquire/release the Update lease in the established order.
/// Recovery is deliberately never disarmed on error, and selector A is unchanged.
enum VPNRescueReplacementCoordinator {
    enum Failure: Error { case requiresRoot, invalidState }
    enum Progress {
        case pending, protectedReady, protectedExchanged, protectedSynced, protectedValidated, destinationStaged
    }

    private enum Mode {
        #if VPN_RESCUE_SYSTEM_ENTRY
        case system
        #endif
        #if VPN_RESCUE_REPLACEMENT_COORDINATOR_TESTING
        case fixture
        #endif
        var productionDestination: Bool {
            switch self {
            #if VPN_RESCUE_SYSTEM_ENTRY
            case .system: return true
            #endif
            #if VPN_RESCUE_REPLACEMENT_COORDINATOR_TESTING
            case .fixture: return false
            #endif
            }
        }
    }

    #if VPN_RESCUE_REPLACEMENT_COORDINATOR_TESTING
    static func testRun(service: Int32, update: Int32, destination: Int32,
                        authority: VPNReleaseAuthority, lease: VPNLifecycleLease,
                        preparationExecutor: VPNRescuePreparationExecutor,
                        executor: VPNRescueExecutor,
                        armCandidateRecovery: (VPNAuthorizedDeployment) throws -> Void,
                        drainPreviousService: () throws -> Void,
                        checkpoint: (String) throws -> Void = { _ in }) throws
        -> VPNApplicationDestinationExchange.Outcome {
        try perform(service: service, update: update, destination: destination,
            authority: authority, lease: lease, preparationExecutor: preparationExecutor,
            executor: executor, mode: .fixture, armCandidateRecovery: armCandidateRecovery,
            drainPreviousService: drainPreviousService, checkpoint: checkpoint)
    }
    #endif

    #if VPN_RESCUE_SYSTEM_ENTRY
    static func runSystem(service: Int32, update: Int32,
                          authority: VPNReleaseAuthority, lease: VPNLifecycleLease,
                          preparationExecutor: VPNRescuePreparationExecutor,
                          executor: VPNRescueExecutor,
                          armCandidateRecovery: (VPNAuthorizedDeployment) throws -> Void,
                          drainPreviousService: () throws -> Void,
                          progress: (Progress) -> Void = { _ in }) throws
        -> VPNApplicationDestinationExchange.Outcome {
        guard getuid() == 0, geteuid() == 0 else { throw Failure.requiresRoot }
        try VPNDirectoryProvisioner.requireSystemDirectory(service)
        try VPNDirectoryProvisioner.requireSystemUpdateDirectory(update)
        let applications = open("/Applications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard applications >= 0 else { throw Failure.invalidState }
        defer { close(applications) }
        return try perform(service: service, update: update, destination: applications,
            authority: authority, lease: lease, preparationExecutor: preparationExecutor,
            executor: executor, mode: .system, armCandidateRecovery: armCandidateRecovery,
            drainPreviousService: drainPreviousService, checkpoint: { point in
                // Fixed internal checkpoints only; no dynamic identifiers,
                // paths, error descriptions or arbitrary callback text.
                switch point {
                case "afterPending": progress(.pending)
                case "protected:beforeExchange": progress(.protectedReady)
                case "protected:afterExchange": progress(.protectedExchanged)
                case "protected:afterSync": progress(.protectedSynced)
                case "afterProtectedSwap": progress(.protectedValidated)
                case "afterDestinationStage": progress(.destinationStaged)
                default: break
                }
            })
    }
    #endif

    private static func perform(service: Int32, update: Int32, destination: Int32,
                                authority: VPNReleaseAuthority, lease: VPNLifecycleLease,
                                preparationExecutor: VPNRescuePreparationExecutor,
                                executor: VPNRescueExecutor, mode: Mode,
                                armCandidateRecovery: (VPNAuthorizedDeployment) throws -> Void,
                                drainPreviousService: () throws -> Void,
                                checkpoint: (String) throws -> Void) throws
        -> VPNApplicationDestinationExchange.Outcome {
        guard getuid() == 0, geteuid() == 0 else { throw Failure.requiresRoot }
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
        guard try lease.checkedStorageIdentity() == store.storageIdentity(),
              try store.loadUpdatePreparation() == nil,
              try store.loadUpdateCleanupReceipt() == nil,
              let initial = try store.loadUpdateJournal() else { throw Failure.invalidState }
        let previous = initial.previous.release, candidate = initial.candidate.release
        let transactionID = initial.transactionID
        try preparationExecutor.validateEdge(previous: previous, candidate: candidate,
                                              transition: initial.transition)
        guard executor.authorization.matchesSource(previous),
              executor.authorization.matchesDestination(candidate),
              executor.authorization.matchesTransition(initial.transition) else { throw Failure.invalidState }
        var prepared: VPNRescuePreparationContext?
        var pending: VPNRescueJournalContext?
        if initial.phase == .prepared, initial.revision == 0 {
            let context = try VPNRescuePreparationContext.capture(
                authorization: preparationExecutor.authorization, candidate: candidate,
                transition: initial.transition, store: store, lease: lease)
            guard context.state == .prepared(transactionID) else { throw Failure.invalidState }
            prepared = context
        } else if initial.phase == .replacementPending, initial.revision == 1 {
            pending = try VPNRescueJournalContext.capture(authorization: executor.authorization,
                                                          store: store, lease: lease)
        } else { throw Failure.invalidState }

        func validate() throws {
            try lease.check()
            guard try lease.checkedStorageIdentity() == store.storageIdentity() else { throw Failure.invalidState }
            if let prepared { try prepared.validate() }
            else if let pending {
                try pending.validate()
                guard pending.transactionID == transactionID else { throw Failure.invalidState }
            } else { throw Failure.invalidState }
            try preparationExecutor.validateEdge(previous: previous, candidate: candidate,
                                                  transition: initial.transition)
            try executor.revalidate()
        }
        func checkedCheckpoint(_ point: String) throws { try checkpoint(point); try validate() }
        func installedCandidate() throws -> Bool {
            let source = try? VPNStagedApplication.inspectInstalled(inApplicationsDirectory: destination,
                ownerUserID: 0, productionParent: mode.productionDestination, release: previous)
            let next = try? VPNStagedApplication.inspectInstalled(inApplicationsDirectory: destination,
                ownerUserID: 0, productionParent: mode.productionDestination, release: candidate)
            guard (source == nil) != (next == nil) else { throw Failure.invalidState }
            return next != nil
        }
        try validate()
        let layout = try VPNApplicationTransactionStager.validatePreparedOrExchanged(
            inTrustedDirectory: update, previous: previous, candidate: candidate,
            transition: initial.transition)
        let alreadyInstalled = try installedCandidate()
        guard !(prepared != nil && (layout == .exchanged || alreadyInstalled)),
              !(alreadyInstalled && layout != .exchanged) else { throw Failure.invalidState }
        try validate()

        var armed = false, drained = false
        func arm() throws {
            try validate()
            if !armed {
                try armCandidateRecovery(initial.candidate)
                try checkedCheckpoint("afterArm")
                armed = true
            }
        }
        func drain() throws {
            try validate()
            if !drained {
                try drainPreviousService()
                try checkedCheckpoint("afterDrain")
                drained = true
            }
        }
        func authorizeReplacement() throws {
            try arm(); try drain(); try validate()
            if prepared != nil {
                let advanced = try store.markUpdateReplacementPending(
                    transactionID: transactionID, expectedRevision: 0)
                guard advanced.transactionID == transactionID, advanced.revision == 1,
                      advanced.phase == .replacementPending else { throw Failure.invalidState }
                // A crash here resumes from the existing pending journal.
                try checkpoint("afterPending")
                pending = try VPNRescueJournalContext.capture(authorization: executor.authorization,
                                                              store: store, lease: lease)
                prepared = nil
                try validate()
            }
        }
        switch mode {
        #if VPN_RESCUE_SYSTEM_ENTRY
        case .system:
            _ = try VPNProtectedApplicationSwap.rescueExchange(inTrustedDirectory: update,
                previous: previous, candidate: candidate, transition: initial.transition,
                executor: preparationExecutor, authorizeMutation: authorizeReplacement,
                checkpoint: { try checkedCheckpoint("protected:" + $0) })
        #endif
        #if VPN_RESCUE_REPLACEMENT_COORDINATOR_TESTING
        case .fixture:
            _ = try VPNProtectedApplicationSwap.testRescueExchange(inTrustedDirectory: update,
                previous: previous, candidate: candidate, transition: initial.transition,
                executor: preparationExecutor, authorizeMutation: authorizeReplacement,
                checkpoint: { try checkedCheckpoint("protected:" + $0) })
        #endif
        }
        try checkedCheckpoint("afterProtectedSwap")
        guard let pending else { throw Failure.invalidState }
        // A completed destination exchange retains A at the stage name. Never
        // overwrite it by trying to stage B again on a pending-B retry.
        if try !installedCandidate() {
            switch mode {
            #if VPN_RESCUE_SYSTEM_ENTRY
            case .system:
                _ = try VPNApplicationDestinationStage.prepare(inTrustedDirectory: update, release: candidate)
            #endif
            #if VPN_RESCUE_REPLACEMENT_COORDINATOR_TESTING
            case .fixture:
                _ = try VPNApplicationDestinationStage.testPrepare(inTrustedDirectory: update,
                    destination: destination, release: candidate,
                    checkpoint: { try checkedCheckpoint("destinationStage:" + $0) })
            #endif
            }
        }
        try checkedCheckpoint("afterDestinationStage")
        let outcome: VPNApplicationDestinationExchange.Outcome
        switch mode {
        #if VPN_RESCUE_SYSTEM_ENTRY
        case .system:
            outcome = try VPNRescuePendingCoordinator.runSystem(service: service, update: update,
                lease: lease, context: pending, executor: executor,
                armCandidateRecovery: arm, drainPreviousService: drain)
        #endif
        #if VPN_RESCUE_REPLACEMENT_COORDINATOR_TESTING
        case .fixture:
            outcome = try VPNRescuePendingCoordinator.testRun(context: pending, executor: executor,
                inTrustedDirectory: update, destination: destination,
                armCandidateRecovery: arm, drainPreviousService: drain,
                checkpoint: { try checkedCheckpoint("destination:" + $0) })
        #endif
        }
        try validate()
        return outcome
    }
}
#endif
