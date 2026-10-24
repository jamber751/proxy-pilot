import Foundation

/// Experimental pending-only orchestration. It never selects, retires, or
/// modifies release state. Production entry is deliberately absent: a future
/// boundary must obtain fixed protected descriptors, hold all required leases,
/// and implement authenticated candidate recovery arming and service draining.
/// Once exchange starts, failure is forward-only; callers must retain recovery
/// and retry the same pending edge, never swap back or cancel the journal.
enum VPNRescuePendingCoordinator {
    #if VPN_EXPLICIT_RESCUE && VPN_APPLICATION_DESTINATION_ROOT_TESTING
    static func testRun(context: VPNRescueJournalContext,
                        executor: VPNRescueExecutor,
                        inTrustedDirectory base: Int32, destination: Int32,
                        armCandidateRecovery: () throws -> Void,
                        drainPreviousService: () throws -> Void,
                        checkpoint: (String) throws -> Void = { _ in }) throws
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
        // Exchange inspects all protected app slots before invoking this
        // callback and independently revalidates them before publication.
        let outcome = try VPNApplicationDestinationExchange.testRescueExchange(
            inTrustedDirectory: base, destination: destination,
            previous: context.previous.release, previousOwnerUserID: context.ownerUserID,
            candidate: context.candidate.release, transition: context.transition,
            executor: executor, authorizeMutation: {
                try validate()
                try armCandidateRecovery()
                try validate()
                try drainPreviousService()
                try validate()
            }, checkpoint: checkpoint)
        try validate()
        return outcome
    }
    #endif
}
