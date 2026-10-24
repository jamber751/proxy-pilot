import Darwin
import Foundation

#if VPN_RESCUE_PREPARATION && VPN_RESCUE_PREPARATION_COORDINATOR_TESTING
/// Disposable root-fixture entry only. Uses the existing preparation/journal
/// protocol and never supersedes foreign state, drains a service or swaps apps.
enum VPNRescuePreparationCoordinator {
    enum Failure: Error { case requiresRoot }
    enum Outcome { case prepared, resumed, alreadyPrepared }
    struct Result {
        let journal: VPNUpdateJournalSnapshot
        let outcome: Outcome
    }

    static func testPrepare(service: Int32, update: Int32,
                            previousSource: Int32, candidateSource: Int32,
                            payload: VPNJointUpdatePayload, authority: VPNReleaseAuthority,
                            executor: VPNRescuePreparationExecutor,
                            checkpoint: (String) throws -> Void = { _ in }) throws -> Result {
        guard getuid() == 0, geteuid() == 0 else {
            throw Failure.requiresRoot
        }
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
        defer { lease.release() }
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
        func capture() throws -> VPNRescuePreparationContext {
            try executor.validateEdge(previous: payload.previous,
                candidate: payload.candidate.release, transition: payload.transition)
            return try VPNRescuePreparationContext.capture(authorization: executor.authorization,
                candidate: payload.candidate.release, transition: payload.transition,
                store: store, lease: lease)
        }
        var context = try capture()
        let initialState = context.state
        func validate() throws {
            try context.validate()
            try executor.validateEdge(previous: payload.previous,
                candidate: payload.candidate.release, transition: payload.transition)
        }
        func advanced(to expected: VPNRescuePreparationContext.State) throws {
            let fresh = try capture()
            guard fresh.state == expected, fresh.ownerUserID == context.ownerUserID,
                  fresh.previous.release.isSameRelease(as: context.previous.release) else {
                throw VPNRescuePreparationContextError.changed
            }
            context = fresh
            try validate()
        }

        // Reject incompatible/invalid input trees before creating authority.
        _ = try VPNStagedApplication.inspectInstalled(inApplicationsDirectory: previousSource,
            ownerUserID: 0, productionParent: false, release: payload.previous)
        let candidate = try VPNStagedApplication.inspect(inTrustedDirectory: candidateSource,
            release: payload.candidate.release)
        try VPNStagedApplication.requireUpdateExecutorCompatibility(candidate,
            inApplicationsDirectory: candidateSource)
        try validate()

        if context.state == .clean {
            let preparation = try store.beginUpdatePreparation(payload: payload.candidate.manifest,
                signature: payload.candidate.signature, helper: payload.candidate.helper,
                engine: payload.candidate.engine, transitionPayload: payload.transitionPayload,
                transitionSignature: payload.transitionSignature,
                expectedSequence: payload.previous.sequence)
            try checkpoint("afterPreparation")
            try advanced(to: .staging(preparation.transactionID))
        }
        if case .conversionPending(let transactionID) = context.state {
            try validate()
            _ = try store.commitUpdatePreparation(transactionID: transactionID,
                helper: payload.candidate.helper, engine: payload.candidate.engine)
            try checkpoint("afterConversion")
            try advanced(to: .prepared(transactionID))
        }

        try validate()
        let staging = try VPNApplicationTransactionStager.testRescuePrepare(base: update,
            previousSource: previousSource, candidateSource: candidateSource,
            previous: payload.previous, candidate: payload.candidate.release,
            transition: payload.transition, executor: executor)
        try checkpoint("afterApplicationStaging")
        try validate()
        if case .staging(let transactionID) = context.state {
            _ = try store.commitUpdatePreparation(transactionID: transactionID,
                helper: payload.candidate.helper, engine: payload.candidate.engine)
            try checkpoint("afterJournal")
            try advanced(to: .prepared(transactionID))
        }
        guard case .prepared(let transactionID) = context.state else {
            throw VPNRescuePreparationContextError.invalidPreparationState
        }
        try validate()
        let provisioned = try VPNReplacementExecutorProvisioner.prepare(
            inTrustedDirectory: update, release: payload.previous)
        try checkpoint("afterExecutor")
        try validate()
        guard let journal = try store.loadUpdateJournal(), journal.transactionID == transactionID else {
            throw VPNRescuePreparationContextError.changed
        }
        let outcome: Outcome
        if case .prepared = initialState, staging == .alreadyStaged, provisioned == .alreadyPrepared {
            outcome = .alreadyPrepared
        } else if initialState == .clean, staging == .staged, provisioned == .prepared {
            outcome = .prepared
        } else {
            outcome = .resumed
        }
        return Result(journal: journal, outcome: outcome)
    }
}
#endif
