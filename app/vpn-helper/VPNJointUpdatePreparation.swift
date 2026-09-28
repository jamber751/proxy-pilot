import Darwin
import Foundation

enum VPNJointUpdatePreparationError: Error {
    case requiresRoot, invalidState, commitUncertain
}

/// Stages exact application A/B, persists the signed helper/app journal, and
/// provisions executor A without stopping a service or changing either selector.
/// Lock order is always service lifecycle, then application namespace.
enum VPNJointUpdatePreparation {
    enum Outcome { case prepared, resumed, alreadyPrepared }
    struct Result {
        let journal: VPNUpdateJournalSnapshot
        let outcome: Outcome
    }

    static func prepare(candidateDirectory: Int32,
                        payload: VPNJointUpdatePayload,
                        authority: VPNReleaseAuthority) throws -> Result {
        guard getuid() == 0, geteuid() == 0 else {
            throw VPNJointUpdatePreparationError.requiresRoot
        }
        try VPNPeerAuthentication.validateCurrentProcess(
            policy: payload.candidate.release.installerPolicy())
        let service = try VPNDirectoryProvisioner.openSystemDirectory(create: false)
        defer { close(service) }
        return try perform(
            service: service, payload: payload, authority: authority,
            authenticateCandidate: {},
            cleanupCompleted: { lease in
                try VPNJointUpdateCleanup.completeSystem(
                    service: service, lease: lease, authority: authority)
            },
            openUpdate: { try VPNDirectoryProvisioner.openSystemUpdateDirectory(create: true) },
            stage: { update, owner in
                try VPNApplicationTransactionStager.prepare(
                    candidateDirectory: candidateDirectory,
                    previousOwnerUserID: owner,
                    previous: payload.previous,
                    candidate: payload.candidate.release,
                    transition: payload.transition)
            },
            provision: { update in
                try VPNReplacementExecutorProvisioner.prepare(
                    inTrustedDirectory: update, release: payload.previous)
            }, validatePending: { update in
                _ = try VPNApplicationTransactionStager.validatePreparedOrExchanged(
                    inTrustedDirectory: update, previous: payload.previous,
                    candidate: payload.candidate.release,
                    transition: payload.transition)
                let executor = try VPNReplacementExecutor.inspectPrepared(
                    inTrustedDirectory: update, release: payload.previous)
                try executor.revalidatePrepared()
            }, checkpoint: { _ in })
    }

    #if VPN_JOINT_UPDATE_PREPARATION_TESTING
    static func testPrepare(service: Int32, update: Int32,
                            previousSource: Int32, candidateSource: Int32,
                            payload: VPNJointUpdatePayload,
                            authority: VPNReleaseAuthority,
                            checkpoint: (String) throws -> Void = { _ in }) throws -> Result {
        guard getuid() != 0, geteuid() == getuid() else {
            throw VPNPeerAuthenticationError.denied
        }
        return try perform(
            service: service, payload: payload, authority: authority,
            authenticateCandidate: {
                try VPNPeerAuthentication.validateCurrentProcess(
                    policy: VPNPeerAuthentication.testCurrentPolicy(userID: geteuid()))
            },
            cleanupCompleted: { _ in },
            openUpdate: {
                let copy = fcntl(update, F_DUPFD_CLOEXEC, 0)
                guard copy >= 0 else { throw VPNJointUpdatePreparationError.invalidState }
                return copy
            },
            stage: { update, owner in
                guard owner == geteuid() else {
                    throw VPNJointUpdatePreparationError.invalidState
                }
                return try VPNApplicationTransactionStager.testPrepare(
                    base: update, previousSource: previousSource,
                    candidateSource: candidateSource,
                    previous: payload.previous,
                    candidate: payload.candidate.release,
                    transition: payload.transition)
            },
            provision: { update in
                try VPNReplacementExecutorProvisioner.testPrepare(
                    inTrustedDirectory: update, release: payload.previous)
            }, validatePending: { update in
                _ = try VPNApplicationTransactionStager.testValidatePreparedOrExchanged(
                    inTrustedDirectory: update, previous: payload.previous,
                    candidate: payload.candidate.release,
                    transition: payload.transition)
                let executor = try VPNReplacementExecutor.inspectPrepared(
                    inTrustedDirectory: update, release: payload.previous)
                try executor.revalidatePrepared()
            }, checkpoint: checkpoint)
    }
    #endif

    private static func perform(
        service: Int32,
        payload: VPNJointUpdatePayload,
        authority: VPNReleaseAuthority,
        authenticateCandidate: () throws -> Void,
        cleanupCompleted: (VPNLifecycleLease) throws -> Void,
        openUpdate: () throws -> Int32,
        stage: (Int32, uid_t) throws -> VPNApplicationTransactionStager.Outcome,
        provision: (Int32) throws -> VPNReplacementExecutorProvisioner.Outcome,
        validatePending: (Int32) throws -> Void,
        checkpoint: (String) throws -> Void) throws -> Result {
        try authenticateCandidate()
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
        defer { lease.release() }
        let store = try VPNReleaseStore(
            trustedDirectoryDescriptor: service, authority: authority)
        // Before touching A/B/executor staging, finish any authenticated prior
        // cleanup while this same service lease owns the transition.
        try cleanupCompleted(lease)
        try lease.check()
        let current = try store.loadDeployment()
        guard current.release.isSameRelease(as: payload.previous),
              payload.transition.matchesSource(current.release),
              payload.transition.matchesDestination(payload.candidate.release) else {
            throw VPNJointUpdatePreparationError.invalidState
        }

        func existingJournal() throws -> VPNUpdateJournalSnapshot? {
            guard let journal = try store.loadUpdateJournal() else { return nil }
            let prepared = journal.phase == .prepared
                && journal.recovery == .canCancelOrReplace && journal.revision == 0
            let pending = journal.phase == .replacementPending
                && journal.recovery == .inspectApplication && journal.revision == 1
            guard prepared || pending,
                  journal.previous.ownerUserID == current.ownerUserID,
                  journal.previous.release.isSameRelease(as: payload.previous),
                  journal.candidate.release.isSameRelease(as: payload.candidate.release),
                  journal.transition.matchesSource(payload.previous),
                  journal.transition.matchesDestination(payload.candidate.release) else {
                throw VPNJointUpdatePreparationError.invalidState
            }
            return journal
        }

        var before = try existingJournal()
        if before == nil {
            let preparation = try store.beginUpdatePreparation(
                payload: payload.candidate.manifest,
                signature: payload.candidate.signature,
                helper: payload.candidate.helper, engine: payload.candidate.engine,
                transitionPayload: payload.transitionPayload,
                transitionSignature: payload.transitionSignature,
                expectedSequence: payload.previous.sequence)
            try checkpoint("afterPreparation")
            try lease.check()
            // A crash after update.json commit leaves both records. The same
            // package proves equality and completes the ordered unlink before
            // any namespace is touched again.
            if try store.loadUpdateJournal() != nil {
                _ = try store.commitUpdatePreparation(
                    transactionID: preparation.transactionID,
                    helper: payload.candidate.helper,
                    engine: payload.candidate.engine)
                before = try existingJournal()
            }
        } else if try store.loadUpdatePreparation() != nil {
            // Existing-journal behavior is unchanged except for finishing the
            // crash-safe conversion when both canonical records are present.
            let preparation = try store.beginUpdatePreparation(
                payload: payload.candidate.manifest,
                signature: payload.candidate.signature,
                helper: payload.candidate.helper, engine: payload.candidate.engine,
                transitionPayload: payload.transitionPayload,
                transitionSignature: payload.transitionSignature,
                expectedSequence: payload.previous.sequence)
            _ = try store.commitUpdatePreparation(
                transactionID: preparation.transactionID,
                helper: payload.candidate.helper,
                engine: payload.candidate.engine)
            before = try existingJournal()
        }
        // The canonical preparation authority is durable before creating or
        // opening the application staging namespace.
        let update = try openUpdate()
        defer { close(update) }
        if let before, before.phase == .replacementPending {
            // Once replacement is pending, A may already have left
            // /Applications and the protected slots may already be B/A. Resume
            // exclusively from the signed journal and protected A/B/executor
            // material. Re-staging from the live destination could reverse the
            // transaction or reject a safe post-swap retry.
            try lease.check()
            try validatePending(update)
            try checkpoint("afterPendingValidation")
            try lease.check()
            guard let final = try existingJournal(),
                  final.transactionID == before.transactionID,
                  final.revision == before.revision else {
                throw VPNJointUpdatePreparationError.commitUncertain
            }
            return Result(journal: final, outcome: .alreadyPrepared)
        }
        try lease.check()
        let staging = try stage(update, current.ownerUserID)
        try checkpoint("afterApplicationStaging")
        try lease.check()
        guard (try store.loadDeployment()).release.isSameRelease(as: payload.previous) else {
            throw VPNJointUpdatePreparationError.invalidState
        }

        let journal: VPNUpdateJournalSnapshot
        if let before {
            journal = before
        } else {
            guard let preparation = try store.loadUpdatePreparation() else {
                throw VPNJointUpdatePreparationError.commitUncertain
            }
            journal = try store.commitUpdatePreparation(
                transactionID: preparation.transactionID,
                helper: payload.candidate.helper, engine: payload.candidate.engine)
        }
        try checkpoint("afterJournal")
        try lease.check()
        let executor = try provision(update)
        try checkpoint("afterExecutor")
        try lease.check()
        guard let final = try existingJournal(),
              final.transactionID == journal.transactionID,
              final.revision == journal.revision else {
            throw VPNJointUpdatePreparationError.commitUncertain
        }
        if before != nil,
           staging == .alreadyStaged,
           executor == .alreadyPrepared {
            return Result(journal: final, outcome: .alreadyPrepared)
        }
        if before != nil || staging != .staged || executor != .prepared {
            return Result(journal: final, outcome: .resumed)
        }
        return Result(journal: final, outcome: .prepared)
    }
}
