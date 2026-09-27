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
        let update = try VPNDirectoryProvisioner.openSystemUpdateDirectory(create: true)
        defer { close(update) }
        return try perform(
            service: service, update: update, payload: payload, authority: authority,
            authenticateCandidate: {},
            stage: {
                try VPNApplicationTransactionStager.prepare(
                    candidateDirectory: candidateDirectory,
                    previousOwnerUserID: $0,
                    previous: payload.previous,
                    candidate: payload.candidate.release,
                    transition: payload.transition)
            },
            provision: {
                try VPNReplacementExecutorProvisioner.prepare(
                    inTrustedDirectory: update, release: payload.previous)
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
            service: service, update: update, payload: payload, authority: authority,
            authenticateCandidate: {
                try VPNPeerAuthentication.validateCurrentProcess(
                    policy: VPNPeerAuthentication.testCurrentPolicy(userID: geteuid()))
            },
            stage: { owner in
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
            provision: {
                try VPNReplacementExecutorProvisioner.testPrepare(
                    inTrustedDirectory: update, release: payload.previous)
            }, checkpoint: checkpoint)
    }
    #endif

    private static func perform(
        service: Int32, update: Int32,
        payload: VPNJointUpdatePayload,
        authority: VPNReleaseAuthority,
        authenticateCandidate: () throws -> Void,
        stage: (uid_t) throws -> VPNApplicationTransactionStager.Outcome,
        provision: () throws -> VPNReplacementExecutorProvisioner.Outcome,
        checkpoint: (String) throws -> Void) throws -> Result {
        try authenticateCandidate()
        let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
        defer { lease.release() }
        let store = try VPNReleaseStore(
            trustedDirectoryDescriptor: service, authority: authority)
        let current = try store.loadDeployment()
        guard current.release.isSameRelease(as: payload.previous),
              payload.transition.matchesSource(current.release),
              payload.transition.matchesDestination(payload.candidate.release) else {
            throw VPNJointUpdatePreparationError.invalidState
        }

        func existingPrepared() throws -> VPNUpdateJournalSnapshot? {
            guard let journal = try store.loadUpdateJournal() else { return nil }
            guard journal.phase == .prepared,
                  journal.recovery == .canCancelOrReplace,
                  journal.revision == 0,
                  journal.previous.ownerUserID == current.ownerUserID,
                  journal.previous.release.isSameRelease(as: payload.previous),
                  journal.candidate.release.isSameRelease(as: payload.candidate.release),
                  journal.transition.matchesSource(payload.previous),
                  journal.transition.matchesDestination(payload.candidate.release) else {
                throw VPNJointUpdatePreparationError.invalidState
            }
            return journal
        }

        let before = try existingPrepared()
        try lease.check()
        let staging = try stage(current.ownerUserID)
        try checkpoint("afterApplicationStaging")
        try lease.check()
        guard (try store.loadDeployment()).release.isSameRelease(as: payload.previous) else {
            throw VPNJointUpdatePreparationError.invalidState
        }

        let journal: VPNUpdateJournalSnapshot
        if let before {
            journal = before
        } else {
            journal = try store.prepareUpdateJournal(
                payload: payload.candidate.manifest,
                signature: payload.candidate.signature,
                helper: payload.candidate.helper,
                engine: payload.candidate.engine,
                transitionPayload: payload.transitionPayload,
                transitionSignature: payload.transitionSignature,
                expectedSequence: payload.previous.sequence)
        }
        try checkpoint("afterJournal")
        try lease.check()
        let executor = try provision()
        try checkpoint("afterExecutor")
        try lease.check()
        guard let final = try existingPrepared(),
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
