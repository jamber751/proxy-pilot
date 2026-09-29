import Darwin
import Dispatch
import Foundation

enum VPNUpdateBrokerRotationError: Error {
    case invalidTransaction
}

/// Completes the broker half of an authenticated A→B replacement. A broker
/// receipt is only an index: every call reopens the content-addressed inbox,
/// verifies its signatures, and binds it to the signed completed journal and
/// the selected B deployment before changing launchd ownership.
enum VPNUpdateBrokerRotation {
    struct Completion {
        let identity: Data
        let fromSequence: UInt64
        let toSequence: UInt64
        let journal: VPNUpdateBrokerJournalReference
        let candidate: VPNAuthorizedDeployment
    }

    static func rotateIfRequired(
        serviceDirectory: Int32, store: VPNReleaseStore,
        lease: VPNLifecycleLease, journal: VPNUpdateJournalSnapshot,
        authority: VPNReleaseAuthority
    ) throws -> Completion? {
        let brokerDirectory: Int32
        do {
            brokerDirectory = try VPNDirectoryProvisioner
                .openSystemBrokerDirectory(create: false)
        } catch {
            // Legacy, non-broker updates have no broker state. Once the
            // directory exists, all malformed or mismatched state fails closed.
            return nil
        }
        defer { close(brokerDirectory) }
        let transactions = try VPNUpdateBrokerTransactionStore(
            trustedDirectoryDescriptor: brokerDirectory)
        guard var transaction = try transactions.load() else { return nil }
        if transaction.phase == .complete { return nil }
        guard transaction.phase == .handoffStarted
                || transaction.phase == .handoffComplete
                || transaction.phase == .rotatingBroker,
              let recorded = transaction.journal,
              recorded.transactionID == journal.transactionID,
              recorded.revision <= journal.revision,
              (recorded.phase == .prepared
                || recorded.phase == .replacementPending
                || recorded.phase == .completed),
              transaction.fromSequence == journal.previous.release.sequence,
              transaction.toSequence == journal.candidate.release.sequence,
              journal.phase == .completed,
              journal.recovery == .completed else {
            throw VPNUpdateBrokerRotationError.invalidTransaction
        }
        try lease.check()
        guard let current = try store.loadUpdateJournal(),
              current.transactionID == journal.transactionID,
              current.revision == journal.revision,
              current.phase == .completed,
              current.recovery == .completed else {
            throw VPNUpdateBrokerRotationError.invalidTransaction
        }
        let selected = try store.loadDeployment()
        guard selected.ownerUserID == journal.candidate.ownerUserID,
              selected.release.isSameRelease(as: journal.candidate.release) else {
            throw VPNUpdateBrokerRotationError.invalidTransaction
        }

        let inbox = try VPNUpdateBrokerInbox(trustedParent: brokerDirectory)
        let published = try inbox.openPublished(identity: transaction.identity)
        defer { close(published) }
        let payload = try VPNJointUpdatePayload.loadForBroker(
            inTrustedDirectory: published, authority: authority)
        guard payload.previous.isSameRelease(as: journal.previous.release),
              payload.candidate.release.isSameRelease(as: journal.candidate.release),
              payload.transition.matchesSource(journal.previous.release),
              payload.transition.matchesDestination(journal.candidate.release),
              journal.transition.matchesSource(payload.previous),
              journal.transition.matchesDestination(payload.candidate.release) else {
            throw VPNUpdateBrokerRotationError.invalidTransaction
        }

        let reference = brokerJournal(journal)
        transaction = try transactions.advance(
            identity: transaction.identity,
            expectedRevision: transaction.revision,
            phase: .handoffComplete, journal: reference,
            recovery: .executorCommitted, rotation: .pending)
        try lease.check()
        let job = try VPNUpdateBrokerLaunchdJob.system(
            storageDirectory: serviceDirectory)
        try job.installAndStart(
            journal.candidate,
            deadline: DispatchTime.now().uptimeNanoseconds + 20_000_000_000)
        try lease.check()
        _ = try transactions.advance(
            identity: transaction.identity,
            expectedRevision: transaction.revision,
            phase: .rotatingBroker, journal: reference,
            recovery: .executorCommitted, rotation: .complete)
        return Completion(
            identity: transaction.identity,
            fromSequence: transaction.fromSequence,
            toSequence: transaction.toSequence, journal: reference,
            candidate: journal.candidate)
    }

    /// Called only after the same signed journal was retired under the same
    /// service lease. It publishes bounded completion; it does not authorize or
    /// repeat any protected mutation.
    static func finish(_ completion: Completion, serviceDirectory: Int32,
                       lease: VPNLifecycleLease,
                       authority: VPNReleaseAuthority) throws {
        try lease.check()
        let store = try VPNReleaseStore(
            trustedDirectoryDescriptor: serviceDirectory,
            authority: authority)
        try store.requireNoPendingUpdate()
        let selected = try store.loadDeployment()
        guard selected.ownerUserID == completion.candidate.ownerUserID,
              selected.release.isSameRelease(as: completion.candidate.release),
              selected.release.sequence == completion.toSequence else {
            throw VPNUpdateBrokerRotationError.invalidTransaction
        }
        try lease.check()
        let brokerDirectory = try VPNDirectoryProvisioner
            .openSystemBrokerDirectory(create: false)
        defer { close(brokerDirectory) }
        let transactions = try VPNUpdateBrokerTransactionStore(
            trustedDirectoryDescriptor: brokerDirectory)
        guard let current = try transactions.load(),
              current.identity == completion.identity,
              current.phase == .rotatingBroker,
              current.rotation == .complete,
              current.journal == completion.journal else {
            throw VPNUpdateBrokerRotationError.invalidTransaction
        }
        _ = try transactions.advance(
            identity: current.identity, expectedRevision: current.revision,
            phase: .complete, journal: completion.journal,
            recovery: .complete, rotation: .complete)
        let statuses = try VPNUpdateBrokerStatusStore(
            trustedDirectoryDescriptor: brokerDirectory)
        _ = try statuses.publish(
            state: .complete, fromSequence: completion.fromSequence,
            toSequence: completion.toSequence)
    }

    private static func brokerJournal(_ value: VPNUpdateJournalSnapshot)
        -> VPNUpdateBrokerJournalReference {
        // Rotation is only legal after finalization has committed `completed`.
        VPNUpdateBrokerJournalReference(
            transactionID: value.transactionID, revision: value.revision,
            phase: .completed)
    }
}
