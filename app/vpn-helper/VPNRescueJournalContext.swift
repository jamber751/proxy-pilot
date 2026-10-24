import Darwin
import Foundation

enum VPNRescueJournalContextError: Error {
    case mismatchedStorage, invalidPendingState, changed
}

/// Read-only binding to ONE exact pending journal under ONE live lifecycle
/// lease. This does not authenticate a rescue executable, authorize root work,
/// inspect installed/staged apps, drain a service, mutate or retire a journal.
/// Production must obtain the store/lease from fixed protected system storage.
/// Keeping the object alive is not enough: validate immediately at every action
/// boundary. Releasing/replacing the lease permanently invalidates this context.
final class VPNRescueJournalContext {
    let transactionID: UUID
    let revision: UInt64
    let ownerUserID: uid_t
    let previous: VPNAuthorizedDeployment
    let candidate: VPNAuthorizedDeployment
    private let authorization: VerifiedVPNRescueAuthorization
    private let store: VPNReleaseStore
    private let lease: VPNLifecycleLease
    private let storage: (device: UInt64, inode: UInt64)

    private init(authorization: VerifiedVPNRescueAuthorization, store: VPNReleaseStore,
                 lease: VPNLifecycleLease, journal: VPNUpdateJournalSnapshot,
                 storage: (device: UInt64, inode: UInt64)) {
        self.authorization = authorization; self.store = store; self.lease = lease
        self.storage = storage
        transactionID = journal.transactionID; revision = journal.revision
        ownerUserID = journal.previous.ownerUserID
        previous = journal.previous; candidate = journal.candidate
    }

    static func capture(authorization: VerifiedVPNRescueAuthorization,
                        store: VPNReleaseStore, lease: VPNLifecycleLease) throws
        -> VPNRescueJournalContext {
        let storage = try boundStorage(store: store, lease: lease)
        let journal = try pending(authorization: authorization, store: store, lease: lease)
        let result = VPNRescueJournalContext(authorization: authorization, store: store,
            lease: lease, journal: journal, storage: storage)
        try result.validate()
        return result
    }

    func validate() throws {
        guard try Self.boundStorage(store: store, lease: lease) == storage else {
            throw VPNRescueJournalContextError.changed
        }
        let fresh = try Self.pending(authorization: authorization, store: store, lease: lease)
        guard fresh.transactionID == transactionID, fresh.revision == revision,
              fresh.previous.ownerUserID == ownerUserID,
              fresh.candidate.ownerUserID == ownerUserID,
              fresh.previous.release.isSameRelease(as: previous.release),
              fresh.candidate.release.isSameRelease(as: candidate.release) else {
            throw VPNRescueJournalContextError.changed
        }
        guard try Self.boundStorage(store: store, lease: lease) == storage else {
            throw VPNRescueJournalContextError.changed
        }
    }

    private static func boundStorage(store: VPNReleaseStore, lease: VPNLifecycleLease) throws
        -> (device: UInt64, inode: UInt64) {
        let locked = try lease.checkedStorageIdentity()
        let stored = try store.storageIdentity()
        guard locked == stored else { throw VPNRescueJournalContextError.mismatchedStorage }
        try lease.check()
        return stored
    }

    private static func pending(authorization: VerifiedVPNRescueAuthorization,
                                store: VPNReleaseStore, lease: VPNLifecycleLease) throws
        -> VPNUpdateJournalSnapshot {
        _ = try boundStorage(store: store, lease: lease)
        // Preparation conversion/cleanup must be resolved by their own trusted
        // coordinators. A read-only rescue gate never repairs ambiguous records.
        guard try store.loadUpdatePreparation() == nil,
              try store.loadUpdateCleanupReceipt() == nil else {
            throw VPNRescueJournalContextError.invalidPendingState
        }
        let selected = try store.loadDeployment()
        guard let journal = try store.loadUpdateJournal(),
              journal.phase == .replacementPending, journal.recovery == .inspectApplication,
              journal.previous.ownerUserID >= 500, journal.previous.ownerUserID != uid_t.max,
              journal.previous.ownerUserID == journal.candidate.ownerUserID,
              selected.ownerUserID == journal.previous.ownerUserID,
              selected.release.isSameRelease(as: journal.previous.release),
              authorization.matchesSource(journal.previous.release),
              authorization.matchesDestination(journal.candidate.release),
              authorization.matchesTransition(journal.transition) else {
            throw VPNRescueJournalContextError.invalidPendingState
        }
        let selectedAfter = try store.loadDeployment()
        guard selectedAfter.ownerUserID == selected.ownerUserID,
              selectedAfter.release.isSameRelease(as: selected.release) else {
            throw VPNRescueJournalContextError.changed
        }
        _ = try boundStorage(store: store, lease: lease)
        return journal
    }
}
