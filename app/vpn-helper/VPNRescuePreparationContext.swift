import Darwin
import Foundation

enum VPNRescuePreparationContextError: Error {
    case mismatchedStorage, invalidPreparationState, changed
}

/// Read-only selected-source binding. It grants no live/root/staging authority.
/// An intentional state advance requires a fresh capture; foreign state is never
/// superseded or cleaned up here. Production must supply fixed protected storage.
final class VPNRescuePreparationContext {
    enum State: Equatable {
        case clean
        case staging(UUID)
        case prepared(UUID)
        case conversionPending(UUID)
    }
    let state: State
    let ownerUserID: uid_t
    let previous: VPNAuthorizedDeployment
    let candidate: VerifiedVPNRelease
    let transition: VerifiedVPNUpdateTransition
    private let authorization: VerifiedVPNRescuePreparationAuthorization
    private let store: VPNReleaseStore
    private let lease: VPNLifecycleLease
    private let storage: (device: UInt64, inode: UInt64)

    private init(authorization: VerifiedVPNRescuePreparationAuthorization, store: VPNReleaseStore,
                 lease: VPNLifecycleLease, candidate: VerifiedVPNRelease,
                 transition: VerifiedVPNUpdateTransition, selected: VPNAuthorizedDeployment,
                 state: State, storage: (device: UInt64, inode: UInt64)) {
        self.authorization = authorization; self.store = store; self.lease = lease
        self.candidate = candidate; self.transition = transition; previous = selected
        ownerUserID = selected.ownerUserID; self.state = state; self.storage = storage
    }

    static func capture(authorization: VerifiedVPNRescuePreparationAuthorization,
                        candidate: VerifiedVPNRelease, transition: VerifiedVPNUpdateTransition,
                        store: VPNReleaseStore, lease: VPNLifecycleLease) throws -> VPNRescuePreparationContext {
        let storage = try boundStorage(store: store, lease: lease)
        let (selected, state) = try inspect(authorization: authorization, candidate: candidate,
            transition: transition, store: store, lease: lease)
        let result = VPNRescuePreparationContext(authorization: authorization, store: store,
            lease: lease, candidate: candidate, transition: transition, selected: selected,
            state: state, storage: storage)
        try result.validate()
        return result
    }

    func validate() throws {
        guard try Self.boundStorage(store: store, lease: lease) == storage else {
            throw VPNRescuePreparationContextError.changed
        }
        let (selected, fresh) = try Self.inspect(authorization: authorization, candidate: candidate,
            transition: transition, store: store, lease: lease)
        guard fresh == state, selected.ownerUserID == ownerUserID,
              selected.release.isSameRelease(as: previous.release),
              try Self.boundStorage(store: store, lease: lease) == storage else {
            throw VPNRescuePreparationContextError.changed
        }
    }

    func checkedStorageIdentity(holding lease: VPNLifecycleLease) throws -> (device: UInt64, inode: UInt64) {
        guard self.lease === lease else { throw VPNRescuePreparationContextError.mismatchedStorage }
        try validate()
        return storage
    }

    private static func boundStorage(store: VPNReleaseStore, lease: VPNLifecycleLease) throws
        -> (device: UInt64, inode: UInt64) {
        let locked = try lease.checkedStorageIdentity(), stored = try store.storageIdentity()
        guard locked == stored else { throw VPNRescuePreparationContextError.mismatchedStorage }
        try lease.check()
        return stored
    }

    private static func inspect(authorization: VerifiedVPNRescuePreparationAuthorization,
                                candidate: VerifiedVPNRelease, transition: VerifiedVPNUpdateTransition,
                                store: VPNReleaseStore, lease: VPNLifecycleLease) throws
        -> (VPNAuthorizedDeployment, State) {
        _ = try boundStorage(store: store, lease: lease)
        guard try store.loadUpdateCleanupReceipt() == nil else {
            throw VPNRescuePreparationContextError.invalidPreparationState
        }
        let selected = try store.loadDeployment()
        guard selected.ownerUserID >= 500, selected.ownerUserID != uid_t.max,
              authorization.matchesSource(selected.release), authorization.matchesDestination(candidate),
              authorization.matchesTransition(transition) else {
            throw VPNRescuePreparationContextError.invalidPreparationState
        }
        let preparation = try store.loadUpdatePreparation(), journal = try store.loadUpdateJournal()
        func exact(_ previous: VPNAuthorizedDeployment, _ next: VPNAuthorizedDeployment,
                   _ edge: VerifiedVPNUpdateTransition) -> Bool {
            previous.ownerUserID == selected.ownerUserID && next.ownerUserID == selected.ownerUserID
                && previous.release.isSameRelease(as: selected.release)
                && next.release.isSameRelease(as: candidate) && authorization.matchesTransition(edge)
        }
        if let preparation {
            guard preparation.phase == .staging, preparation.cleanupRoots == nil,
                  preparation.ownerUserID == selected.ownerUserID,
                  exact(preparation.previous, preparation.candidate, preparation.transition) else {
                throw VPNRescuePreparationContextError.invalidPreparationState
            }
        }
        if let journal {
            guard journal.phase == .prepared, journal.revision == 0,
                  journal.recovery == .canCancelOrReplace, journal.cancellationGCRoots == nil,
                  exact(journal.previous, journal.candidate, journal.transition) else {
                throw VPNRescuePreparationContextError.invalidPreparationState
            }
        }
        let state: State
        switch (preparation, journal) {
        case (nil, nil): state = .clean
        case (let preparation?, nil): state = .staging(preparation.transactionID)
        case (nil, let journal?): state = .prepared(journal.transactionID)
        case (let preparation?, let journal?):
            guard preparation.transactionID == journal.transactionID else {
                throw VPNRescuePreparationContextError.invalidPreparationState
            }
            state = .conversionPending(journal.transactionID)
        }
        let after = try store.loadDeployment()
        guard after.ownerUserID == selected.ownerUserID,
              after.release.isSameRelease(as: selected.release) else {
            throw VPNRescuePreparationContextError.changed
        }
        _ = try boundStorage(store: store, lease: lease)
        return (selected, state)
    }
}
