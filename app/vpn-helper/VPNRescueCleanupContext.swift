import Darwin
import Foundation

enum VPNRescueCleanupContextError: Error {
    case mismatchedStorage, invalidCleanupState, needsSeparateCompletionProof, changed
}

/// Read-only binding to one completed exact-edge receipt under one lifecycle
/// lease. This is neither installed-application proof nor deletion authority.
/// Production callers must independently authenticate the live rescue and B.
/// A receipt phase advance requires a new capture; absence is never completion.
final class VPNRescueCleanupContext {
    let transactionID: UUID
    let revision: UInt64
    let ownerUserID: uid_t
    let previous: VPNAuthorizedDeployment
    let candidate: VPNAuthorizedDeployment
    let transition: VerifiedVPNUpdateTransition
    let cleanupPhase: VPNUpdateCleanupPhase
    let gcRoots: [VPNUpdateCleanupRootIdentity]?
    private let authorization: VerifiedVPNRescueAuthorization
    private let store: VPNReleaseStore
    private let lease: VPNLifecycleLease
    private let storage: (device: UInt64, inode: UInt64)

    private init(authorization: VerifiedVPNRescueAuthorization, store: VPNReleaseStore,
                 lease: VPNLifecycleLease, receipt: VPNUpdateCleanupReceiptSnapshot,
                 storage: (device: UInt64, inode: UInt64)) {
        self.authorization = authorization; self.store = store; self.lease = lease
        self.storage = storage
        transactionID = receipt.transactionID; revision = receipt.revision
        ownerUserID = receipt.ownerUserID
        previous = receipt.previous; candidate = receipt.candidate
        transition = receipt.transition; cleanupPhase = receipt.cleanupPhase
        gcRoots = receipt.gcRoots
    }

    static func capture(authorization: VerifiedVPNRescueAuthorization,
                        store: VPNReleaseStore, lease: VPNLifecycleLease) throws
        -> VPNRescueCleanupContext {
        let storage = try boundStorage(store: store, lease: lease)
        let receipt = try completed(authorization: authorization, store: store, lease: lease)
        let result = VPNRescueCleanupContext(authorization: authorization, store: store,
            lease: lease, receipt: receipt, storage: storage)
        try result.validate()
        return result
    }

    func validate() throws {
        guard try Self.boundStorage(store: store, lease: lease) == storage else {
            throw VPNRescueCleanupContextError.changed
        }
        let fresh = try Self.completed(authorization: authorization, store: store, lease: lease)
        guard fresh.transactionID == transactionID, fresh.revision == revision,
              fresh.ownerUserID == ownerUserID, fresh.cleanupPhase == cleanupPhase,
              fresh.gcRoots == gcRoots,
              fresh.previous.release.isSameRelease(as: previous.release),
              fresh.candidate.release.isSameRelease(as: candidate.release) else {
            throw VPNRescueCleanupContextError.changed
        }
        guard try Self.boundStorage(store: store, lease: lease) == storage else {
            throw VPNRescueCleanupContextError.changed
        }
    }

    private static func boundStorage(store: VPNReleaseStore, lease: VPNLifecycleLease) throws
        -> (device: UInt64, inode: UInt64) {
        let locked = try lease.checkedStorageIdentity()
        let stored = try store.storageIdentity()
        guard locked == stored else { throw VPNRescueCleanupContextError.mismatchedStorage }
        try lease.check()
        return stored
    }

    private static func completed(authorization: VerifiedVPNRescueAuthorization,
                                  store: VPNReleaseStore, lease: VPNLifecycleLease) throws
        -> VPNUpdateCleanupReceiptSnapshot {
        _ = try boundStorage(store: store, lease: lease)
        guard try store.loadUpdatePreparation() == nil,
              try store.loadUpdateJournal() == nil else {
            throw VPNRescueCleanupContextError.invalidCleanupState
        }
        guard let receipt = try store.loadUpdateCleanupReceipt() else {
            throw VPNRescueCleanupContextError.needsSeparateCompletionProof
        }
        let selected = try store.loadDeployment()
        guard receipt.phase == .completed, receipt.revision == 3,
              receipt.ownerUserID >= 500, receipt.ownerUserID != uid_t.max,
              receipt.previous.ownerUserID == receipt.ownerUserID,
              receipt.candidate.ownerUserID == receipt.ownerUserID,
              selected.ownerUserID == receipt.ownerUserID,
              selected.release.isSameRelease(as: receipt.candidate.release),
              authorization.matchesSource(receipt.previous.release),
              authorization.matchesDestination(receipt.candidate.release),
              authorization.matchesTransition(receipt.transition) else {
            throw VPNRescueCleanupContextError.invalidCleanupState
        }
        let selectedAfter = try store.loadDeployment()
        guard selectedAfter.ownerUserID == selected.ownerUserID,
              selectedAfter.release.isSameRelease(as: selected.release) else {
            throw VPNRescueCleanupContextError.changed
        }
        _ = try boundStorage(store: store, lease: lease)
        return receipt
    }
}
