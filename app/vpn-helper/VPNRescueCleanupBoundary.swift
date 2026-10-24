import Darwin
import Foundation

#if VPN_EXPLICIT_RESCUE && VPN_JOINT_UPDATE_CLEANUP_ROOT_TESTING
/// Test-only bridge to the existing cleanup engine. No system entry is exposed.
/// The engine retains its installed-B checks and inode-bound deletion walker.
/// One lease serializes receipt writes; only explicit expected phase advances
/// may replace this gate's immutable context.
final class VPNRescueCleanupBoundary {
    private var context: VPNRescueCleanupContext
    private let executor: VPNRescueExecutor
    private let store: VPNReleaseStore
    private let lease: VPNLifecycleLease
    private let storage: (device: UInt64, inode: UInt64)
    private var finished = false

    init(context: VPNRescueCleanupContext, executor: VPNRescueExecutor,
         store: VPNReleaseStore, lease: VPNLifecycleLease) throws {
        self.context = context; self.executor = executor
        self.store = store; self.lease = lease
        storage = try context.checkedStorageIdentity(holding: lease)
        try validate()
    }

    func validate(receipt: VPNUpdateCleanupReceiptSnapshot? = nil) throws {
        guard !finished, try store.storageIdentity() == storage,
              try context.checkedStorageIdentity(holding: lease) == storage,
              executor.authorization.matchesSource(context.previous.release),
              executor.authorization.matchesDestination(context.candidate.release),
              executor.authorization.matchesTransition(context.transition) else {
            throw VPNRescueCleanupContextError.changed
        }
        try executor.revalidate()
        if let receipt { try requireSnapshot(receipt, context: context) }
    }

    func advanced(to receipt: VPNUpdateCleanupReceiptSnapshot) throws {
        guard !finished,
              (context.cleanupPhase == .pending && receipt.cleanupPhase == .applicationRetired)
                || (context.cleanupPhase == .applicationRetired && receipt.cleanupPhase == .updateRetired)
                || (context.cleanupPhase == .updateRetired && receipt.cleanupPhase == .gcAuthorized) else {
            throw VPNRescueCleanupContextError.changed
        }
        let fresh = try VPNRescueCleanupContext.capture(authorization: executor.authorization,
                                                       store: store, lease: lease)
        guard fresh.transactionID == context.transactionID, fresh.revision == context.revision,
              fresh.ownerUserID == context.ownerUserID,
              fresh.previous.release.isSameRelease(as: context.previous.release),
              fresh.candidate.release.isSameRelease(as: context.candidate.release),
              try fresh.checkedStorageIdentity(holding: lease) == storage else {
            throw VPNRescueCleanupContextError.changed
        }
        try requireSnapshot(receipt, context: fresh)
        context = fresh
        try validate()
    }

    /// Called only after this engine successfully retired the receipt it just
    /// validated. Entry with an already absent receipt cannot reach this point.
    func retired() throws {
        guard !finished, context.cleanupPhase == .gcAuthorized,
              try lease.checkedStorageIdentity() == storage,
              try store.storageIdentity() == storage,
              try store.loadUpdateCleanupReceipt() == nil,
              try store.loadUpdatePreparation() == nil,
              try store.loadUpdateJournal() == nil else {
            throw VPNRescueCleanupContextError.changed
        }
        try executor.revalidate()
        let selected = try store.loadDeployment()
        guard selected.ownerUserID == context.ownerUserID,
              selected.release.isSameRelease(as: context.candidate.release) else {
            throw VPNRescueCleanupContextError.changed
        }
        try lease.check()
        finished = true
    }

    func requireRetired() throws {
        guard finished else { throw VPNRescueCleanupContextError.needsSeparateCompletionProof }
    }

    private func requireSnapshot(_ receipt: VPNUpdateCleanupReceiptSnapshot,
                                 context: VPNRescueCleanupContext) throws {
        guard receipt.transactionID == context.transactionID, receipt.revision == context.revision,
              receipt.ownerUserID == context.ownerUserID, receipt.cleanupPhase == context.cleanupPhase,
              receipt.gcRoots == context.gcRoots,
              receipt.previous.release.isSameRelease(as: context.previous.release),
              receipt.candidate.release.isSameRelease(as: context.candidate.release),
              executor.authorization.matchesTransition(receipt.transition) else {
            throw VPNRescueCleanupContextError.changed
        }
    }
}
#endif
