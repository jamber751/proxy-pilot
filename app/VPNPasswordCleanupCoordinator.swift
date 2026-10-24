import Foundation

/// One fresh authenticated worker, prepared outside Store.lock. The driver must
/// use the Store's exact pending-reference/locator deletion gate and return
/// .deleted only after that gate has acknowledged removal successfully.
protocol VPNPasswordCleanupSession {
    func deletePendingOutcome(store: VPNStore, reference: VPNPasswordReference) throws -> VPNPasswordDeleteOutcome
}

/// Counts only: no references, paths, item locators or credentials in reporting.
struct VPNPasswordCleanupReport: Equatable {
    var visited = 0
    var deleted = 0
    var retiredWithoutIO = 0
    var pendingSkipped = 0
    var quarantinedSkipped = 0
    var retained = 0
    var prepareFailed = 0
    var capacitySkipped = 0
    var storageUnavailable = false
    var stoppedOnUnknown = false
}

/// Explicit lifecycle requests only. Remaining queue entries never schedule
/// another pass by themselves, and an uncertain mutation is never reissued in
/// this process, even if its child has exited. Stop each pass at its first
/// unknown mutation; another explicit request may process other references.
/// Limits bound operation counts, not Apple's synchronous API wall-clock time.
/// Availability stays inert by
/// default until a real authenticated driver and lifecycle wiring are enabled.
final class VPNPasswordCleanupCoordinator {
    typealias Prepare = (VPNStore) throws -> VPNPasswordCleanupSession?
    typealias Schedule = (@escaping () -> Void) -> Void
    static let maximumVisitedReferences = 64
    private static let queue = DispatchQueue(label: "ProxyPilot.password-cleanup")
    let available: Bool
    private let store: VPNStore
    private let prepare: Prepare
    private let schedule: Schedule
    private let onPass: (VPNPasswordCleanupReport) -> Void
    private let lock = NSLock()
    private var running = false
    private var requested = false
    // Process-owned, not a retryable instance cache. Recreating a coordinator
    // must not issue another GO for a still-unknown exact reference.
    private static let quarantineLock = NSLock()
    private static var quarantine: [VPNPasswordReference] = []
    private enum Reservation { case reserved, existing, full }

    init(store: VPNStore, available: Bool = false,
         prepare: @escaping Prepare = { _ in nil }, schedule: Schedule? = nil,
         onPass: @escaping (VPNPasswordCleanupReport) -> Void = { _ in }) {
        self.store = store; self.available = available; self.prepare = prepare
        self.schedule = schedule ?? { work in Self.queue.async(execute: DispatchWorkItem(block: work)) }
        self.onPass = onPass
    }

    func request() {
        guard available else { return }
        lock.lock()
        if running { requested = true; lock.unlock(); return }
        running = true
        lock.unlock()
        schedule { [self] in drain() }
    }

    private func drain() {
        // Requests received before this snapshot are already covered by it.
        lock.lock(); requested = false; lock.unlock()
        var attempted: [VPNPasswordReference] = []
        while true {
            let report = pass(attempted: &attempted)
            onPass(report)
            lock.lock()
            if requested { requested = false; lock.unlock(); continue }
            running = false
            lock.unlock()
            return
        }
    }

    private func pass(attempted: inout [VPNPasswordReference]) -> VPNPasswordCleanupReport {
        var report = VPNPasswordCleanupReport()
        let slots: [VPNPasswordSlot]
        do { slots = Array(try store.load()?.passwordLedger.pendingDeletion.prefix(Self.maximumVisitedReferences) ?? []) }
        catch { report.storageUnavailable = true; return report }
        // Coalesced requests may discover new refs, but cannot retry a retained
        // one in the same burst. Keep this set bounded to the current queue.
        attempted.removeAll { old in !slots.contains(where: { $0.reference == old }) }
        for slot in slots where !attempted.contains(slot.reference) {
            attempted.append(slot.reference); report.visited += 1
            if Self.isQuarantined(slot.reference) {
                report.quarantinedSkipped += 1; continue
            }
            if slot.writeState == .pending {
                report.pendingSkipped += 1; continue
            }
            if slot.writeState == .notIssued || slot.writeState == .noItem {
                do {
                    try store.deletePendingPassword(reference: slot.reference) { _, _ in
                        // A concurrent change to settled must not silently turn
                        // metadata retirement into a credential operation.
                        throw VPNValidationError.storageUnavailable
                    }
                    guard try isRemoved(slot.reference) else { throw VPNValidationError.storageUnavailable }
                    report.retiredWithoutIO += 1
                } catch { report.retained += 1 }
                continue
            }
            guard slot.writeState == .settled, slot.locator != nil else {
                report.retained += 1; continue
            }
            // Reserve quarantine space BEFORE any possible mutation. A full
            // history stops new operations instead of evicting unknown refs.
            guard Self.hasQuarantineCapacity else {
                report.capacitySkipped += 1; continue
            }
            let worker: VPNPasswordCleanupSession
            do {
                guard let prepared = try prepare(store) else { report.prepareFailed += 1; continue }
                worker = prepared
                guard let fresh = try store.load()?.passwordLedger.pendingDeletion.first(where: { $0.reference == slot.reference }),
                      fresh == slot else { report.retained += 1; continue }
            } catch { report.prepareFailed += 1; continue }
            switch Self.reserve(slot.reference) {
            case .existing: report.quarantinedSkipped += 1; continue
            case .full: report.capacitySkipped += 1; continue
            case .reserved: break
            }
            do {
                let result = try worker.deletePendingOutcome(store: store, reference: slot.reference)
                switch result {
                case .deleted:
                    // Queue absence alone is not an API receipt. Both the typed
                    // positive result and successful fresh Store read are needed.
                    guard try observePositiveRemoval(slot.reference) else {
                        report.retained += 1; report.stoppedOnUnknown = true; return report
                    }
                    Self.release(slot.reference)
                    report.deleted += 1
                case .notFound, .unavailable:
                    Self.release(slot.reference)
                    report.retained += 1
                case .indeterminate:
                    report.retained += 1; report.stoppedOnUnknown = true; return report
                }
            } catch {
                // The call may have sent GO even if no result is observable.
                // Do not infer cancellation, failure or absence from an error.
                report.retained += 1; report.stoppedOnUnknown = true; return report
            }
        }
        return report
    }

    private static var hasQuarantineCapacity: Bool {
        quarantineLock.lock(); defer { quarantineLock.unlock() }
        return quarantine.count < maximumVisitedReferences
    }
    private static func isQuarantined(_ reference: VPNPasswordReference) -> Bool {
        quarantineLock.lock(); defer { quarantineLock.unlock() }
        return quarantine.contains(reference)
    }
    private static func reserve(_ reference: VPNPasswordReference) -> Reservation {
        quarantineLock.lock(); defer { quarantineLock.unlock() }
        if quarantine.contains(reference) { return .existing }
        guard quarantine.count < maximumVisitedReferences else { return .full }
        quarantine.append(reference)
        return .reserved
    }
    private static func release(_ reference: VPNPasswordReference) {
        quarantineLock.lock(); defer { quarantineLock.unlock() }
        quarantine.removeAll { $0 == reference }
    }

    /// A typed positive already includes Store acknowledgment. Its child's late
    /// exact settlement can briefly contend with our read-only observation.
    /// Retry only this observation: one monotonic budget, at most three reads,
    /// no second GO, preparation, mutation or automatically scheduled pass.
    private func observePositiveRemoval(_ reference: VPNPasswordReference) throws -> Bool {
        let deadline = DispatchTime.now().uptimeNanoseconds + 50_000_000
        for attempt in 0..<3 {
            if attempt > 0, DispatchTime.now().uptimeNanoseconds >= deadline {
                throw VPNValidationError.storageUnavailable
            }
            do { return try isRemoved(reference) }
            catch VPNValidationError.storageUnavailable {
                let now = DispatchTime.now().uptimeNanoseconds
                guard attempt < 2, now < deadline, deadline - now >= 10_000_000 else {
                    throw VPNValidationError.storageUnavailable
                }
                Thread.sleep(forTimeInterval: 0.01)
            }
        }
        throw VPNValidationError.storageUnavailable
    }

    #if VPN_PASSWORD_CLEANUP_TESTING
    static var testAfterBusyObservation: (() -> Void)?
    #endif
    private func isRemoved(_ reference: VPNPasswordReference) throws -> Bool {
        do {
            guard let state = try store.load() else { throw VPNValidationError.storageUnavailable }
            return !state.passwordLedger.pendingDeletion.contains { $0.reference == reference }
        } catch VPNValidationError.storageUnavailable {
            #if VPN_PASSWORD_CLEANUP_TESTING
            Self.testAfterBusyObservation?()
            #endif
            throw VPNValidationError.storageUnavailable
        }
    }
}
