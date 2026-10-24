import Foundation

/// Explicit application owner. Construction never opens a worker or reads the
/// Store. Previews and normal dependency-injection callers remain unavailable.
final class VPNPasswordRuntime {
    // Enable only after the genuine default-Keychain authenticated VM gate
    // AND the unlocked-Worker contention regression gate.
    static let liveIntegrationEnabled = false
    let available: Bool
    private let store: VPNStore
    private let statusLock = NSLock()
    private var started = false
    private var unknownMutation = false
    private var detail: String?
    private var handler: (String?) -> Void = { _ in }

    private final class Callbacks { weak var owner: VPNPasswordRuntime? }
    let persistence: VPNPasswordPersistenceCoordinator
    let cleanup: VPNPasswordCleanupCoordinator
    let configuration: VPNModel
    let controller: VPNLiveController

    init(store: VPNStore, available: Bool = false,
         persistencePrepare: @escaping VPNPasswordPersistenceCoordinator.Prepare = { _ in nil },
         cleanupPrepare: @escaping VPNPasswordCleanupCoordinator.Prepare = { _ in nil },
         schedule: VPNPasswordCleanupCoordinator.Schedule? = nil,
         openSession: (() throws -> VPNLiveSession)? = nil) {
        self.store = store; self.available = available
        let callbacks = Callbacks()
        persistence = VPNPasswordPersistenceCoordinator(store: store, available: available,
            prepare: persistencePrepare, schedule: schedule,
            onSaveFinished: { [callbacks] in callbacks.owner?.requestCleanup() })
        cleanup = VPNPasswordCleanupCoordinator(store: store, available: available,
            prepare: cleanupPrepare, schedule: schedule,
            onPass: { [callbacks] report in callbacks.owner?.received(report) })
        configuration = VPNModel(store: store, didPersist: { [callbacks] in
            // Clears even a candidate held through a private-key prompt.
            callbacks.owner?.persistence.invalidatePendingSave()
            callbacks.owner?.requestCleanup()
        })
        if let openSession {
            controller = VPNLiveController(store: store, passwordPersistence: persistence, openSession: openSession)
        } else {
            #if VPN_LIVE_CONTROLLER_TESTING
            controller = VPNLiveController(store: store, passwordPersistence: persistence,
                openSession: { throw VPNValidationError.storageUnavailable })
            #else
            controller = VPNLiveController(store: store, passwordPersistence: persistence)
            #endif
        }
        callbacks.owner = self
    }

    /// One explicit lifecycle request; leftover entries never trigger retries.
    func start() {
        guard available else { return }
        statusLock.lock()
        guard !started else { statusLock.unlock(); return }
        started = true; statusLock.unlock()
        requestCleanup()
    }
    func requestCleanup() { guard available else { return }; cleanup.request() }
    var cleanupDetail: String? { statusLock.lock(); defer { statusLock.unlock() }; return detail }
    func setCleanupHandler(_ value: @escaping (String?) -> Void) {
        statusLock.lock(); handler = value; let current = detail; statusLock.unlock()
        value(current)
    }

    private func received(_ report: VPNPasswordCleanupReport) {
        // A stopped pass may not have visited the rest of the queue. Observe
        // remaining metadata separately; never mistake zero per-pass failures
        // for completion, or queue absence for an unknown mutation receipt.
        let remaining: Int?
        do { remaining = try store.load()?.passwordLedger.pendingDeletion.count ?? 0 }
        catch { remaining = nil }
        statusLock.lock()
        unknownMutation = unknownMutation || report.stoppedOnUnknown || report.quarantinedSkipped > 0 || report.pendingSkipped > 0
        if unknownMutation {
            detail = "Не удалось подтвердить удаление сохранённого пароля."
        } else if remaining == nil || report.storageUnavailable {
            detail = "Нужно подтвердить удаление сохранённых паролей."
        } else if remaining! > 0 {
            detail = "Не все сохранённые пароли удалены."
        } else { detail = nil }
        let current = detail, callback = handler
        statusLock.unlock()
        callback(current)
    }
}
