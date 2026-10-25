import Darwin
import Foundation

/// Daemon-lifetime custody of one persistent namespace. Restore is one-shot and
/// must complete before listener/readiness publication. This does not activate
/// a tunnel, install DNS scopes or grant permission to release a DNS answer.
final class VPNRetainedFenceRuntime {
    private enum State { case fresh, restoring, ready, failed }
    private var directory: Int32 = -1
    let store: VPNExactFenceStore
    private let transaction: VPNExactFenceTransaction
    private let checkNamespace: (Int32) throws -> Void
    private let lock = NSRecursiveLock()
    private var state = State.fresh

    init(trustedDirectoryDescriptor: Int32, kernel: VPNExactFenceKernel,
         checkNamespace: @escaping (Int32) throws -> Void) throws {
        self.checkNamespace = checkNamespace
        let owned = fcntl(trustedDirectoryDescriptor,F_DUPFD_CLOEXEC,64)
        guard owned >= 0 else { throw VPNExactFenceStoreError.unsafeStorage }
        do {
            try checkNamespace(owned)
            let value = try VPNExactFenceStore(trustedDirectoryDescriptor:owned)
            store = value; transaction = VPNExactFenceTransaction(store:value,kernel:kernel)
            directory = owned
        } catch { close(owned); throw error }
    }
    deinit { if directory >= 0 { close(directory) } }

    static func system(deadline: DispatchTime, checkCurrent: () throws -> Void) throws -> VPNRetainedFenceRuntime {
        guard getuid() == 0, geteuid() == 0 else { throw VPNDirectoryError.requiresRoot }
        guard DispatchTime.now().uptimeNanoseconds < deadline.uptimeNanoseconds else { throw VPNDarwinRouteError.timeout }
        try checkCurrent()
        let directory = try VPNDirectoryProvisioner.openSystemFenceDirectory(create:true)
        defer { close(directory) }
        let kernel = try VPNDarwinRouteSocket.production()
        let runtime = try VPNRetainedFenceRuntime(trustedDirectoryDescriptor:directory,kernel:kernel,
            checkNamespace:VPNDirectoryProvisioner.requireSystemFenceDirectory)
        _ = try runtime.restore(deadline:deadline,checkCurrent:checkCurrent)
        return runtime
    }

    @discardableResult
    func restore(deadline: DispatchTime, checkCurrent: () throws -> Void) throws -> [VPNExactFenceEntry] {
        lock.lock(); defer { lock.unlock() }
        guard state == .fresh else { throw VPNExactFenceStoreError.recoveryRequired }
        state = .restoring
        do {
            func current() throws {
                guard DispatchTime.now().uptimeNanoseconds < deadline.uptimeNanoseconds else { throw VPNDarwinRouteError.timeout }
                try checkCurrent(); try namespace()
                guard DispatchTime.now().uptimeNanoseconds < deadline.uptimeNanoseconds else { throw VPNDarwinRouteError.timeout }
            }
            try current()
            let retained = try transaction.restoreRetained(deadline:deadline,checkOwner:current)
            try current(); state = .ready; return retained
        } catch { state = .failed; throw error }
    }

    /// Successful boot plus continued filesystem custody, NOT an answer/route
    /// permit. Each future output transaction still needs live full proof.
    func check() throws {
        lock.lock(); defer { lock.unlock() }
        guard state == .ready else { throw VPNExactFenceStoreError.recoveryRequired }
        do { try namespace() } catch { state = .failed; throw error }
    }
    private func namespace() throws {
        guard directory >= 0 else { throw VPNExactFenceStoreError.unsafeStorage }
        try checkNamespace(directory); try store.validateOwner()
    }
}
