import Darwin
import Dispatch
import Foundation

/// Trusted synchronous backend runs ONLY in the isolated child. The real
/// Keychain locator is intentionally not integrated: current-default-keychain
/// changes must not turn not-found in a different keychain into deletion proof.
protocol VPNPasswordWorkerBackend {
    var available: Bool { get }
    func execute(_ request: inout VPNPasswordWorkerWire.Request) throws -> VPNPasswordWorkerWire.Response
}

private struct VPNPasswordWorkerUnavailableBackend: VPNPasswordWorkerBackend {
    let available = false
    func execute(_ request: inout VPNPasswordWorkerWire.Request) throws -> VPNPasswordWorkerWire.Response {
        throw VPNPasswordWorkerError.unavailable
    }
}

enum VPNPasswordWorker {
    static let argument = "--vpn-password-worker-v1"
    private static let childSocket: Int32 = 20
    private static let childDirectory: Int32 = 21
    private static let readyMagic = Data("PPPWRD01".utf8)
    private static let softTimeout: UInt64 = 5_000_000_000

    /// Must be called before acquiring the user Store lock. No profile or item
    /// is read here; READY authenticates the exact spawned executable and UID.
    static func prepare(store: VPNStore) throws -> Prepared {
        try prepare(store: store, executableOverride: nil)
    }

    static func runIfRequested(arguments: [String]) -> Int32? {
        runIfRequested(arguments: arguments, backend: { _ in VPNPasswordWorkerUnavailableBackend() })
    }

    final class Prepared {
        private let socket: Int32
        private let child: pid_t
        private let stamp: VPNPasswordWorkerIdentity.ProcessStamp
        private let identity: VPNPasswordWorkerIdentity
        private let directory: VPNPasswordWorkerDirectory
        private let nonce: Data
        private var used = false
        private var dispatchAttempted = false

        fileprivate init(socket: Int32, child: pid_t, stamp: VPNPasswordWorkerIdentity.ProcessStamp,
                         identity: VPNPasswordWorkerIdentity, directory: VPNPasswordWorkerDirectory, nonce: Data) {
            self.socket = socket; self.child = child; self.stamp = stamp
            self.identity = identity; self.directory = directory; self.nonce = nonce
        }

        deinit {
            close(socket)
            // Once GO may have arrived, timeout/EOF cannot cancel a mutation.
            // Child finishes even if this parent exits; process source only reaps.
            if !dispatchAttempted { kill(child, SIGKILL) }
            VPNPasswordWorker.reapWhenExited(child)
        }

        @discardableResult
        func addOnce(store: VPNStore, reference: VPNPasswordReference, revision: UInt64,
                     secret: inout Data) throws -> VPNPasswordAddOutcome {
            defer { VPNPasswordWorkerWire.clear(&secret) }
            try directory.requireSameDirectory(as: store.directory)
            return try store.addPasswordOnce(reference: reference, expectedRevision: revision) { _ in
                let result = try perform(operation: .add, reference: reference, revision: revision,
                                         secret: &secret, timeout: VPNPasswordWorker.softTimeout)
                if result.status == .indeterminate { return .indeterminate }
                return result.status == .success ? .definiteSuccess : .definiteFailure
            }
        }

        func read(store: VPNStore, reference: VPNPasswordReference, revision: UInt64) throws -> VPNPasswordWorkerWire.Response {
            try directory.requireSameDirectory(as: store.directory)
            return try store.readPassword(reference: reference, expectedRevision: revision) { _ in
                var empty = Data()
                return try perform(operation: .read, reference: reference, revision: revision,
                                   secret: &empty, timeout: VPNPasswordWorker.softTimeout)
            }
        }

        func deletePending(store: VPNStore, reference: VPNPasswordReference) throws {
            try directory.requireSameDirectory(as: store.directory)
            let revision = try store.load()?.saved.configuration.revision ?? 0
            try store.deletePendingPassword(reference: reference) { _ in
                var empty = Data()
                let result = try perform(operation: .delete, reference: reference, revision: revision,
                                         secret: &empty, timeout: VPNPasswordWorker.softTimeout)
                // A production backend must eventually supply positive deletion
                // proof bound to its real locator. NotFound is NOT such proof.
                guard result.status == .success else { throw VPNPasswordWorkerError.unavailable }
            }
        }

        private func perform(operation: VPNPasswordWorkerOperation, reference: VPNPasswordReference,
                             revision: UInt64, secret: inout Data, timeout: UInt64) throws -> VPNPasswordWorkerWire.Response {
            defer { VPNPasswordWorkerWire.clear(&secret) }
            guard !used else { throw VPNPasswordWorkerError.invalid }
            used = true
            try identity.requireSameProcess(child, expected: stamp, parent: getpid())
            var bytes = try VPNPasswordWorkerWire.request(.init(metadata: .init(operation: operation,
                reference: reference, revision: revision), secret: secret), nonce: nonce)
            defer { VPNPasswordWorkerWire.clear(&bytes) }
            let deadline = DispatchTime.now().uptimeNanoseconds + timeout
            dispatchAttempted = true
            do {
                try VPNPasswordWorkerWire.send(bytes, socket: socket, deadline: deadline)
                var response = try VPNPasswordWorkerWire.receive(socket: socket, deadline: deadline)
                defer { VPNPasswordWorkerWire.clear(&response) }
                return try VPNPasswordWorkerWire.decodeResponse(response, nonce: nonce, operation: operation)
            } catch {
                return .init(status: .indeterminate, secret: Data())
            }
        }

        #if VPN_PASSWORD_WORKER_TESTING
        func testPerform(operation: VPNPasswordWorkerOperation, reference: VPNPasswordReference,
                         revision: UInt64, secret: inout Data, timeout: UInt64) throws -> VPNPasswordWorkerWire.Response {
            try perform(operation: operation, reference: reference, revision: revision, secret: &secret, timeout: timeout)
        }
        func testTruncatedGO() throws {
            guard !used else { throw VPNPasswordWorkerError.invalid }
            used = true; dispatchAttempted = true
            var bytes: [UInt8] = [0, 0, 0, 100, 1, 2, 3]
            _ = bytes.withUnsafeMutableBytes { Darwin.send(socket, $0.baseAddress, $0.count, MSG_NOSIGNAL) }
            shutdown(socket, SHUT_WR)
        }
        func testWrongNonceGO(reference: VPNPasswordReference, revision: UInt64) throws {
            guard !used else { throw VPNPasswordWorkerError.invalid }
            used = true; dispatchAttempted = true
            var wrong = nonce; wrong[0] ^= 1
            var bytes = try VPNPasswordWorkerWire.request(.init(metadata: .init(operation: .read,
                reference: reference, revision: revision), secret: Data()), nonce: wrong)
            defer { VPNPasswordWorkerWire.clear(&bytes) }
            try VPNPasswordWorkerWire.send(bytes, socket: socket, deadline: DispatchTime.now().uptimeNanoseconds + softTimeout)
            shutdown(socket, SHUT_WR)
        }
        func testReplayGO(reference: VPNPasswordReference, revision: UInt64,
                          secret: inout Data) throws -> VPNPasswordWorkerWire.Response {
            defer { VPNPasswordWorkerWire.clear(&secret) }
            guard !used else { throw VPNPasswordWorkerError.invalid }
            used = true; dispatchAttempted = true
            var bytes = try VPNPasswordWorkerWire.request(.init(metadata: .init(operation: .add,
                reference: reference, revision: revision), secret: secret), nonce: nonce)
            defer { VPNPasswordWorkerWire.clear(&bytes) }
            let deadline = DispatchTime.now().uptimeNanoseconds + softTimeout
            try VPNPasswordWorkerWire.send(bytes, socket: socket, deadline: deadline)
            try VPNPasswordWorkerWire.send(bytes, socket: socket, deadline: deadline)
            var response = try VPNPasswordWorkerWire.receive(socket: socket, deadline: deadline)
            defer { VPNPasswordWorkerWire.clear(&response) }
            return try VPNPasswordWorkerWire.decodeResponse(response, nonce: nonce, operation: .add)
        }
        #endif
    }

    private static func prepare(store: VPNStore, executableOverride: String?) throws -> Prepared {
        let identity = try VPNPasswordWorkerIdentity()
        let source = open(store.directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard source >= 0 else { throw VPNPasswordWorkerError.denied }
        defer { close(source) }
        let directory = try VPNPasswordWorkerDirectory(duplicating: source)
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw VPNPasswordWorkerError.transport }
        guard fcntl(pair[0], F_SETFD, FD_CLOEXEC) == 0,
              fcntl(pair[1], F_SETFD, FD_CLOEXEC) == 0 else {
            close(pair[0]); close(pair[1]); throw VPNPasswordWorkerError.transport
        }
        var socket = pair[0]
        let childSource = fcntl(pair[1], F_DUPFD_CLOEXEC, 64)
        close(pair[1])
        guard childSource >= 0 else { close(socket); throw VPNPasswordWorkerError.transport }
        defer { close(childSource); if socket >= 0 { close(socket) } }
        let child = try spawn(path: executableOverride ?? identity.path, socket: childSource, directory: directory.descriptor)
        var accepted = false
        defer { if !accepted { kill(child, SIGKILL); reapWhenExited(child) } }
        let deadline = DispatchTime.now().uptimeNanoseconds + softTimeout
        let ready = try VPNPasswordWorkerWire.receive(socket: socket, deadline: deadline)
        guard ready.count == readyMagic.count + VPNPasswordWorkerWire.nonceBytes + 1,
              ready.prefix(8) == readyMagic else { throw VPNPasswordWorkerError.denied }
        // Actual posix_spawn PID, its birth stamp, exact image inode and live
        // hardened code are the child proof, NOT socketpair creator credentials.
        let stamp = try identity.validateProcess(child, parent: getpid())
        guard ready.last == VPNPasswordWorkerStatus.success.rawValue else { throw VPNPasswordWorkerError.unavailable }
        let prepared = Prepared(socket: socket, child: child, stamp: stamp, identity: identity,
                                directory: directory, nonce: ready.subdata(in: 8..<(8 + VPNPasswordWorkerWire.nonceBytes)))
        socket = -1; accepted = true
        return prepared
    }

    private static func runIfRequested(arguments: [String],
                                       backend makeBackend: (Int32) throws -> VPNPasswordWorkerBackend) -> Int32? {
        guard arguments.dropFirst().contains(argument) else { return nil }
        guard arguments.count == 2, arguments[1] == argument else { return 64 }
        // Before storage, code identity, backend or any Keychain API.
        guard getuid() == geteuid(), getuid() >= 500 else { return 77 }
        do {
            let identity = try VPNPasswordWorkerIdentity()
            let parent = getppid()
            _ = try identity.validateProcess(parent)
            let directory = try VPNPasswordWorkerDirectory(duplicating: childDirectory)
            var kind: Int32 = 0, uid: uid_t = 0, gid: gid_t = 0
            var size = socklen_t(MemoryLayout.size(ofValue: kind))
            guard getsockopt(childSocket, SOL_SOCKET, SO_TYPE, &kind, &size) == 0, kind == SOCK_STREAM,
                  getpeereid(childSocket, &uid, &gid) == 0, uid == getuid() else { return 77 }
            let backend = try makeBackend(directory.descriptor)
            var uuid = UUID().uuid
            let nonce = withUnsafeBytes(of: &uuid) { Data($0) }
            let ready = readyMagic + nonce + Data([backend.available ? VPNPasswordWorkerStatus.success.rawValue : VPNPasswordWorkerStatus.unavailable.rawValue])
            try VPNPasswordWorkerWire.send(ready, socket: childSocket, deadline: DispatchTime.now().uptimeNanoseconds + softTimeout)
            guard backend.available else {
                // Stay alive for the parent's PID/image authentication. It will
                // refuse before GO and close/terminate this unavailable child.
                _ = try? VPNPasswordWorkerWire.receive(socket: childSocket, deadline: DispatchTime.now().uptimeNanoseconds + softTimeout)
                return 78
            }
            var frame = try VPNPasswordWorkerWire.receive(socket: childSocket, deadline: DispatchTime.now().uptimeNanoseconds + softTimeout)
            defer { VPNPasswordWorkerWire.clear(&frame) }
            var request = try VPNPasswordWorkerWire.decodeRequest(frame, nonce: nonce)
            defer { VPNPasswordWorkerWire.clear(&request.secret) }
            // Full private GO accepted. Do not re-authenticate a now-dead or
            // reparented parent; finish exactly this one captured operation.
            var response = try backend.execute(&request)
            defer { VPNPasswordWorkerWire.clear(&response.secret) }
            var result = try VPNPasswordWorkerWire.response(response, nonce: nonce)
            defer { VPNPasswordWorkerWire.clear(&result) }
            // Send BEFORE taking Store lock: the parent can be awaiting this
            // result while still holding the lock inside its bounded callback.
            try? VPNPasswordWorkerWire.send(result, socket: childSocket, deadline: DispatchTime.now().uptimeNanoseconds + 1_000_000_000)
            if response.status != .indeterminate, request.metadata.operation == .add {
                settleAdd(request.metadata.reference, directory: directory)
            } else if request.metadata.operation == .delete, response.status == .success {
                settleDeletion(request.metadata.reference, directory: directory)
            }
            return 0
        } catch { return 77 }
    }

    private static func settleAdd(_ reference: VPNPasswordReference, directory: VPNPasswordWorkerDirectory) {
        retrySettlement(directory) { store in
            let ledger = try store.load()?.passwordLedger
            if ledger?.active?.reference == reference, ledger?.active?.writeState == .settled { return }
            if ledger?.pendingDeletion.contains(where: { $0.reference == reference && $0.writeState == .settled }) == true { return }
            // Already retired exact UUID is also terminal, never recreated.
            if ledger?.active?.reference != reference,
               ledger?.pendingDeletion.contains(where: { $0.reference == reference }) != true { return }
            try store.completePasswordAdd(reference: reference)
        }
    }

    private static func settleDeletion(_ reference: VPNPasswordReference, directory: VPNPasswordWorkerDirectory) {
        retrySettlement(directory) { store in
            guard try store.load()?.passwordLedger.pendingDeletion.contains(where: { $0.reference == reference }) == true else { return }
            // Trusted result of this child's own exact delete, not a wire
            // command that can authorize settlement of an arbitrary reference.
            try store.deletePendingPassword(reference: reference) { _ in }
        }
    }

    private static func retrySettlement(_ directory: VPNPasswordWorkerDirectory, _ action: (VPNStore) throws -> Void) {
        let deadline = DispatchTime.now().uptimeNanoseconds + softTimeout
        repeat {
            do { try directory.revalidate(); try action(VPNStore(directory: directory.url)); return }
            catch VPNValidationError.storageUnavailable { usleep(20_000) }
            catch { return }
        } while DispatchTime.now().uptimeNanoseconds < deadline
        // Honest pending state if access never becomes available; no invented
        // completion receipt, automatic second Add or background service.
    }

    private static func spawn(path: String, socket: Int32, directory: Int32) throws -> pid_t {
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw VPNPasswordWorkerError.unavailable }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw VPNPasswordWorkerError.unavailable }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawn_file_actions_adddup2(&actions, socket, childSocket) == 0,
              posix_spawn_file_actions_adddup2(&actions, directory, childDirectory) == 0,
              posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0) == 0,
              posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else {
            throw VPNPasswordWorkerError.unavailable
        }
        var argv = [strdup(path), strdup(argument), nil]
        defer { for pointer in argv { if let pointer { free(pointer) } } }
        var environment: [UnsafeMutablePointer<CChar>?] = [nil]
        var pid: pid_t = 0
        guard path.withCString({ posix_spawn(&pid, $0, &actions, &attributes, &argv, &environment) }) == 0, pid > 0 else {
            throw VPNPasswordWorkerError.unavailable
        }
        return pid
    }

    private static func reapWhenExited(_ pid: pid_t) {
        var status: Int32 = 0
        let checked = waitpid(pid, &status, WNOHANG)
        if checked == pid || (checked < 0 && errno == ECHILD) { return }
        let source = DispatchSource.makeProcessSource(identifier: pid, eventMask: .exit, queue: .global(qos: .utility))
        source.setEventHandler {
            var status: Int32 = 0
            _ = waitpid(pid, &status, WNOHANG)
            source.setEventHandler {}
            source.cancel()
        }
        source.resume()
    }

    #if VPN_PASSWORD_WORKER_TESTING
    static func testRunIfRequested(arguments: [String], backend: (Int32) throws -> VPNPasswordWorkerBackend) -> Int32? {
        runIfRequested(arguments: arguments, backend: backend)
    }
    static func testPrepare(store: VPNStore, executableOverride: String?) throws -> Prepared {
        try prepare(store: store, executableOverride: executableOverride)
    }
    #endif
}
