import Darwin
import Dispatch
import Foundation

enum VPNHelperListenerError: Error { case unsafeStorage, unavailable, invalidTimeout }

/// Server side of the readiness handshake, inside the privileged helper. It is
/// not a command dispatcher: the only reachable behaviour is answering one fixed
/// 56-byte challenge with 56 bytes, and there is no path, argument, profile or
/// operation a caller can name. Every connection is authenticated as the owner's
/// signed application, bounded by a deadline, and served one at a time.
final class VPNHelperListener {
    static let socketName = "helper.sock"
    private static let request = Array("PPVNRQ01".utf8)
    private static let response = Array("PPVNOK01".utf8)
    private var listener: Int32
    private let release: VerifiedVPNRelease
    private let policy: VPNPeerPolicy

    /// Creates the fixed endpoint inside an already-protected directory. It never
    /// unlinks an existing socket: a stale endpoint means the supervisor did not
    /// confirm the previous stop, and quietly stealing it would hide that.
    static func bind(inTrustedDirectory trusted: Int32, release: VerifiedVPNRelease,
                     ownerUserID: uid_t) throws -> VPNHelperListener {
        let policy = try release.clientPolicy(forTrustedUserID: ownerUserID)
        let directory = fcntl(trusted, F_DUPFD_CLOEXEC, 0)
        guard directory >= 0 else { throw VPNHelperListenerError.unsafeStorage }
        defer { Darwin.close(directory) }
        var attributes = stat()
        guard fstat(directory, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFDIR,
              attributes.st_uid == geteuid(), attributes.st_mode & 0o7777 == 0o700 else {
            throw VPNHelperListenerError.unsafeStorage
        }
        // bind(2) has no descriptor-relative form: resolve the path from the
        // checked descriptor and confirm the name still means that directory.
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        var named = stat()
        guard fcntl(directory, F_GETPATH, &path) == 0 else { throw VPNHelperListenerError.unsafeStorage }
        let folder = String(cString: path)
        guard lstat(folder, &named) == 0, named.st_dev == attributes.st_dev,
              named.st_ino == attributes.st_ino else { throw VPNHelperListenerError.unsafeStorage }
        let endpoint = folder + "/" + socketName
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(endpoint.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw VPNHelperListenerError.unsafeStorage
        }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let socketDescriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard socketDescriptor >= 0, fcntl(socketDescriptor, F_SETFD, FD_CLOEXEC) == 0 else {
            if socketDescriptor >= 0 { Darwin.close(socketDescriptor) }
            throw VPNHelperListenerError.unavailable
        }
        let previous = umask(0o177)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(socketDescriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        umask(previous)
        var created = stat()
        guard bound == 0, listen(socketDescriptor, 4) == 0,
              fstatat(directory, socketName, &created, AT_SYMLINK_NOFOLLOW) == 0,
              created.st_mode & S_IFMT == S_IFSOCK, created.st_uid == geteuid(),
              created.st_mode & 0o7777 == 0o600 else {
            Darwin.close(socketDescriptor)
            throw VPNHelperListenerError.unavailable
        }
        return VPNHelperListener(listener: socketDescriptor, release: release, policy: policy)
    }

    private init(listener: Int32, release: VerifiedVPNRelease, policy: VPNPeerPolicy) {
        self.listener = listener
        self.release = release
        self.policy = policy
    }

    deinit { close() }

    func close() {
        if listener >= 0 { Darwin.close(listener); listener = -1 }
    }

    /// Waits for one connection and answers at most one challenge. A rejected,
    /// slow or malformed peer costs that connection only: nothing is retried,
    /// nothing is remembered, and the listener stays available for the next one.
    /// `isReady` is asked immediately before replying, so the receipt reflects
    /// the helper's state at that moment rather than the fact it is running.
    @discardableResult
    func serveOnce(timeoutMilliseconds: Int = 2000, isReady: () -> Bool) throws -> Bool {
        guard (1...5000).contains(timeoutMilliseconds) else { throw VPNHelperListenerError.invalidTimeout }
        guard listener >= 0 else { throw VPNHelperListenerError.unavailable }
        let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(timeoutMilliseconds) * 1_000_000
        try wait(listener, events: Int16(POLLIN), deadline: deadline)
        let client = accept(listener, nil, nil)
        guard client >= 0 else { throw VPNHelperListenerError.unavailable }
        defer { Darwin.close(client) }
        guard fcntl(client, F_SETFD, FD_CLOEXEC) == 0 else { return false }
        var enabled: Int32 = 1
        guard setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &enabled,
                         socklen_t(MemoryLayout.size(ofValue: enabled))) == 0 else { return false }
        do {
            try VPNPeerAuthentication.validate(connectedSocket: client, policy: policy)
            let challenge = try read(count: 56, socket: client, deadline: deadline)
            guard Array(challenge.prefix(8)) == Self.request,
                  Array(challenge[8..<16]) == Self.encoded(release.protocolVersion),
                  Array(challenge[16..<24]) == Self.encoded(release.sequence) else { return false }
            // Answer only for the state at this instant. A running process is
            // not readiness, and a rejected answer must not be a stale success.
            guard isReady() else { return false }
            try VPNPeerAuthentication.validate(connectedSocket: client, policy: policy)
            try write(Self.response + challenge.dropFirst(8), socket: client, deadline: deadline)
            // Hold the connection while the peer re-checks our running signature;
            // it closes first, and a slow peer only spends its own deadline.
            var byte: UInt8 = 0
            try? wait(client, events: Int16(POLLIN), deadline: deadline)
            _ = recv(client, &byte, 1, MSG_DONTWAIT)
            return true
        } catch { return false }
    }

    private static func encoded(_ value: UInt64) -> [UInt8] {
        (0..<8).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
    }

    private func wait(_ socket: Int32, events: Int16, deadline: UInt64) throws {
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw VPNHelperListenerError.unavailable }
            var descriptor = pollfd(fd: socket, events: events, revents: 0)
            let result = poll(&descriptor, 1, Int32((deadline - now + 999_999) / 1_000_000))
            if result < 0, errno == EINTR { continue }
            guard result >= 0 else { throw VPNHelperListenerError.unavailable }
            if result == 0 { continue }
            guard descriptor.revents & Int16(POLLNVAL | POLLERR) == 0 else { throw VPNHelperListenerError.unavailable }
            guard descriptor.revents & (events | Int16(POLLHUP)) != 0 else { continue }
            return
        }
    }

    private func read(count: Int, socket: Int32, deadline: UInt64) throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count), offset = 0
        while offset < count {
            try wait(socket, events: Int16(POLLIN), deadline: deadline)
            let received = bytes.withUnsafeMutableBytes {
                recv(socket, $0.baseAddress!.advanced(by: offset), count - offset, MSG_DONTWAIT)
            }
            if received < 0, [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
            guard received > 0 else { throw VPNHelperListenerError.unavailable }
            offset += received
        }
        return bytes
    }

    private func write(_ bytes: [UInt8], socket: Int32, deadline: UInt64) throws {
        var offset = 0
        while offset < bytes.count {
            try wait(socket, events: Int16(POLLOUT), deadline: deadline)
            let sent = bytes.withUnsafeBytes {
                send(socket, $0.baseAddress!.advanced(by: offset), bytes.count - offset, MSG_DONTWAIT)
            }
            if sent < 0, [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
            guard sent > 0 else { throw VPNHelperListenerError.unavailable }
            offset += sent
        }
    }
}
