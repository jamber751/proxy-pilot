import Darwin
import Foundation

/// Lifetime ownership and conservative recovery of this daemon's endpoint.
/// The installer holds a DIFFERENT lifecycle lock while starting/stopping us.
/// No PID/name/port-based takeover; only a dead owned UNIX socket can be removed.
final class VPNHelperRuntime {
    private let lease: VPNLifecycleLease

    init(storageDirectory: Int32) throws {
        lease = try VPNLifecycleOwnership.acquireRuntime(inTrustedDirectory: storageDirectory)
    }

    func check() throws { try lease.check() }

    func prepareEndpoint(directory: Int32, shared: Bool) throws {
        try check()
        let folder = try VPNEndpointDirectory.checkedPath(directory, owner: geteuid(), shared: shared)
        var before = stat()
        if fstatat(directory, VPNHelperProtocol.socketName, &before, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw VPNHelperListenerError.unsafeStorage }
            return
        }
        let mode: mode_t = shared ? 0o666 : 0o600
        guard before.st_mode & S_IFMT == S_IFSOCK, before.st_uid == geteuid(),
              before.st_nlink == 1, before.st_mode & 0o7777 == mode else {
            throw VPNHelperListenerError.unsafeStorage
        }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array((folder + "/" + VPNHelperProtocol.socketName).utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
            throw VPNHelperListenerError.unsafeStorage
        }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw VPNHelperListenerError.unavailable }
        defer { close(descriptor) }
        guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(descriptor, F_SETFL, O_NONBLOCK) == 0 else { throw VPNHelperListenerError.unavailable }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        // A live listener, full backlog, timeout or resource failure is NOT a
        // dead endpoint. Only explicit refusal permits stale-socket cleanup.
        guard result == -1, errno == ECONNREFUSED else { throw VPNHelperListenerError.unavailable }
        try check()
        var after = stat()
        guard fstatat(directory, VPNHelperProtocol.socketName, &after, AT_SYMLINK_NOFOLLOW) == 0,
              after.st_dev == before.st_dev, after.st_ino == before.st_ino,
              after.st_mode == before.st_mode, after.st_uid == before.st_uid,
              after.st_nlink == 1,
              unlinkat(directory, VPNHelperProtocol.socketName, 0) == 0 else {
            throw VPNHelperListenerError.unsafeStorage
        }
    }
}
