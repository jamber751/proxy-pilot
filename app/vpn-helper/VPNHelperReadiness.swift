import Darwin
import Dispatch
import Foundation
import Security

enum VPNHelperReadinessError: Error { case timeout, transport, invalidResponse, invalidTimeout }

/// A point-in-time authenticated readiness response, never VPN/tunnel health.
/// Not Codable: an IPC peer cannot manufacture this result from response fields.
struct VPNHelperReady {
    let release: VerifiedVPNRelease
    fileprivate init(release: VerifiedVPNRelease) { self.release = release }
}

enum VPNHelperReadiness {
    /// Consumes an exclusively owned, connected descriptor on every path. The
    /// trusted launcher must secure the endpoint and prevent fd close/reuse or
    /// transfer. No arbitrary endpoint, UID, pin or timeout comes from IPC.
    static func probe(takingSocket socket: Int32, release: VerifiedVPNRelease,
                      timeoutMilliseconds: Int = 2000) throws -> VPNHelperReady {
        try probe(takingSocket: socket, release: release, policy: release.helperPolicy(),
                  timeoutMilliseconds: timeoutMilliseconds)
    }

    #if VPN_HELPER_READINESS_TESTING
    static func testProbe(takingSocket socket: Int32, release: VerifiedVPNRelease,
                          timeoutMilliseconds: Int = 2000) throws -> VPNHelperReady {
        try probe(takingSocket: socket, release: release, policy: release.testHelperPolicy(),
                  timeoutMilliseconds: timeoutMilliseconds)
    }
    #endif

    private static func probe(takingSocket socket: Int32, release: VerifiedVPNRelease,
                              policy: VPNPeerPolicy, timeoutMilliseconds: Int) throws -> VPNHelperReady {
        defer { if socket >= 0 { close(socket) } }
        guard (1...5000).contains(timeoutMilliseconds) else { throw VPNHelperReadinessError.invalidTimeout }
        let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(timeoutMilliseconds) * 1_000_000
        guard fcntl(socket, F_SETFD, FD_CLOEXEC) == 0 else { throw VPNHelperReadinessError.transport }
        var enabled: Int32 = 1
        guard setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout.size(ofValue: enabled))) == 0 else {
            throw VPNHelperReadinessError.transport
        }
        try VPNPeerAuthentication.validate(connectedSocket: socket, policy: policy)
        var nonce = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce) == errSecSuccess else {
            throw VPNHelperReadinessError.transport
        }
        func encoded(_ value: UInt64) -> [UInt8] {
            (0..<8).reversed().map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
        }
        let suffix = encoded(release.protocolVersion) + encoded(release.sequence) + nonce
        let request = Array("PPVNRQ01".utf8) + suffix
        let expected = Array("PPVNOK01".utf8) + suffix
        try write(request, socket: socket, deadline: deadline)
        let response = try read(count: expected.count, socket: socket, deadline: deadline)
        guard response == expected else { throw VPNHelperReadinessError.invalidResponse }
        // Revalidate after receiving data; no reusable cached authorization.
        try VPNPeerAuthentication.validate(connectedSocket: socket, policy: policy)
        guard DispatchTime.now().uptimeNanoseconds < deadline else { throw VPNHelperReadinessError.timeout }
        return VPNHelperReady(release: release)
    }

    private static func wait(socket: Int32, events: Int16, deadline: UInt64) throws {
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else { throw VPNHelperReadinessError.timeout }
            let remaining = Int32((deadline - now + 999_999) / 1_000_000)
            var descriptor = pollfd(fd: socket, events: events, revents: 0)
            let result = poll(&descriptor, 1, remaining)
            if result < 0, errno == EINTR { continue }
            guard result >= 0 else { throw VPNHelperReadinessError.transport }
            if result == 0 { continue }
            guard descriptor.revents & Int16(POLLNVAL | POLLERR) == 0 else { throw VPNHelperReadinessError.transport }
            // Allow a final buffered read on HUP; recv returning zero rejects EOF.
            guard descriptor.revents & (events | Int16(POLLHUP)) != 0 else { continue }
            return
        }
    }

    private static func write(_ bytes: [UInt8], socket: Int32, deadline: UInt64) throws {
        var offset = 0
        while offset < bytes.count {
            try wait(socket: socket, events: Int16(POLLOUT), deadline: deadline)
            let count = bytes.withUnsafeBytes {
                send(socket, $0.baseAddress!.advanced(by: offset), bytes.count - offset, MSG_DONTWAIT)
            }
            if count < 0, [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
            guard count > 0 else { throw VPNHelperReadinessError.transport }
            offset += count
        }
    }

    private static func read(count: Int, socket: Int32, deadline: UInt64) throws -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count), offset = 0
        while offset < count {
            try wait(socket: socket, events: Int16(POLLIN), deadline: deadline)
            let received = bytes.withUnsafeMutableBytes {
                recv(socket, $0.baseAddress!.advanced(by: offset), count - offset, MSG_DONTWAIT)
            }
            if received < 0, [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) { continue }
            guard received > 0 else { throw VPNHelperReadinessError.transport }
            offset += received
        }
        return bytes
    }
}
