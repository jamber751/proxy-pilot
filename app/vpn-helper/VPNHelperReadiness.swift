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
        defer { if socket >= 0 { close(socket) } }
        return try exchange(onSocket: socket, release: release, policy: release.helperPolicy(),
                            timeoutMilliseconds: timeoutMilliseconds)
    }

    #if VPN_HELPER_READINESS_TESTING
    static func testProbe(takingSocket socket: Int32, release: VerifiedVPNRelease,
                          timeoutMilliseconds: Int = 2000) throws -> VPNHelperReady {
        defer { if socket >= 0 { close(socket) } }
        return try exchange(onSocket: socket, release: release, policy: release.testHelperPolicy(),
                            timeoutMilliseconds: timeoutMilliseconds)
    }
    #endif

    /// Leaves the descriptor open and owned by the caller: a session continues
    /// the conversation on it, while `probe` closes it as soon as it is done.
    static func exchange(onSocket socket: Int32, release: VerifiedVPNRelease,
                         policy: VPNPeerPolicy, timeoutMilliseconds: Int) throws -> VPNHelperReady {
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
        let response: [UInt8]
        do {
            try VPNHelperProtocol.write(request, socket: socket, deadline: deadline)
            response = try VPNHelperProtocol.read(count: expected.count, socket: socket, deadline: deadline)
        } catch VPNHelperTransportError.timeout { throw VPNHelperReadinessError.timeout }
        catch { throw VPNHelperReadinessError.transport }
        guard response == expected else { throw VPNHelperReadinessError.invalidResponse }
        // Revalidate after receiving data; no reusable cached authorization.
        try VPNPeerAuthentication.validate(connectedSocket: socket, policy: policy)
        guard DispatchTime.now().uptimeNanoseconds < deadline else { throw VPNHelperReadinessError.timeout }
        return VPNHelperReady(release: release)
    }
}
