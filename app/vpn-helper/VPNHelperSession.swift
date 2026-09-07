import Darwin
import Dispatch

enum VPNHelperSessionError: Error { case exhausted, closed, payloadTooLarge, invalidResponse, timeout, transport }

/// Client side of one short conversation with the helper: authenticate readiness
/// first, then send a bounded number of typed requests on that same connection.
/// It carries no ambient authority — the caller must hand it a descriptor that a
/// trusted launcher connected, and each request re-authenticates the peer.
final class VPNHelperSession {
    let ready: VPNHelperReady
    private var socket: Int32
    private let policy: VPNPeerPolicy
    private let release: VerifiedVPNRelease
    private var remaining = VPNHelperProtocol.maximumRequestsPerConnection

    /// Takes ownership of the descriptor, including on every failure path.
    static func open(takingSocket socket: Int32, release: VerifiedVPNRelease,
                     timeoutMilliseconds: Int = 2000) throws -> VPNHelperSession {
        try open(takingSocket: socket, release: release, policy: release.helperPolicy(),
                 timeoutMilliseconds: timeoutMilliseconds)
    }

    #if VPN_HELPER_READINESS_TESTING
    static func testOpen(takingSocket socket: Int32, release: VerifiedVPNRelease,
                         timeoutMilliseconds: Int = 2000) throws -> VPNHelperSession {
        try open(takingSocket: socket, release: release, policy: release.testHelperPolicy(),
                 timeoutMilliseconds: timeoutMilliseconds)
    }
    #endif

    private static func open(takingSocket socket: Int32, release: VerifiedVPNRelease,
                             policy: VPNPeerPolicy, timeoutMilliseconds: Int) throws -> VPNHelperSession {
        do {
            let ready = try VPNHelperReadiness.exchange(onSocket: socket, release: release, policy: policy,
                                                        timeoutMilliseconds: timeoutMilliseconds)
            return VPNHelperSession(socket: socket, release: release, policy: policy, ready: ready)
        } catch {
            if socket >= 0 { Darwin.close(socket) }
            throw error
        }
    }

    private init(socket: Int32, release: VerifiedVPNRelease, policy: VPNPeerPolicy, ready: VPNHelperReady) {
        self.socket = socket
        self.release = release
        self.policy = policy
        self.ready = ready
    }

    deinit { close() }

    func close() {
        if socket >= 0 { Darwin.close(socket); socket = -1 }
    }

    /// One request, one answer, both exactly framed. The peer is revalidated
    /// before sending and after receiving: authorization is never cached across
    /// requests. The connection is spent after a bounded number of them.
    func request(_ operation: VPNHelperOperation, payload: [UInt8] = []) throws -> (VPNHelperStatus, [UInt8]) {
        guard socket >= 0 else { throw VPNHelperSessionError.closed }
        guard remaining > 0 else { throw VPNHelperSessionError.exhausted }
        guard payload.count <= VPNHelperProtocol.maximumPayloadBytes else { throw VPNHelperSessionError.payloadTooLarge }
        remaining -= 1
        let deadline = DispatchTime.now().uptimeNanoseconds
            + UInt64(VPNHelperProtocol.requestTimeoutMilliseconds) * 1_000_000
        do {
            try VPNPeerAuthentication.validate(connectedSocket: socket, policy: policy)
            let frame = VPNHelperProtocol.request(operation, revision: release.sequence, payload: payload)
            try VPNHelperProtocol.write(frame, socket: socket, deadline: deadline)
            let header = try VPNHelperProtocol.read(count: 8 + 2 + 4, socket: socket, deadline: deadline)
            guard Array(header.prefix(8)) == VPNHelperProtocol.responseMagic,
                  let status = VPNHelperStatus(rawValue: UInt16(VPNHelperProtocol.number(header[8..<10]))) else {
                throw VPNHelperSessionError.invalidResponse
            }
            let length = Int(VPNHelperProtocol.number(header[10..<14]))
            guard length <= VPNHelperProtocol.maximumPayloadBytes else { throw VPNHelperSessionError.invalidResponse }
            let body = length == 0 ? [] : try VPNHelperProtocol.read(count: length, socket: socket, deadline: deadline)
            try VPNPeerAuthentication.validate(connectedSocket: socket, policy: policy)
            return (status, body)
        } catch VPNHelperTransportError.timeout {
            close()
            throw VPNHelperSessionError.timeout
        } catch let error as VPNHelperSessionError {
            close()
            throw error
        } catch {
            // A refused or broken peer ends the conversation; nothing is retried
            // on a connection whose identity we could not confirm again.
            close()
            throw VPNHelperSessionError.transport
        }
    }
}
