import Darwin
import Dispatch
import Foundation

enum VPNHelperSessionError: Error { case exhausted, closed, payloadTooLarge, invalidResponse, timeout, transport, busy, bootstrapUnavailable }

/// Activation returns an owned runtime only after its boot cache/initial GOST
/// policy is installed and its listener is ready. Failed activation must clean
/// its partial child itself. retire must synchronously stop only that runtime.
protocol VPNBridgeBootstrapOwnedRuntime: AnyObject { func retire() }

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
    private var bootstrapping = false

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
        guard !bootstrapping else { throw VPNHelperSessionError.busy }
        guard operation != .bootstrapBridge else { throw VPNHelperSessionError.invalidResponse }
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
    /// Root holds retained mutations and serializes configuration edits from
    /// offer through the final reply. activate must durably merge ALL root and
    /// App cached/configured numeric obligations before its first listen, using
    /// the original deadline. Success establishes only initial bridge custody;
    /// ongoing dynamic answer updates still need their own synchronous ACK gate.
    func bootstrapBridgeTransaction<T: VPNBridgeBootstrapOwnedRuntime>(
        activate: (Data, DispatchTime) throws -> (runtime: T, acknowledgement: [UInt8])) throws -> T {
        guard !bootstrapping else { throw VPNHelperSessionError.busy }
        guard socket>=0 else { throw VPNHelperSessionError.closed }
        guard remaining>0 else { throw VPNHelperSessionError.exhausted }
        remaining-=1;bootstrapping=true;defer { bootstrapping=false }
        let deadline=DispatchTime.now().uptimeNanoseconds
            + UInt64(VPNHelperProtocol.requestTimeoutMilliseconds)*1_000_000
        var owned: T?
        func current() throws {
            guard DispatchTime.now().uptimeNanoseconds<deadline else { throw VPNHelperSessionError.timeout }
            try VPNPeerAuthentication.validate(connectedSocket:socket,policy:policy)
            guard DispatchTime.now().uptimeNanoseconds<deadline else { throw VPNHelperSessionError.timeout }
        }
        func reply() throws -> (VPNHelperStatus,Data) {
            let header=try VPNHelperProtocol.read(count:14,socket:socket,deadline:deadline)
            guard Array(header.prefix(8))==VPNHelperProtocol.responseMagic,
                  let status=VPNHelperStatus(rawValue:UInt16(VPNHelperProtocol.number(header[8..<10]))) else {
                throw VPNHelperSessionError.invalidResponse
            }
            let length=Int(VPNHelperProtocol.number(header[10..<14]))
            guard length<=VPNHelperProtocol.maximumPayloadBytes else { throw VPNHelperSessionError.invalidResponse }
            let bytes=length==0 ? []:try VPNHelperProtocol.read(count:length,socket:socket,deadline:deadline)
            try current();return (status,Data(bytes))
        }
        do {
            try current()
            try VPNHelperProtocol.write(VPNHelperProtocol.request(.bootstrapBridge,revision:release.sequence,payload:[]),socket:socket,deadline:deadline)
            let (status,data)=try reply()
            guard status == .ok else {
                guard data.isEmpty else { throw VPNHelperSessionError.invalidResponse }
                throw VPNHelperSessionError.bootstrapUnavailable
            }
            try current()
            let activation=try activate(data,DispatchTime(uptimeNanoseconds:deadline))
            owned=activation.runtime
            guard activation.acknowledgement.count==40 else { throw VPNHelperSessionError.invalidResponse }
            try current()
            try VPNHelperProtocol.write(activation.acknowledgement,socket:socket,deadline:deadline)
            let (finalStatus,finalBody)=try reply()
            guard finalStatus == .ok,finalBody.isEmpty else { throw VPNHelperSessionError.invalidResponse }
            return owned!
        } catch {
            // Keep the root conversation alive while retiring a returned child.
            // No retry or rollback of durable boot protection is permitted.
            owned?.retire();close()
            if error is VPNHelperTransportError { throw VPNHelperSessionError.transport }
            throw error
        }
    }

}
