import Darwin
import Foundation

@_cdecl("if_indextoname")
func upstreamFakeInterface(_ index: UInt32, _ output: UnsafeMutablePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let output, let name = [7:"en7",42:"utun42",43:"utun43"][index] else { return nil }
    for (offset, byte) in name.utf8CString.enumerated() { output[offset] = byte }
    return output
}

private final class Authority: VPNDNSUpstreamAuthority {
    var held = false, valid = true, replay = false
    var generation: UInt64 = 7, revision: UInt64 = 11
    var proof: VPNRouteAppliedProof
    var checks = 0
    var deadlines: [UInt64] = []
    var before: (() throws -> Void)?, after: (() -> Void)?
    var io: Calls!
    init(_ proof: VPNRouteAppliedProof) { self.proof = proof }
    func withCurrentAuthority<T>(binding: VPNDNSUpstreamBinding, deadline: DispatchTime,
                                _ operation: () throws -> T) throws -> T {
        precondition(!held)
        checks += 1; deadlines.append(deadline.uptimeNanoseconds); try before?()
        guard valid, generation == binding.generation, revision == binding.revision,
              proof == binding.routeProof, io.clock < deadline.uptimeNanoseconds else {
            throw VPNBoundDNSUpstreamError.invalidBinding
        }
        held = true
        defer { held = false }
        let result = try operation()
        if replay { _ = try operation() }
        after?()
        return result
    }
}
private final class Calls: VPNDNSUpstreamSyscalls {
    weak var authority: Authority?
    var clock: UInt64 = 1_000_000_000
    var snapshot: VPNKernelInterfaceSnapshot
    var events: [String] = [], closed: [Int32] = []
    var family: Int32 = 0, transport: VPNDNSUpstreamTransport = .udp
    var bound: UInt32 = 42, boundSize = 4
    var fail: String?, connectErrors: [Int32] = [], sendSteps: [Int] = [], readErrors: [Int32] = []
    var pollSteps: [Int16] = [], pollErrors: [Int32] = [], pollAdvance: UInt64 = 1_000_000
    var connectionStatus: Int32 = 0, maxRead = Int.max
    var pollHook: (() -> Void)?, sendHook: (() throws -> Void)?
    var outgoing = Data(), incoming = Data(), truncated = false
    var sendCount = 0, readCount = 0, connectCount = 0
    var pollMilliseconds: [Int32] = [], endpoints: [VPNRoutePrefix] = []
    init(snapshot: VPNKernelInterfaceSnapshot) { self.snapshot = snapshot }
    private func event(_ name: String) throws {
        precondition(authority?.held == true)
        events.append(name)
        if fail == name { throw VPNBoundDNSUpstreamError.posix(EIO) }
    }
    func now() -> UInt64 { clock }
    func interfaces() throws -> VPNKernelInterfaceSnapshot { try event("interfaces"); return snapshot }
    func socket(family: Int32, transport: VPNDNSUpstreamTransport) throws -> Int32 {
        try event("socket"); self.family = family; self.transport = transport; return 77
    }
    func configure(_ descriptor: Int32) throws { precondition(descriptor == 77); try event("configure") }
    func bindInterface(_ descriptor: Int32, family: Int32, index: UInt32) throws {
        precondition(descriptor == 77 && family == self.family && index == 42); try event("bind")
    }
    func boundInterface(_ descriptor: Int32, family: Int32) throws -> (UInt32, Int) {
        precondition(descriptor == 77 && family == self.family); try event("getBinding"); return (bound, boundSize)
    }
    func connect(_ descriptor: Int32, binding: VPNDNSUpstreamBinding) throws {
        precondition(descriptor == 77 && binding.family == family && VPNDNSUpstreamBinding.port == 53)
        try event("connect"); connectCount += 1; endpoints.append(binding.server)
        if !connectErrors.isEmpty {
            let error = connectErrors.removeFirst()
            if error != 0 { throw VPNBoundDNSUpstreamError.posix(error) }
        }
    }
    func connectionError(_ descriptor: Int32) throws -> Int32 { try event("connectionError"); return connectionStatus }
    func send(_ descriptor: Int32, bytes: Data, offset: Int) throws -> Int {
        try event("send"); sendCount += 1; try sendHook?()
        let count = sendSteps.isEmpty ? bytes.count - offset : sendSteps.removeFirst()
        if count < 0 { throw VPNBoundDNSUpstreamError.posix(Int32(-count)) }
        if count <= bytes.count - offset && count > 0 { outgoing.append(bytes.dropFirst(offset).prefix(count)) }
        return count
    }
    func receive(_ descriptor: Int32, maximum: Int, datagram: Bool) throws -> (Data, Bool) {
        try event("receive"); readCount += 1
        precondition(datagram == (transport == .udp) && maximum > 0 && maximum <= 65535)
        if !readErrors.isEmpty {
            let error = readErrors.removeFirst()
            if error != 0 { throw VPNBoundDNSUpstreamError.posix(error) }
        }
        let count = min(maximum, min(maxRead, incoming.count))
        let bytes = Data(incoming.prefix(count)); incoming.removeFirst(count)
        return (bytes, truncated)
    }
    func poll(_ descriptor: Int32, events: Int16, milliseconds: Int32) throws -> Int16 {
        precondition(authority?.held == false && descriptor == 77 && milliseconds > 0)
        self.events.append("poll"); pollMilliseconds.append(milliseconds)
        clock += pollAdvance; pollHook?()
        if !pollErrors.isEmpty {
            let error = pollErrors.removeFirst()
            if error != 0 { throw VPNBoundDNSUpstreamError.posix(error) }
        }
        return pollSteps.isEmpty ? events : pollSteps.removeFirst()
    }
    func close(_ descriptor: Int32) {
        precondition(authority?.held == false && descriptor == 77)
        events.append("close"); closed.append(descriptor)
    }
}

@main private enum Checks {
    enum Failure: Error { case assertion }
    static let query = Data([0x12,0x34,0x01,0,0,1,0,0,0,0,0,0])
    static let answer = Data([0x12,0x34,0x81,0x80,0,1,0,0,0,0,0,0])
    static func check(_ value: @autoclosure () throws -> Bool) throws {
        if try !value() { throw Failure.assertion }
    }
    static func rejects(_ operation: () throws -> Void) throws {
        do { try operation() } catch { return }
        throw Failure.assertion
    }
    static func address() throws -> OpenVPNIPAddress { try OpenVPNIPAddress(parsing: "10.255.254.1", family: .ipv4) }
    static func snapshot(index: UInt32 = 42, name: String = "utun42", up: Bool = true,
                         running: Bool = true, point: Bool = true, addresses: [OpenVPNIPAddress]? = nil) throws -> VPNKernelInterfaceSnapshot {
        try VPNKernelInterfaceSnapshot(interfaces: [VPNKernelInterfaceRecord(index: index, name: name,
            isUp: up, isRunning: running, isPointToPoint: point, addresses: addresses ?? [address()])])
    }
    static func binding(_ server: String = "10.44.0.53") throws -> VPNDNSUpstreamBinding {
        var peer = in_addr(); precondition("198.51.100.9".withCString { inet_pton(AF_INET, $0, &peer) } == 1)
        let tunnel = try VPNTunnelInterfaceResolver.resolve(baseline: VPNKernelInterfaceSnapshot(interfaces: []),
            after: snapshot(), management: OpenVPNConnectedEvidence(tunnelLocalIPv4: address(), tunnelLocalIPv6: nil,
                remoteAddress: OpenVPNIPAddress(parsing: "198.51.100.9", family: .ipv4), remotePort: 443))
        let network = try VPNDomainNetworkPlan(generation: 7, revision: 11,
            resources: [VPNResource(address: "portal.corp.test")], corporateDNS: [server],
            peer: VPNRoutePeerEvidence(peer: peer, gateway: nil, interfaceIndex: 7), tunnel: tunnel)
        let proof = try VPNRouteAppliedProof(generation: 7, revision: 11,
            identities: VPNRouteIdentityFactory.make(plan: network.staticRoutes))
        return try VPNDNSUpstreamBinding(networkPlan: network, routeProof: proof, tunnel: tunnel,
            server: VPNRoutePrefix(resource: VPNResource(address: server)))
    }
    static func fixture(_ server: String = "10.44.0.53", transport: VPNDNSUpstreamTransport = .udp) throws
        -> (VPNDNSUpstreamBinding, Authority, Calls) {
        let value = try binding(server), authority = Authority(value.routeProof), calls = try Calls(snapshot: snapshot())
        authority.io = calls; calls.authority = authority
        calls.incoming = transport == .udp ? answer : Data([0,UInt8(answer.count)]) + answer
        return (value, authority, calls)
    }
    static func end(_ calls: Calls) -> DispatchTime { DispatchTime(uptimeNanoseconds: calls.clock + 1_000_000_000) }
    static func prepare(_ value: VPNDNSUpstreamBinding, _ authority: Authority, _ calls: Calls,
                        _ transport: VPNDNSUpstreamTransport = .udp) throws -> VPNBoundDNSUpstreamSocket {
        try VPNBoundDNSUpstreamSocket.prepare(binding: value, transport: transport, authority: authority,
            deadline: end(calls), syscalls: calls)
    }
    static func roundtrip() throws {
        for server in ["10.44.0.53","2001:db8::53"] {
            for kind: VPNDNSUpstreamTransport in [.udp,.tcp] {
                let (value, authority, calls) = try fixture(server, transport: kind)
                var socket: VPNBoundDNSUpstreamSocket? = try prepare(value, authority, calls, kind)
                try check(try socket!.exchange(question: query, deadline: end(calls)) == answer)
                try check(calls.family == value.family && calls.endpoints == [value.server])
                try check(calls.events.firstIndex(of: "configure")! < calls.events.firstIndex(of: "bind")!)
                try check(calls.events.firstIndex(of: "bind")! < calls.events.firstIndex(of: "getBinding")!)
                try check(calls.events.firstIndex(of: "getBinding")! < calls.events.firstIndex(of: "connect")!)
                try check(calls.outgoing == (kind == .udp ? query : Data([0,UInt8(query.count)]) + query))
                try check(calls.closed.isEmpty && !authority.held)
                socket = nil; try check(calls.closed == [77])
            }
        }
    }
    static func setupFailure(_ mode: String) throws {
        let (value, authority, calls) = try fixture()
        switch mode {
        case "lease": authority.valid = false
        case "generation": authority.generation = 8
        case "revision": authority.revision = 12
        case "proof": authority.proof = VPNRouteAppliedProof(generation: 7, revision: 11, identities: [])
        case "configure", "bind", "getBinding", "socket", "interfaces": calls.fail = mode
        case "wrong-bound": calls.bound = 43
        case "wrong-size": calls.boundSize = 8
        case "authority-overrun": authority.before = { calls.clock += 30_000_000_000 }
        case "authority-after-overrun": authority.after = { calls.clock += 30_000_000_000 }
        case "authority-replay": authority.replay = true
        default: throw Failure.assertion
        }
        try rejects { _ = try prepare(value, authority, calls) }
        try check(calls.connectCount == 0 && calls.sendCount == 0)
        let created = calls.events.contains("socket") && mode != "socket"
        try check(calls.closed == (created ? [77] : []))
    }
    static func invalidBinding() throws {
        let value = try binding()
        try rejects { _ = try VPNDNSUpstreamBinding(networkPlan: value.networkPlan,
            routeProof: VPNRouteAppliedProof(generation: 8, revision: 11, identities: value.routeProof.identities),
            tunnel: value.tunnel, server: value.server) }
        try rejects { _ = try VPNDNSUpstreamBinding(networkPlan: value.networkPlan,
            routeProof: VPNRouteAppliedProof(generation: 7, revision: 11, identities: Array(value.routeProof.identities.dropFirst())),
            tunnel: value.tunnel, server: value.server) }
        try rejects { _ = try VPNDNSUpstreamBinding(networkPlan: value.networkPlan, routeProof: value.routeProof,
            tunnel: value.tunnel, server: VPNRoutePrefix(resource: VPNResource(address: "10.44.0.54"))) }
    }
    static func revoke(_ mode: String) throws {
        let (value, authority, calls) = try fixture()
        let socket = try prepare(value, authority, calls)
        switch mode {
        case "lease": authority.valid = false
        case "generation": authority.generation = 8
        case "revision": authority.revision = 12
        case "proof": authority.proof = VPNRouteAppliedProof(generation: 7, revision: 11, identities: [])
        case "death": calls.snapshot = try VPNKernelInterfaceSnapshot(interfaces: [])
        case "index": calls.snapshot = try snapshot(index: 43)
        case "name": calls.snapshot = try snapshot(name: "utun43")
        case "up": calls.snapshot = try snapshot(up: false)
        case "running": calls.snapshot = try snapshot(running: false)
        case "point": calls.snapshot = try snapshot(point: false)
        case "address": calls.snapshot = try snapshot(addresses: [])
        case "bound": calls.bound = 0
        default: throw Failure.assertion
        }
        try rejects { _ = try socket.exchange(question: query, deadline: end(calls)) }
        try check(calls.sendCount == 0 && calls.closed == [77])
        try rejects { _ = try socket.exchange(question: query, deadline: end(calls)) }
        try check(calls.sendCount == 0 && calls.closed == [77])
    }
    static func connecting(_ mode: String) throws {
        let (value, authority, calls) = try fixture(transport: .tcp)
        calls.connectErrors = [mode == "again" || mode == "isconn" ? EAGAIN : mode == "interrupted" ? EINTR : EINPROGRESS,
                               mode == "isconn" ? EISCONN : 0]
        if mode == "soerror" { calls.connectionStatus = ECONNREFUSED }
        if mode == "stale" { calls.pollHook = { authority.valid = false } }
        if mode == "dead" { calls.pollHook = { calls.snapshot = try! snapshot(up: false) } }
        if mode == "bound" { calls.pollHook = { calls.bound = 0 } }
        if mode == "timeout" { calls.pollSteps = [0] }
        if mode == "expired" { calls.pollAdvance = 2_000_000_000 }
        if mode == "hangup" { calls.pollSteps = [Int16(POLLHUP)] }
        if ["soerror","stale","dead","bound","timeout","expired","hangup"].contains(mode) {
            try rejects { _ = try prepare(value, authority, calls, .tcp) }
            try check(calls.sendCount == 0 && calls.closed == [77])
        } else {
            let socket = try prepare(value, authority, calls, .tcp)
            try check(calls.connectCount == (mode == "again" || mode == "isconn" ? 2 : 1))
            try check(try socket.exchange(question: query, deadline: end(calls)) == answer)
        }
        try check(!authority.held && calls.pollMilliseconds.allSatisfy { $0 <= 1000 })
    }
    static func io(_ mode: String) throws {
        let tcp = mode.hasPrefix("tcp")
        let (value, authority, calls) = try fixture(transport: tcp ? .tcp : .udp)
        let socket = try prepare(value, authority, calls, tcp ? .tcp : .udp)
        switch mode {
        case "udp-eintr": calls.sendSteps = [-Int(EINTR)]; calls.readErrors = [EINTR]
        case "udp-again": calls.sendSteps = [-Int(EAGAIN)]; calls.readErrors = [EAGAIN]; calls.pollErrors = [EINTR,0,0]
        case "tcp-partial": calls.sendSteps = [1,2,-Int(EINTR),-Int(EAGAIN)]; calls.maxRead = 1; calls.readErrors = [EINTR,EAGAIN]
        case "udp-short": calls.sendSteps = [2]
        case "udp-truncated": calls.truncated = true
        case "udp-eof": calls.incoming = Data()
        case "udp-id": calls.incoming[0] = 0xff
        case "udp-qr": calls.incoming[2] = 0
        case "udp-timeout": calls.sendSteps = [-Int(EAGAIN)]; calls.pollSteps = [0]
        case "udp-expired": calls.sendSteps = [-Int(EAGAIN)]; calls.pollAdvance = 2_000_000_000
        case "udp-send-error": calls.fail = "send"
        case "udp-read-error": calls.fail = "receive"
        case "tcp-zero-write": calls.sendSteps = [0]
        case "tcp-invalid-frame": calls.incoming = Data([0,1,0])
        case "tcp-eof": calls.incoming = Data([0,12,1])
        case "tcp-revoke-partial":
            calls.sendSteps = [2]
            authority.after = { if calls.sendCount == 1 { authority.valid = false } }
        case "udp-revoke-after-read":
            authority.after = { if calls.readCount == 1 { authority.valid = false } }
        case "udp-authority-overrun": authority.before = { calls.clock += 30_000_000_000 }
        default: throw Failure.assertion
        }
        if ["udp-eintr","udp-again","tcp-partial"].contains(mode) {
            try check(try socket.exchange(question: query, deadline: end(calls)) == answer)
            try check(calls.outgoing == (tcp ? Data([0,12]) + query : query))
        } else {
            try rejects { _ = try socket.exchange(question: query, deadline: end(calls)) }
            try check(calls.closed == [77])
            if mode == "tcp-revoke-partial" { try check(calls.sendCount == 1 && calls.outgoing == Data([0,12])) }
            if ["udp-timeout","udp-expired"].contains(mode) { try check(calls.sendCount == 1 && calls.outgoing.isEmpty) }
        }
    }
    static func invalidMessage() throws {
        for bytes in [Data(), Data(repeating: 0, count: 11), Data(repeating: 0, count: 65536), answer] {
            let (value, authority, calls) = try fixture()
            let socket = try prepare(value, authority, calls)
            try rejects { _ = try socket.exchange(question: bytes, deadline: end(calls)) }
            try check(calls.sendCount == 0 && calls.closed == [77])
        }
        // A Data subsequence can have nonzero indices; no raw index trap.
        let (value, authority, calls) = try fixture()
        let socket = try prepare(value, authority, calls)
        try check(try socket.exchange(question: (Data([1,2,3,4]) + query).dropFirst(4), deadline: end(calls)) == answer)
    }
    static func budgetAndBusy() throws {
        let (value, authority, calls) = try fixture()
        try rejects { _ = try VPNBoundDNSUpstreamSocket.prepare(binding: value, transport: .udp,
            authority: authority, deadline: DispatchTime(uptimeNanoseconds: calls.clock), syscalls: calls) }
        try check(calls.events.isEmpty)
        let socket = try prepare(value, authority, calls)
        calls.sendHook = {
            do { _ = try socket.exchange(question: query, deadline: end(calls)); throw Failure.assertion }
            catch VPNBoundDNSUpstreamError.busy {}
        }
        try check(try socket.exchange(question: query, deadline: end(calls)) == answer)
        try check(calls.closed.isEmpty && calls.sendCount == 1)
    }
    static func absoluteDeadline() throws {
        let (value, authority, calls) = try fixture(transport: .tcp)
        let limit = calls.clock + 20_000_000_000
        calls.connectErrors = [EINPROGRESS]
        calls.pollAdvance = 5_000_000_000
        let socket = try VPNBoundDNSUpstreamSocket.prepare(binding: value, transport: .tcp,
            authority: authority, deadline: .distantFuture, syscalls: calls)
        calls.sendSteps = [-Int(EAGAIN)]; calls.readErrors = [EAGAIN]
        try check(try socket.exchange(question: query, deadline: DispatchTime(uptimeNanoseconds: limit)) == answer)
        try check(calls.pollMilliseconds == [20000,15000,10000])
        try check(authority.deadlines.allSatisfy { $0 == limit })
    }
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        let mode = CommandLine.arguments[1]
        if mode == "roundtrip" { try roundtrip() }
        else if mode == "binding" { try invalidBinding() }
        else if mode == "messages" { try invalidMessage() }
        else if mode == "budget-busy" { try budgetAndBusy() }
        else if mode == "deadline" { try absoluteDeadline() }
        else if mode.hasPrefix("setup-") { try setupFailure(String(mode.dropFirst(6))) }
        else if mode.hasPrefix("revoke-") { try revoke(String(mode.dropFirst(7))) }
        else if mode.hasPrefix("connect-") { try connecting(String(mode.dropFirst(8))) }
        else { try io(mode) }
        print("bound numeric DNS upstream checks passed")
    }
}
