import Darwin
import Foundation

private final class BroadcastRouteBus {
    var transports: [BroadcastRouteTransport] = []
    var sent: [rt_msghdr] = []
    var firstReply: ((rt_msghdr) throws -> Data)?
    func send(_ message: Data) throws {
        let header = try VPNDarwinRouteCodec.identify(message)
        sent.append(header)
        let reply: Data
        if sent.count == 1, let firstReply { reply = try firstReply(header) }
        else { reply = try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET),
            sequence: header.rtm_seq, pid: header.rtm_pid,
            error: sent.count == 1 ? EPERM : ESRCH, identity: nil) }
        for transport in transports { transport.queue.append(reply) }
    }
}
private final class BroadcastRouteTransport: VPNRouteSocketTransport {
    let bus: BroadcastRouteBus
    var queue: [Data] = []
    init(_ bus: BroadcastRouteBus) { self.bus = bus; bus.transports.append(self) }
    func send(_ message: Data, deadline: DispatchTime) throws { try bus.send(message) }
    func receive(maximumBytes: Int, deadline: DispatchTime) throws -> Data {
        guard !queue.isEmpty else { throw VPNRouteSocketTransportError.timeout }
        return queue.removeFirst()
    }
}
private final class Sequences {
    let lock = NSLock()
    var values: [Int32] = []
    func append(_ value: Int32?) { lock.lock(); defer { lock.unlock() }; if let value { values.append(value) } }
}
@main enum VPNRouteSequenceChecks {
    static func require(_ value: @autoclosure () -> Bool) throws {
        guard value() else { throw NSError(domain: "sequence-check", code: 1) }
    }
    static func prefix() throws -> VPNRoutePrefix {
        try VPNRoutePrefix(resource: VPNResource(address: "192.0.2.1"))
    }
    static func peer() throws -> OpenVPNIPAddress { try OpenVPNIPAddress(parsing: "192.0.2.2", family: .ipv4) }

    static func routeRoute() throws {
        let bus = BroadcastRouteBus(), a = BroadcastRouteTransport(bus), b = BroadcastRouteTransport(bus)
        let first = VPNDarwinRouteSocket(transport: a), second = VPNDarwinRouteSocket(transport: b)
        do { _ = try first.lookupExact(prefix()); throw NSError(domain: "first", code: 1) }
        catch VPNDarwinRouteError.kernel(EPERM) {}
        let absent = try second.lookupExact(prefix())
        try require(absent == nil && bus.sent.count == 2)
        try require(bus.sent[0].rtm_pid == bus.sent[1].rtm_pid && bus.sent[0].rtm_seq != bus.sent[1].rtm_seq)
        try require(b.queue.isEmpty)
    }
    static func routePeer(_ peerFirst: Bool) throws {
        let bus = BroadcastRouteBus(), a = BroadcastRouteTransport(bus), b = BroadcastRouteTransport(bus)
        if peerFirst {
            do { _ = try VPNPeerRouteEvidenceResolver(transport: a).resolve(peer: peer()); throw NSError(domain: "first", code: 1) }
            catch VPNPeerRouteEvidenceError.kernel(EPERM) {}
            let absent = try VPNDarwinRouteSocket(transport: b).lookupExact(prefix())
            try require(absent == nil)
        } else {
            do { _ = try VPNDarwinRouteSocket(transport: a).lookupExact(prefix()); throw NSError(domain: "first", code: 1) }
            catch VPNDarwinRouteError.kernel(EPERM) {}
            do { _ = try VPNPeerRouteEvidenceResolver(transport: b).resolve(peer: peer()); throw NSError(domain: "second", code: 1) }
            catch VPNPeerRouteEvidenceError.kernel(ESRCH) {}
        }
        try require(bus.sent[0].rtm_seq != bus.sent[1].rtm_seq && b.queue.isEmpty)
    }
    static func stale(_ kind: String) throws {
        let bus = BroadcastRouteBus(), a = BroadcastRouteTransport(bus), b = BroadcastRouteTransport(bus)
        bus.firstReply = { header in
            if kind == "type" { return try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_ADD), sequence: header.rtm_seq, pid: header.rtm_pid, error: 0, identity: nil) }
            if kind == "error" { return try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET), sequence: header.rtm_seq, pid: header.rtm_pid, error: EACCES, identity: nil) }
            // A complete but different host destination cannot answer this request.
            // It must be skipped by correlation, not accepted as exact absence.
            var reply = try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET), sequence: header.rtm_seq, pid: header.rtm_pid, error: 0, identity: nil)
            var changed = try VPNDarwinRouteCodec.identify(reply)
            changed.rtm_addrs = RTA_DST
            changed.rtm_flags = RTF_UP | RTF_HOST
            var destination = sockaddr_in()
            destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            destination.sin_family = sa_family_t(AF_INET)
            destination.sin_addr.s_addr = UInt32(0xc6336407).bigEndian
            withUnsafeBytes(of: destination) { reply.append(contentsOf: $0) }
            changed.rtm_msglen = UInt16(reply.count)
            withUnsafeBytes(of: changed) { reply.replaceSubrange(0..<$0.count, with: $0) }
            return reply
        }
        do { _ = try VPNDarwinRouteSocket(transport: a).lookupExact(prefix()) }
        catch { /* The first request's bad reply cannot authorize anything. */ }
        let result = try VPNDarwinRouteSocket(transport: b).lookupExact(prefix())
        try require(result == nil && b.queue.isEmpty)
    }
    static func matchingBadType() throws {
        let bus = BroadcastRouteBus(), transport = BroadcastRouteTransport(bus)
        bus.firstReply = { header in try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_ADD), sequence: header.rtm_seq, pid: header.rtm_pid, error: 0, identity: nil) }
        do { _ = try VPNDarwinRouteSocket(transport: transport).lookupExact(prefix()); throw NSError(domain: "type accepted", code: 1) }
        catch VPNDarwinRouteError.malformedMessage {}
    }
    static func explicitInputs() throws {
        for mode in 0..<3 {
            let bus = BroadcastRouteBus(), transport = BroadcastRouteTransport(bus)
            let route = mode == 0 ? VPNDarwinRouteSocket(transport: transport, pid: getpid())
                : mode == 1 ? VPNDarwinRouteSocket(transport: transport, initialSequence: 0)
                : VPNDarwinRouteSocket(transport: transport, pid: 515, initialSequence: 40)
            do { _ = try route.lookupExact(prefix()) } catch VPNDarwinRouteError.kernel(EPERM) {}
            try require(bus.sent[0].rtm_seq == (mode == 2 ? 41 : 1))
            try require(bus.sent[0].rtm_pid == (mode == 2 ? 515 : getpid()))
        }
        let bus = BroadcastRouteBus(), transport = BroadcastRouteTransport(bus)
        do { _ = try VPNDarwinRouteSocket(transport: transport, initialSequence: Int32.max).lookupExact(prefix()); throw NSError(domain: "wrapped", code: 1) }
        catch VPNDarwinRouteError.responseLimit {}
        do { _ = try VPNPeerRouteEvidenceResolver(transport: transport, initialSequence: Int32.max).resolve(peer: peer()); throw NSError(domain: "wrapped", code: 1) }
        catch VPNPeerRouteEvidenceError.responseLimit {}
        try require(bus.sent.isEmpty)
        let end = VPNDarwinRouteSequenceAllocator(initialSequence: Int32.max - 1)
        try require(end.next() == Int32.max && end.next() == nil && end.next() == nil)
    }
    static func concurrent() throws {
        let allocator = VPNDarwinRouteSequenceAllocator(), results = Sequences()
        DispatchQueue.concurrentPerform(iterations: 1000) { _ in results.append(allocator.next()) }
        try require(results.values.count == 1000 && Set(results.values).count == 1000)
        try require(results.values.min() == 1 && results.values.max() == 1000)
    }
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        switch CommandLine.arguments[1] {
        case "route-route": try routeRoute()
        case "route-peer": try routePeer(false)
        case "peer-route": try routePeer(true)
        case "stale-type": try stale("type")
        case "stale-error": try stale("error")
        case "stale-address": try stale("address")
        case "matching-type": try matchingBadType()
        case "explicit": try explicitInputs()
        case "concurrent": try concurrent()
        default: exit(64)
        }
        print("PASS route-sequence")
    }
}
