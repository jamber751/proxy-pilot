import Darwin
import Foundation

private func require(_ value: @autoclosure () throws -> Bool) throws {
    if try !value() { throw NSError(domain:"fence-check",code:1) }
}
private func change(_ data: Data, _ body: (inout rt_msghdr) -> Void) -> Data {
    var output = data, header = rt_msghdr()
    _ = withUnsafeMutableBytes(of:&header) { data.copyBytes(to:$0,from:0..<MemoryLayout<rt_msghdr>.size) }
    body(&header)
    withUnsafeBytes(of:&header) { output.replaceSubrange(0..<$0.count,with:$0) }
    return output
}
private final class Kernel: VPNRouteSocketTransport {
    let identity: VPNExactRouteFenceIdentity
    var installed = false, hostFallback = false, scoped = false, wrongIP = false, wrongGateway = false
    var echoMiss = false, failReadAfterAdd = false, addRace = false, lateReply = false
    var down = false, wrongTypeEcho = false, staleError = false
    var sparseAck = false, noMutation = false
    var request = Data(), sent = [rt_msghdr](), deadlines = [UInt64]()
    init(_ identity: VPNExactRouteFenceIdentity) { self.identity = identity }
    func send(_ message: Data, deadline: DispatchTime) throws {
        request = message; let h = try VPNDarwinRouteCodec.identify(message); sent.append(h); deadlines.append(deadline.uptimeNanoseconds)
        if h.rtm_type == RTM_ADD {
            if addRace { installed = true; throw VPNRouteSocketTransportError.posix(EEXIST) }
            if !noMutation { installed = true }
        }
        if h.rtm_type == RTM_DELETE { installed = false }
    }
    func receive(maximumBytes: Int, deadline: DispatchTime) throws -> Data {
        let h = try VPNDarwinRouteCodec.identify(request)
        if failReadAfterAdd && h.rtm_type == RTM_ADD { throw VPNRouteSocketTransportError.timeout }
        if sparseAck && h.rtm_type != RTM_GET {
            return change(request) { $0.rtm_index = 0 }
        }
        if lateReply { usleep(30_000) }
        if staleError { staleError = false; return change(request) { $0.rtm_seq -= 1; $0.rtm_errno = ESRCH } }
        if h.rtm_type == RTM_GET && !installed && !hostFallback {
            if echoMiss { return change(request) { $0.rtm_errno = ESRCH; if wrongTypeEcho { $0.rtm_type = UInt8(RTM_ADD) } } }
            return try VPNDarwinRouteCodec.encodeReply(type:h.rtm_type,sequence:h.rtm_seq,pid:h.rtm_pid,error:ESRCH,identity:nil)
        }
        var reply = try VPNDarwinRouteCodec.encodeExactFence(type:UInt8(RTM_ADD),sequence:h.rtm_seq,pid:h.rtm_pid,identity:identity)
        reply = change(reply) {
            $0.rtm_type = h.rtm_type; $0.rtm_flags = Int32(bitPattern:identity.flags) | RTF_DONE
            if h.rtm_type == RTM_GET && !installed && hostFallback { $0.rtm_flags |= RTF_HOST }
            if scoped { $0.rtm_flags |= RTF_IFSCOPE }
            if down { $0.rtm_flags &= ~RTF_UP }
        }
        // Corrupt only an exact own fixture field, never source/host data.
        let at = MemoryLayout<rt_msghdr>.size
        if wrongIP { reply[at+(identity.address.family == .ipv4 ? 7 : 23)] ^= 1 }
        if wrongGateway { reply[at+(identity.address.family == .ipv4 ? 16+7 : 28+23)] ^= 1 }
        return reply
    }
}
private func identity(_ family: Int) throws -> VPNExactRouteFenceIdentity {
    let resource = try VPNResource(address:family == 4 ? "198.19.253.201" : "2001:db8:fff:fd::c9")
    return try VPNExactRouteFenceIdentity(address:VPNRoutePrefix(resource:resource),loopbackIndex:if_nametoindex("lo0"))
}
private func end() -> DispatchTime { .now()+2 }
private func expect(_ expected: VPNDarwinRouteError, _ body: () throws -> Void) throws {
    do { try body(); throw NSError(domain:"missing-error",code:1) }
    catch let error as VPNDarwinRouteError { try require(error == expected) }
}
@main private enum Main {
    static func main() throws {
        let mode = CommandLine.arguments[1]
        for family in [4,6] {
            let id = try identity(family), fake = Kernel(try identity(family))
            let socket = VPNDarwinRouteSocket(transport:fake,pid:7654,timeout:1)
            switch mode {
            case "codec":
                let query = try VPNDarwinRouteCodec.encodeExactFenceLookup(id,sequence:1,pid:7654)
                let q = try VPNDarwinRouteCodec.identify(query)
                try require(q.rtm_flags & RTF_HOST == 0 && q.rtm_addrs & RTA_NETMASK != 0)
                let legacy = try VPNDarwinRouteCodec.encodeLookup(destination:id.address,sequence:2,pid:7654)
                let l = try VPNDarwinRouteCodec.identify(legacy)
                try require(l.rtm_flags & RTF_HOST != 0 && l.rtm_addrs & RTA_NETMASK == 0)
                let data = try VPNDarwinRouteCodec.encodeExactFence(type:UInt8(RTM_ADD),sequence:3,pid:7654,identity:id)
                let requestHeader = try VPNDarwinRouteCodec.identify(data)
                try require(UInt32(bitPattern:requestHeader.rtm_flags) == id.flags & ~UInt32(RTF_PRCLONING))
                let reply = change(data) { $0.rtm_flags = Int32(bitPattern:id.flags) }
                let snapshot = try VPNDarwinRouteCodec.decode(reply).snapshot
                try require(snapshot != nil && id.matches(snapshot!))
            case "install-delete":
                let original = end()
                try socket.installExactFence(id,deadline:original)
                try require(fake.installed && fake.sent.map(\.rtm_type) == [UInt8(RTM_GET),UInt8(RTM_ADD),UInt8(RTM_GET)])
                try require(fake.deadlines.allSatisfy { $0 <= original.uptimeNanoseconds } && Set(fake.deadlines).count == 1)
                try socket.deleteExactFence(id,deadline:original)
                try require(!fake.installed && fake.sent.last?.rtm_type == UInt8(RTM_GET))
            case "sparse-ack":
                fake.sparseAck = true
                try socket.installExactFence(id,deadline:end())
                try socket.deleteExactFence(id,deadline:end())
                try require(!fake.installed && fake.sent.count == 6)
            case "ack-without-state":
                fake.sparseAck = true; fake.noMutation = true
                try expect(.verificationFailed) { try socket.installExactFence(id,deadline:end()) }
                try require(!fake.installed && fake.sent.count == 3)
            case "host-distinction":
                fake.hostFallback = true
                try require(try socket.lookupExactFence(id,deadline:end()) == nil)
                try socket.installExactFence(id,deadline:end())
                try socket.deleteExactFence(id,deadline:end())
                try require(fake.hostFallback && !fake.installed)
            case "no-adoption":
                fake.installed = true
                try expect(.preexistingNonIdentical) { try socket.installExactFence(id,deadline:end()) }
                try require(fake.sent.count == 1)
            case "foreign":
                fake.installed = true; fake.wrongGateway = true
                try expect(.missingOrForeign) { try socket.deleteExactFence(id,deadline:end()) }
                try require(fake.installed && fake.sent.count == 1)
            case "scope":
                fake.installed = true; fake.scoped = true
                try expect(.verificationFailed) { _ = try socket.lookupExactFence(id,deadline:end()) }
                try require(fake.sent.count == 1)
            case "wrong-address":
                fake.installed = true; fake.wrongIP = true
                try expect(.verificationFailed) { _ = try socket.lookupExactFence(id,deadline:end()) }
            case "echo-miss":
                fake.echoMiss = true
                try require(try socket.lookupExactFence(id,deadline:end()) == nil)
            case "down":
                fake.installed = true; fake.down = true
                try expect(.verificationFailed) { _ = try socket.lookupExactFence(id,deadline:end()) }
            case "wrong-type-error":
                fake.echoMiss = true; fake.wrongTypeEcho = true
                try expect(.malformedMessage) { _ = try socket.lookupExactFence(id,deadline:end()) }
            case "stale-error":
                fake.installed = true; fake.staleError = true
                try require(try socket.lookupExactFence(id,deadline:end()).map(id.matches) == true)
            case "shared-sequence":
                let other = Kernel(id), exact = VPNDarwinRouteSocket(transport:fake)
                let legacy = VPNDarwinRouteSocket(transport:other)
                try require(try legacy.lookupExact(id.address) == nil)
                try require(try exact.lookupExactFence(id,deadline:end()) == nil)
                try require(other.sent.count == 1 && fake.sent.count == 1 && other.sent[0].rtm_pid == getpid()
                    && fake.sent[0].rtm_pid == getpid() && other.sent[0].rtm_seq != fake.sent[0].rtm_seq)
            case "unknown-add":
                fake.failReadAfterAdd = true
                try expect(.timeout) { try socket.installExactFence(id,deadline:end()) }
                try require(fake.installed && !fake.sent.contains { $0.rtm_type == RTM_DELETE })
            case "race":
                fake.addRace = true
                try expect(.transport(EEXIST)) { try socket.installExactFence(id,deadline:end()) }
                try require(fake.installed && fake.sent.count == 2)
            case "expired":
                try expect(.timeout) { try socket.installExactFence(id,deadline:DispatchTime(uptimeNanoseconds:1)) }
                try require(fake.sent.isEmpty)
            case "late":
                fake.installed = true; fake.lateReply = true
                try expect(.timeout) { _ = try socket.lookupExactFence(id,deadline: .now() + .milliseconds(10)) }
            case "validation":
                var row = try JSONSerialization.jsonObject(with:JSONEncoder().encode(id)) as! [String:Any]
                row["flags"] = Int(id.flags | UInt32(RTF_HOST))
                let bad = try JSONDecoder().decode(VPNExactRouteFenceIdentity.self,from:JSONSerialization.data(withJSONObject:row))
                try expect(.invalidIdentity) { _ = try VPNDarwinRouteCodec.encodeExactFenceLookup(bad,sequence:1,pid:7654) }
            default: throw NSError(domain:"arguments",code:1)
            }
        }
        if mode == "validation" {
            for text in ["127.0.0.1","0.0.0.0","224.0.0.1","169.254.2.1","::1","::","ff02::1","fe80::1","::ffff:192.0.2.1","198.19.253.0/24"] {
                do {
                    let f: VPNRouteAddressFamily = text.contains(":") ? .ipv6 : .ipv4
                    let host: VPNRoutePrefix
                    if text.contains("/") { host = try VPNRoutePrefix(resource:VPNResource(address:text)) }
                    else {
                        var bytes = [UInt8](repeating:0,count:f == .ipv4 ? 4 : 16)
                        _ = text.withCString { inet_pton(f == .ipv4 ? AF_INET : AF_INET6,$0,&bytes) }
                        host = try VPNRoutePrefix(hostBytes:bytes,family:f)
                    }
                    _ = try VPNExactRouteFenceIdentity(address:host,loopbackIndex:if_nametoindex("lo0"))
                    throw NSError(domain:"accepted-invalid-fence",code:1)
                } catch is VPNValidationError {} catch is VPNRoutePlanError {} catch VPNDarwinRouteError.invalidIdentity {}
            }
        }
        print("PASS exact-fence-"+mode)
    }
}
