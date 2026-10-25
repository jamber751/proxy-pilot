import Darwin
import Foundation

// Test executable only. No host interface lookup or kernel/network mutations.
@_cdecl("if_indextoname")
func pairInterface(_ index: UInt32, _ output: UnsafeMutablePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let output, let name = [1:"lo0",42:"utun42"][index] else { return nil }
    for (i,c) in name.utf8CString.enumerated() { output[i] = c }; return output
}
private func check(_ value: @autoclosure () throws -> Bool) throws {
    if try !value() { throw NSError(domain:"pair",code:1) }
}
private final class Kernel: VPNRouteSocketTransport {
    let active: VPNOwnedRouteIdentity, fence: VPNExactRouteFenceIdentity
    var hasFence = true, hasHost = false, foreign = false, loseFence = false
    var acknowledgeOnly = false, unknown = false, race = false, late = false, foreignFence = false
    var request = Data(), sent = [rt_msghdr](), deadlines = [UInt64]()
    init(_ active: VPNOwnedRouteIdentity, _ fence: VPNExactRouteFenceIdentity) { self.active=active;self.fence=fence }
    func send(_ message: Data, deadline: DispatchTime) throws {
        request=message;let h=try VPNDarwinRouteCodec.identify(message);sent.append(h);deadlines.append(deadline.uptimeNanoseconds)
        if h.rtm_type != RTM_GET {
            if race { hasHost=true;throw VPNRouteSocketTransportError.posix(EEXIST) }
            if !acknowledgeOnly { hasHost = h.rtm_type == RTM_ADD }
            if loseFence { hasFence=false }
        }
    }
    func receive(maximumBytes: Int, deadline: DispatchTime) throws -> Data {
        let h=try VPNDarwinRouteCodec.identify(request)
        if late { usleep(30_000) }
        if h.rtm_type != RTM_GET {
            if unknown { throw VPNRouteSocketTransportError.timeout }
            // Deliberately sparse ACK. Separate GET must prove both keys.
            return try VPNDarwinRouteCodec.encodeReply(type:h.rtm_type,sequence:h.rtm_seq,pid:h.rtm_pid,error:0,identity:nil)
        }
        if h.rtm_flags & RTF_HOST != 0 && hasHost {
            return try VPNDarwinRouteCodec.encodeReply(type:h.rtm_type,sequence:h.rtm_seq,pid:h.rtm_pid,error:0,
                identity:active,responseFlags:foreign ? UInt32(RTF_REJECT):0)
        }
        if !hasFence { return try VPNDarwinRouteCodec.encodeReply(type:h.rtm_type,sequence:h.rtm_seq,pid:h.rtm_pid,error:ESRCH,identity:nil) }
        var data=try VPNDarwinRouteCodec.encodeExactFence(type:UInt8(RTM_ADD),sequence:h.rtm_seq,pid:h.rtm_pid,identity:fence)
        var header=try VPNDarwinRouteCodec.identify(data)
        header.rtm_type=h.rtm_type;header.rtm_flags=Int32(bitPattern:fence.flags | (foreignFence ? UInt32(RTF_REJECT):0))
        withUnsafeBytes(of:&header) { data.replaceSubrange(0..<$0.count,with:$0) }
        return data
    }
}
@main private enum Checks {
    static func run() throws {
        let mode=CommandLine.arguments[1]
        for family in [VPNRouteAddressFamily.ipv4,.ipv6] {
            let prefix=try VPNRoutePrefix(resource:VPNResource(address:family == .ipv4 ? "198.19.253.201":"2001:db8:fff:fd::c9"))
            let route=VPNPlannedRoute(role:.resource,destination:prefix,physicalGatewayBytes:nil,interfaceIndex:42,interfaceName:"utun42")
            let flags=VPNManagedIPv6HostRoute.flags(for:route)
            let evidence: VPNRouteKernelEvidence
            if family == .ipv4 { evidence=try VPNRouteKernelEvidence(gateway:Optional<in_addr>.none,interfaceIndex:42,flags:flags) }
            else { evidence=try VPNRouteKernelEvidence(gateway:Optional<in6_addr>.none,interfaceIndex:42,flags:flags) }
            let active=try VPNOwnedRouteIdentity(planned:route,evidence:evidence)
            let fence=try VPNExactRouteFenceIdentity(address:prefix,loopbackIndex:1)
            let fake=Kernel(active,fence), socket=VPNDarwinRouteSocket(transport:fake,pid:817)
            let end=DispatchTime.now()+2
            func install(_ current: () throws -> Void = {}) throws { try socket.installFencedHost(active,fence:fence,deadline:end,checkCurrent:current) }
            func remove() throws { try socket.deleteFencedHost(active,fence:fence,deadline:end,checkCurrent:{}) }
            func fails(_ code: VPNDarwinRouteError, _ body: () throws -> Void) throws {
                do { try body();throw NSError(domain:"no-failure",code:1) }
                catch let error as VPNDarwinRouteError { try check(error == code) }
            }
            switch mode {
            case "lifecycle":
                try install();try check(fake.hasHost && fake.hasFence)
                try remove();try check(!fake.hasHost && fake.hasFence)
                try check(fake.sent.filter { $0.rtm_type != RTM_GET }.map(\.rtm_type) == [UInt8(RTM_ADD),UInt8(RTM_DELETE)])
                try check(Set(fake.deadlines).count == 1 && fake.deadlines.allSatisfy { $0 <= end.uptimeNanoseconds })
            case "no-adoption":
                fake.hasHost=true;try fails(.preexistingNonIdentical) { try install() }
                try check(fake.sent.allSatisfy { $0.rtm_type == RTM_GET })
            case "missing-fence":
                fake.hasFence=false;try fails(.missingOrForeign) { try install() };try check(fake.sent.count == 1)
            case "foreign-fence":
                fake.foreignFence=true;try fails(.missingOrForeign) { try install() };try check(fake.sent.count == 1)
            case "foreign-host":
                fake.hasHost=true;fake.foreign=true;try fails(.missingOrForeign) { try remove() }
                try check(fake.hasHost && fake.sent.allSatisfy { $0.rtm_type == RTM_GET })
            case "fence-loss":
                fake.loseFence=true;try fails(.missingOrForeign) { try install() }
                try check(fake.hasHost && fake.sent.filter { $0.rtm_type == RTM_DELETE }.isEmpty)
            case "ack-without-state":
                fake.acknowledgeOnly=true;try fails(.verificationFailed) { try install() };try check(!fake.hasHost && fake.hasFence)
            case "unknown-write":
                fake.unknown=true;try fails(.timeout) { try install() };try check(fake.hasHost && fake.hasFence)
                try check(fake.sent.filter { $0.rtm_type != RTM_GET }.count == 1)
            case "unknown-delete":
                fake.hasHost=true;fake.unknown=true;try fails(.timeout) { try remove() }
                try check(!fake.hasHost && fake.hasFence && fake.sent.filter { $0.rtm_type != RTM_GET }.count == 1)
            case "delete-ack-without-state":
                fake.hasHost=true;fake.acknowledgeOnly=true;try fails(.verificationFailed) { try remove() }
                try check(fake.hasHost && fake.hasFence)
            case "race":
                fake.race=true;try fails(.transport(EEXIST)) { try install() };try check(fake.hasHost && fake.hasFence)
            case "cancelled":
                var calls=0
                do { try install { calls+=1;if calls == 6 { throw VPNExactFenceStoreError.stale } };throw NSError(domain:"no-cancel",code:1) }
                catch VPNExactFenceStoreError.stale {}
                try check(!fake.hasHost && fake.sent.allSatisfy { $0.rtm_type == RTM_GET })
            case "cancelled-after-write":
                var calls=0
                do { try install { calls+=1;if calls == 7 { throw VPNExactFenceStoreError.stale } };throw NSError(domain:"no-cancel",code:1) }
                catch VPNExactFenceStoreError.stale {}
                try check(fake.hasHost && fake.hasFence && fake.sent.filter { $0.rtm_type != RTM_GET }.count == 1)
            case "expired":
                try fails(.timeout) { try socket.installFencedHost(active,fence:fence,deadline:.now(),checkCurrent:{}) }
                try check(fake.sent.isEmpty)
            case "late":
                fake.late=true
                try fails(.timeout) { try socket.installFencedHost(active,fence:fence,deadline:.now()+0.01,checkCurrent:{}) }
                try check(!fake.hasHost)
            case "delete-absent":
                try fails(.missingOrForeign) { try remove() };try check(fake.hasFence)
                try check(fake.sent.allSatisfy { $0.rtm_type == RTM_GET })
            default: throw NSError(domain:"mode",code:1)
            }
        }
        print("PASS fenced-host-"+mode)
    }
    static func main() { do { try run() } catch { fputs("FAIL fenced-host\n",stderr);exit(1) } }
}
