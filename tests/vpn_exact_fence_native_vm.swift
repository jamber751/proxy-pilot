// VM-only bridge: same production route socket/codec, no TESTING in production.
// The C fixture owns all sockets/interfaces and checks packets/cleanup itself.
import Darwin
import Foundation

private final class ObservedTransport: VPNRouteSocketTransport {
    let real: VPNDarwinRouteSocketTransport
    var request: rt_msghdr?, observedFlags: UInt32 = 0
    var observedType: UInt8 = 0, observedIndex: UInt16 = 0, observedMask: Int32 = 0
    var maskLength = 0, maskFamily = 0, gatewayFamily = 0
    init() throws { real = try VPNDarwinRouteSocketTransport() }
    func send(_ bytes: Data, deadline: DispatchTime) throws {
        request = try VPNDarwinRouteCodec.identify(bytes)
        try real.send(bytes,deadline:deadline)
    }
    func receive(maximumBytes: Int, deadline: DispatchTime) throws -> Data {
        let data = try real.receive(maximumBytes:maximumBytes,deadline:deadline)
        if let q = request, let h = try? VPNDarwinRouteCodec.identify(data),
           h.rtm_pid == q.rtm_pid, h.rtm_seq == q.rtm_seq, h.rtm_type == q.rtm_type, h.rtm_errno == 0 {
            observedFlags = UInt32(bitPattern:h.rtm_flags) & ~UInt32(RTF_DONE)
            observedType = h.rtm_type; observedIndex = h.rtm_index; observedMask = h.rtm_addrs
            var at = MemoryLayout<rt_msghdr>.size
            for i in 0..<Int(RTAX_MAX) where h.rtm_addrs & (1 << i) != 0 {
                guard at+2 <= data.count else { break }
                let n = Int(data[at]), f = Int(data[at+1]), step = n == 0 ? 4 : (n+3) & ~3
                guard step >= 4, at+step <= data.count else { break }
                if i == RTAX_NETMASK { maskLength = n; maskFamily = f }
                if i == RTAX_GATEWAY { gatewayFamily = f }
                at += step
            }
        }
        return data
    }
}
@_cdecl("pp_exact_fence_control")
func exactFenceControl(_ action: Int32, _ family: Int32, _ bytes: UnsafePointer<UInt8>?) -> Int32 {
    let env = ProcessInfo.processInfo.environment
    guard getuid() == 0, geteuid() == 0, env["GITHUB_ACTIONS"] == "true",
          env["PROXYPILOT_VM_NATIVE_EXACT_FENCE"] == "1",
          env["PROXYPILOT_VM_EXACT_ROUTE_PACKETS"] == "1",
          env["PROXYPILOT_VM_DNS_UTUN_TESTS"] == "1",
          family == 4 || family == 6, action == RTM_ADD || action == RTM_DELETE,
          let bytes else { return 77 }
    var observer: ObservedTransport?
    do {
        let prefix = try VPNRoutePrefix(hostBytes:Array(UnsafeBufferPointer(start:bytes,count:family == 4 ? 4 : 16)),family:family == 4 ? .ipv4 : .ipv6)
        // Never accept an arbitrary root caller's destination in this VM hook.
        guard prefix.canonical == (family == 4 ? "198.19.253.201" : "2001:db8:fff:fd::c9") else { return 77 }
        let identity = try VPNExactRouteFenceIdentity(address:prefix,loopbackIndex:if_nametoindex("lo0"))
        let transport = try ObservedTransport(); observer = transport
        let socket = VPNDarwinRouteSocket(transport:transport)
        let deadline = DispatchTime.now() + 2
        if action == RTM_ADD { try socket.installExactFence(identity,deadline:deadline) }
        else { try socket.deleteExactFence(identity,deadline:deadline) }
        print("PASS native-exact-fence-"+(action == RTM_ADD ? "add" : "delete")+"-"+String(family)); fflush(stdout)
        return 0
    } catch {
        let code = (error as? VPNFlowDiagnosticError)?.vpnFlowFailureCode.rawValue ?? "unknown"
        let number = (error as? VPNFlowDiagnosticError)?.vpnFlowErrorNumber ?? 0
        print("FAIL native-exact-fence action=\(action) family=\(family) category=\(code) errno=\(number) expectedFlags=\(VPNExactRouteFenceIdentity.expectedFlags) observedFlags=\(observer?.observedFlags ?? 0)"); fflush(stdout)
        if let observer {
            print("API native-exact-fence type=\(observer.observedType) index=\(observer.observedIndex) addrs=\(observer.observedMask) maskLength=\(observer.maskLength) maskFamily=\(observer.maskFamily) gatewayFamily=\(observer.gatewayFamily)"); fflush(stdout)
        }
        return 1
    }
}
