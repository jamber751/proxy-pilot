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
enum NativeStore {
    static var value: VPNExactFenceStore?
    static func get() throws -> VPNExactFenceStore {
        if let value { return value }
        let env = ProcessInfo.processInfo.environment
        guard let path = env["PROXYPILOT_VM_NATIVE_FENCE_DIRECTORY"], let root = env["RUNNER_TEMP"],
              path.hasPrefix(root+"/"), URL(fileURLWithPath:path).standardizedFileURL.path == path else {
            throw VPNExactFenceStoreError.unsafeStorage
        }
        let fd = open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        guard fd >= 0 else { throw VPNExactFenceStoreError.unsafeStorage }
        defer { close(fd) }
        let store = try VPNExactFenceStore(trustedDirectoryDescriptor:fd)
        value = store; return store
    }
}
@_cdecl("pp_exact_fence_startup")
func exactFenceStartup() -> Int32 {
    let env = ProcessInfo.processInfo.environment
    guard getuid() == 0, geteuid() == 0, env["GITHUB_ACTIONS"] == "true",
          env["PROXYPILOT_VM_NATIVE_EXACT_FENCE"] == "1",
          env["PROXYPILOT_VM_EXACT_ROUTE_PACKETS"] == "1",
          env["PROXYPILOT_VM_DNS_UTUN_TESTS"] == "1" else { return 77 }
    do {
        let store = try NativeStore.get()
        let socket = try VPNDarwinRouteSocket.production()
        _ = try VPNExactFenceTransaction(store:store,kernel:socket).restoreRetained(deadline:.now()+2,checkOwner:{})
        print("PASS native-exact-fence-startup-ready"); fflush(stdout)
        return 0
    } catch {
        let code = (error as? VPNFlowDiagnosticError)?.vpnFlowFailureCode.rawValue ?? "unknown"
        print("FAIL native-exact-fence-startup category="+code); fflush(stdout)
        return 1
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
        let store = try NativeStore.get()
        let transport = try ObservedTransport(); observer = transport
        let socket = VPNDarwinRouteSocket(transport:transport)
        let transaction = VPNExactFenceTransaction(store:store,kernel:socket)
        let deadline = DispatchTime.now() + 2
        if action == RTM_ADD {
            let claim = VPNExactFenceClaim(resourceID:UUID(uuidString:"12345678-1234-1234-1234-123456789abc")!,profileSHA256:String(repeating:"a",count:64),generation:1,revision:1)
            let entry = try transaction.ensure(identity,claim:claim,deadline:deadline,checkCurrent:{})
            guard entry.phase == .applied, try store.load(prefix) == entry else { throw VPNExactFenceStoreError.invalidState }
        } else {
            guard let entry = try store.load(prefix) else { throw VPNExactFenceStoreError.invalidState }
            let retired = try transaction.retire(entry,deadline:deadline,checkCurrent:{})
            guard retired.phase == .retired, try store.load(prefix) == retired else { throw VPNExactFenceStoreError.invalidState }
        }
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

// VM packet fixture owns the active interface/clients. This exercises the real
// pair boundary, not a production active-route journal or DNS answer permit.
@_cdecl("pp_fenced_host_cycle")
func fencedHostCycle(_ family: Int32, _ bytes: UnsafePointer<UInt8>?, _ index: UInt32) -> Int32 {
    let env = ProcessInfo.processInfo.environment
    guard getuid() == 0, geteuid() == 0, env["GITHUB_ACTIONS"] == "true",
          env["PROXYPILOT_VM_NATIVE_EXACT_FENCE"] == "1",
          env["PROXYPILOT_VM_EXACT_ROUTE_PACKETS"] == "1",
          env["PROXYPILOT_VM_DNS_UTUN_TESTS"] == "1",
          env["PROXYPILOT_VM_NATIVE_FENCE_AFTER_ACTIVE"] == "0",
          family == 4 || family == 6, let bytes else { return 77 }
    do {
        let prefix = try VPNRoutePrefix(hostBytes:Array(UnsafeBufferPointer(start:bytes,count:family == 4 ? 4:16)),family:family == 4 ? .ipv4:.ipv6)
        guard prefix.canonical == (family == 4 ? "198.19.253.201":"2001:db8:fff:fd::c9") else { return 77 }
        let store = try NativeStore.get()
        guard let receipt = try store.load(prefix), receipt.phase == .applied else { throw VPNExactFenceStoreError.invalidState }
        var name = [CChar](repeating:0,count:Int(IFNAMSIZ))
        guard if_indextoname(index,&name) != nil else { throw VPNDarwinRouteError.invalidIdentity }
        let route = VPNPlannedRoute(role:.resource,destination:prefix,physicalGatewayBytes:nil,interfaceIndex:index,interfaceName:String(cString:name))
        let flags = VPNManagedIPv6HostRoute.flags(for:route), evidence: VPNRouteKernelEvidence
        if family == 4 { evidence = try VPNRouteKernelEvidence(gateway:Optional<in_addr>.none,interfaceIndex:index,flags:flags) }
        else { evidence = try VPNRouteKernelEvidence(gateway:Optional<in6_addr>.none,interfaceIndex:index,flags:flags) }
        let identity = try VPNOwnedRouteIdentity(planned:route,evidence:evidence)
        let socket = try VPNDarwinRouteSocket.production(), deadline = DispatchTime.now()+5
        func current() throws {
            guard try store.load(prefix) == receipt else { throw VPNExactFenceStoreError.stale }
        }
        try socket.installFencedHost(identity,fence:receipt.identity,deadline:deadline,checkCurrent:current)
        try socket.deleteFencedHost(identity,fence:receipt.identity,deadline:deadline,checkCurrent:current)
        try socket.installFencedHost(identity,fence:receipt.identity,deadline:deadline,checkCurrent:current)
        print("PASS native-fenced-host-cycle-"+String(family)); fflush(stdout)
        return 0
    } catch {
        let code = (error as? VPNFlowDiagnosticError)?.vpnFlowFailureCode.rawValue ?? "unknown"
        print("FAIL native-fenced-host category="+code); fflush(stdout); return 1
    }
}
