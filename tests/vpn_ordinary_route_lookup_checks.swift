import Darwin
import Foundation

// Entirely synthetic interface table; never inspect/create host interfaces.
@_cdecl("if_indextoname")
func ordinaryLookupInterface(_ index: UInt32, _ output: UnsafeMutablePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let output, let name = [7:"en7",42:"utun42",43:"utun43"][index] else { return nil }
    for (i, c) in name.utf8CString.enumerated() { output[i] = c }; return output
}
private final class Transport: VPNRouteSocketTransport {
    var replies: [Data] = [], sent: [UInt8] = []
    func send(_ bytes: Data, deadline: DispatchTime) throws { sent.append(try VPNDarwinRouteCodec.identify(bytes).rtm_type) }
    func receive(maximumBytes: Int, deadline: DispatchTime) throws -> Data {
        guard !replies.isEmpty else { throw VPNRouteSocketTransportError.timeout }; return replies.removeFirst()
    }
}
@main private enum Checks {
    enum Failure: Error { case check }
    static func check(_ value: @autoclosure () throws -> Bool) throws { if try !value() { throw Failure.check } }
    static func ip4(_ text: String) -> in_addr {
        var a = in_addr(); precondition(text.withCString { inet_pton(AF_INET, $0, &a) } == 1); return a
    }
    static func identity(_ text: String, role: VPNPlannedRouteRole = .resource) throws -> VPNOwnedRouteIdentity {
        let prefix = try VPNRoutePrefix(resource: VPNResource(address: text))
        let scope = role == .dnsDependency ? try plan(prefix.family).tunnelInterface : nil
        let route = VPNPlannedRoute(role: role, destination: prefix, physicalGatewayBytes: nil, interfaceIndex: 42, interfaceName: "utun42", interfaceScope: scope)
        let flags = UInt32(RTF_UP | RTF_STATIC | RTF_PROTO2)
            | (prefix.prefixLength == (prefix.family == .ipv4 ? 32 : 128) ? UInt32(RTF_HOST) : 0)
            | (role == .dnsDependency ? UInt32(RTF_IFSCOPE) : 0)
        if prefix.family == .ipv4 {
            return try VPNOwnedRouteIdentity(planned: route, evidence: VPNRouteKernelEvidence(gateway: Optional<in_addr>.none, interfaceIndex: 42, flags: flags))
        }
        return try VPNOwnedRouteIdentity(planned: route, evidence: VPNRouteKernelEvidence(gateway: Optional<in6_addr>.none, interfaceIndex: 42, flags: flags))
    }
    static func reply(_ value: VPNOwnedRouteIdentity?, error: Int32 = 0) throws -> Data {
        try VPNDarwinRouteCodec.encodeReply(type: UInt8(RTM_GET), sequence: 1, pid: 414, error: error, identity: value)
    }
    // Independent ABI fixture: zero-length netmask occupies four bytes. A
    // default destination may echo the query; zero netmask still denotes /0.
    static func defaultReply(_ family: VPNRouteAddressFamily, link: Bool = false) -> Data {
        var destination: Data, gateway: Data
        if family == .ipv4 {
            var dst = sockaddr_in(); dst.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); dst.sin_family = sa_family_t(AF_INET); dst.sin_addr = ip4("10.0.0.1")
            var gw = dst; gw.sin_addr = ip4("192.0.2.1")
            destination = withUnsafeBytes(of: &dst) { Data($0) }; gateway = withUnsafeBytes(of: &gw) { Data($0) }
        } else {
            var dst = sockaddr_in6(); dst.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); dst.sin6_family = sa_family_t(AF_INET6)
            precondition("2001:db8::7".withCString { inet_pton(AF_INET6, $0, &dst.sin6_addr) } == 1)
            var gw = dst; precondition("2001:db8::1".withCString { inet_pton(AF_INET6, $0, &gw.sin6_addr) } == 1)
            destination = withUnsafeBytes(of: &dst) { Data($0) }; gateway = withUnsafeBytes(of: &gw) { Data($0) }
        }
        if link {
            gateway = Data([11, UInt8(AF_LINK), 7, 0, 0, 3, 0, 0] + Array("en7".utf8)); gateway.append(0)
        }
        var body = destination; body.append(gateway); body.append(Data(repeating: 0, count: 4))
        var header = rt_msghdr(); header.rtm_msglen = UInt16(MemoryLayout<rt_msghdr>.size + body.count)
        header.rtm_version = UInt8(RTM_VERSION); header.rtm_type = UInt8(RTM_GET); header.rtm_index = 7
        header.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK
        header.rtm_flags = RTF_UP | RTF_STATIC | RTF_DONE | (link ? 0 : RTF_GATEWAY)
        header.rtm_pid = 414; header.rtm_seq = 1
        var result = withUnsafeBytes(of: &header) { Data($0) }; result.append(body); return result
    }
    static func plan(_ family: VPNRouteAddressFamily) throws -> VPNRoutePlan {
        let v4 = try OpenVPNIPAddress(parsing: "10.255.254.1", family: .ipv4)
        let v6 = try OpenVPNIPAddress(parsing: "fd00::1", family: .ipv6)
        let tunnel = try VPNTunnelInterfaceResolver.resolve(baseline: VPNKernelInterfaceSnapshot(interfaces: []),
            after: VPNKernelInterfaceSnapshot(interfaces: [VPNKernelInterfaceRecord(index: 42, name: "utun42", isUp: true, isRunning: true, isPointToPoint: true, addresses: [v4, v6])]),
            management: OpenVPNConnectedEvidence(tunnelLocalIPv4: v4, tunnelLocalIPv6: v6,
                remoteAddress: OpenVPNIPAddress(parsing: "198.51.100.9", family: .ipv4), remotePort: 443))
        return try VPNRoutePlan(generation: 7, revision: 11,
            resources: [VPNResource(address: family == .ipv4 ? "10.0.0.0/8" : "2001:db8::/32")],
            peer: VPNRoutePeerEvidence(peer: ip4("198.51.100.9"), gateway: ip4("192.0.2.1"), interfaceIndex: 7), tunnel: tunnel).preservingPeerRoute()
    }
    static func contradictory(_ mode: String, _ family: VPNRouteAddressFamily) throws -> Data {
        if mode == "default-family" { return defaultReply(family == .ipv4 ? .ipv6 : .ipv4) }
        if mode == "missing" { return try reply(nil) }
        let text: String
        switch mode {
        case "narrower": text = family == .ipv4 ? "10.0.0.0/24" : "2001:db8::/64"
        case "unrelated": text = family == .ipv4 ? "192.0.0.0/4" : "3000::/16"
        default: text = family == .ipv4 ? "2001:db8::/32" : "10.0.0.0/8"
        }
        return try reply(identity(text))
    }
    static func recovery(_ mode: String, _ path: String) throws {
        for family in [VPNRouteAddressFamily.ipv4, .ipv6] { for applied in [false, true] {
            let folder = URL(fileURLWithPath: path).appendingPathComponent("\(family.rawValue)-\(applied)")
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            let fd = open(folder.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); guard fd >= 0 else { throw Failure.check }; defer { close(fd) }
            let journal = try VPNRouteJournal(trustedDirectoryDescriptor: fd), plan = try plan(family)
            let entry = try VPNRouteIdentityFactory.make(plan: plan).last!
            try journal.create(plan); try journal.beginInstall(entry, generation: 7, revision: 11)
            if applied { try journal.resolveInstall(entry, present: true, generation: 7, revision: 11) }
            let file = folder.appendingPathComponent(VPNRouteJournal.name), before = try Data(contentsOf: file)
            let transport = Transport(); transport.replies = [try contradictory(mode, family)]
            do { try VPNRouteTransaction(journal: journal, kernel: VPNDarwinRouteSocket(transport: transport, pid: 414)).recoverToIdle(); throw Failure.check }
            catch VPNRouteTransactionError.recoveryRequired {}
            try check(before == Data(contentsOf: file) && transport.sent == [UInt8(RTM_GET)])
        }}
    }
    static func main() throws {
        let mode = CommandLine.arguments[1]
        if mode.hasPrefix("recovery-") { try recovery(String(mode.dropFirst(9)), CommandLine.arguments[2]) }
        else { for family in [VPNRouteAddressFamily.ipv4, .ipv6] {
            let desired = try identity(family == .ipv4 ? "10.0.0.0/8" : "2001:db8::/32")
            let transport = Transport()
            if mode == "scoped" {
                let text = family == .ipv4 ? "10.0.0.1" : "2001:db8::1"
                let scoped = try identity(text, role: .dnsDependency)
                transport.replies = [try reply(identity(text))]
                try check(VPNDarwinRouteSocket(transport: transport, pid: 414).lookupExact(scoped.lookupKey) == nil)
                let fallback = Transport(); fallback.replies = [defaultReply(family)]
                do { _ = try VPNDarwinRouteSocket(transport: fallback, pid: 414).lookupExact(scoped.lookupKey); throw Failure.check }
                catch VPNDarwinRouteError.verificationFailed {}
                continue
            }
            if mode == "exact" { transport.replies = [try reply(desired)] }
            else if mode == "default" || mode == "default-link" { transport.replies = [defaultReply(family, link: mode == "default-link")] }
            else if mode == "absent" { transport.replies = [try reply(nil, error: ESRCH)] }
            else if mode == "enoent" { transport.replies = [try reply(nil, error: ENOENT)] }
            else if mode == "broader" || mode == "broader-cidr" {
                let text = mode == "broader" ? (family == .ipv4 ? "10.1.2.3" : "2001:db8::9")
                    : (family == .ipv4 ? "10.32.0.0/16" : "2001:db8:1::/48")
                let host = try identity(text)
                transport.replies = [try reply(desired)]
                try check(VPNDarwinRouteSocket(transport: transport, pid: 414).lookupExact(host.destination) == nil)
                try check(transport.sent == [UInt8(RTM_GET)]); continue
            } else { transport.replies = [try contradictory(mode, family)] }
            let observer = VPNDarwinRouteSocket(transport: transport, pid: 414)
            if ["exact", "default", "default-link", "absent", "enoent"].contains(mode) {
                let found = try observer.lookupExact(desired.destination)
                try check(mode == "exact" ? found?.matches(desired) == true : found == nil)
            } else {
                do { _ = try observer.lookupExact(desired.destination); throw Failure.check }
                catch VPNDarwinRouteError.verificationFailed {}
            }
            try check(transport.sent == [UInt8(RTM_GET)])
        }}
        print("ordinary route evidence passed")
    }
}
