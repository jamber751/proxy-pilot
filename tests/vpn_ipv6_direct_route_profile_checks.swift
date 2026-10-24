import Darwin
import Foundation
import CryptoKit

// Private interface table only. Never inspect/create a host interface or socket.
@_cdecl("if_indextoname")
func custodyInterfaceName(_ index: UInt32, _ output: UnsafeMutablePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let output, let name = [7:"en7", 42:"utun42", 43:"utun43"][index] else { return nil }
    for (offset, byte) in name.utf8CString.enumerated() { output[offset] = byte }
    return output
}

private final class Kernel: VPNRouteKernelController {
    var rows: [String: VPNDarwinRouteSnapshot] = [:]
    var queries: [VPNRouteLookupKey] = []
    var deleted: [VPNOwnedRouteIdentity] = []
    var failBefore: Int?, failAfter: Int?
    var failDeleteAfter = false
    private var count = 0
    static func key(_ query: VPNRouteLookupKey) -> String {
        "\(query.destination.family.rawValue):\(query.destination.canonical):\(query.interfaceScope?.interfaceIndex ?? 0)"
    }
    static func snapshot(_ value: VPNOwnedRouteIdentity) -> VPNDarwinRouteSnapshot {
        VPNDarwinRouteSnapshot(destination: value.destination, gatewayBytes: value.gatewayBytes,
            interfaceIndex: value.interfaceIndex, interfaceName: value.interfaceName, flags: value.flags)
    }
    func lookupExact(_ prefix: VPNRoutePrefix) throws -> VPNDarwinRouteSnapshot? {
        try lookupExact(VPNRouteLookupKey(destination: prefix, interfaceScope: nil))
    }
    func lookupExact(_ query: VPNRouteLookupKey) throws -> VPNDarwinRouteSnapshot? {
        try query.validate(); queries.append(query)
        return rows[Self.key(query)]
    }
    func add(_ value: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult {
        defer { count += 1 }
        if failBefore == count { throw VPNDarwinRouteError.timeout }
        let key = Self.key(value.lookupKey)
        if rows[key] != nil { return .alreadyPresent }
        rows[key] = Self.snapshot(value)
        if failAfter == count { throw VPNDarwinRouteError.timeout }
        return .installed
    }
    func delete(_ value: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult {
        let key = Self.key(value.lookupKey)
        guard rows[key]?.matches(value) == true else { throw VPNDarwinRouteError.missingOrForeign }
        rows.removeValue(forKey: key); deleted.append(value)
        if failDeleteAfter { failDeleteAfter = false; throw VPNDarwinRouteError.timeout }
        return .removed
    }
}
private final class Transport: VPNRouteSocketTransport {
    var sent: [Data] = [], replies: [Data] = []
    func send(_ message: Data, deadline: DispatchTime) throws { sent.append(message) }
    func receive(maximumBytes: Int, deadline: DispatchTime) throws -> Data {
        guard !replies.isEmpty else { throw VPNRouteSocketTransportError.timeout }
        return replies.removeFirst()
    }
}
@main private enum Checks {
    enum Failure: Error { case check }
    static func check(_ value: @autoclosure () throws -> Bool) throws {
        if try !value() { throw Failure.check }
    }
    static func rejects(_ operation: () throws -> Void) throws {
        do { try operation() } catch { return }
        throw Failure.check
    }
    static func ip4(_ value: String) -> in_addr {
        var result = in_addr()
        precondition(value.withCString { inet_pton(AF_INET, $0, &result) } == 1)
        return result
    }
    static func tunnel(_ index: UInt32 = 42) throws -> VPNTunnelInterfaceEvidence {
        let address = try OpenVPNIPAddress(parsing: "10.255.254.1", family: .ipv4)
        return try VPNTunnelInterfaceResolver.resolve(baseline: VPNKernelInterfaceSnapshot(interfaces: []),
            after: VPNKernelInterfaceSnapshot(interfaces: [VPNKernelInterfaceRecord(index: index, name: "utun\(index)",
                isUp: true, isRunning: true, isPointToPoint: true, addresses: [address])]),
            management: OpenVPNConnectedEvidence(tunnelLocalIPv4: address, tunnelLocalIPv6: nil,
                remoteAddress: OpenVPNIPAddress(parsing: "198.51.100.9", family: .ipv4), remotePort: 443))
    }
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }
    static func mutate<T: Codable>(_ value: T, _ edit: (inout [String: Any]) -> Void) throws -> T {
        var object = try JSONSerialization.jsonObject(with: encode(value)) as! [String: Any]
        edit(&object)
        return try JSONDecoder().decode(T.self, from: JSONSerialization.data(withJSONObject: object))
    }
    static func reply(_ value: VPNOwnedRouteIdentity?, _ type: Int32, _ sequence: Int32,
                      error: Int32 = 0) throws -> Data {
        try VPNDarwinRouteCodec.encodeReply(type: UInt8(type), sequence: sequence, pid: 414, error: error, identity: value)
    }
    static func mixedPlan(_ scoped: Bool) throws -> VPNRoutePlan {
        try VPNRoutePlan(generation: 7, revision: 11,
            resources: scoped ? [VPNResource(address:"10.44.0.1")] : [VPNResource(address:"10.44.0.1"), VPNResource(address:"2001:db8:44::1"), VPNResource(address:"2001:db8:55::/64")],
            peer: VPNRoutePeerEvidence(peer:ip4("198.51.100.9"),gateway:ip4("192.0.2.1"),interfaceIndex:7),
            tunnel:tunnel(), dnsDependencies:scoped ? ["10.55.0.53","2001:db8:53::53"].map { try VPNRoutePrefix(resource:VPNResource(address:$0)) } : [])
    }
    static func hostPlan(_ scoped: Bool) throws -> VPNRoutePlan {
        try VPNRoutePlan(generation:7,revision:11,
            resources:scoped ? [] : [VPNResource(address:"2001:db8:53::53")],
            peer:VPNRoutePeerEvidence(peer:ip4("198.51.100.9"),gateway:ip4("192.0.2.1"),interfaceIndex:7),
            tunnel:tunnel(),dnsDependencies:scoped ? [VPNRoutePrefix(resource:VPNResource(address:"2001:db8:53::53"))] : [])
    }
    static func identities(_ plan: VPNRoutePlan, legacy: Bool = false) throws -> [VPNOwnedRouteIdentity] {
        try VPNRouteIdentityFactory.make(plan:plan).map { identity in
            if legacy { return try mutate(identity) { $0["flags"] = identity.flags & ~UInt32(RTF_LLINFO) } }
            return identity
        }
    }
    static func replaceGateway(_ packet: Data, _ replacement: Data?) throws -> Data {
        var header = try VPNDarwinRouteCodec.identify(packet)
        var offset = MemoryLayout<rt_msghdr>.size, body = Data()
        for index in 0..<Int(RTAX_MAX) where header.rtm_addrs & (1 << index) != 0 {
            let length = Int(packet[offset]); let rounded = (length + 3) & ~3
            let address = index == Int(RTAX_GATEWAY) ? replacement : packet.subdata(in:offset..<offset+length)
            if let address { body.append(address); body.append(Data(repeating:0,count:((address.count+3) & ~3)-address.count)) }
            else { header.rtm_addrs &= ~(1 << index) }
            offset += rounded
        }
        header.rtm_msglen = UInt16(MemoryLayout<rt_msghdr>.size+body.count)
        var output = withUnsafeBytes(of:&header) { Data($0) }; output.append(body); return output
    }
    static func link(_ name: String = "", index: UInt16 = 42, address: UInt8 = 0, selector: UInt8 = 0) -> Data {
        var bytes:[UInt8] = [UInt8(8+name.utf8.count+Int(address)+Int(selector)),UInt8(AF_LINK),UInt8(index & 255),UInt8(index >> 8),0,UInt8(name.utf8.count),address,selector]
        bytes += name.utf8; bytes += [UInt8](repeating:0,count:Int(address)+Int(selector)); return Data(bytes)
    }
    static func profile(_ mode: String, _ scoped: Bool, _ directory: String) throws {
        let plan = try mixedPlan(scoped), entries = try identities(plan)
        let value = entries.first(where:VPNManagedIPv6HostRoute.isExact)!
        switch mode {
        case "factory":
            try check(plan.schemaVersion == (scoped ? 3 : 2))
            try check(value.flags == UInt32(RTF_UP|RTF_STATIC|RTF_HOST|RTF_PROTO2|RTF_LLINFO) | (scoped ? UInt32(RTF_IFSCOPE) : 0))
            try check(entries.filter { !VPNManagedIPv6HostRoute.applies(to:$0) }.allSatisfy { $0.flags & UInt32(RTF_LLINFO) == 0 })
        case "domain-proof":
            let network = try VPNDomainNetworkPlan(generation:7,revision:11,
                resources:[VPNResource(address:"portal.corp.test")],corporateDNS:["2001:db8:53::53"],
                peer:VPNRoutePeerEvidence(peer:ip4("198.51.100.9"),gateway:ip4("192.0.2.1"),interfaceIndex:7),tunnel:tunnel())
            let actual = try identities(network.staticRoutes)
            let proof = VPNRouteAppliedProof(generation:7,revision:11,identities:actual)
            let dns = try network.dnsPlan(tunnel:tunnel(),routeProof:proof)
            try check(dns.serverEvidence.first?.verifiedRoute.flags == actual.last?.flags)
            let old = try identities(network.staticRoutes,legacy:true)
            try rejects { _ = try network.dnsPlan(tunnel:tunnel(),routeProof:VPNRouteAppliedProof(generation:7,revision:11,identities:old)) }
        case "journal-unneeded":
            let noHost = try VPNRoutePlan(generation:7,revision:11,resources:[VPNResource(address:"2001:db8:55::/64")],
                peer:VPNRoutePeerEvidence(peer:ip4("198.51.100.9"),gateway:ip4("192.0.2.1"),interfaceIndex:7),tunnel:tunnel())
            try check(VPNRouteJournalSnapshot.schema(for:noHost) == 1)
            try rejects { try VPNRouteJournalSnapshot(schemaVersion:3,plan:noHost,phase:.planned,applied:[],operation:nil).validate() }
        case "identity-negative":
            for flag in [RTF_GATEWAY,RTF_REJECT,RTF_DYNAMIC,RTF_WASCLONED,RTF_LOCAL] {
                let bad = try mutate(value) { $0["flags"] = value.flags | UInt32(flag) }
                try rejects { try bad.validate() }
            }
            let bad = try mutate(value) { $0["interfaceName"] = "en7" }
            try rejects { try bad.validate() }
        case "wire":
            for kind in [RTM_GET,RTM_ADD,RTM_DELETE] {
                let packet = try VPNDarwinRouteCodec.encode(type:UInt8(kind),sequence:1,pid:414,identity:value)
                try check(UInt32(bitPattern:VPNDarwinRouteCodec.identify(packet).rtm_flags) == value.flags & ~UInt32(RTF_LLINFO))
                try check(try VPNDarwinRouteCodec.decode(packet).snapshot?.matches(value) == false)
                try check(try VPNDarwinRouteCodec.decode(reply(value,kind,1)).snapshot?.matches(value) == true)
            }
        case "link-empty-name", "link-missing", "link-numeric", "link-wrong-index", "link-wrong-name", "link-address", "link-selector":
            let original = try reply(value,RTM_GET,1)
            let gateway:Data?
            switch mode {
            case "link-missing": gateway = nil
            case "link-numeric": gateway = Data([28,UInt8(AF_INET6)]+[UInt8](repeating:0,count:26))
            case "link-wrong-index": gateway = link(index:43)
            case "link-wrong-name": gateway = link("utun43")
            case "link-address": gateway = link(address:1)
            case "link-selector": gateway = link(selector:1)
            default: gateway = link()
            }
            let packet = try replaceGateway(original,gateway)
            if mode == "link-empty-name" { try check(try VPNDarwinRouteCodec.decode(packet).snapshot?.matches(value) == true) }
            else { try rejects { _ = try VPNDarwinRouteCodec.decode(packet) } }
        case "journal3", "journal-invalid", "legacy-goldens":
            let legacy = try identities(plan,legacy:true)
            let old = VPNRouteJournalSnapshot(schemaVersion:scoped ? 2 : 1,plan:plan,phase:.applied,applied:legacy,operation:nil)
            try old.validate()
            if mode == "legacy-goldens" {
                // Pre-change snapshots were compiled/captured before this profile
                // increment. These hashes include original JSON slash escaping.
                let planHash = scoped ? "3c683ce814627ef66548aee2ebbbf4edc5d8599aeee68b42448ada60385c0147" : "4dca774e22158e5893dc73a6d8c4baf7c270cca32d7a636fbc1e5fa35f23f226"
                let journalHash = scoped ? "3fe2b80b1b7d3e9128064cefea8ff4ac62cf06bb0f64ef2ce7e5b7df56751b74" : "973d3317e88b8f13e9d68b904e25fc2e00bdee7fcea2c9ed72d617cd7954e935"
                func hash(_ data:Data)->String { SHA256.hash(data:data).map { String(format:"%02x",$0) }.joined() }
                try check(hash(encode(plan)) == planHash); try check(hash(encode(old)) == journalHash)
                try check(try encode(JSONDecoder().decode(VPNRouteJournalSnapshot.self,from:encode(old))) == encode(old))
                // Frozen legacy reader's accepted format is exactly 1/plan2 or 2/plan3.
                try check(VPNRouteJournalSnapshot.schema(for:plan) != (plan.schemaVersion == 3 ? 2 : 1))
            } else {
                let current = VPNRouteJournalSnapshot(schemaVersion:3,plan:plan,phase:.applied,applied:entries,operation:nil)
                try current.validate()
                if mode == "journal-invalid" {
                    try rejects { try VPNRouteJournalSnapshot(schemaVersion:3,plan:plan,phase:.applied,applied:legacy,operation:nil).validate() }
                    try rejects { try VPNRouteJournalSnapshot(schemaVersion:scoped ? 2 : 1,plan:plan,phase:.applied,applied:entries,operation:nil).validate() }
                }
            }
        case "adapter", "adapter-missing-llinfo", "preexisting-adapter":
            let transport = Transport(), socket = VPNDarwinRouteSocket(transport:transport,pid:414)
            if mode == "preexisting-adapter" {
                transport.replies = [try reply(value,RTM_GET,1)]
                try check(try socket.add(value) == .alreadyPresent); try check(transport.sent.count == 1)
            } else {
                let observed = mode == "adapter" ? value : try mutate(value) { $0["flags"] = value.flags & ~UInt32(RTF_LLINFO) }
                transport.replies = [try reply(nil,RTM_GET,1,error:ESRCH),try reply(nil,RTM_ADD,2),try reply(observed,RTM_GET,3)]
                if mode == "adapter-missing-llinfo" { try rejects { _ = try socket.add(value) }; try check(transport.sent.count == 3) }
                else {
                    try check(try socket.add(value) == .installed)
                    transport.replies = [try reply(value,RTM_GET,4),try reply(nil,RTM_DELETE,5),try reply(nil,RTM_GET,6,error:ESRCH)]
                    try check(try socket.delete(value) == .removed)
                    try check(transport.sent.count == 6)
                }
            }
        default: try recovery(mode,scoped,directory)
        }
    }
    static func recovery(_ mode:String,_ scoped:Bool,_ directory:String) throws {
        let fd = open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
        guard fd >= 0 else { throw Failure.check }; defer { close(fd) }
        let journal = try VPNRouteJournal(trustedDirectoryDescriptor:fd), kernel = Kernel()
        let plan = try hostPlan(scoped), current = try identities(plan), target = current.last!
        let tx = VPNRouteTransaction(journal:journal,kernel:kernel)
        let legacy = mode.hasPrefix("legacy-")
        if legacy {
            let entries = try identities(plan,legacy:true)
            let snapshot = VPNRouteJournalSnapshot(schemaVersion:scoped ? 2 : 1,plan:plan,
                phase:mode == "legacy-pending" ? .installing : .applied,
                applied:mode == "legacy-pending" ? Array(entries.dropLast()) : entries,
                operation:mode == "legacy-pending" ? VPNRouteJournalOperation(action:.install,entry:entries.last!) : nil)
            try snapshot.validate()
            try check(FileManager.default.createFile(atPath:directory+"/"+VPNRouteJournal.name,contents:encode(snapshot),attributes:[.posixPermissions:0o600]))
            kernel.rows[Kernel.key(target.lookupKey)] = Kernel.snapshot(target)
        } else if mode == "preexisting-transaction" {
            kernel.rows[Kernel.key(target.lookupKey)] = Kernel.snapshot(target)
            try rejects { _ = try tx.install(plan) }; try check(kernel.deleted.isEmpty)
            try check(kernel.rows.count == 1); try rejects { _ = try journal.load() }; return
        } else {
            kernel.failBefore = mode == "recovery-before" ? 1 : nil
            kernel.failAfter = mode == "recovery-before" || mode == "lifecycle" ? nil : 1
            if mode == "lifecycle" { let proof = try tx.install(plan); try tx.verifyApplied(proof); try check(try journal.load().schemaVersion == 3) }
            else { try rejects { _ = try tx.install(plan) } }
        }
        let path = directory+"/"+VPNRouteJournal.name, before = try Data(contentsOf:URL(fileURLWithPath:path))
        if mode.hasPrefix("foreign-") {
            let row = Kernel.snapshot(target)
            kernel.rows[Kernel.key(target.lookupKey)] = VPNDarwinRouteSnapshot(destination:row.destination,gatewayBytes:nil,
                interfaceIndex:mode == "foreign-interface" ? 43 : 42,interfaceName:mode == "foreign-interface" ? "utun43" : "utun42",
                flags:row.flags & ~(mode == "foreign-missing-llinfo" ? UInt32(RTF_LLINFO) : mode == "foreign-missing-owner" ? UInt32(RTF_PROTO2) : 0))
        }
        if legacy || mode.hasPrefix("foreign-") {
            try rejects { try tx.recoverToIdle() }
            try check(try Data(contentsOf:URL(fileURLWithPath:path)) == before)
            try check(kernel.deleted.isEmpty && kernel.rows[Kernel.key(target.lookupKey)] != nil)
        } else {
            kernel.failBefore = nil; kernel.failAfter = nil
            try tx.recoverToIdle(); try check(kernel.rows.isEmpty)
            try check(kernel.deleted.contains(target) == (mode != "recovery-before"))
            try rejects { _ = try journal.load() }
        }
    }
    static func main() throws {
        guard CommandLine.arguments.count == 3 else { exit(64) }
        for scoped in [false,true] {
            let directory = CommandLine.arguments[2]+(scoped ? "/scoped" : "/ordinary")
            try FileManager.default.createDirectory(atPath:directory,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
            try profile(CommandLine.arguments[1],scoped,directory)
        }
        print("pure IPv6 route profile passed")
    }
}
