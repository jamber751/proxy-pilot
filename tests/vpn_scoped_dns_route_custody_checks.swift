import Darwin
import Foundation

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
private final class LegacyOnlyKernel: VPNRouteKernelController {
    var mutations = 0
    func lookupExact(_ destination: VPNRoutePrefix) throws -> VPNDarwinRouteSnapshot? { nil }
    func add(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult { mutations += 1; return .installed }
    func delete(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult { mutations += 1; return .removed }
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
    static func plan(_ servers: [String] = ["10.44.0.53", "2001:db8::53"], index: UInt32 = 42,
                     legacy: Bool = false) throws -> VPNRoutePlan {
        try VPNRoutePlan(generation: 7, revision: 11,
            resources: legacy ? [VPNResource(address: "10.44.0.53")] : [],
            peer: VPNRoutePeerEvidence(peer: ip4("198.51.100.9"), gateway: ip4("192.0.2.1"), interfaceIndex: 7),
            tunnel: tunnel(index), dnsDependencies: legacy ? [] : servers.map { try VPNRoutePrefix(resource: VPNResource(address: $0)) })
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
    static func scopedIdentity(_ server: String, index: UInt32 = 42) throws -> VPNOwnedRouteIdentity {
        try VPNRouteIdentityFactory.make(plan: plan([server], index: index)).last!
    }
    static func unscopedIdentity(_ server: String, index: UInt32 = 43) throws -> VPNOwnedRouteIdentity {
        let route = VPNPlannedRoute(role: .resource, destination: try VPNRoutePrefix(resource: VPNResource(address: server)),
            physicalGatewayBytes: nil, interfaceIndex: index, interfaceName: "utun\(index)")
        let flags = UInt32(RTF_UP | RTF_STATIC | RTF_PROTO2 | RTF_HOST)
        let evidence: VPNRouteKernelEvidence
        if route.destination.family == .ipv4 {
            evidence = try VPNRouteKernelEvidence(gateway: Optional<in_addr>.none, interfaceIndex: index, flags: flags)
        } else {
            evidence = try VPNRouteKernelEvidence(gateway: Optional<in6_addr>.none, interfaceIndex: index, flags: flags)
        }
        return try VPNOwnedRouteIdentity(planned: route, evidence: evidence)
    }
    static func codec() throws {
        for server in ["10.44.0.53", "2001:db8::53"] {
            let value = try scopedIdentity(server)
            for type in [RTM_GET, RTM_ADD, RTM_DELETE] {
                let data = try VPNDarwinRouteCodec.encode(type: UInt8(type), sequence: 1, pid: 414, identity: value)
                let header = try VPNDarwinRouteCodec.identify(data)
                try check(header.rtm_index == 42 && UInt32(bitPattern: header.rtm_flags) & UInt32(RTF_IFSCOPE) != 0)
                let requestFlags = UInt32(bitPattern: header.rtm_flags)
                try check(requestFlags == value.flags & ~UInt32(RTF_LLINFO))
                let reply = try VPNDarwinRouteCodec.encodeReply(type:UInt8(type),sequence:1,pid:414,error:0,identity:value)
                try check(try VPNDarwinRouteCodec.decode(reply).snapshot?.matches(value) == true)
            }
            let request = try VPNDarwinRouteCodec.encodeLookup(key: value.lookupKey, sequence: 2, pid: 414)
            let header = try VPNDarwinRouteCodec.identify(request)
            try check(header.rtm_index == 42 && header.rtm_flags == RTF_HOST | RTF_IFSCOPE)
            let old = try VPNDarwinRouteCodec.encodeLookup(destination: value.destination, sequence: 2, pid: 414)
            let oldHeader = try VPNDarwinRouteCodec.identify(old)
            try check(oldHeader.rtm_index == 0 && oldHeader.rtm_flags == RTF_HOST)
            for other in [try unscopedIdentity(server), try scopedIdentity(server, index: 43)] {
                let fake = Transport(); fake.replies = [try reply(other, RTM_GET, 1)]
                do {
                    _ = try VPNDarwinRouteSocket(transport: fake, pid: 414).lookupExact(value.lookupKey)
                    throw Failure.check
                } catch VPNDarwinRouteError.verificationFailed {}
            }
            // A same-interface, unscoped fallback must not become scoped custody.
            let fake = Transport(); fake.replies = [try reply(unscopedIdentity(server, index: 42), RTM_GET, 1)]
            try check(try VPNDarwinRouteSocket(transport: fake, pid: 414).lookupExact(value.lookupKey) == nil)
            let network = try VPNResource(address: server.contains(":") ? "2001:db8::/32" : "10.44.0.0/16")
            let broadPlan = try VPNRoutePlan(generation: 7, revision: 11, resources: [network],
                peer: VPNRoutePeerEvidence(peer: ip4("198.51.100.9"), gateway: ip4("192.0.2.1"), interfaceIndex: 7), tunnel: tunnel())
            let broader = try VPNRouteIdentityFactory.make(plan: broadPlan).last!
            let broad = Transport(); broad.replies = [try reply(broader, RTM_GET, 1)]
            try check(try VPNDarwinRouteSocket(transport: broad, pid: 414).lookupExact(value.lookupKey) == nil)
            let absent = Transport(); absent.replies = [try reply(nil, RTM_GET, 1, error: ESRCH)]
            try check(try VPNDarwinRouteSocket(transport: absent, pid: 414).lookupExact(value.lookupKey) == nil)
            let ambiguous = Transport(); ambiguous.replies = [try reply(nil, RTM_GET, 1)]
            do {
                _ = try VPNDarwinRouteSocket(transport: ambiguous, pid: 414).lookupExact(value.lookupKey)
                throw Failure.check
            } catch VPNDarwinRouteError.verificationFailed {}
            let unrelated = Transport()
            unrelated.replies = [try reply(scopedIdentity(server.contains(":") ? "10.44.0.54" : "2001:db8::54"), RTM_GET, 1)]
            do {
                _ = try VPNDarwinRouteSocket(transport: unrelated, pid: 414).lookupExact(value.lookupKey)
                throw Failure.check
            } catch VPNDarwinRouteError.verificationFailed {}
        }
    }
    static func adapter(_ race: Bool) throws {
        for server in ["10.44.0.53", "2001:db8::53"] {
            let value = try scopedIdentity(server), fallback = try unscopedIdentity(server, index: 42)
            let fake = Transport()
            fake.replies = [try reply(fallback, RTM_GET, 1), try reply(race ? nil : value, RTM_ADD, 2, error: race ? EEXIST : 0),
                            try reply(value, RTM_GET, 3)]
            let socket = VPNDarwinRouteSocket(transport: fake, pid: 414)
            try check(try socket.add(value) == (race ? .alreadyPresent : .installed))
            fake.replies = [try reply(value, RTM_GET, 4), try reply(value, RTM_DELETE, 5), try reply(fallback, RTM_GET, 6)]
            try check(try socket.delete(value) == .removed)
            for request in fake.sent {
                let header = try VPNDarwinRouteCodec.identify(request)
                try check(header.rtm_index == 42 && header.rtm_flags & RTF_IFSCOPE != 0)
            }
            try check(fake.replies.isEmpty)
        }
    }
    static func adapterForeign() throws {
        let value = try scopedIdentity("10.44.0.53"), fake = Transport()
        var foreign = try reply(value, RTM_GET, 1)
        var header = try VPNDarwinRouteCodec.identify(foreign)
        header.rtm_flags &= ~RTF_PROTO2
        withUnsafeBytes(of: &header) { foreign.replaceSubrange(0..<MemoryLayout<rt_msghdr>.size, with: $0) }
        fake.replies = [foreign]
        try rejects { _ = try VPNDarwinRouteSocket(transport: fake, pid: 414).delete(value) }
        try check(fake.sent.count == 1 && VPNDarwinRouteCodec.identify(fake.sent[0]).rtm_type == UInt8(RTM_GET))
    }
    static func adapterWrongScope() throws {
        let value = try scopedIdentity("10.44.0.53"), fake = Transport()
        fake.replies = [try reply(scopedIdentity("10.44.0.53", index: 43), RTM_GET, 1)]
        do {
            _ = try VPNDarwinRouteSocket(transport: fake, pid: 414).delete(value)
            throw Failure.check
        } catch VPNDarwinRouteError.verificationFailed {}
        try check(fake.sent.count == 1 && VPNDarwinRouteCodec.identify(fake.sent[0]).rtm_type == UInt8(RTM_GET))
    }
    static func validation() throws {
        let value = try plan(), identity = try VPNRouteIdentityFactory.make(plan: value).last!
        try check(value.schemaVersion == 3 && identity.role == .dnsDependency)
        for edit: (inout [String: Any]) -> Void in [
            { $0.removeValue(forKey: "interfaceScope") },
            { $0["flags"] = identity.flags & ~UInt32(RTF_IFSCOPE) },
            { $0["flags"] = identity.flags & ~UInt32(RTF_PROTO2) },
            { $0["role"] = 2 }, { $0["interfaceIndex"] = 43 },
            { $0["interfaceScope"] = ["interfaceIndex":43, "interfaceName":"utun43"] }
        ] {
            let bad = try mutate(identity, edit)
            try rejects { try bad.validate() }
        }
        let downgraded = try mutate(value) { $0["schemaVersion"] = 2 }
        try rejects { try downgraded.validate() }
        let upgradedLegacy = try mutate(plan(legacy: true)) { $0["schemaVersion"] = 3 }
        try rejects { try upgradedLegacy.validate() }
        for (format, plan) in [(1, value), (2, try self.plan(legacy: true))] {
            try rejects { try VPNRouteJournalSnapshot(schemaVersion: format, plan: plan, phase: .planned,
                applied: [], operation: nil).validate() }
        }
        let old = try unscopedIdentity("10.44.0.53")
        let forged = try mutate(old) { $0["flags"] = old.flags | UInt32(RTF_IFSCOPE) }
        try rejects { try forged.validate() }
    }
    static func transaction(_ directory: String, mode: String) throws {
        let fd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Failure.check }; defer { close(fd) }
        let journal = try VPNRouteJournal(trustedDirectoryDescriptor: fd), kernel = Kernel()
        let value = try plan(), identities = try VPNRouteIdentityFactory.make(plan: value)
        let foreign = try [unscopedIdentity("10.44.0.53"), scopedIdentity("10.44.0.53", index: 43)]
        for item in foreign { kernel.rows[Kernel.key(item.lookupKey)] = Kernel.snapshot(item) }
        let untouched = kernel.rows
        let tx = VPNRouteTransaction(journal: journal, kernel: kernel)
        switch mode {
        case "coexist":
            let proof = try tx.install(value)
            try check(try journal.load().schemaVersion == 3)
            try tx.verifyApplied(proof)
        case "crash-before", "crash-after", "foreign", "missing", "wrong-scope-recovery":
            kernel.failBefore = mode == "crash-before" ? 1 : nil
            kernel.failAfter = mode == "crash-before" ? nil : 1
            try rejects { _ = try tx.install(value) }
            let snapshot = try journal.load()
            try check(snapshot.schemaVersion == 3 && snapshot.operation?.entry == identities[1])
            if mode == "wrong-scope-recovery" {
                let before = try Data(contentsOf: URL(fileURLWithPath: directory).appendingPathComponent(VPNRouteJournal.name))
                let fake = Transport()
                fake.replies = [try reply(scopedIdentity("10.44.0.53", index: 43), RTM_GET, 1)]
                let adapter = VPNDarwinRouteSocket(transport: fake, pid: 414)
                do {
                    try VPNRouteTransaction(journal: journal, kernel: adapter).recoverToIdle()
                    throw Failure.check
                } catch VPNRouteTransactionError.recoveryRequired {}
                try check(fake.sent.count == 1 && VPNDarwinRouteCodec.identify(fake.sent[0]).rtm_type == UInt8(RTM_GET))
                try check(try before == Data(contentsOf: URL(fileURLWithPath: directory).appendingPathComponent(VPNRouteJournal.name)))
                return
            }
            if mode == "foreign" {
                let original = Kernel.snapshot(identities[1])
                kernel.rows[Kernel.key(identities[1].lookupKey)] = VPNDarwinRouteSnapshot(
                    destination: original.destination, gatewayBytes: nil, interfaceIndex: 42,
                    interfaceName: "utun42", flags: original.flags & ~UInt32(RTF_PROTO2))
                try rejects { try tx.recoverToIdle() }
                try check(try journal.load() == snapshot)
                try check(kernel.deleted.isEmpty)
                return
            }
            if mode == "missing" { kernel.rows.removeValue(forKey: Kernel.key(identities[1].lookupKey)) }
        case "preexisting":
            kernel.rows[Kernel.key(identities[1].lookupKey)] = Kernel.snapshot(identities[1])
            let before = kernel.rows
            try rejects { _ = try tx.install(value) }
            try check(kernel.rows == before)
            try rejects { _ = try journal.load() }
            return
        case "foreign-delete":
            _ = try tx.install(value)
            let own = identities.last!, snapshot = Kernel.snapshot(own)
            kernel.rows[Kernel.key(own.lookupKey)] = VPNDarwinRouteSnapshot(destination: snapshot.destination,
                gatewayBytes: nil, interfaceIndex: 42, interfaceName: "utun42", flags: snapshot.flags & ~UInt32(RTF_PROTO2))
            let before = try Data(contentsOf: URL(fileURLWithPath: directory).appendingPathComponent(VPNRouteJournal.name))
            try rejects { try tx.recoverToIdle() }
            try check(kernel.deleted.isEmpty)
            try check(try before == Data(contentsOf: URL(fileURLWithPath: directory).appendingPathComponent(VPNRouteJournal.name)))
            return
        case "crash-delete", "wrong-scope-delete-recovery":
            _ = try tx.install(value)
            kernel.failDeleteAfter = true
            try rejects { try tx.recoverToIdle() }
            let checkpoint = try journal.load()
            try check(checkpoint.phase == .removing && checkpoint.operation?.action == .remove)
            try check(checkpoint.operation?.entry == identities.last)
            if mode == "wrong-scope-delete-recovery" {
                let before = try Data(contentsOf: URL(fileURLWithPath: directory).appendingPathComponent(VPNRouteJournal.name))
                let fake = Transport()
                fake.replies = [try reply(scopedIdentity("2001:db8::53", index: 43), RTM_GET, 1)]
                let adapter = VPNDarwinRouteSocket(transport: fake, pid: 414)
                do {
                    try VPNRouteTransaction(journal: journal, kernel: adapter).recoverToIdle()
                    throw Failure.check
                } catch VPNRouteTransactionError.recoveryRequired {}
                try check(fake.sent.count == 1 && VPNDarwinRouteCodec.identify(fake.sent[0]).rtm_type == UInt8(RTM_GET))
                try check(try before == Data(contentsOf: URL(fileURLWithPath: directory).appendingPathComponent(VPNRouteJournal.name)))
                return
            }
        default: throw Failure.check
        }
        try VPNRouteTransaction(journal: journal, kernel: kernel).recoverToIdle()
        try check(kernel.rows == untouched)
        try check(kernel.deleted.filter { $0.role == .dnsDependency }.allSatisfy { $0.interfaceScope?.interfaceIndex == 42 })
        try rejects { _ = try journal.load() }
        let scopedQueries = kernel.queries.filter { $0.destination == identities[1].destination }
        try check(!scopedQueries.isEmpty && scopedQueries.allSatisfy { $0.interfaceScope?.interfaceIndex == 42 })
    }
    static func legacy(_ directory: String) throws {
        let value = try plan(legacy: true), data = try encode(value)
        // Captured by compiling the pre-scope production RoutePlan/Journal at
        // HEAD before this change, with this same private interface table.
        let golden = #"{"generation":7,"revision":11,"routes":[{"destination":{"bytes":[198,51,100,9],"canonical":"198.51.100.9","family":4,"prefixLength":32},"interfaceIndex":7,"interfaceName":"en7","physicalGatewayBytes":[192,0,2,1],"role":1},{"destination":{"bytes":[10,44,0,53],"canonical":"10.44.0.53","family":4,"prefixLength":32},"interfaceIndex":42,"interfaceName":"utun42","role":2}],"schemaVersion":2,"tunnelInterface":{"interfaceIndex":42,"interfaceName":"utun42"}}"#
        try check(data == Data(golden.utf8))
        try check(value.schemaVersion == 2 && !String(decoding: data, as: UTF8.self).contains("interfaceScope"))
        let decoded = try JSONDecoder().decode(VPNRoutePlan.self, from: data)
        try check(try encode(decoded) == data)
        let fd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Failure.check }; defer { close(fd) }
        let journal = try VPNRouteJournal(trustedDirectoryDescriptor: fd), kernel = Kernel()
        _ = try journal.create(value)
        let oldJournal = "{\"applied\":[],\"phase\":\"planned\",\"plan\":" + golden + ",\"schemaVersion\":1}"
        try check(try Data(contentsOf: URL(fileURLWithPath: directory).appendingPathComponent(VPNRouteJournal.name)) == Data(oldJournal.utf8))
        try VPNRouteTransaction(journal: journal, kernel: kernel).recoverToIdle()
        kernel.failAfter = 1
        try rejects { _ = try VPNRouteTransaction(journal: journal, kernel: kernel).install(value) }
        try check(try journal.load().schemaVersion == 1)
        try VPNRouteTransaction(journal: journal, kernel: kernel).recoverToIdle()
        try check(kernel.rows.isEmpty)
        try rejects { _ = try journal.load() }
    }
    static func unsupportedController(_ directory: String) throws {
        let fd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw Failure.check }; defer { close(fd) }
        let journal = try VPNRouteJournal(trustedDirectoryDescriptor: fd), kernel = LegacyOnlyKernel()
        try rejects { _ = try VPNRouteTransaction(journal: journal, kernel: kernel).install(plan()) }
        try check(kernel.mutations == 0)
        try rejects { _ = try journal.load() }
    }
    static func main() throws {
        guard CommandLine.arguments.count == 3 else { exit(64) }
        switch CommandLine.arguments[1] {
        case "codec": try codec()
        case "adapter": try adapter(false)
        case "race": try adapter(true)
        case "adapter-foreign": try adapterForeign()
        case "adapter-wrong-scope": try adapterWrongScope()
        case "validation": try validation()
        case "legacy": try legacy(CommandLine.arguments[2])
        case "unsupported": try unsupportedController(CommandLine.arguments[2])
        default: try transaction(CommandLine.arguments[2], mode: CommandLine.arguments[1])
        }
        print("scoped DNS route custody passed")
    }
}
