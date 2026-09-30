import Darwin
import Foundation

@main enum VPNRoutePlanChecks {
    static func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        guard condition() else { throw NSError(domain: message, code: 1) }
    }

    static func ipv4(_ text: String) -> in_addr {
        var value = in_addr()
        guard text.withCString({ inet_pton(AF_INET, $0, &value) }) == 1 else { exit(64) }
        return value
    }

    static func ipv6(_ text: String) -> in6_addr {
        var value = in6_addr()
        guard text.withCString({ inet_pton(AF_INET6, $0, &value) }) == 1 else { exit(64) }
        return value
    }

    static func interfaceIndex() -> UInt32 {
        for name in ["lo0", "en0", "en1"] {
            let value = if_nametoindex(name)
            if value > 0 { return value }
        }
        exit(77)
    }

    static func tunnelIdentity() -> (UInt32, String) {
        guard let first = if_nameindex() else { exit(77) }
        defer { if_freenameindex(first) }
        var cursor = first
        while cursor.pointee.if_index != 0, let raw = cursor.pointee.if_name {
            let item = cursor.pointee
            let name = String(cString: raw)
            if name.hasPrefix("utun"), !name.dropFirst(4).isEmpty,
               name.dropFirst(4).utf8.allSatisfy({ (48...57).contains($0) }) {
                return (item.if_index, name)
            }
            cursor = cursor.advanced(by: 1)
        }
        exit(77)
    }

    static func tunnelEvidence() throws -> VPNTunnelInterfaceEvidence {
        let identity = tunnelIdentity()
        let address = try OpenVPNIPAddress(parsing: "10.255.254.1", family: .ipv4)
        let baseline = try VPNKernelInterfaceSnapshot(interfaces: [])
        let after = try VPNKernelInterfaceSnapshot(interfaces: [
            try VPNKernelInterfaceRecord(index: identity.0, name: identity.1, isUp: true,
                isRunning: true, isPointToPoint: true, addresses: [address])
        ])
        let management = OpenVPNConnectedEvidence(tunnelLocalIPv4: address,
            tunnelLocalIPv6: nil,
            remoteAddress: try OpenVPNIPAddress(parsing: "198.51.100.9", family: .ipv4),
            remotePort: 443)
        return try VPNTunnelInterfaceResolver.resolve(baseline: baseline, after: after,
                                                       management: management)
    }

    static func evidence() throws -> VPNRoutePeerEvidence {
        try VPNRoutePeerEvidence(peer: ipv4("198.51.100.9"), gateway: ipv4("192.0.2.1"),
                                 interfaceIndex: interfaceIndex())
    }

    static func plan() throws -> VPNRoutePlan {
        try VPNRoutePlan(generation: 7, revision: 11, resources: [
            VPNResource(address: "2001:db8:2::/48"),
            VPNResource(address: "172.16.2.9"),
            VPNResource(address: "10.20.0.0/16"),
        ], peer: evidence(), tunnel: try tunnelEvidence())
    }

    static func planning() throws {
        let value = try plan()
        try require(value.routes.map { $0.role } == [.peerBypass, .resource, .resource, .resource], "roles")
        try require(value.routes.map { $0.destination.canonical } == [
            "198.51.100.9", "10.20.0.0/16", "172.16.2.9", "2001:db8:2::/48"
        ], "deterministic order")
        let gateway = try VPNRoutePrefix.format(value.routes[0].physicalGatewayBytes!, family: .ipv4)
        try require(gateway == "192.0.2.1", "peer gateway")
        try require(value.routes[0].interfaceIndex == interfaceIndex(), "peer interface")
        let tunnel = tunnelIdentity()
        try require(value.routes.dropFirst().allSatisfy {
            $0.interfaceIndex == tunnel.0 && $0.interfaceName == tunnel.1
        }, "resource tunnel binding")
        try value.validate()
        print("planning passed")
    }

    static func rejected(_ mode: String) throws {
        if mode == "binding" {
            let valid = try plan()
            var object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(valid))
                as! [String: Any]
            var routes = object["routes"] as! [[String: Any]]
            routes[1]["interfaceName"] = "utun999"
            object["routes"] = routes
            let altered = try JSONDecoder().decode(VPNRoutePlan.self,
                from: JSONSerialization.data(withJSONObject: object))
            do {
                try altered.validate()
                throw NSError(domain: "mismatched binding accepted", code: 1)
            } catch VPNRoutePlanError.invalidTunnelEvidence {}
            var arbitrary = try JSONSerialization.jsonObject(with: JSONEncoder().encode(valid))
                as! [String: Any]
            var arbitraryRoutes = arbitrary["routes"] as! [[String: Any]]
            arbitraryRoutes[1]["interfaceName"] = "en0"
            arbitrary["routes"] = arbitraryRoutes
            var binding = arbitrary["tunnelInterface"] as! [String: Any]
            binding["interfaceName"] = "en0"
            arbitrary["tunnelInterface"] = binding
            let forged = try JSONDecoder().decode(VPNRoutePlan.self,
                from: JSONSerialization.data(withJSONObject: arbitrary))
            do {
                try forged.validate()
                throw NSError(domain: "arbitrary interface accepted", code: 1)
            } catch VPNRoutePlanError.invalidTunnelEvidence {}
            print("binding rejected")
            return
        }
        let resources: [VPNResource]
        switch mode {
        case "domain": resources = [try VPNResource(address: "internal.example")]
        case "duplicate": resources = [try VPNResource(address: "10.0.0.1"),
                                        try VPNResource(address: "10.0.0.1")]
        case "overlap": resources = [try VPNResource(address: "10.0.0.0/8"),
                                      try VPNResource(address: "10.20.0.0/16")]
        case "peer": resources = [try VPNResource(address: "198.51.100.0/24")]
        case "default":
            do { _ = try VPNResource(address: "0.0.0.0/0"); throw NSError(domain: "accepted", code: 1) }
            catch VPNValidationError.defaultRoute { print("default rejected"); return }
        default: exit(64)
        }
        do {
            _ = try VPNRoutePlan(generation: 7, revision: 11, resources: resources,
                                 peer: evidence(), tunnel: try tunnelEvidence())
            throw NSError(domain: "accepted", code: 1)
        } catch is VPNRoutePlanError { print("\(mode) rejected") }
    }

    static func identities(_ plan: VPNRoutePlan) throws -> [VPNOwnedRouteIdentity] {
        let physical = try VPNRouteKernelEvidence(gateway: ipv4("192.0.2.1"),
            interfaceIndex: interfaceIndex(), flags: 0x807)
        let tunnelIndex = tunnelIdentity().0
        let tunnel = try VPNRouteKernelEvidence(gateway: Optional<in_addr>.none,
            interfaceIndex: tunnelIndex, flags: 0x801)
        let tunnel6 = try VPNRouteKernelEvidence(gateway: Optional<in6_addr>.none,
            interfaceIndex: tunnelIndex, flags: 0x801)
        return try plan.routes.map {
            let evidence = $0.role == .peerBypass ? physical
                : ($0.destination.family == .ipv4 ? tunnel : tunnel6)
            return try VPNOwnedRouteIdentity(planned: $0, evidence: evidence)
        }
    }

    static func openDirectory(_ path: String) -> Int32 {
        open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }

    static func journal(_ path: String) throws {
        let descriptor = openDirectory(path); guard descriptor >= 0 else { exit(70) }
        defer { close(descriptor) }
        let journal = try VPNRouteJournal(trustedDirectoryDescriptor: descriptor)
        let routePlan = try plan(), entries = try identities(routePlan)
        var snapshot = try journal.create(routePlan)
        try require(snapshot.phase == .planned && snapshot.applied.isEmpty, "planned")
        do {
            try journal.retireAndRemove(generation: 7, revision: 11)
            throw NSError(domain: "live journal removed", code: 1)
        } catch VPNRouteJournalError.invalidState {}
        var forgedObject = try JSONSerialization.jsonObject(with: JSONEncoder().encode(entries[1]))
            as! [String: Any]
        forgedObject["interfaceIndex"] = interfaceIndex()
        var physicalName = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        guard if_indextoname(interfaceIndex(), &physicalName) != nil else { exit(77) }
        forgedObject["interfaceName"] = String(cString: physicalName)
        let forgedEntry = try JSONDecoder().decode(VPNOwnedRouteIdentity.self,
            from: JSONSerialization.data(withJSONObject: forgedObject))
        let forgedSnapshot = VPNRouteJournalSnapshot(schemaVersion: VPNRouteJournalSnapshot.schema,
            plan: routePlan, phase: .installing, applied: [],
            operation: VPNRouteJournalOperation(action: .install, entry: forgedEntry))
        do {
            try forgedSnapshot.validate()
            throw NSError(domain: "forged journal binding accepted", code: 1)
        } catch VPNRouteJournalError.invalidState {}
        do {
            _ = try journal.beginInstall(entries[1], generation: 7, revision: 11)
            throw NSError(domain: "out of order install", code: 1)
        } catch VPNRouteJournalError.invalidState {}
        for (index, entry) in entries.enumerated() {
            snapshot = try journal.beginInstall(entry, generation: 7, revision: 11)
            try require(snapshot.operation?.action == .install, "install checkpoint")
            let recovered = try VPNRouteJournal(trustedDirectoryDescriptor: descriptor).load()
            try require(recovered == snapshot, "durable install checkpoint")
            snapshot = try journal.resolveInstall(entry, present: true, generation: 7, revision: 11)
            try require(snapshot.applied.count == index + 1, "applied count")
        }
        try require(snapshot.phase == .applied && snapshot.operation == nil, "applied")
        let wrongEvidence = try VPNRouteKernelEvidence(gateway: Optional<in6_addr>.none,
            interfaceIndex: interfaceIndex(), flags: 0x901)
        do {
            _ = try VPNOwnedRouteIdentity(planned: routePlan.routes.last!, evidence: wrongEvidence)
            throw NSError(domain: "foreign interface accepted", code: 1)
        } catch VPNRoutePlanError.invalidKernelEvidence {}
        for entry in entries.reversed() {
            snapshot = try journal.beginRemove(entry, generation: 7, revision: 11)
            try require(snapshot.operation?.action == .remove, "remove checkpoint")
            let recovered = try VPNRouteJournal(trustedDirectoryDescriptor: descriptor).load()
            try require(recovered == snapshot, "durable remove checkpoint")
            snapshot = try journal.resolveRemove(entry, present: false, generation: 7, revision: 11)
        }
        try require(snapshot.phase == .retired && snapshot.applied.isEmpty, "retired")
        let file = URL(fileURLWithPath: path).appendingPathComponent(VPNRouteJournal.name)
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        try require((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600, "mode")
        try journal.retireAndRemove(generation: 7, revision: 11)
        try require(!FileManager.default.fileExists(atPath: file.path), "retired journal remains")
        do {
            _ = try journal.load()
            throw NSError(domain: "removed journal loaded", code: 1)
        } catch VPNRouteJournalError.missing {}
        print("journal passed")
    }

    static func stale(_ path: String) throws {
        let descriptor = openDirectory(path); defer { close(descriptor) }
        let journal = try VPNRouteJournal(trustedDirectoryDescriptor: descriptor)
        let routePlan = try plan(), first = try identities(routePlan)[0]
        _ = try journal.create(routePlan)
        let before = try Data(contentsOf: URL(fileURLWithPath: path).appendingPathComponent(VPNRouteJournal.name))
        do {
            _ = try journal.beginInstall(first, generation: 8, revision: 11)
            throw NSError(domain: "stale accepted", code: 1)
        } catch VPNRouteJournalError.stale {}
        let after = try Data(contentsOf: URL(fileURLWithPath: path).appendingPathComponent(VPNRouteJournal.name))
        try require(before == after, "stale changed journal")
        print("stale rejected")
    }

    static func security(_ path: String, mode: String) throws {
        let file = URL(fileURLWithPath: path).appendingPathComponent(VPNRouteJournal.name).path
        if mode == "corrupt" { try Data("{}".utf8).write(to: URL(fileURLWithPath: file)); chmod(file, 0o600) }
        if mode == "mode" { try Data("{}".utf8).write(to: URL(fileURLWithPath: file)); chmod(file, 0o644) }
        if mode == "link" { symlink("target", file) }
        if mode == "directory" { chmod(path, 0o755) }
        let descriptor = openDirectory(path); defer { close(descriptor) }
        var didReject = false
        do { _ = try VPNRouteJournal(trustedDirectoryDescriptor: descriptor).load() }
        catch { didReject = true }
        try require(didReject, "unsafe journal accepted")
        print("\(mode) rejected")
    }

    static func main() throws {
        guard CommandLine.arguments.count >= 2 else { exit(64) }
        let mode = CommandLine.arguments[1]
        if mode == "planning" { try planning(); return }
        if ["domain", "duplicate", "overlap", "peer", "default", "binding"].contains(mode) {
            try rejected(mode); return
        }
        guard CommandLine.arguments.count == 3 else { exit(64) }
        if mode == "journal" { try journal(CommandLine.arguments[2]) }
        else if mode == "stale" { try stale(CommandLine.arguments[2]) }
        else { try security(CommandLine.arguments[2], mode: mode) }
    }
}
