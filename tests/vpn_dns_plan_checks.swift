import Darwin
import Foundation

enum DNSCheckError: Error { case failed(String) }

@main enum VPNDNSPlanChecks {
    static func require(_ value: @autoclosure () -> Bool, _ message: String) throws {
        guard value() else { throw DNSCheckError.failed(message) }
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

    static func tunnelIdentity() -> (UInt32, String) {
        guard let first = if_nameindex() else { exit(77) }
        defer { if_freenameindex(first) }
        var cursor = first
        while cursor.pointee.if_index != 0, let raw = cursor.pointee.if_name {
            let item = cursor.pointee, name = String(cString: raw), suffix = name.dropFirst(4)
            if name.hasPrefix("utun"), !suffix.isEmpty,
               suffix.utf8.allSatisfy({ (48...57).contains($0) }) {
                return (item.if_index, name)
            }
            cursor = cursor.advanced(by: 1)
        }
        exit(77)
    }

    static func tunnelEvidence() throws -> VPNTunnelInterfaceEvidence {
        let identity = tunnelIdentity()
        let local = try OpenVPNIPAddress(parsing: "10.255.253.1", family: .ipv4)
        let after = try VPNKernelInterfaceSnapshot(interfaces: [
            try VPNKernelInterfaceRecord(index: identity.0, name: identity.1, isUp: true,
                isRunning: true, isPointToPoint: true, addresses: [local])
        ])
        return try VPNTunnelInterfaceResolver.resolve(
            baseline: VPNKernelInterfaceSnapshot(interfaces: []), after: after,
            management: OpenVPNConnectedEvidence(tunnelLocalIPv4: local, tunnelLocalIPv6: nil,
                remoteAddress: try OpenVPNIPAddress(parsing: "198.51.100.8", family: .ipv4),
                remotePort: 443))
    }

    static func serverRoute(_ address: String,
                            tunnel: VPNTunnelInterfaceEvidence,
                            owned: Bool = true) throws
        -> VPNOwnedRouteIdentity {
        let resource = try VPNResource(address: address)
        let prefix = try VPNRoutePrefix(resource: resource)
        let route = VPNPlannedRoute(role: .resource, destination: prefix,
            physicalGatewayBytes: nil, interfaceIndex: tunnel.index, interfaceName: tunnel.name)
        let kernel: VPNRouteKernelEvidence
        if resource.kind == .ipv4 {
            kernel = try VPNRouteKernelEvidence(gateway: Optional<in_addr>.none,
                interfaceIndex: tunnel.index,
                flags: UInt32(RTF_UP | RTF_STATIC | RTF_HOST)
                    | (owned ? UInt32(RTF_PROTO2) : 0))
        } else {
            kernel = try VPNRouteKernelEvidence(gateway: Optional<in6_addr>.none,
                interfaceIndex: tunnel.index,
                flags: UInt32(RTF_UP | RTF_STATIC | RTF_HOST)
                    | (owned ? UInt32(RTF_PROTO2) : 0))
        }
        return try VPNOwnedRouteIdentity(planned: route, evidence: kernel)
    }

    static func routeProof(_ addresses: [String], tunnel: VPNTunnelInterfaceEvidence,
                           generation: UInt64 = 41, revision: UInt64 = 9) throws
        -> VPNRouteAppliedProof {
        VPNRouteAppliedProof(generation: generation, revision: revision,
            identities: try addresses.map { try serverRoute($0, tunnel: tunnel) })
    }

    static func plan() throws -> VPNDNSPlan {
        let tunnel = try tunnelEvidence()
        return try VPNDNSPlan(generation: 41, revision: 9, resources: [
            VPNResource(address: "Zeta.Corp.Example."),
            VPNResource(address: "alpha.corp.example"),
            VPNResource(address: "10.44.0.0/16")
        ], corporateDNS: ["2001:db8::53", "10.44.0.53"], tunnel: tunnel,
           routeProof: routeProof(["10.44.0.53", "2001:db8::53"], tunnel: tunnel))
    }

    static func planning() throws {
        let value = try plan()
        try require(value.scopes.map(\.domain) == ["alpha.corp.example", "zeta.corp.example"],
                    "domain normalization/order")
        try require(value.scopes.allSatisfy { $0.servers == value.serverEvidence.map(\.server) },
                    "scope servers")
        try require(value.scopes.allSatisfy {
            $0.tunnelInterface.interfaceIndex == tunnelIdentity().0
                && $0.tunnelInterface.interfaceName == tunnelIdentity().1
        }, "tunnel binding")
        try value.validate()
        print("planning passed")
    }

    static func rejected(_ mode: String) throws {
        let tunnel = try tunnelEvidence()
        switch mode {
        case "no-domain":
            do {
                _ = try VPNDNSPlan(generation: 1, revision: 1,
                    resources: [VPNResource(address: "10.0.0.1")],
                    corporateDNS: ["10.44.0.53"],
                    tunnel: tunnel,
                    routeProof: routeProof(["10.44.0.53"], tunnel: tunnel,
                                           generation: 1, revision: 1))
                throw DNSCheckError.failed("accepted")
            } catch VPNDNSPlanError.noScopedDomains {}
        case "overlap":
            do {
                _ = try VPNDNSPlan(generation: 1, revision: 1, resources: [
                    VPNResource(address: "corp.example"),
                    VPNResource(address: "sub.corp.example")
                ], corporateDNS: ["10.44.0.53"],
                   tunnel: tunnel,
                   routeProof: routeProof(["10.44.0.53"], tunnel: tunnel,
                                          generation: 1, revision: 1))
                throw DNSCheckError.failed("accepted")
            } catch VPNDNSPlanError.overlappingDomain {}
        case "unproved":
            do {
                _ = try VPNDNSPlan(generation: 1, revision: 1,
                    resources: [VPNResource(address: "corp.example")],
                    corporateDNS: ["10.44.0.53"], tunnel: tunnel,
                    routeProof: routeProof(["10.44.0.54"], tunnel: tunnel,
                                           generation: 1, revision: 1))
                throw DNSCheckError.failed("accepted")
            } catch VPNDNSPlanError.invalidServerEvidence {}
        case "foreign-route":
            do {
                let proof = VPNRouteAppliedProof(generation: 1, revision: 1,
                    identities: [try serverRoute("10.44.0.53", tunnel: tunnel,
                                                 owned: false)])
                _ = try VPNDNSPlan(generation: 1, revision: 1,
                    resources: [VPNResource(address: "corp.example")],
                    corporateDNS: ["10.44.0.53"], tunnel: tunnel,
                    routeProof: proof)
                throw DNSCheckError.failed("accepted")
            } catch VPNDNSPlanError.invalidServerEvidence {}
        case "stale-proof":
            do {
                _ = try VPNDNSPlan(generation: 1, revision: 1,
                    resources: [VPNResource(address: "corp.example")],
                    corporateDNS: ["10.44.0.53"], tunnel: tunnel,
                    routeProof: routeProof(["10.44.0.53"], tunnel: tunnel,
                                           generation: 2, revision: 1))
                throw DNSCheckError.failed("accepted")
            } catch VPNDNSPlanError.invalidServerEvidence {}
        case "global":
            let valid = try plan()
            var object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(valid))
                as! [String: Any]
            var scopes = object["scopes"] as! [[String: Any]]
            scopes[0]["domain"] = ""
            object["scopes"] = scopes
            let forged = try JSONDecoder().decode(VPNDNSPlan.self,
                from: JSONSerialization.data(withJSONObject: object))
            do { try forged.validate(); throw DNSCheckError.failed("accepted") }
            catch is VPNDNSPlanError {}
        default: exit(64)
        }
        print("\(mode) rejected")
    }

    static func openDirectory(_ path: String) -> Int32 {
        open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }

    static func journal(_ path: String) throws {
        let descriptor = openDirectory(path)
        guard descriptor >= 0 else { exit(70) }
        defer { close(descriptor) }
        let journal = try VPNDNSJournal(trustedDirectoryDescriptor: descriptor)
        let expected = try plan()
        var state = try journal.create(expected)
        try require(state.phase == .planned, "planned")
        let journalPath = URL(fileURLWithPath: path).appendingPathComponent(VPNDNSJournal.name).path
        let attributes = try FileManager.default.attributesOfItem(atPath: journalPath)
        try require((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600,
                    "private file mode")
        do {
            _ = try journal.beginInstall(expected.scopes[1], generation: 41, revision: 9)
            throw DNSCheckError.failed("out of order")
        } catch VPNDNSJournalError.invalidState {}
        for scope in expected.scopes {
            state = try journal.beginInstall(scope, generation: 41, revision: 9)
            let recovered = try VPNDNSJournal(trustedDirectoryDescriptor: descriptor).load()
            try require(recovered == state, "install checkpoint")
            state = try journal.resolveInstall(scope, present: true, generation: 41, revision: 9)
        }
        try require(state.phase == .applied, "applied")
        do {
            _ = try journal.beginRemove(expected.scopes[0], generation: 41, revision: 9)
            throw DNSCheckError.failed("out of order remove")
        } catch VPNDNSJournalError.invalidState {}
        for scope in expected.scopes.reversed() {
            state = try journal.beginRemove(scope, generation: 41, revision: 9)
            let recovered = try VPNDNSJournal(trustedDirectoryDescriptor: descriptor).load()
            try require(recovered == state, "remove checkpoint")
            state = try journal.resolveRemove(scope, present: false, generation: 41, revision: 9)
        }
        try require(state.phase == .retired, "retired")
        try journal.retireAndRemove(generation: 41, revision: 9)
        do { _ = try journal.load(); throw DNSCheckError.failed("not removed") }
        catch VPNDNSJournalError.missing {}
        print("journal passed")
    }

    static func stale(_ path: String) throws {
        let descriptor = openDirectory(path); defer { close(descriptor) }
        let journal = try VPNDNSJournal(trustedDirectoryDescriptor: descriptor)
        let value = try plan(); _ = try journal.create(value)
        do {
            _ = try journal.beginInstall(value.scopes[0], generation: 42, revision: 9)
            throw DNSCheckError.failed("stale accepted")
        } catch VPNDNSJournalError.stale {}
        print("stale rejected")
    }

    static func security(_ path: String, mode: String) throws {
        let target = URL(fileURLWithPath: path).appendingPathComponent(VPNDNSJournal.name).path
        if mode == "directory" {
            chmod(path, 0o755)
            let descriptor = openDirectory(path); defer { close(descriptor) }
            do {
                _ = try VPNDNSJournal(trustedDirectoryDescriptor: descriptor)
                throw DNSCheckError.failed("shared directory accepted")
            } catch VPNDNSJournalError.unsafeStorage {
                print("directory rejected")
                return
            }
        }
        if mode == "corrupt" {
            try Data("{}".utf8).write(to: URL(fileURLWithPath: target)); chmod(target, 0o600)
        }
        if mode == "mode" { try Data("{}".utf8).write(to: URL(fileURLWithPath: target)); chmod(target, 0o644) }
        if mode == "link" { symlink("target", target) }
        let descriptor = openDirectory(path); defer { close(descriptor) }
        let journal = try VPNDNSJournal(trustedDirectoryDescriptor: descriptor)
        do { _ = try journal.load(); throw DNSCheckError.failed("unsafe accepted") }
        catch { print("\(mode) rejected") }
    }

    static func main() throws {
        guard CommandLine.arguments.count >= 2 else { exit(64) }
        let mode = CommandLine.arguments[1]
        if mode == "planning" { try planning(); return }
        if ["no-domain", "overlap", "unproved", "foreign-route", "stale-proof",
            "global"].contains(mode) {
            try rejected(mode); return
        }
        guard CommandLine.arguments.count == 3 else { exit(64) }
        if mode == "journal" { try journal(CommandLine.arguments[2]) }
        else if mode == "stale" { try stale(CommandLine.arguments[2]) }
        else { try security(CommandLine.arguments[2], mode: mode) }
    }
}
