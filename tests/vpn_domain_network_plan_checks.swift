import Darwin
import Foundation

// The existing route validators resolve interface index -> name. Interpose only
// in this private test executable: no host interface inspection or mutation.
@_cdecl("if_indextoname")
func domainPlanFakeInterfaceName(_ index: UInt32, _ output: UnsafeMutablePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let output, let name = [7: "en7", 42: "utun42", 43: "utun43"][index] else { return nil }
    for (offset, byte) in name.utf8CString.enumerated() { output[offset] = byte }
    return output
}

@main enum VPNDomainNetworkPlanChecks {
    enum Failure: Error { case assertion }
    static func check(_ value: @autoclosure () throws -> Bool) throws {
        if try !value() { throw Failure.assertion }
    }
    static func rejects(_ operation: () throws -> Void) throws {
        var refused = false
        do { try operation() } catch { refused = true }
        try check(refused)
    }
    static func ip4(_ text: String) -> in_addr {
        var value = in_addr()
        guard text.withCString({ inet_pton(AF_INET, $0, &value) }) == 1 else { exit(64) }
        return value
    }
    static func ip6(_ text: String) -> in6_addr {
        var value = in6_addr()
        guard text.withCString({ inet_pton(AF_INET6, $0, &value) }) == 1 else { exit(64) }
        return value
    }
    static func tunnel(_ index: UInt32 = 42) throws -> VPNTunnelInterfaceEvidence {
        let v4 = try OpenVPNIPAddress(parsing: "10.255.254.1", family: .ipv4)
        let v6 = try OpenVPNIPAddress(parsing: "2001:db8:ffff::1", family: .ipv6)
        return try VPNTunnelInterfaceResolver.resolve(baseline: VPNKernelInterfaceSnapshot(interfaces: []),
            after: VPNKernelInterfaceSnapshot(interfaces: [VPNKernelInterfaceRecord(index: index, name: "utun\(index)",
                isUp: true, isRunning: true, isPointToPoint: true, addresses: [v4, v6])]),
            management: OpenVPNConnectedEvidence(tunnelLocalIPv4: v4, tunnelLocalIPv6: v6,
                remoteAddress: OpenVPNIPAddress(parsing: "198.51.100.9", family: .ipv4), remotePort: 443))
    }
    static func peer(_ address: String = "198.51.100.9", index: UInt32 = 7) throws -> VPNRoutePeerEvidence {
        try VPNRoutePeerEvidence(peer: ip4(address), gateway: ip4("192.0.2.1"), interfaceIndex: index)
    }
    static func resources(_ values: [String]) throws -> [VPNResource] {
        try values.map { try VPNResource(address: $0) }
    }
    static func plan(_ values: [String] = ["portal.corp.test"], dns: [String] = ["10.44.0.53"],
                     generation: UInt64 = 7, revision: UInt64 = 11) throws -> VPNDomainNetworkPlan {
        try VPNDomainNetworkPlan(generation: generation, revision: revision, resources: resources(values),
                                 corporateDNS: dns, peer: peer(), tunnel: tunnel())
    }
    // Synthetic identity proofs only. No route transaction, socket, lookup or
    // mutation is performed; real kernel application acceptance remains open.
    static func proof(_ plan: VPNDomainNetworkPlan, preserved: Bool = false) throws -> VPNRouteAppliedProof {
        let identities = try VPNRouteIdentityFactory.make(plan: plan.staticRoutes)
        return VPNRouteAppliedProof(generation: plan.staticRoutes.generation, revision: plan.staticRoutes.revision,
            identities: preserved ? Array(identities.dropFirst()) : identities,
            preservedPeerRoute: preserved ? plan.staticRoutes.routes.first : nil)
    }
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        switch CommandLine.arguments[1] {
        case "hosts":
            let value = try plan(dns: ["2001:0DB8::0053", " 10.44.0.53 "])
            try check(value.corporateUpstreams.map(\.canonical) == ["10.44.0.53", "2001:db8::53"])
            try check(value.staticRoutes.routes.map { $0.destination.canonical } == ["198.51.100.9", "10.44.0.53", "2001:db8::53"])
            try check(value.staticRoutes.routes.first?.role == .peerBypass)
            try check(value.staticRoutes.routes.first?.interfaceIndex == 7)
            try check(value.staticRoutes.schemaVersion == 3)
            try check(value.staticRoutes.routes.dropFirst().allSatisfy { $0.role == .dnsDependency && $0.interfaceIndex == 42 && $0.interfaceName == "utun42" && $0.interfaceScope == value.staticRoutes.tunnelInterface })
            let ipv6Peer = try VPNRoutePeerEvidence(peer: ip6("2001:db8:feed::9"), gateway: ip6("2001:db8:feed::1"), interfaceIndex: 7)
            let v6 = try VPNDomainNetworkPlan(generation: 7, revision: 11, resources: resources(["portal.corp.test"]),
                corporateDNS: ["2001:db8::53"], peer: ipv6Peer, tunnel: tunnel())
            try check(v6.staticRoutes.routes.first?.destination.family == .ipv6)
        case "coverage":
            let value = try plan(["portal.corp.test", "10.44.0.0/16", "2001:db8::/32"], dns: ["10.44.0.53", "10.44.0.54", "2001:db8::53"])
            try check(value.staticRoutes.routes.map { $0.destination.canonical } == ["198.51.100.9", "10.44.0.0/16", "2001:db8::/32"])
            try check(value.staticRoutes.schemaVersion == 2 && value.staticRoutes.routes.allSatisfy { $0.interfaceScope == nil })
            let dns = try value.dnsPlan(tunnel: tunnel(), routeProof: proof(value))
            try check(dns.serverEvidence.count == 3 && dns.scopes.count == 1)
            try check(dns.serverEvidence[0].verifiedRoute.destination.canonical == "10.44.0.0/16")
            let exact = try plan(["portal.corp.test", "10.44.0.53"])
            try check(exact.staticRoutes.routes.count == 2)
            let oneFamily = try plan(["portal.corp.test", "10.44.0.0/16"], dns: ["10.44.0.53", "2001:db8::53"])
            try check(oneFamily.staticRoutes.routes.count == 3)
        case "identity":
            let input = try resources(["Portal.Corp.Test.", "10.44.0.0/16", "zeta.corp.test"])
            let before = input
            let value = try VPNDomainNetworkPlan(generation: 7, revision: 11, resources: input,
                corporateDNS: ["2001:0db8::0053", "10.44.0.53"], peer: peer(), tunnel: tunnel())
            let reversed = try VPNDomainNetworkPlan(generation: 7, revision: 11, resources: Array(input.reversed()),
                corporateDNS: ["10.44.0.53", "2001:db8::53"], peer: peer(), tunnel: tunnel())
            try check(value == reversed && input == before)
            try check(value.domainResources == [input[0], input[2]])
            try check(value.domainResources.map(\.address) == ["portal.corp.test", "zeta.corp.test"])
            let distinctExact = try plan(["corp.test", "portal.corp.test"])
            try check(distinctExact.domainResources.map(\.address) == ["corp.test", "portal.corp.test"])
            // Approved policy includes descendants. Redundant OS suffix scopes
            // coalesce while the original resource UUIDs remain separate above.
            let scoped = try distinctExact.dnsPlan(tunnel: tunnel(), routeProof: proof(distinctExact))
            try check(scoped.scopes.map(\.domain) == ["corp.test"])
        case "selection":
            let input = try resources(["corp.test", "portal.corp.test", "ops.portal.corp.test", "other.test"])
            let value = try VPNDomainNetworkPlan(generation: 7, revision: 11, resources: input,
                corporateDNS: ["10.44.0.53"], peer: peer(), tunnel: tunnel())
            for (query, index) in [("corp.test", 0), ("mail.corp.test", 0),
                                   ("portal.corp.test", 1), ("deep.portal.corp.test", 1),
                                   ("ops.portal.corp.test", 2), ("a.b.ops.portal.corp.test", 2),
                                   ("a.other.test", 3)] {
                try check(value.resource(forCanonicalDNSName: query) == input[index])
            }
        case "canonical":
            let value = try plan(["corp.test", "portal.corp.test"])
            for query in ["Corp.test", "corp.test.", " corp.test", "corp.test\n", "https://corp.test", "*.corp.test",
                          "corp..test", "-x.corp.test", "x_.corp.test", "corp.test.evil.test", "notcorp.test",
                          "portalcorp.test", "corp", "", "10.0.0.1", "a\0.corp.test"] {
                try check(value.resource(forCanonicalDNSName: query) == nil)
            }
            try check(value.resource(forCanonicalDNSName: "portalx.corp.test")?.address == "corp.test")
        case "coalescing":
            let input = try resources(["ops.portal.corp.test", "z.other.test", "corp.test", "portal.corp.test",
                                       "other.test", "notcorp.test"])
            let value = try VPNDomainNetworkPlan(generation: 7, revision: 11, resources: input,
                corporateDNS: ["10.44.0.53"], peer: peer(), tunnel: tunnel())
            let scoped = try value.dnsPlan(tunnel: tunnel(), routeProof: proof(value))
            let reversed = try VPNDomainNetworkPlan(generation: 7, revision: 11, resources: Array(input.reversed()),
                corporateDNS: ["10.44.0.53"], peer: peer(), tunnel: tunnel())
            try check(scoped.scopes.map(\.domain) == ["corp.test", "notcorp.test", "other.test"])
            try check(scoped == reversed.dnsPlan(tunnel: tunnel(), routeProof: proof(reversed)))
            try check(Set(value.domainResources.map(\.id)) == Set(input.map(\.id)))
        case "scope-validation":
            try rejects { _ = try plan(["corp.test", "corp.test"]) }
            let value = try plan(["corp.test", "other.test"])
            let scoped = try value.dnsPlan(tunnel: tunnel(), routeProof: proof(value))
            var fields = try JSONSerialization.jsonObject(with: JSONEncoder().encode(scoped)) as! [String: Any]
            var scopes = fields["scopes"] as! [[String: Any]]
            scopes[1]["domain"] = "sub.corp.test"; fields["scopes"] = scopes
            let overlapping = try JSONDecoder().decode(VPNDNSPlan.self, from: JSONSerialization.data(withJSONObject: fields))
            try rejects { try overlapping.validate() }
            scopes[1]["domain"] = "corp.test"; fields["scopes"] = scopes
            let duplicate = try JSONDecoder().decode(VPNDNSPlan.self, from: JSONSerialization.data(withJSONObject: fields))
            try rejects { try duplicate.validate() }
        case "removal":
            let input = try resources(["corp.test", "portal.corp.test"])
            let before = try VPNDomainNetworkPlan(generation: 7, revision: 11, resources: input,
                corporateDNS: ["10.44.0.53"], peer: peer(), tunnel: tunnel())
            let after = try VPNDomainNetworkPlan(generation: 7, revision: 12, resources: [input[0]],
                corporateDNS: ["10.44.0.53"], peer: peer(), tunnel: tunnel())
            try check(before.resource(forCanonicalDNSName: "mail.portal.corp.test") == input[1])
            try check(after.resource(forCanonicalDNSName: "mail.portal.corp.test") == input[0])
            try check(after.domainResources == [input[0]])
        case "peer-conflict":
            for values in [["portal.corp.test", "198.51.100.0/24"], ["portal.corp.test", "198.51.100.9"]] {
                do { _ = try plan(values); throw Failure.assertion }
                catch VPNRoutePlanError.peerWouldBeCaptured {}
            }
            do { _ = try plan(dns: ["198.51.100.9"]); throw Failure.assertion }
            catch VPNRoutePlanError.peerWouldBeCaptured {}
            let ipv6Peer = try VPNRoutePeerEvidence(peer: ip6("2001:db8::53"), gateway: ip6("2001:db8::1"), interfaceIndex: 7)
            try rejects { _ = try VPNDomainNetworkPlan(generation: 7, revision: 11,
                resources: resources(["portal.corp.test"]), corporateDNS: ["2001:db8::53"], peer: ipv6Peer, tunnel: tunnel()) }
        case "invalid":
            for dns in [[], ["dns.corp.test"], ["127.0.0.1"], ["::1"], ["fe80::53"], ["::ffff:10.44.0.53"],
                        ["10.44.0.53", "10.44.0.53"], ["2001:db8::53", "2001:0db8::0053"],
                        ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]] {
                try rejects { _ = try plan(dns: dns) }
            }
            try rejects { _ = try plan(["10.44.0.0/16"]) }
            try rejects { _ = try plan([], dns: ["10.44.0.53"]) }
            try rejects { _ = try plan(generation: 0) }
            try rejects { _ = try plan(revision: 0) }
            try rejects { _ = try plan(["portal.corp.test", "10.44.0.0/16", "10.44.1.0/24"]) }
            try rejects { _ = try plan(["portal.corp.test", "10.44.0.53", "10.44.0.53"]) }
        case "interface":
            try rejects { _ = try VPNDomainNetworkPlan(generation: 7, revision: 11,
                resources: resources(["portal.corp.test"]), corporateDNS: ["10.44.0.53"], peer: peer(index: 42), tunnel: tunnel()) }
            try rejects { _ = try peer(index: 999) }
            let address = try OpenVPNIPAddress(parsing: "10.255.254.1", family: .ipv4)
            for name in ["en7", "utunx"] {
                try rejects { _ = try VPNTunnelInterfaceResolver.resolve(baseline: VPNKernelInterfaceSnapshot(interfaces: []),
                    after: VPNKernelInterfaceSnapshot(interfaces: [VPNKernelInterfaceRecord(index: 42, name: name,
                        isUp: true, isRunning: true, isPointToPoint: true, addresses: [address])]),
                    management: OpenVPNConnectedEvidence(tunnelLocalIPv4: address, tunnelLocalIPv6: nil,
                        remoteAddress: OpenVPNIPAddress(parsing: "198.51.100.9", family: .ipv4), remotePort: 443)) }
            }
        case "proof":
            let value = try plan(dns: ["10.44.0.53", "2001:db8::53"])
            let full = try proof(value)
            let dns = try value.dnsPlan(tunnel: tunnel(), routeProof: full)
            try check(dns.generation == 7 && dns.revision == 11 && dns.serverEvidence.map(\.server) == value.corporateUpstreams)
            _ = try value.dnsPlan(tunnel: tunnel(), routeProof: proof(value, preserved: true))
            try rejects { _ = try value.dnsPlan(tunnel: tunnel(43), routeProof: full) }
            for (generation, revision) in [(UInt64(8), UInt64(11)), (7, 12)] {
                try rejects { _ = try value.dnsPlan(tunnel: tunnel(), routeProof: VPNRouteAppliedProof(
                    generation: generation, revision: revision, identities: full.identities)) }
            }
            try rejects { _ = try value.dnsPlan(tunnel: tunnel(), routeProof: VPNRouteAppliedProof(
                generation: 7, revision: 11, identities: Array(full.identities.dropLast()))) }
            let extra = try proof(plan(["portal.corp.test", "10.55.0.1"], dns: ["10.44.0.53", "2001:db8::53"]))
            try rejects { _ = try value.dnsPlan(tunnel: tunnel(), routeProof: extra) }
            let withResource = try plan(["portal.corp.test", "10.55.0.1"])
            let missingResource = try proof(withResource).identities.filter { $0.destination.canonical != "10.55.0.1" }
            // DNS server coverage alone is insufficient: every static resource
            // in this exact plan must also be represented by the applied proof.
            try rejects { _ = try withResource.dnsPlan(tunnel: tunnel(), routeProof: VPNRouteAppliedProof(
                generation: 7, revision: 11, identities: missingResource)) }
            var unowned = try JSONSerialization.jsonObject(with: JSONEncoder().encode(full.identities[1])) as! [String: Any]
            unowned["flags"] = full.identities[1].flags & ~UInt32(RTF_PROTO2)
            let foreign = try JSONDecoder().decode(VPNOwnedRouteIdentity.self, from: JSONSerialization.data(withJSONObject: unowned))
            try rejects { try foreign.validate() }
            var foreignIdentities = full.identities; foreignIdentities[1] = foreign
            try rejects { _ = try value.dnsPlan(tunnel: tunnel(), routeProof: VPNRouteAppliedProof(
                generation: 7, revision: 11, identities: foreignIdentities)) }
            try rejects { _ = try value.dnsPlan(tunnel: tunnel(), routeProof: VPNRouteAppliedProof(
                generation: 7, revision: 11, identities: Array(full.identities.dropFirst()),
                preservedPeerRoute: plan(dns: ["10.44.0.54"]).staticRoutes.routes.last)) }
        case "capacity":
            var values = ["portal.corp.test"]
            for index in 0..<999 { values.append("10.\(index / 256).\(index % 256).1") }
            let covered = try plan(values, dns: ["10.0.0.1"])
            try check(covered.staticRoutes.routes.count == 1000)
            let limit = try plan(values, dns: ["10.44.0.53"])
            try check(limit.staticRoutes.routes.count == 1001) // 1000 resources + peer
            try rejects { _ = try plan(values, dns: ["10.44.0.53", "10.44.0.54"]) }
            try rejects { _ = try plan(values + ["10.88.0.1"], dns: ["10.0.0.1"]) }
        default: exit(64)
        }
        print("domain network groundwork passed")
    }
}
