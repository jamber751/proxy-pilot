import Darwin
import Foundation

enum VPNDNSPlanError: Error, Equatable {
    case invalidGeneration
    case invalidRevision
    case noScopedDomains
    case invalidDomain
    case overlappingDomain
    case invalidServerEvidence
    case invalidTunnelEvidence
    case unsupportedGlobalScope
}

/// Proof carried into an inert DNS plan: the configured DNS host is covered by
/// an exact resource route whose observed identity is bound to the proven utun.
struct VPNTunnelDNSServerEvidence: Codable, Equatable, Comparable {
    let server: VPNRoutePrefix
    let tunnelInterface: VPNTunnelRouteBinding
    let verifiedRoute: VPNOwnedRouteIdentity

    static func < (left: Self, right: Self) -> Bool { left.server < right.server }

    fileprivate init(configuredAddress: String, tunnel: VPNTunnelInterfaceEvidence,
                     verifiedRoute: VPNOwnedRouteIdentity) throws {
        let resource: VPNResource
        do { resource = try VPNResource(address: configuredAddress) }
        catch { throw VPNDNSPlanError.invalidServerEvidence }
        guard [.ipv4, .ipv6].contains(resource.kind) else {
            throw VPNDNSPlanError.invalidServerEvidence
        }
        do { server = try VPNRoutePrefix(resource: resource) }
        catch { throw VPNDNSPlanError.invalidServerEvidence }
        do { tunnelInterface = try VPNTunnelRouteBinding(evidence: tunnel) }
        catch { throw VPNDNSPlanError.invalidTunnelEvidence }
        self.verifiedRoute = verifiedRoute
        try validate()
    }

    func validate() throws {
        do { try server.validate(); try tunnelInterface.validate(); try verifiedRoute.validate() }
        catch { throw VPNDNSPlanError.invalidServerEvidence }
        let hostLength: UInt8 = server.family == .ipv4 ? 32 : 128
        guard server.prefixLength == hostLength,
              verifiedRoute.role == .resource,
              verifiedRoute.destination.contains(host: server),
              verifiedRoute.gatewayBytes == nil,
              verifiedRoute.flags & UInt32(RTF_PROTO2) != 0,
              verifiedRoute.interfaceIndex == tunnelInterface.interfaceIndex,
              verifiedRoute.interfaceName == tunnelInterface.interfaceName else {
            throw VPNDNSPlanError.invalidServerEvidence
        }
    }
}

struct VPNDNSResolverScope: Codable, Equatable, Comparable {
    let domain: String
    let servers: [VPNRoutePrefix]
    let tunnelInterface: VPNTunnelRouteBinding

    static func < (left: Self, right: Self) -> Bool { left.domain < right.domain }

    func validate() throws {
        let normalized: VPNResource
        do { normalized = try VPNResource(address: domain) }
        catch { throw VPNDNSPlanError.invalidDomain }
        guard normalized.kind == .domain, normalized.address == domain,
              !domain.isEmpty, domain != ".", !domain.hasPrefix("*."),
              !servers.isEmpty, servers.count <= 4, servers == servers.sorted(),
              VPNDNSPlan.unique(servers) else {
            throw VPNDNSPlanError.unsupportedGlobalScope
        }
        do { try tunnelInterface.validate() }
        catch { throw VPNDNSPlanError.invalidTunnelEvidence }
        for server in servers {
            try server.validate()
            let hostLength: UInt8 = server.family == .ipv4 ? 32 : 128
            guard server.prefixLength == hostLength else {
                throw VPNDNSPlanError.invalidServerEvidence
            }
        }
    }
}

/// Deterministic model only. It neither changes SystemConfiguration nor claims
/// that any scoped resolver is installed.
struct VPNDNSPlan: Codable, Equatable {
    static let schema = 1
    let schemaVersion: Int
    let generation: UInt64
    let revision: UInt64
    let serverEvidence: [VPNTunnelDNSServerEvidence]
    let scopes: [VPNDNSResolverScope]

    init(generation: UInt64, revision: UInt64, resources: [VPNResource],
         corporateDNS: [String], tunnel: VPNTunnelInterfaceEvidence,
         routeProof: VPNRouteAppliedProof) throws {
        guard generation > 0 else { throw VPNDNSPlanError.invalidGeneration }
        guard revision > 0 else { throw VPNDNSPlanError.invalidRevision }
        guard routeProof.generation == generation, routeProof.revision == revision else {
            throw VPNDNSPlanError.invalidServerEvidence
        }
        let domains = try resources.filter { $0.kind == .domain }.map { resource -> String in
            do { try resource.validate() }
            catch { throw VPNDNSPlanError.invalidDomain }
            return resource.address
        }.sorted()
        guard !domains.isEmpty, domains.count <= 1000 else {
            throw VPNDNSPlanError.noScopedDomains
        }
        try Self.validateDomains(domains)
        guard !corporateDNS.isEmpty, corporateDNS.count <= 4 else {
            throw VPNDNSPlanError.invalidServerEvidence
        }
        var dnsProbe = VPNConfiguration()
        do { try dnsProbe.setDNS(corporateDNS) }
        catch { throw VPNDNSPlanError.invalidServerEvidence }
        let normalizedServers = try dnsProbe.corporateDNS.map {
            try VPNRoutePrefix(resource: VPNResource(address: $0))
        }.sorted()
        let tunnelBinding: VPNTunnelRouteBinding
        do { tunnelBinding = try VPNTunnelRouteBinding(evidence: tunnel) }
        catch { throw VPNDNSPlanError.invalidTunnelEvidence }
        let sortedEvidence = try normalizedServers.map { server -> VPNTunnelDNSServerEvidence in
            let matches = routeProof.identities.filter {
                $0.role == .resource && $0.destination.contains(host: server)
                    && $0.gatewayBytes == nil && $0.flags & UInt32(RTF_PROTO2) != 0
                    && $0.interfaceIndex == tunnelBinding.interfaceIndex
                    && $0.interfaceName == tunnelBinding.interfaceName
            }
            guard matches.count == 1 else { throw VPNDNSPlanError.invalidServerEvidence }
            return try VPNTunnelDNSServerEvidence(configuredAddress: server.canonical,
                                                   tunnel: tunnel,
                                                   verifiedRoute: matches[0])
        }.sorted()
        guard sortedEvidence.count == normalizedServers.count,
              sortedEvidence.map(\.server) == normalizedServers,
              Self.unique(sortedEvidence.map(\.server)),
              let tunnel = sortedEvidence.first?.tunnelInterface,
              sortedEvidence.allSatisfy({ $0.tunnelInterface == tunnel }) else {
            throw VPNDNSPlanError.invalidServerEvidence
        }
        for item in sortedEvidence { try item.validate() }
        schemaVersion = Self.schema
        self.generation = generation
        self.revision = revision
        serverEvidence = sortedEvidence
        scopes = domains.map {
            VPNDNSResolverScope(domain: $0, servers: normalizedServers, tunnelInterface: tunnel)
        }
        try validate()
    }

    func validate() throws {
        guard schemaVersion == Self.schema, generation > 0, revision > 0,
              !serverEvidence.isEmpty, serverEvidence.count <= 4,
              serverEvidence == serverEvidence.sorted(),
              Self.unique(serverEvidence.map(\.server)),
              !scopes.isEmpty, scopes.count <= 1000, scopes == scopes.sorted(),
              Set(scopes.map(\.domain)).count == scopes.count,
              let tunnel = serverEvidence.first?.tunnelInterface,
              serverEvidence.allSatisfy({ $0.tunnelInterface == tunnel }) else {
            throw VPNDNSPlanError.invalidServerEvidence
        }
        for item in serverEvidence { try item.validate() }
        let servers = serverEvidence.map(\.server)
        for scope in scopes {
            try scope.validate()
            guard scope.servers == servers, scope.tunnelInterface == tunnel else {
                throw VPNDNSPlanError.invalidTunnelEvidence
            }
        }
        try Self.validateDomains(scopes.map(\.domain))
    }

    private static func validateDomains(_ domains: [String]) throws {
        for index in domains.indices {
            let resource: VPNResource
            do { resource = try VPNResource(address: domains[index]) }
            catch { throw VPNDNSPlanError.invalidDomain }
            guard resource.kind == .domain, resource.address == domains[index] else {
                throw VPNDNSPlanError.invalidDomain
            }
            for earlier in domains[..<index] {
                let current = domains[index]
                guard current != earlier, !current.hasSuffix("." + earlier),
                      !earlier.hasSuffix("." + current) else {
                    throw VPNDNSPlanError.overlappingDomain
                }
            }
        }
    }

    fileprivate static func unique(_ values: [VPNRoutePrefix]) -> Bool {
        guard values.count > 1 else { return true }
        return values.indices.dropFirst().allSatisfy { values[$0] != values[$0 - 1] }
    }
}
