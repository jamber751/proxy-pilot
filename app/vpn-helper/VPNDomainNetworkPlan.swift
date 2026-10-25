import Foundation

enum VPNDomainNetworkPlanError: Error, Equatable {
    case invalidResources, domainRequired, invalidCorporateDNS, capacity, routeProofMismatch
}

/// Inert groundwork for a future combined network transaction. Domain resources
/// retain their configured roots/UUIDs separately from descendant client query
/// names. This type cannot publish SC suffixes, resolve names or declare ready.
struct VPNDomainNetworkPlan: Equatable {
    let staticRoutes: VPNRoutePlan
    /// Real remote corporate servers, never a synthesized loopback relay binding.
    let corporateUpstreams: [VPNRoutePrefix]
    /// Original resource identities/names are preserved, sorted by domain root.
    let domainResources: [VPNResource]

    init(generation: UInt64, revision: UInt64, resources: [VPNResource],
         corporateDNS: [String], peer: VPNRoutePeerEvidence,
         tunnel: VPNTunnelInterfaceEvidence) throws {
        guard !resources.isEmpty, resources.count <= 1000,
              Set(resources.map(\.id)).count == resources.count,
              Set(resources.map(\.address)).count == resources.count else {
            throw VPNDomainNetworkPlanError.invalidResources
        }
        for resource in resources { try resource.validate() }
        let domains = resources.filter { $0.kind == .domain }.sorted { $0.address < $1.address }
        guard !domains.isEmpty else { throw VPNDomainNetworkPlanError.domainRequired }
        guard !corporateDNS.isEmpty, corporateDNS.count <= 4 else {
            throw VPNDomainNetworkPlanError.invalidCorporateDNS
        }
        var configuration = VPNConfiguration()
        do { try configuration.setDNS(corporateDNS) }
        catch { throw VPNDomainNetworkPlanError.invalidCorporateDNS }
        let upstreams = try configuration.corporateDNS.map {
            try VPNRoutePrefix(resource: VPNResource(address: $0))
        }.sorted()

        // Only configured resource prefixes can cover an upstream. The peer
        // bypass is a physical transport dependency, never DNS tunnel coverage.
        let combined = resources.filter { $0.kind != .domain }
        let configuredPrefixes = try combined.map(VPNRoutePrefix.init(resource:))
        let dependencies = upstreams.filter { server in
            !configuredPrefixes.contains(where: { $0.contains(host: server) })
        }
        guard combined.count + dependencies.count <= 1000 else { throw VPNDomainNetworkPlanError.capacity }
        // Reuse the existing no-overlap, peer-capture and typed-utun validators.
        staticRoutes = try VPNRoutePlan(generation: generation, revision: revision,
                                       resources: combined, peer: peer, tunnel: tunnel,
                                       dnsDependencies: dependencies)
        corporateUpstreams = upstreams
        domainResources = domains
    }

    /// The DNS codec supplies a canonical label name. Reject display/user-input
    /// spellings here; callers must not widen scope by URL or whitespace cleanup.
    /// Overlapping configured roots select the most specific ORIGINAL resource,
    /// retaining its UUID/name for answer custody, revocation and resource edits.
    func resource(forCanonicalDNSName name: String) -> VPNResource? {
        guard let normalized = try? VPNResource.normalize(name),
              normalized.1 == .domain, normalized.0 == name else { return nil }
        return domainResources.filter {
            name == $0.address || name.hasSuffix("." + $0.address)
        }.max { $0.address.utf8.count < $1.address.utf8.count }
    }

    /// Bridge into the EXISTING inert DNS model only after an actual verified
    /// route transaction. The proof is ephemeral; these checks bind its exact
    /// identities to this plan, but cannot replace live kernel verification.
    /// Redundant ancestor/descendant scopes share this plan's tunnel/upstreams;
    /// VPNDNSPlan coalesces only that OS projection, retaining resources above.
    /// Returning this model authorizes neither SC publication nor a local relay.
    func dnsPlan(tunnel: VPNTunnelInterfaceEvidence,
                 routeProof: VPNRouteAppliedProof) throws -> VPNDNSPlan {
        guard routeProof.generation == staticRoutes.generation,
              routeProof.revision == staticRoutes.revision,
              try VPNTunnelRouteBinding(evidence: tunnel) == staticRoutes.tunnelInterface else {
            throw VPNDomainNetworkPlanError.routeProofMismatch
        }
        let expected = try VPNRouteIdentityFactory.make(plan: staticRoutes)
        if let preserved = routeProof.preservedPeerRoute {
            guard preserved == staticRoutes.routes.first,
                  routeProof.identities == Array(expected.dropFirst()) else {
                throw VPNDomainNetworkPlanError.routeProofMismatch
            }
        } else if routeProof.identities != expected {
            throw VPNDomainNetworkPlanError.routeProofMismatch
        }
        return try VPNDNSPlan(generation: staticRoutes.generation, revision: staticRoutes.revision,
                              resources: domainResources, corporateDNS: corporateUpstreams.map(\.canonical),
                              tunnel: tunnel, routeProof: routeProof)
    }
}
