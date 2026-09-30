import Foundation

enum VPNTunnelRouteControllerError: Error, Equatable {
    case invalidBootstrap
    case staleGeneration
    case inactiveApplication
    case applicationMismatch
    case peerRouteUsesTunnel
    case alreadyApplied
    case recoveryRequired
}

/// Ephemeral authority that binds installed routes to one daemon generation and
/// the exact active application revision. It is deliberately not Codable and
/// is not a user-visible Connected proof.
struct VPNTunnelRouteAppliedProof: Equatable {
    let generation: UInt64
    let revision: UInt64
    let profileSHA256: String
    let routes: VPNRouteAppliedProof
}

/// Internal orchestration only. This type neither controls the OpenVPN process
/// nor publishes DNS/UI state. A caller must successfully call
/// `prepareForProcessStop` before stopping the process.
final class VPNTunnelRouteController {
    private let loadSnapshot: () throws -> VPNTunnelSnapshot
    private let resolvePeer: (OpenVPNIPAddress) throws -> VPNRoutePeerEvidence
    private let transaction: VPNRouteTransaction
    private let checkAuthority: () throws -> Void
    private let lock = NSLock()
    private var applied: VPNTunnelRouteAppliedProof?

    #if VPN_TUNNEL_ROUTE_CONTROLLER_TESTING
    init(loadSnapshot: @escaping () throws -> VPNTunnelSnapshot,
         resolvePeer: @escaping (OpenVPNIPAddress) throws -> VPNRoutePeerEvidence,
         transaction: VPNRouteTransaction,
         checkAuthority: @escaping () throws -> Void = {}) {
        self.loadSnapshot = loadSnapshot
        self.resolvePeer = resolvePeer
        self.transaction = transaction
        self.checkAuthority = checkAuthority
    }
    #else
    init(state: VPNTunnelStateStore, resolver: VPNPeerRouteEvidenceResolver,
         transaction: VPNRouteTransaction, runtimeLease: VPNLifecycleLease) {
        loadSnapshot = { try state.load() }
        resolvePeer = { try resolver.resolve(peer: $0) }
        self.transaction = transaction
        checkAuthority = { try runtimeLease.check() }
    }
    #endif

    func install(bootstrap: VPNTunnelBootstrapProof,
                 activeApplication: VPNValidatedApplication) throws
        -> VPNTunnelRouteAppliedProof {
        lock.lock(); defer { lock.unlock() }
        guard applied == nil else { throw VPNTunnelRouteControllerError.alreadyApplied }
        try authority()

        // A daemon restart never resumes a partially installed plan forward.
        // Converge to idle before accepting any fresh bootstrap evidence.
        do { try transaction.recoverToIdle() }
        catch { throw VPNTunnelRouteControllerError.recoveryRequired }
        try authority()

        do { try activeApplication.validate() }
        catch { throw VPNTunnelRouteControllerError.applicationMismatch }
        try validateIntent(bootstrap: bootstrap, application: activeApplication)
        try validate(bootstrap)
        try authority()

        let peer: VPNRoutePeerEvidence
        do { peer = try resolvePeer(bootstrap.management.remoteAddress) }
        catch { throw VPNTunnelRouteControllerError.recoveryRequired }
        guard peer.peer.family.rawValue == bootstrap.management.remoteAddress.family.rawValue,
              peer.peer.bytes == bootstrap.management.remoteAddress.bytes else {
            throw VPNTunnelRouteControllerError.invalidBootstrap
        }
        guard peer.interfaceIndex != bootstrap.tunnel.index,
              peer.interfaceName != bootstrap.tunnel.name else {
            throw VPNTunnelRouteControllerError.peerRouteUsesTunnel
        }
        try authority()

        let plan: VPNRoutePlan
        do {
            plan = try VPNRoutePlan(generation: bootstrap.generation,
                revision: activeApplication.spec.revision,
                resources: activeApplication.spec.resources,
                peer: peer, tunnel: bootstrap.tunnel)
        } catch VPNRoutePlanError.invalidPeerEvidence {
            throw VPNTunnelRouteControllerError.peerRouteUsesTunnel
        }
        // The listener can change durable intent inside this same daemon while
        // the read-only kernel lookup is in flight. Re-read it immediately
        // before the first route checkpoint/mutation.
        try authority()
        try validateIntent(bootstrap: bootstrap, application: activeApplication)

        let routeProof: VPNRouteAppliedProof
        do {
            routeProof = try transaction.install(plan)
            try transaction.verifyApplied(routeProof)
            try authority()
            try validateIntent(bootstrap: bootstrap, application: activeApplication)
        } catch {
            // Cleanup is mandatory before the owner may stop OpenVPN. If it
            // cannot be proven, retain the journal for startup recovery.
            do { try transaction.recoverToIdle() }
            catch { throw VPNTunnelRouteControllerError.recoveryRequired }
            throw error
        }
        let proof = VPNTunnelRouteAppliedProof(generation: bootstrap.generation,
            revision: activeApplication.spec.revision,
            profileSHA256: activeApplication.spec.profileSHA256,
            routes: routeProof)
        applied = proof
        return proof
    }

    func verifyApplied(_ proof: VPNTunnelRouteAppliedProof) throws {
        lock.lock(); defer { lock.unlock() }
        guard applied == proof, proof.generation == proof.routes.generation,
              proof.revision == proof.routes.revision else {
            throw VPNTunnelRouteControllerError.recoveryRequired
        }
        try authority()
        try transaction.verifyApplied(proof.routes)
    }

    /// This is the only successful transition from routed to idle. Process
    /// ownership code must complete it before asking OpenVPN to stop.
    func prepareForProcessStop() throws {
        lock.lock(); defer { lock.unlock() }
        do { try transaction.recoverToIdle() }
        catch { throw VPNTunnelRouteControllerError.recoveryRequired }
        applied = nil
    }

    /// Startup recovery uses the same reverse rollback and journal retirement,
    /// but does not imply that an engine process exists.
    func recoverToIdle() throws {
        lock.lock(); defer { lock.unlock() }
        do { try transaction.recoverToIdle() }
        catch { throw VPNTunnelRouteControllerError.recoveryRequired }
        applied = nil
    }

    private func authority() throws {
        do { try checkAuthority() }
        catch { throw VPNTunnelRouteControllerError.recoveryRequired }
    }

    private func validateIntent(bootstrap: VPNTunnelBootstrapProof,
                                application: VPNValidatedApplication) throws {
        let snapshot: VPNTunnelSnapshot
        do { snapshot = try loadSnapshot() }
        catch { throw VPNTunnelRouteControllerError.recoveryRequired }
        guard snapshot.generation == bootstrap.generation else {
            throw VPNTunnelRouteControllerError.staleGeneration
        }
        guard snapshot.desiredEnabled, snapshot.phase == .connecting,
              let current = snapshot.active else {
            throw VPNTunnelRouteControllerError.inactiveApplication
        }
        guard current == application else {
            throw VPNTunnelRouteControllerError.applicationMismatch
        }
    }

    private func validate(_ proof: VPNTunnelBootstrapProof) throws {
        guard proof.generation > 0, proof.management.remotePort > 0 else {
            throw VPNTunnelRouteControllerError.invalidBootstrap
        }
        let required = [proof.management.tunnelLocalIPv4,
                        proof.management.tunnelLocalIPv6].compactMap { $0 }
        guard !required.isEmpty, required.allSatisfy(proof.tunnel.addresses.contains),
              !required.contains(proof.management.remoteAddress),
              (try? VPNTunnelRouteBinding(evidence: proof.tunnel)) != nil else {
            throw VPNTunnelRouteControllerError.invalidBootstrap
        }
    }
}
