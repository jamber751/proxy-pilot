import Darwin
import Foundation

enum TunnelRouteControllerCheckFailure: Error { case failed(String) }
enum TunnelRouteControllerAuthorityFailure: Error { case lost }

func requireTunnelRoutes(_ condition: @autoclosure () -> Bool,
                         _ message: String) throws {
    if !condition() { throw TunnelRouteControllerCheckFailure.failed(message) }
}

final class TunnelRouteFakeKernel: VPNRouteKernelController {
    var routes: [String: VPNDarwinRouteSnapshot] = [:]
    var added: [VPNOwnedRouteIdentity] = []
    var deleted: [VPNOwnedRouteIdentity] = []

    func lookupExact(_ destination: VPNRoutePrefix) throws -> VPNDarwinRouteSnapshot? {
        routes[destination.canonical]
    }

    func add(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult {
        guard routes[identity.destination.canonical] == nil else { return .alreadyPresent }
        routes[identity.destination.canonical] = VPNDarwinRouteSnapshot(
            destination: identity.destination, gatewayBytes: identity.gatewayBytes,
            interfaceIndex: identity.interfaceIndex, interfaceName: identity.interfaceName,
            flags: identity.flags)
        added.append(identity)
        return .installed
    }

    func delete(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult {
        guard routes[identity.destination.canonical]?.matches(identity) == true else {
            throw VPNDarwinRouteError.missingOrForeign
        }
        routes.removeValue(forKey: identity.destination.canonical)
        deleted.append(identity)
        return .removed
    }
}

@main enum VPNTunnelRouteControllerChecks {
    static func ipv4(_ text: String) -> in_addr {
        var value = in_addr()
        guard text.withCString({ inet_pton(AF_INET, $0, &value) }) == 1 else { exit(64) }
        return value
    }

    static func interface(named candidates: [String]) -> (UInt32, String) {
        for name in candidates {
            let index = if_nametoindex(name)
            if index > 0 { return (index, name) }
        }
        exit(77)
    }

    static func tunnelIdentity() -> (UInt32, String) {
        guard let first = if_nameindex() else { exit(77) }
        defer { if_freenameindex(first) }
        var cursor = first
        while cursor.pointee.if_index != 0, let raw = cursor.pointee.if_name {
            let index = cursor.pointee.if_index, name = String(cString: raw)
            let suffix = name.dropFirst(4)
            if name.hasPrefix("utun"), !suffix.isEmpty,
               suffix.utf8.allSatisfy({ (48...57).contains($0) }) {
                return (index, name)
            }
            cursor = cursor.advanced(by: 1)
        }
        exit(77)
    }

    static func application(revision: UInt64 = 9, resource: String = "10.44.0.0/16") throws
        -> VPNValidatedApplication {
        let spec = try VPNApplicationSpec(revision: revision,
            profileSHA256: String(repeating: "a", count: 64),
            resources: [VPNResource(address: resource)], corporateDNS: [],
            authentication: VPNAuthentication(mode: .certificate))
        return VPNValidatedApplication(spec: spec, requiresVPNCredentials: false,
                                       requiresPrivateKeyPassword: false)
    }

    static func bootstrap(generation: UInt64 = 41) throws -> VPNTunnelBootstrapProof {
        let identity = tunnelIdentity()
        let local = try OpenVPNIPAddress(parsing: "10.253.0.2", family: .ipv4)
        let management = OpenVPNConnectedEvidence(tunnelLocalIPv4: local,
            tunnelLocalIPv6: nil,
            remoteAddress: try OpenVPNIPAddress(parsing: "198.51.100.77", family: .ipv4),
            remotePort: 443)
        let baseline = try VPNKernelInterfaceSnapshot(interfaces: [])
        let after = try VPNKernelInterfaceSnapshot(interfaces: [
            try VPNKernelInterfaceRecord(index: identity.0, name: identity.1,
                isUp: true, isRunning: true, isPointToPoint: true, addresses: [local])
        ])
        let tunnel = try VPNTunnelInterfaceResolver.resolve(baseline: baseline,
            after: after, management: management)
        return VPNTunnelBootstrapProof(generation: generation, management: management,
                                       tunnel: tunnel)
    }

    static func snapshot(generation: UInt64 = 41,
                         active: VPNValidatedApplication) -> VPNTunnelSnapshot {
        VPNTunnelSnapshot(schemaVersion: 2, generation: generation,
            desiredEnabled: true, phase: .connecting, active: active,
            pending: nil, challenge: nil)
    }

    static func journal(_ folder: String) throws -> VPNRouteJournal {
        let descriptor = open(folder, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { exit(70) }
        defer { close(descriptor) }
        return try VPNRouteJournal(trustedDirectoryDescriptor: descriptor)
    }

    static func peer(interface value: (UInt32, String)? = nil) throws -> VPNRoutePeerEvidence {
        let selected = value ?? interface(named: ["en0", "en1", "bridge0", "awdl0"])
        return try VPNRoutePeerEvidence(peer: ipv4("198.51.100.77"),
            gateway: ipv4("192.0.2.1"), interfaceIndex: selected.0)
    }

    static func controller(folder: String, active: VPNValidatedApplication,
                           generation: UInt64 = 41,
                           resolvedPeer: VPNRoutePeerEvidence,
                           kernel: TunnelRouteFakeKernel,
                           authority: @escaping () throws -> Void = {}) throws
        -> VPNTunnelRouteController {
        let transaction = VPNRouteTransaction(journal: try journal(folder), kernel: kernel)
        return VPNTunnelRouteController(loadSnapshot: {
            snapshot(generation: generation, active: active)
        }, resolvePeer: { address in
            try requireTunnelRoutes(address.bytes == resolvedPeer.peer.bytes,
                                    "resolver received another peer")
            return resolvedPeer
        }, transaction: transaction, checkAuthority: authority)
    }

    static func lifecycle(_ folder: String) throws {
        let active = try application(), kernel = TunnelRouteFakeKernel()
        let value = try controller(folder: folder, active: active,
                                   resolvedPeer: peer(), kernel: kernel)
        let proof = try value.install(bootstrap: bootstrap(), activeApplication: active)
        try requireTunnelRoutes(proof.generation == 41 && proof.revision == 9,
                                "generation/revision not bound")
        try requireTunnelRoutes(proof.profileSHA256 == active.spec.profileSHA256,
                                "application digest not bound")
        try requireTunnelRoutes(kernel.added.map(\.role) == [.peerBypass, .resource],
                                "unsafe install order")
        try value.verifyApplied(proof)
        try value.prepareForProcessStop()
        try requireTunnelRoutes(kernel.routes.isEmpty, "routes remain before process stop")
        try requireTunnelRoutes(kernel.deleted == Array(kernel.added.reversed()),
                                "cleanup was not reverse ordered")
        print("lifecycle passed")
    }

    static func preservedPeerLifecycle(_ folder: String) throws {
        let active = try application(), kernel = TunnelRouteFakeKernel()
        let resolved = try peer()
        let plan = try VPNRoutePlan(generation: 41, revision: 9,
            resources: active.spec.resources, peer: resolved, tunnel: bootstrap().tunnel)
        let identity = try VPNRouteIdentityFactory.make(plan: plan)[0]
        let existing = VPNDarwinRouteSnapshot(destination: identity.destination,
            gatewayBytes: identity.gatewayBytes, interfaceIndex: identity.interfaceIndex,
            interfaceName: identity.interfaceName,
            flags: UInt32(RTF_UP | RTF_HOST | RTF_GATEWAY | RTF_WASCLONED))
        kernel.routes[identity.destination.canonical] = existing
        let value = try controller(folder: folder, active: active,
                                   resolvedPeer: resolved, kernel: kernel)
        let proof = try value.install(bootstrap: bootstrap(), activeApplication: active)
        try requireTunnelRoutes(proof.routes.identities.map(\.role) == [.resource],
                                "controller acquired foreign peer")
        try value.verifyApplied(proof)
        try value.prepareForProcessStop()
        try requireTunnelRoutes(kernel.routes.count == 1
                                && kernel.routes[identity.destination.canonical] == existing,
                                "controller changed system peer route")
        print("preserved peer lifecycle passed")
    }

    static func stale(_ folder: String, mismatchApplication: Bool) throws {
        let active = try application(), kernel = TunnelRouteFakeKernel()
        var resolved = false
        let transaction = VPNRouteTransaction(journal: try journal(folder), kernel: kernel)
        let controller = VPNTunnelRouteController(loadSnapshot: {
            snapshot(generation: 41, active: active)
        }, resolvePeer: { _ in resolved = true; return try peer() }, transaction: transaction)
        do {
            let supplied = mismatchApplication ? try application(revision: 10) : active
            _ = try controller.install(bootstrap: bootstrap(generation: mismatchApplication ? 41 : 42),
                                       activeApplication: supplied)
            throw TunnelRouteControllerCheckFailure.failed("stale input accepted")
        } catch VPNTunnelRouteControllerError.staleGeneration where !mismatchApplication {
        } catch VPNTunnelRouteControllerError.applicationMismatch where mismatchApplication {
        }
        try requireTunnelRoutes(!resolved && kernel.added.isEmpty,
                                "kernel evidence used before state binding")
        print("stale passed")
    }

    static func peerTunnel(_ folder: String) throws {
        let active = try application(), kernel = TunnelRouteFakeKernel(), tunnel = tunnelIdentity()
        let value = try controller(folder: folder, active: active,
            resolvedPeer: peer(interface: tunnel), kernel: kernel)
        do {
            _ = try value.install(bootstrap: bootstrap(), activeApplication: active)
            throw TunnelRouteControllerCheckFailure.failed("tunnel peer route accepted")
        } catch VPNTunnelRouteControllerError.peerRouteUsesTunnel {}
        try requireTunnelRoutes(kernel.added.isEmpty, "route mutated after unsafe peer evidence")
        print("peer-tunnel passed")
    }

    static func intentRace(_ folder: String, afterMutation: Bool) throws {
        let active = try application(), kernel = TunnelRouteFakeKernel()
        let transaction = VPNRouteTransaction(journal: try journal(folder), kernel: kernel)
        var loads = 0
        let controller = VPNTunnelRouteController(loadSnapshot: {
            loads += 1
            let staleAt = afterMutation ? 3 : 2
            return snapshot(generation: loads >= staleAt ? 42 : 41, active: active)
        }, resolvePeer: { _ in try peer() }, transaction: transaction)
        do {
            _ = try controller.install(bootstrap: bootstrap(), activeApplication: active)
            throw TunnelRouteControllerCheckFailure.failed("changed intent accepted")
        } catch VPNTunnelRouteControllerError.staleGeneration {}
        try requireTunnelRoutes(kernel.routes.isEmpty, "changed intent left routes installed")
        if afterMutation {
            try requireTunnelRoutes(!kernel.added.isEmpty &&
                                    kernel.deleted == Array(kernel.added.reversed()),
                                    "post-install intent race did not roll back")
        } else {
            try requireTunnelRoutes(kernel.added.isEmpty,
                                    "pre-install intent race reached mutation")
        }
        print("intent-race passed")
    }

    static func authority(_ folder: String) throws {
        let active = try application(), kernel = TunnelRouteFakeKernel()
        let value = try controller(folder: folder, active: active,
            resolvedPeer: peer(), kernel: kernel,
            authority: { throw TunnelRouteControllerAuthorityFailure.lost })
        do {
            _ = try value.install(bootstrap: bootstrap(), activeApplication: active)
            throw TunnelRouteControllerCheckFailure.failed("lost authority accepted")
        } catch VPNTunnelRouteControllerError.recoveryRequired {}
        try requireTunnelRoutes(kernel.added.isEmpty, "route changed without authority")
        print("authority passed")
    }

    static func main() throws {
        guard CommandLine.arguments.count == 3 else { exit(64) }
        let mode = CommandLine.arguments[1], folder = CommandLine.arguments[2]
        switch mode {
        case "lifecycle": try lifecycle(folder)
        case "preserved-peer": try preservedPeerLifecycle(folder)
        case "stale-generation": try stale(folder, mismatchApplication: false)
        case "stale-application": try stale(folder, mismatchApplication: true)
        case "peer-tunnel": try peerTunnel(folder)
        case "intent-race-before": try intentRace(folder, afterMutation: false)
        case "intent-race-after": try intentRace(folder, afterMutation: true)
        case "authority": try authority(folder)
        default: exit(64)
        }
    }
}
