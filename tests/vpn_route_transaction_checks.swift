import Darwin
import Foundation

enum TransactionCheckFailure: Error { case failed(String) }

func requireTransaction(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw TransactionCheckFailure.failed(message) }
}

final class FakeRouteKernel: VPNRouteKernelController {
    var routes: [String: VPNDarwinRouteSnapshot] = [:]
    var added: [VPNOwnedRouteIdentity] = []
    var deleted: [VPNOwnedRouteIdentity] = []
    var failAddBefore: Int?
    var failAddAfter: Int?
    var onAdd: (() -> Void)?
    private var addCount = 0

    func lookupExact(_ destination: VPNRoutePrefix) throws -> VPNDarwinRouteSnapshot? {
        routes[Self.key(destination)]
    }

    func add(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult {
        defer { addCount += 1 }
        if failAddBefore == addCount { throw VPNDarwinRouteError.timeout }
        if let existing = routes[Self.key(identity.destination)] {
            guard existing.matches(identity) else { throw VPNDarwinRouteError.preexistingNonIdentical }
            return .alreadyPresent
        }
        routes[Self.key(identity.destination)] = Self.snapshot(identity)
        added.append(identity)
        onAdd?()
        if failAddAfter == addCount { throw VPNDarwinRouteError.timeout }
        return .installed
    }

    func delete(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult {
        guard routes[Self.key(identity.destination)]?.matches(identity) == true else {
            throw VPNDarwinRouteError.missingOrForeign
        }
        routes.removeValue(forKey: Self.key(identity.destination))
        deleted.append(identity)
        return .removed
    }

    static func snapshot(_ identity: VPNOwnedRouteIdentity) -> VPNDarwinRouteSnapshot {
        VPNDarwinRouteSnapshot(destination: identity.destination,
            gatewayBytes: identity.gatewayBytes, interfaceIndex: identity.interfaceIndex,
            interfaceName: identity.interfaceName, flags: identity.flags)
    }

    static func key(_ destination: VPNRoutePrefix) -> String {
        "\(destination.family.rawValue):\(destination.canonical)"
    }
}

@main enum VPNRouteTransactionChecks {
    static func ipv4(_ text: String) -> in_addr {
        var result = in_addr()
        guard text.withCString({ inet_pton(AF_INET, $0, &result) }) == 1 else { exit(64) }
        return result
    }

    static func physicalInterface() -> UInt32 {
        for name in ["en0", "en1", "bridge0", "awdl0"] {
            let index = if_nametoindex(name); if index > 0 { return index }
        }
        exit(77)
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
        let address = try OpenVPNIPAddress(parsing: "10.253.0.2", family: .ipv4)
        let baseline = try VPNKernelInterfaceSnapshot(interfaces: [])
        let after = try VPNKernelInterfaceSnapshot(interfaces: [
            try VPNKernelInterfaceRecord(index: identity.0, name: identity.1,
                isUp: true, isRunning: true, isPointToPoint: true, addresses: [address])
        ])
        let management = OpenVPNConnectedEvidence(tunnelLocalIPv4: address,
            tunnelLocalIPv6: nil,
            remoteAddress: try OpenVPNIPAddress(parsing: "198.51.100.77", family: .ipv4),
            remotePort: 443)
        return try VPNTunnelInterfaceResolver.resolve(baseline: baseline, after: after,
                                                       management: management)
    }

    static func plan() throws -> VPNRoutePlan {
        try VPNRoutePlan(generation: 41, revision: 9, resources: [
            VPNResource(address: "10.44.0.0/16"), VPNResource(address: "172.20.4.9")
        ], peer: VPNRoutePeerEvidence(peer: ipv4("198.51.100.77"),
             gateway: ipv4("192.0.2.1"), interfaceIndex: physicalInterface()),
           tunnel: tunnelEvidence())
    }

    static func journal(_ path: String) throws -> VPNRouteJournal {
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { exit(70) }
        defer { close(descriptor) }
        return try VPNRouteJournal(trustedDirectoryDescriptor: descriptor)
    }

    static func lifecycle(_ path: String) throws {
        let value = try plan(), kernel = FakeRouteKernel()
        let transaction = VPNRouteTransaction(journal: try journal(path), kernel: kernel)
        let proof = try transaction.install(value)
        try requireTransaction(proof.identities.map(\.role) == [.peerBypass, .resource, .resource],
                               "install order")
        try requireTransaction(kernel.added == proof.identities, "kernel install order")
        try transaction.verifyApplied(proof)
        try transaction.recoverToIdle()
        try requireTransaction(kernel.routes.isEmpty, "routes remain")
        try requireTransaction(kernel.deleted == Array(proof.identities.reversed()), "reverse delete")
        do { _ = try journal(path).load(); throw TransactionCheckFailure.failed("journal remains") }
        catch VPNRouteJournalError.missing {}
        print("lifecycle passed")
    }

    static func preexisting(_ path: String) throws {
        let value = try plan(), kernel = FakeRouteKernel()
        let identities = try VPNRouteIdentityFactory.make(plan: value)
        kernel.routes[FakeRouteKernel.key(identities[0].destination)] = FakeRouteKernel.snapshot(identities[0])
        do {
            _ = try VPNRouteTransaction(journal: try journal(path), kernel: kernel).install(value)
            throw TransactionCheckFailure.failed("preexisting route claimed")
        } catch VPNRouteTransactionError.preexistingRoute {}
        try requireTransaction(kernel.routes.count == 1, "preexisting route changed")
        do { _ = try journal(path).load(); throw TransactionCheckFailure.failed("journal created") }
        catch VPNRouteJournalError.missing {}
        print("preexisting passed")
    }

    static func preservedPeer(_ path: String) throws {
        let value = try plan(), kernel = FakeRouteKernel()
        let peer = try VPNRouteIdentityFactory.make(plan: value)[0]
        // Darwin creates this unowned host-route cache for a UDP connection.
        let existing = VPNDarwinRouteSnapshot(destination: peer.destination,
            gatewayBytes: peer.gatewayBytes, interfaceIndex: peer.interfaceIndex,
            interfaceName: peer.interfaceName,
            flags: UInt32(RTF_UP | RTF_HOST | RTF_GATEWAY | RTF_WASCLONED))
        let key = FakeRouteKernel.key(peer.destination)
        kernel.routes[key] = existing
        let transaction = VPNRouteTransaction(journal: try journal(path), kernel: kernel)
        let proof = try transaction.install(value)
        try requireTransaction(proof.identities.allSatisfy { $0.role == .resource },
                               "foreign peer route claimed")
        try transaction.verifyApplied(proof)
        // A new transaction instance simulates restart; no ephemeral proof is
        // needed to know that the peer route must never be removed.
        try VPNRouteTransaction(journal: try journal(path), kernel: kernel).recoverToIdle()
        try requireTransaction(kernel.routes.count == 1 && kernel.routes[key] == existing,
                               "system peer route changed")
        try requireTransaction(kernel.deleted.allSatisfy { $0.role == .resource },
                               "system peer route deleted")
        print("preserved peer passed")
    }

    static func rejectedPreservedPeer(_ path: String) throws {
        let value = try plan(), identities = try VPNRouteIdentityFactory.make(plan: value)
        let peer = identities[0], flags = UInt32(RTF_UP | RTF_HOST | RTF_GATEWAY | RTF_WASCLONED)
        let variants = [
            (peer.gatewayBytes, flags | UInt32(RTF_REJECT)),
            (peer.gatewayBytes, flags | UInt32(RTF_BLACKHOLE)),
            (peer.gatewayBytes, flags | UInt32(RTF_PROTO2)),
            (peer.gatewayBytes, flags & ~UInt32(RTF_UP)),
            (peer.gatewayBytes, flags & ~UInt32(RTF_GATEWAY)),
            (Optional([UInt8](arrayLiteral: 192, 0, 2, 254)), flags)
        ]
        for (gateway, valueFlags) in variants {
            let kernel = FakeRouteKernel()
            kernel.routes[FakeRouteKernel.key(peer.destination)] = VPNDarwinRouteSnapshot(
                destination: peer.destination, gatewayBytes: gateway,
                interfaceIndex: peer.interfaceIndex, interfaceName: peer.interfaceName, flags: valueFlags)
            do {
                _ = try VPNRouteTransaction(journal: try journal(path), kernel: kernel).install(value)
                throw TransactionCheckFailure.failed("incompatible peer accepted")
            } catch VPNRouteTransactionError.preexistingRoute {}
            try requireTransaction(kernel.added.isEmpty && kernel.deleted.isEmpty, "preflight mutated routes")
        }
        let kernel = FakeRouteKernel(), resource = identities[1]
        kernel.routes[FakeRouteKernel.key(resource.destination)] = FakeRouteKernel.snapshot(resource)
        do {
            _ = try VPNRouteTransaction(journal: try journal(path), kernel: kernel).install(value)
            throw TransactionCheckFailure.failed("resource adopted")
        } catch VPNRouteTransactionError.preexistingRoute {}
        print("rejected preserved peer passed")
    }

    static func preservedPeerFailure(_ path: String, crash: Bool) throws {
        let value = try plan(), kernel = FakeRouteKernel()
        let peer = try VPNRouteIdentityFactory.make(plan: value)[0]
        let key = FakeRouteKernel.key(peer.destination)
        let existing = VPNDarwinRouteSnapshot(destination: peer.destination,
            gatewayBytes: peer.gatewayBytes, interfaceIndex: peer.interfaceIndex,
            interfaceName: peer.interfaceName, flags: UInt32(RTF_UP | RTF_HOST | RTF_GATEWAY | RTF_WASCLONED))
        kernel.routes[key] = existing
        let transaction = VPNRouteTransaction(journal: try journal(path), kernel: kernel)
        if crash {
            kernel.failAddAfter = 0
            do {
                _ = try transaction.install(value)
                throw TransactionCheckFailure.failed("crash accepted")
            } catch VPNRouteTransactionError.recoveryRequired {}
        } else {
            let proof = try transaction.install(value)
            kernel.routes.removeValue(forKey: key)
            do {
                try transaction.verifyApplied(proof)
                throw TransactionCheckFailure.failed("lost dependency accepted")
            } catch VPNRouteTransactionError.notApplied {}
            // Recovery is permitted even when the dependency has disappeared.
            kernel.routes[key] = existing
        }
        try VPNRouteTransaction(journal: try journal(path), kernel: kernel).recoverToIdle()
        try requireTransaction(kernel.routes.count == 1 && kernel.routes[key] == existing,
                               "recovery removed foreign peer")
        try requireTransaction(kernel.deleted.allSatisfy { $0.role == .resource }, "peer deleted")
        print("preserved peer failure passed")
    }

    static func preservedPeerRace(_ path: String) throws {
        let value = try plan(), kernel = FakeRouteKernel()
        let peer = try VPNRouteIdentityFactory.make(plan: value)[0]
        let key = FakeRouteKernel.key(peer.destination)
        let existing = VPNDarwinRouteSnapshot(destination: peer.destination,
            gatewayBytes: peer.gatewayBytes, interfaceIndex: peer.interfaceIndex,
            interfaceName: peer.interfaceName, flags: UInt32(RTF_UP | RTF_HOST | RTF_GATEWAY | RTF_WASCLONED))
        let replacement = VPNDarwinRouteSnapshot(destination: peer.destination,
            gatewayBytes: [192, 0, 2, 254], interfaceIndex: peer.interfaceIndex,
            interfaceName: peer.interfaceName, flags: existing.flags)
        kernel.routes[key] = existing
        kernel.onAdd = { kernel.routes[key] = replacement }
        let transaction = VPNRouteTransaction(journal: try journal(path), kernel: kernel)
        do {
            _ = try transaction.install(value)
            throw TransactionCheckFailure.failed("changed peer accepted")
        } catch VPNRouteTransactionError.notApplied {}
        try transaction.recoverToIdle()
        try requireTransaction(kernel.added.count == 1 && kernel.routes.count == 1
                               && kernel.routes[key] == replacement, "race cleanup changed foreign route")
        print("preserved peer race passed")
    }

    static func nativeCachedPeer(_ path: String) throws {
        // UDP connect selects a kernel route without sending any datagram.
        // No credentials/profile, TUN setup, RTM_ADD or RTM_DELETE are used.
        let descriptor = socket(AF_INET, SOCK_DGRAM, 0)
        guard descriptor >= 0 else { exit(77) }
        defer { close(descriptor) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr = ipv4("198.51.100.77"); address.sin_port = UInt16(443).bigEndian
        let status = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard status == 0 else { exit(77) }
        let prefix = try VPNRoutePrefix(resource: VPNResource(address: "198.51.100.77"))
        let observer = try VPNDarwinRouteSocket.production()
        guard let observed = try observer.lookupExact(prefix) else { exit(77) }
        let gateway: in_addr? = observed.gatewayBytes.map { $0.withUnsafeBytes { $0.loadUnaligned(as: in_addr.self) } }
        let value = try VPNRoutePlan(generation: 41, revision: 9,
            resources: [VPNResource(address: "10.44.0.0/16")],
            peer: VPNRoutePeerEvidence(peer: address.sin_addr, gateway: gateway,
                                      interfaceIndex: observed.interfaceIndex), tunnel: tunnelEvidence())
        let kernel = FakeRouteKernel(), key = FakeRouteKernel.key(prefix)
        kernel.routes[key] = observed
        let transaction = VPNRouteTransaction(journal: try journal(path), kernel: kernel)
        let proof = try transaction.install(value)
        try transaction.verifyApplied(proof)
        try transaction.recoverToIdle()
        try requireTransaction(kernel.routes[key] == observed && kernel.deleted.count == 1,
                               "native cached peer not preserved")
        print("native cached peer passed")
    }

    static func crash(_ path: String, afterMutation: Bool) throws {
        let value = try plan(), kernel = FakeRouteKernel()
        if afterMutation { kernel.failAddAfter = 0 } else { kernel.failAddBefore = 0 }
        let transaction = VPNRouteTransaction(journal: try journal(path), kernel: kernel)
        do {
            _ = try transaction.install(value)
            throw TransactionCheckFailure.failed("injected crash ignored")
        } catch VPNRouteTransactionError.recoveryRequired {}
        let interrupted = try journal(path).load()
        try requireTransaction(interrupted.phase == .installing
                               && interrupted.operation?.action == .install, "checkpoint missing")
        kernel.failAddAfter = nil; kernel.failAddBefore = nil
        try VPNRouteTransaction(journal: try journal(path), kernel: kernel).recoverToIdle()
        try requireTransaction(kernel.routes.isEmpty, "crash route remains")
        do { _ = try journal(path).load(); throw TransactionCheckFailure.failed("crash journal remains") }
        catch VPNRouteJournalError.missing {}
        print(afterMutation ? "crash after passed" : "crash before passed")
    }

    static func missing(_ path: String) throws {
        let value = try plan(), kernel = FakeRouteKernel()
        let transaction = VPNRouteTransaction(journal: try journal(path), kernel: kernel)
        let proof = try transaction.install(value)
        kernel.routes.removeValue(forKey: FakeRouteKernel.key(proof.identities.last!.destination))
        try transaction.recoverToIdle()
        try requireTransaction(kernel.routes.isEmpty, "missing cleanup left routes")
        print("missing passed")
    }

    static func foreign(_ path: String) throws {
        let value = try plan(), kernel = FakeRouteKernel()
        let transaction = VPNRouteTransaction(journal: try journal(path), kernel: kernel)
        let proof = try transaction.install(value), last = proof.identities.last!
        kernel.routes[FakeRouteKernel.key(last.destination)] = VPNDarwinRouteSnapshot(destination: last.destination,
            gatewayBytes: last.gatewayBytes, interfaceIndex: last.interfaceIndex,
            interfaceName: last.interfaceName, flags: last.flags & ~UInt32(RTF_PROTO2))
        do {
            try transaction.recoverToIdle()
            throw TransactionCheckFailure.failed("foreign route deleted")
        } catch VPNRouteTransactionError.cleanupBlocked {}
        try requireTransaction(kernel.routes[FakeRouteKernel.key(last.destination)]?.flags != last.flags,
                               "foreign route changed")
        let retained = try journal(path).load()
        try requireTransaction(retained.phase == .applied, "ownership journal erased")
        print("foreign passed")
    }

    static func main() throws {
        guard CommandLine.arguments.count == 3 else { exit(64) }
        switch CommandLine.arguments[1] {
        case "lifecycle": try lifecycle(CommandLine.arguments[2])
        case "preexisting": try preexisting(CommandLine.arguments[2])
        case "preserved-peer": try preservedPeer(CommandLine.arguments[2])
        case "rejected-preserved-peer": try rejectedPreservedPeer(CommandLine.arguments[2])
        case "preserved-peer-crash": try preservedPeerFailure(CommandLine.arguments[2], crash: true)
        case "preserved-peer-lost": try preservedPeerFailure(CommandLine.arguments[2], crash: false)
        case "preserved-peer-race": try preservedPeerRace(CommandLine.arguments[2])
        case "native-cached-peer": try nativeCachedPeer(CommandLine.arguments[2])
        case "crash-before": try crash(CommandLine.arguments[2], afterMutation: false)
        case "crash-after": try crash(CommandLine.arguments[2], afterMutation: true)
        case "missing": try missing(CommandLine.arguments[2])
        case "foreign": try foreign(CommandLine.arguments[2])
        default: exit(64)
        }
    }
}
