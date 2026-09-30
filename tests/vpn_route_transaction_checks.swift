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
        case "crash-before": try crash(CommandLine.arguments[2], afterMutation: false)
        case "crash-after": try crash(CommandLine.arguments[2], afterMutation: true)
        case "missing": try missing(CommandLine.arguments[2])
        case "foreign": try foreign(CommandLine.arguments[2])
        default: exit(64)
        }
    }
}
