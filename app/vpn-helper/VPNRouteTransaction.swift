import Darwin
import Foundation

enum VPNRouteTransactionError: Error, Equatable {
    case invalidPlan
    case preexistingRoute
    case recoveryRequired
    case cleanupBlocked
    case notApplied
}

protocol VPNRouteKernelController: AnyObject {
    func lookupExact(_ destination: VPNRoutePrefix) throws -> VPNDarwinRouteSnapshot?
    func add(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult
    func delete(_ identity: VPNOwnedRouteIdentity) throws -> VPNDarwinRouteMutationResult
}

extension VPNDarwinRouteSocket: VPNRouteKernelController {}

/// Ephemeral proof only. It is deliberately not Codable and cannot cross IPC.
struct VPNRouteAppliedProof: Equatable {
    let generation: UInt64
    let revision: UInt64
    let identities: [VPNOwnedRouteIdentity]
}

enum VPNRouteIdentityFactory {
    static func make(plan: VPNRoutePlan) throws -> [VPNOwnedRouteIdentity] {
        do { try plan.validate() } catch { throw VPNRouteTransactionError.invalidPlan }
        return try plan.routes.map { route in
            var flags = UInt32(RTF_UP | RTF_STATIC | RTF_PROTO2)
            if Int(route.destination.prefixLength) == route.destination.bytes.count * 8 {
                flags |= UInt32(RTF_HOST)
            }
            if route.physicalGatewayBytes != nil { flags |= UInt32(RTF_GATEWAY) }
            guard let index = route.interfaceIndex else {
                throw VPNRouteTransactionError.invalidPlan
            }
            let evidence: VPNRouteKernelEvidence
            switch route.destination.family {
            case .ipv4:
                let gateway: in_addr? = try route.physicalGatewayBytes.map {
                    try value($0, as: in_addr.self)
                }
                evidence = try VPNRouteKernelEvidence(gateway: gateway,
                    interfaceIndex: index, flags: flags)
            case .ipv6:
                let gateway: in6_addr? = try route.physicalGatewayBytes.map {
                    try value($0, as: in6_addr.self)
                }
                evidence = try VPNRouteKernelEvidence(gateway: gateway,
                    interfaceIndex: index, flags: flags)
            }
            return try VPNOwnedRouteIdentity(planned: route, evidence: evidence)
        }
    }

    private static func value<T>(_ bytes: [UInt8], as: T.Type) throws -> T {
        guard bytes.count == MemoryLayout<T>.size else {
            throw VPNRouteTransactionError.invalidPlan
        }
        return bytes.withUnsafeBytes { $0.loadUnaligned(as: T.self) }
    }
}

/// Owns only the route journal and PF_ROUTE mutations. It never releases the
/// OpenVPN hold, changes DNS or publishes a user-visible Connected state.
final class VPNRouteTransaction {
    private let journal: VPNRouteJournal
    private let kernel: VPNRouteKernelController
    private let checkAuthority: () throws -> Void
    private let lock = NSLock()

    #if VPN_ROUTE_TRANSACTION_TESTING
    init(journal: VPNRouteJournal, kernel: VPNRouteKernelController) {
        self.journal = journal
        self.kernel = kernel
        checkAuthority = {}
    }
    #else
    init(journal: VPNRouteJournal, kernel: VPNRouteKernelController,
         runtimeLease: VPNLifecycleLease) {
        self.journal = journal
        self.kernel = kernel
        checkAuthority = { try runtimeLease.check() }
    }
    #endif

    func install(_ plan: VPNRoutePlan) throws -> VPNRouteAppliedProof {
        lock.lock(); defer { lock.unlock() }
        do { try checkAuthority() }
        catch { throw VPNRouteTransactionError.recoveryRequired }
        let identities = try VPNRouteIdentityFactory.make(plan: plan)
        guard identities.count == plan.routes.count else {
            throw VPNRouteTransactionError.invalidPlan
        }
        // A matching pre-existing route is still foreign on a fresh install.
        // Ownership begins only after our durable beginInstall checkpoint.
        for identity in identities {
            do { try checkAuthority() }
            catch { throw VPNRouteTransactionError.recoveryRequired }
            guard try kernel.lookupExact(identity.destination) == nil else {
                throw VPNRouteTransactionError.preexistingRoute
            }
        }
        do { try checkAuthority(); _ = try journal.create(plan) }
        catch { throw VPNRouteTransactionError.recoveryRequired }

        for identity in identities {
            do { try checkAuthority(); _ = try journal.beginInstall(identity, generation: plan.generation,
                                               revision: plan.revision) }
            catch { throw VPNRouteTransactionError.recoveryRequired }
            do {
                try checkAuthority()
                let result = try kernel.add(identity)
                guard result == .installed else {
                    _ = try journal.resolveInstall(identity, present: false,
                        generation: plan.generation, revision: plan.revision)
                    try rollbackAndRetireLocked()
                    throw VPNRouteTransactionError.preexistingRoute
                }
                _ = try journal.resolveInstall(identity, present: true,
                    generation: plan.generation, revision: plan.revision)
            } catch VPNDarwinRouteError.preexistingNonIdentical {
                _ = try? journal.resolveInstall(identity, present: false,
                    generation: plan.generation, revision: plan.revision)
                do { try rollbackAndRetireLocked() }
                catch { throw VPNRouteTransactionError.cleanupBlocked }
                throw VPNRouteTransactionError.preexistingRoute
            } catch let error as VPNRouteTransactionError {
                throw error
            } catch {
                // The request may have reached the kernel. Preserve the
                // in-flight checkpoint for deterministic startup recovery.
                throw VPNRouteTransactionError.recoveryRequired
            }
        }
        let proof = VPNRouteAppliedProof(generation: plan.generation,
                                         revision: plan.revision,
                                         identities: identities)
        try verifyAppliedLocked(proof)
        return proof
    }

    func verifyApplied(_ proof: VPNRouteAppliedProof) throws {
        lock.lock(); defer { lock.unlock() }
        do { try checkAuthority() }
        catch { throw VPNRouteTransactionError.notApplied }
        try verifyAppliedLocked(proof)
    }

    /// Startup and disconnect both converge to the same safe state. Recovery
    /// never resumes installation forward; it reconciles and rolls back.
    func recoverToIdle() throws {
        lock.lock(); defer { lock.unlock() }
        do { try checkAuthority() }
        catch { throw VPNRouteTransactionError.recoveryRequired }
        try rollbackAndRetireLocked()
    }

    private func verifyAppliedLocked(_ proof: VPNRouteAppliedProof) throws {
        do { try checkAuthority() }
        catch { throw VPNRouteTransactionError.notApplied }
        let snapshot: VPNRouteJournalSnapshot
        do { snapshot = try journal.load() }
        catch { throw VPNRouteTransactionError.notApplied }
        guard snapshot.phase == .applied, snapshot.operation == nil,
              snapshot.plan.generation == proof.generation,
              snapshot.plan.revision == proof.revision,
              snapshot.applied == proof.identities else {
            throw VPNRouteTransactionError.notApplied
        }
        for identity in proof.identities {
            do { try checkAuthority() }
            catch { throw VPNRouteTransactionError.notApplied }
            guard let observed = try kernel.lookupExact(identity.destination),
                  observed.matches(identity) else {
                throw VPNRouteTransactionError.notApplied
            }
        }
    }

    private func rollbackAndRetireLocked() throws {
        let limit = 2_010
        for _ in 0..<limit {
            do { try checkAuthority() }
            catch { throw VPNRouteTransactionError.recoveryRequired }
            let snapshot: VPNRouteJournalSnapshot
            do { snapshot = try journal.load() }
            catch VPNRouteJournalError.missing { return }
            catch { throw VPNRouteTransactionError.cleanupBlocked }

            switch snapshot.phase {
            case .planned:
                do { _ = try journal.abandonUnapplied(generation: snapshot.plan.generation,
                                                       revision: snapshot.plan.revision) }
                catch { throw VPNRouteTransactionError.cleanupBlocked }
            case .installing:
                if let operation = snapshot.operation {
                    try reconcileInstall(operation, plan: snapshot.plan)
                } else if let last = snapshot.applied.last {
                    try remove(last, plan: snapshot.plan)
                } else {
                    do { _ = try journal.abandonUnapplied(generation: snapshot.plan.generation,
                                                           revision: snapshot.plan.revision) }
                    catch { throw VPNRouteTransactionError.cleanupBlocked }
                }
            case .applied:
                guard let last = snapshot.applied.last else {
                    throw VPNRouteTransactionError.cleanupBlocked
                }
                try remove(last, plan: snapshot.plan)
            case .removing:
                if let operation = snapshot.operation {
                    try reconcileRemove(operation, plan: snapshot.plan)
                } else if let last = snapshot.applied.last {
                    try remove(last, plan: snapshot.plan)
                } else { throw VPNRouteTransactionError.cleanupBlocked }
            case .retired:
                do { try journal.retireAndRemove(generation: snapshot.plan.generation,
                                                  revision: snapshot.plan.revision) }
                catch { throw VPNRouteTransactionError.cleanupBlocked }
                return
            }
        }
        throw VPNRouteTransactionError.cleanupBlocked
    }

    private func reconcileInstall(_ operation: VPNRouteJournalOperation,
                                  plan: VPNRoutePlan) throws {
        guard operation.action == .install else {
            throw VPNRouteTransactionError.cleanupBlocked
        }
        let observed: VPNDarwinRouteSnapshot?
        do { try checkAuthority(); observed = try kernel.lookupExact(operation.entry.destination) }
        catch { throw VPNRouteTransactionError.recoveryRequired }
        let owned = observed?.matches(operation.entry) == true
        do { _ = try journal.resolveInstall(operation.entry, present: owned,
                                             generation: plan.generation,
                                             revision: plan.revision) }
        catch { throw VPNRouteTransactionError.cleanupBlocked }
    }

    private func remove(_ identity: VPNOwnedRouteIdentity,
                        plan: VPNRoutePlan) throws {
        let observed: VPNDarwinRouteSnapshot?
        do { try checkAuthority(); observed = try kernel.lookupExact(identity.destination) }
        catch { throw VPNRouteTransactionError.recoveryRequired }
        if let observed, !observed.matches(identity) {
            throw VPNRouteTransactionError.cleanupBlocked
        }
        do { try checkAuthority(); _ = try journal.beginRemove(identity, generation: plan.generation,
                                          revision: plan.revision) }
        catch { throw VPNRouteTransactionError.cleanupBlocked }
        guard observed != nil else {
            do { _ = try journal.resolveRemove(identity, present: false,
                                                generation: plan.generation,
                                                revision: plan.revision) }
            catch { throw VPNRouteTransactionError.cleanupBlocked }
            return
        }
        do {
            try checkAuthority()
            guard try kernel.delete(identity) == .removed else {
                throw VPNRouteTransactionError.recoveryRequired
            }
            _ = try journal.resolveRemove(identity, present: false,
                                           generation: plan.generation,
                                           revision: plan.revision)
        } catch let error as VPNRouteTransactionError { throw error }
        catch { throw VPNRouteTransactionError.recoveryRequired }
    }

    private func reconcileRemove(_ operation: VPNRouteJournalOperation,
                                 plan: VPNRoutePlan) throws {
        guard operation.action == .remove else {
            throw VPNRouteTransactionError.cleanupBlocked
        }
        let observed: VPNDarwinRouteSnapshot?
        do { try checkAuthority(); observed = try kernel.lookupExact(operation.entry.destination) }
        catch { throw VPNRouteTransactionError.recoveryRequired }
        if let observed, !observed.matches(operation.entry) {
            throw VPNRouteTransactionError.cleanupBlocked
        }
        if observed != nil {
            do {
                try checkAuthority()
                guard try kernel.delete(operation.entry) == .removed else {
                    throw VPNRouteTransactionError.recoveryRequired
                }
            } catch let error as VPNRouteTransactionError { throw error }
            catch { throw VPNRouteTransactionError.recoveryRequired }
        }
        do { _ = try journal.resolveRemove(operation.entry, present: false,
                                            generation: plan.generation,
                                            revision: plan.revision) }
        catch { throw VPNRouteTransactionError.cleanupBlocked }
    }
}
