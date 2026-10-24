import Darwin
import Dispatch
import Foundation

#if VPN_RESCUE_SYSTEM_ENTRY || VPN_RESCUE_BROKER_TESTING
/// Serializes manual rescue against submissions, then reconciles only the
/// selected C broker job. The VPN runtime and desired-state budget are read-only.
final class VPNRescueBrokerCoordinator {
    enum Failure: Error { case invalidState, ownershipLost, changed, deadlineExceeded }
    enum Outcome { case alreadyReady, reconciled }
    private struct Actions {
        let installed: (VerifiedVPNRelease) throws -> Void
        let running: (Int32, VPNAuthorizedDeployment, UInt64) throws -> Void
        let install: (Int32, VPNAuthorizedDeployment, UInt64, () throws -> Void) throws -> Void
    }
    private let service: Int32, broker: Int32
    private let authority: VPNReleaseAuthority
    private let first: VerifiedVPNRescueAuthorization, second: VerifiedVPNRescueAuthorization
    private let final: VerifiedVPNRelease
    private let checkInputs: () throws -> Void
    private let actions: Actions
    private let system: Bool
    private var ownership: VPNLifecycleLease?
    private var captured = false
    private var previousTransaction: VPNUpdateBrokerTransactionSnapshot?
    private var trustedOwner: uid_t?

    private init(service: Int32, broker: Int32, authority: VPNReleaseAuthority,
                 first: VerifiedVPNRescueAuthorization, second: VerifiedVPNRescueAuthorization,
                 final: VerifiedVPNRelease, system: Bool,
                 checkInputs: @escaping () throws -> Void, actions: Actions) throws {
        guard second.matchesDestination(final) else { throw Failure.invalidState }
        self.service = fcntl(service, F_DUPFD_CLOEXEC, 0)
        self.broker = fcntl(broker, F_DUPFD_CLOEXEC, 0)
        guard self.service >= 0, self.broker >= 0 else {
            if self.service >= 0 { close(self.service) }; if self.broker >= 0 { close(self.broker) }
            throw Failure.invalidState
        }
        self.authority = authority; self.first = first; self.second = second
        self.final = final; self.system = system; self.checkInputs = checkInputs; self.actions = actions
    }
    deinit { ownership?.release(); close(service); close(broker) }

    #if VPN_RESCUE_SYSTEM_ENTRY
    static func system(service: Int32, payload: VPNRescueInstallationPayload,
                       executor: VPNRescueExecutor, authority: VPNReleaseAuthority) throws
        -> VPNRescueBrokerCoordinator {
        guard getuid() == 0, geteuid() == 0 else { throw Failure.invalidState }
        try payload.revalidate(); try executor.revalidate()
        guard executor.authorization.matchesSource(payload.intermediate),
              executor.authorization.matchesDestination(payload.second.candidate.release),
              executor.authorization.matchesTransition(payload.second.transition) else { throw Failure.invalidState }
        try VPNDirectoryProvisioner.requireSystemDirectory(service)
        let broker = try VPNDirectoryProvisioner.openSystemBrokerDirectory(create: true)
        defer { close(broker) }
        return try VPNRescueBrokerCoordinator(service: service, broker: broker, authority: authority,
            first: payload.finishFirst, second: payload.finishSecond, final: payload.second.candidate.release,
            system: true, checkInputs: { try payload.revalidate(); try executor.revalidate() },
            actions: Actions(installed: { try VPNInstalledApplication.inspect(release: $0).revalidate() },
                running: { service, selected, deadline in
                    try VPNUpdateBrokerLaunchdJob.system(storageDirectory: service)
                        .requireRunning(selected, deadline: deadline)
                }, install: { service, selected, deadline, beforeBootstrap in
                    let endpoint = try VPNEndpointDirectory.openSystem(create: true); close(endpoint)
                    try VPNUpdateBrokerLaunchdJob.system(storageDirectory: service)
                        .installAndStart(selected, deadline: deadline, beforeBootstrap: beforeBootstrap)
                }))
    }
    #endif

    #if VPN_RESCUE_BROKER_TESTING
    static func testCreate(service: Int32, broker: Int32, authority: VPNReleaseAuthority,
                           first: VerifiedVPNRescueAuthorization, second: VerifiedVPNRescueAuthorization,
                           final: VerifiedVPNRelease, checkInputs: @escaping () throws -> Void = {},
                           installed: @escaping (VerifiedVPNRelease) throws -> Void = { _ in },
                           running: @escaping (Int32, VPNAuthorizedDeployment, UInt64) throws -> Void,
                           install: @escaping (Int32, VPNAuthorizedDeployment, UInt64, () throws -> Void) throws -> Void) throws
        -> VPNRescueBrokerCoordinator {
        guard getuid() != 0, getuid() == geteuid() else { throw Failure.invalidState }
        return try VPNRescueBrokerCoordinator(service: service, broker: broker, authority: authority,
            first: first, second: second, final: final, system: false, checkInputs: checkInputs,
            actions: Actions(installed: installed, running: running, install: install))
    }
    #endif

    /// Call before acquiring a service lease, including on retry after bootstrap.
    func acquire() throws {
        try checkInputs(); try fixedStorage()
        if let ownership { try ownership.check(); return }
        ownership = try VPNLifecycleOwnership.acquire(inTrustedDirectory: broker)
    }

    /// May advance only an exact prepared broker index after its signed service
    /// journal is already pending. No service journal or retained inbox is changed.
    func validateForRepair(serviceLease: VPNLifecycleLease) throws {
        try requireOwnership(serviceLease)
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
        let selected = try store.loadDeployment()
        guard selected.ownerUserID >= 500, selected.ownerUserID != uid_t.max,
              trustedOwner == nil || trustedOwner == selected.ownerUserID,
              first.matchesSource(selected.release) || first.matchesDestination(selected.release)
                || second.matchesDestination(selected.release) else { throw Failure.invalidState }
        trustedOwner = selected.ownerUserID
        let transactions = try VPNUpdateBrokerTransactionStore(trustedDirectoryDescriptor: broker)
        let normal = try transactions.load(), backup = try transactions.loadRescueRotationBackup()
        guard normal == nil || backup == nil else { throw Failure.invalidState }
        var transaction = normal ?? backup
        try requireProgress(transaction)
        try VPNUpdateBrokerStateRemoval(trustedDirectoryDescriptor: broker).preflight()
        let names = try brokerNames()
        guard !names.contains(where: { $0.hasPrefix(".inbox-") }) else { throw Failure.invalidState }
        let publications = names.filter { $0.hasPrefix("inbox-") }
        if let value = transaction {
            let expected = "inbox-" + value.identity.map { String(format: "%02x", $0) }.joined()
            guard publications.isEmpty || publications == [expected] else { throw Failure.invalidState }
            var payload: VPNJointUpdatePayload?
            if !publications.isEmpty {
                let published = try VPNUpdateBrokerInbox(trustedParent: broker).openPublished(identity: value.identity)
                defer { close(published) }
                let loaded = try VPNJointUpdatePayload.loadForBroker(inTrustedDirectory: published, authority: authority)
                _ = try VPNStagedApplication.inspect(inTrustedDirectory: published, release: loaded.candidate.release)
                guard loaded.previous.sequence == value.fromSequence,
                      loaded.candidate.release.sequence == value.toSequence else { throw Failure.invalidState }
                payload = loaded
            }
            if value.phase == .complete {
                guard value.toSequence <= selected.release.sequence, value.journal?.phase == .completed,
                      value.journal?.revision == 3 else { throw Failure.invalidState }
            } else {
                guard let reference = value.journal,
                      value.phase == .prepared || value.phase == .handoffStarted
                        || value.phase == .handoffComplete || value.phase == .rotatingBroker else {
                    throw Failure.invalidState
                }
                switch value.phase {
                case .prepared:
                    guard value.recovery == .journalRetained,
                          value.rotation == .notStarted || value.rotation == .pending else { throw Failure.invalidState }
                case .handoffStarted:
                    guard value.recovery == .journalRetained, value.rotation == .pending else { throw Failure.invalidState }
                case .handoffComplete:
                    guard value.recovery == .executorCommitted, value.rotation == .pending else { throw Failure.invalidState }
                case .rotatingBroker:
                    guard value.recovery == .executorCommitted, value.rotation == .complete else { throw Failure.invalidState }
                default: throw Failure.invalidState
                }
                let journal = try store.loadUpdateJournal()
                let receipt = try store.loadUpdateCleanupReceipt()
                if let backup {
                    // Immutable B139 cannot retry rotation phase6→5. The fixed
                    // detached raw index lets its normal recovery re-prove VPN
                    // readiness/off before retiring the unchanged signed journal.
                    if let journal {
                        guard journal.phase == .completed, journal.revision == 3,
                              reference.transactionID == journal.transactionID,
                              reference.phase == .completed, reference.revision == 3,
                              selected.release.isSameRelease(as: journal.candidate.release),
                              first.matchesSource(journal.previous.release),
                              first.matchesDestination(journal.candidate.release),
                              first.matchesTransition(journal.transition) else { throw Failure.invalidState }
                        try bind(value, to: journal.previous.release, journal.candidate.release, payload: payload)
                    } else {
                        guard let receipt, receipt.phase == .completed, receipt.revision == 3,
                              reference.transactionID == receipt.transactionID,
                              selected.release.isSameRelease(as: receipt.candidate.release),
                              first.matchesSource(receipt.previous.release),
                              first.matchesDestination(receipt.candidate.release),
                              first.matchesTransition(receipt.transition) else { throw Failure.invalidState }
                        try bind(value, to: receipt.previous.release, receipt.candidate.release, payload: payload)
                        try transactions.restoreRescueRotation(backup)
                        transaction = try completeRetired(value, transactions: transactions)
                    }
                } else if let journal {
                    guard let payload, exactEdge(payload.previous, payload.candidate.release, payload.transition),
                          reference.transactionID == journal.transactionID,
                          reference.revision <= journal.revision, validReference(reference),
                          payload.previous.isSameRelease(as: journal.previous.release),
                          payload.candidate.release.isSameRelease(as: journal.candidate.release),
                          exactEdge(journal.previous.release, journal.candidate.release, journal.transition) else {
                        throw Failure.invalidState
                    }
                    if value.phase == .rotatingBroker, journal.phase == .completed, journal.revision == 3,
                       first.matchesSource(journal.previous.release), first.matchesDestination(journal.candidate.release) {
                        guard reference.phase == .completed, reference.revision == 3,
                              selected.release.isSameRelease(as: journal.candidate.release) else { throw Failure.invalidState }
                        try transactions.detachRescueRotation(value)
                    } else if value.phase == .prepared, journal.phase == .replacementPending, journal.revision == 1 {
                        transaction = try transactions.advance(identity: value.identity, expectedRevision: value.revision,
                            phase: .handoffStarted, journal: .init(transactionID: journal.transactionID,
                                revision: 1, phase: .replacementPending), recovery: .journalRetained, rotation: .pending)
                    }
                } else {
                    guard let payload, let receipt,
                          exactEdge(payload.previous, payload.candidate.release, payload.transition),
                          value.phase == .rotatingBroker, value.rotation == .complete,
                          reference.transactionID == receipt.transactionID,
                          reference.phase == .completed, reference.revision == 3,
                          selected.release.isSameRelease(as: receipt.candidate.release),
                          payload.previous.isSameRelease(as: receipt.previous.release),
                          payload.candidate.release.isSameRelease(as: receipt.candidate.release) else {
                        throw Failure.invalidState
                    }
                    transaction = try completeRetired(value, transactions: transactions)
                }
            }
        } else { guard publications.isEmpty else { throw Failure.invalidState } }
        try requireOwnership(serviceLease)
        previousTransaction = transaction; captured = true
    }

    /// Called outside any service lease. Broker-only maintenance never invokes
    /// helper activation, recovery intent, or writes the desired-state budget.
    func reconcileFinal(deadline: UInt64) throws -> Outcome {
        try requireTime(deadline)
        try acquire()
        var serviceLease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
        var held = true
        defer { if held { serviceLease.release() } }
        try validateForRepair(serviceLease: serviceLease)
        let selected = try finalDeployment(serviceLease)
        let budget = try VPNActivationBudget(trustedDirectoryDescriptor: service).snapshot()
        let probeDeadline = min(deadline, DispatchTime.now().uptimeNanoseconds + 2_000_000_000)
        let ready: Bool
        do { try actions.running(service, selected, probeDeadline); ready = true }
        catch { ready = false }
        try requireFinalSnapshot(selected, budget, serviceLease)
        if ready { return .alreadyReady }
        try requireTime(deadline)
        serviceLease.release(); held = false
        var released = false
        try actions.install(service, selected, deadline, {
            try checkInputs(); try fixedStorage()
            guard let ownership else { throw Failure.ownershipLost }
            try ownership.check(); ownership.release(); self.ownership = nil; released = true
        })
        guard released else { throw Failure.ownershipLost }
        try acquire()
        serviceLease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service); held = true
        try validateForRepair(serviceLease: serviceLease)
        try requireFinalSnapshot(selected, budget, serviceLease)
        try actions.running(service, selected, deadline)
        try requireFinalSnapshot(selected, budget, serviceLease)
        return .reconciled
    }

    /// Fresh readiness proof immediately before the entry reports completion.
    func requireFinalReady(serviceLease: VPNLifecycleLease, deadline: UInt64) throws {
        try requireTime(deadline)
        let selected = try finalDeployment(serviceLease)
        try validateForRepair(serviceLease: serviceLease)
        let budget = try VPNActivationBudget(trustedDirectoryDescriptor: service).snapshot()
        try actions.running(service, selected, deadline)
        try requireFinalSnapshot(selected, budget, serviceLease)
    }

    private func bind(_ value: VPNUpdateBrokerTransactionSnapshot, to previous: VerifiedVPNRelease,
                      _ candidate: VerifiedVPNRelease, payload: VPNJointUpdatePayload?) throws {
        guard value.fromSequence == previous.sequence, value.toSequence == candidate.sequence else {
            throw Failure.invalidState
        }
        if let payload {
            guard payload.previous.isSameRelease(as: previous),
                  payload.candidate.release.isSameRelease(as: candidate),
                  exactEdge(previous, candidate, payload.transition) else { throw Failure.invalidState }
        }
    }
    private func completeRetired(_ value: VPNUpdateBrokerTransactionSnapshot,
                                 transactions: VPNUpdateBrokerTransactionStore) throws
        -> VPNUpdateBrokerTransactionSnapshot {
        let completed = try transactions.advance(identity: value.identity, expectedRevision: value.revision,
            phase: .complete, journal: value.journal, recovery: .complete, rotation: .complete)
        _ = try VPNUpdateBrokerStatusStore(trustedDirectoryDescriptor: broker)
            .publish(state: .complete, fromSequence: value.fromSequence, toSequence: value.toSequence)
        return completed
    }

    private func finalDeployment(_ lease: VPNLifecycleLease) throws -> VPNAuthorizedDeployment {
        try requireOwnership(lease)
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
        guard try store.loadUpdatePreparation() == nil, try store.loadUpdateJournal() == nil,
              try store.loadUpdateCleanupReceipt() == nil else { throw Failure.invalidState }
        let selected = try store.loadDeployment()
        guard selected.ownerUserID >= 500, selected.ownerUserID != uid_t.max,
              trustedOwner == nil || trustedOwner == selected.ownerUserID,
              selected.release.isSameRelease(as: final), second.matchesDestination(selected.release) else {
            throw Failure.invalidState
        }
        let transactions = try VPNUpdateBrokerTransactionStore(trustedDirectoryDescriptor: broker)
        let transaction = try transactions.load()
        guard try transactions.loadRescueRotationBackup() == nil,
              transaction == nil || transaction?.phase == .complete else { throw Failure.invalidState }
        try actions.installed(selected.release)
        return selected
    }

    private func requireFinalSnapshot(_ selected: VPNAuthorizedDeployment,
                                      _ budget: (desired: Bool, failures: Int), _ lease: VPNLifecycleLease) throws {
        let fresh = try finalDeployment(lease)
        let state = try VPNActivationBudget(trustedDirectoryDescriptor: service).snapshot()
        guard fresh.ownerUserID == selected.ownerUserID, fresh.release.isSameRelease(as: selected.release),
              state.desired == budget.desired, state.failures == budget.failures else { throw Failure.changed }
    }
    private func requireOwnership(_ lease: VPNLifecycleLease) throws {
        try checkInputs(); try fixedStorage()
        guard let ownership else { throw Failure.ownershipLost }
        try ownership.check()
        var a = stat(), b = stat()
        guard fstat(service, &a) == 0, fstat(broker, &b) == 0,
              try lease.checkedStorageIdentity() == (UInt64(truncatingIfNeeded: a.st_dev), UInt64(a.st_ino)),
              try ownership.checkedStorageIdentity() == (UInt64(truncatingIfNeeded: b.st_dev), UInt64(b.st_ino)),
              a.st_dev != b.st_dev || a.st_ino != b.st_ino else { throw Failure.ownershipLost }
    }
    private func fixedStorage() throws {
        #if VPN_RESCUE_SYSTEM_ENTRY
        if system {
            try VPNDirectoryProvisioner.requireSystemDirectory(service)
            let current = try VPNDirectoryProvisioner.openSystemBrokerDirectory(create: false)
            defer { close(current) }
            var a = stat(), b = stat()
            guard fstat(current, &a) == 0, fstat(broker, &b) == 0,
                  a.st_dev == b.st_dev, a.st_ino == b.st_ino else { throw Failure.changed }
        }
        #endif
    }
    private func exactEdge(_ previous: VerifiedVPNRelease, _ candidate: VerifiedVPNRelease,
                           _ edge: VerifiedVPNUpdateTransition) -> Bool {
        (first.matchesSource(previous) && first.matchesDestination(candidate) && first.matchesTransition(edge))
            || (second.matchesSource(previous) && second.matchesDestination(candidate) && second.matchesTransition(edge))
    }
    private func validReference(_ reference: VPNUpdateBrokerJournalReference) -> Bool {
        (reference.phase == .prepared && reference.revision == 0)
            || (reference.phase == .replacementPending && reference.revision == 1)
            || (reference.phase == .completed && reference.revision == 3)
    }
    private func requireProgress(_ value: VPNUpdateBrokerTransactionSnapshot?) throws {
        guard captured else { return }
        if let old = previousTransaction, let value {
            guard old.identity == value.identity, old.fromSequence == value.fromSequence,
                  old.toSequence == value.toSequence, value.revision >= old.revision,
                  value.phase.rawValue >= old.phase.rawValue,
                  value.recovery.rawValue >= old.recovery.rawValue,
                  value.rotation.rawValue >= old.rotation.rawValue,
                  (value.journal?.revision ?? 0) >= (old.journal?.revision ?? 0),
                  old.journal?.transactionID == value.journal?.transactionID,
                  old.phase != .complete || value == old else { throw Failure.changed }
        } else { guard previousTransaction == value else { throw Failure.changed } }
    }
    private func requireTime(_ deadline: UInt64) throws {
        guard DispatchTime.now().uptimeNanoseconds < deadline else { throw Failure.deadlineExceeded }
    }
    private func brokerNames() throws -> [String] {
        let copy = openat(broker, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard copy >= 0, let stream = fdopendir(copy) else {
            if copy >= 0 { close(copy) }; throw Failure.invalidState
        }
        defer { closedir(stream) }
        var result: [String] = []
        let offset = MemoryLayout<dirent>.offset(of: \.d_name)!
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw Failure.invalidState }; return result.sorted()
            }
            let name = String(cString: UnsafeRawPointer(entry).advanced(by: offset).assumingMemoryBound(to: CChar.self))
            if name == "." || name == ".." { continue }
            result.append(name); guard result.count <= 1024 else { throw Failure.invalidState }
        }
    }
}
#endif
