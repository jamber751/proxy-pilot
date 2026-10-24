import CryptoKit
import Darwin
import Dispatch
import Foundation

@main enum VPNRescueBrokerCoordinatorChecks {
    enum Injected: Error { case notRunning, installFailed, identityLost }
    static func main() throws {
        let a = CommandLine.arguments
        guard a.count == 16, getuid() != 0 else { exit(64) }
        let operation = a[1]
        let service = open(a[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let broker = open(a[3], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let bDirectory = open(a[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let cDirectory = open(a[5], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard min(service, broker, bDirectory, cDirectory) >= 0 else { exit(65) }
        defer { close(service); close(broker); close(bDirectory); close(cDirectory) }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
            minimumSequence: 1, supportedProtocol: 1)
        let helper = try Data(contentsOf: URL(fileURLWithPath: a[6]))
        let engine = try Data(contentsOf: URL(fileURLWithPath: a[13]))
        func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
        func manifest(_ sequence: Int, _ version: String, _ arm: String, _ intel: String) -> Data {
            Data("format=2\nproduct=kz.documentolog.proxypilot\nsequence=\(sequence)\nversion=\(version)\nprotocol=1\napp-arm64=\(arm)\napp-x86_64=\(intel)\nhelper-arm64=\(a[11])\nhelper-x86_64=\(a[12])\nhelper-sha256=\(hex(Data(SHA256.hash(data: helper))))\nhelper-bytes=\(helper.count)\nengine-version=2.7.7\nengine-crypto-version=3.5.8\nengine-arm64=\(a[14])\nengine-x86_64=\(a[15])\nengine-sha256=\(hex(Data(SHA256.hash(data: engine))))\nengine-bytes=\(engine.count)\n".utf8)
        }
        let ap = manifest(137, "1.5.0", a[7], a[8]), bp = manifest(139, "1.6.0", a[7], a[8])
        let cp = manifest(141, "1.7.0", a[9], a[10])
        func signature(_ data: Data) throws -> Data { try key.signature(for: VPNReleaseAuthority.signatureDomain + data) }
        let ar = try authority.verify(payload: ap, signature: signature(ap), previous: nil)
        let br = try authority.verify(payload: bp, signature: signature(bp), previous: ar)
        let cr = try authority.verify(payload: cp, signature: signature(cp), previous: br)
        func edge(_ previous: Data, _ next: Data, _ from: Int, _ to: Int) -> Data {
            Data("format=1\nproduct=kz.documentolog.proxypilot\nfrom-sequence=\(from)\nfrom-sha256=\(hex(Data(SHA256.hash(data: previous))))\nto-sequence=\(to)\nto-sha256=\(hex(Data(SHA256.hash(data: next))))\n".utf8)
        }
        let ab = edge(ap, bp, 137, 139), bc = edge(bp, cp, 139, 141)
        func edgeSignature(_ data: Data) throws -> Data { try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + data) }
        func token(_ previous: Data, _ next: Data, _ edge: Data, _ release: VerifiedVPNRelease) throws
            -> VerifiedVPNRescueAuthorization {
            let bytes = try VPNRescueAuthorization.encode(previousManifest: previous, candidateManifest: next,
                transitionPayload: edge, rescueArtifact: Data("fixture".utf8),
                arm64CDHash: Data(repeating: 1, count: 20), intelCDHash: Data(repeating: 2, count: 20))
            return try VPNRescueAuthorization.verify(payload: bytes,
                signature: key.signature(for: VPNReleaseAuthority.rescueAuthorizationDomain + bytes),
                authority: authority, previous: release, previousPayload: previous, previousSignature: signature(previous),
                candidatePayload: next, candidateSignature: signature(next),
                transitionPayload: edge, transitionSignature: edgeSignature(edge))
        }
        let first = try token(ap, bp, ab, ar), second = try token(bp, cp, bc, br)
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
        let transactions = try VPNUpdateBrokerTransactionStore(trustedDirectoryDescriptor: broker)
        let budget = try VPNActivationBudget(trustedDirectoryDescriptor: service)
        let rotationCase = operation.hasPrefix("rotation-")
        let finalCase = !operation.hasPrefix("active-") && !operation.hasPrefix("backup-") && !rotationCase
        let bootstrap = rotationCase ? bp : (finalCase ? cp : ap)
        _ = try store.bootstrapDeployment(payload: bootstrap,
            signature: signature(bootstrap), helper: helper, engine: engine, trustedOwnerUserID: 501)
        if operation.contains("-on") { try budget.recordSuccess() } else { try budget.recordManualOff() }
        let originalBudget = try budget.snapshot()
        func populate(_ path: String, previous: Data, next: Data, edge: Data) throws {
            let root = URL(fileURLWithPath: path)
            for (name, bytes) in ["vpn-previous-release.manifest": previous, "vpn-release.manifest": next,
                "vpn-previous-release.sig": Data((try signature(previous).base64EncodedString() + "\n").utf8),
                "vpn-release.sig": Data((try signature(next).base64EncodedString() + "\n").utf8),
                "vpn-update-transition": edge,
                "vpn-update-transition.sig": Data((try edgeSignature(edge).base64EncodedString() + "\n").utf8),
                "vpn-helper": helper, "vpn-engine": engine] {
                let url = root.appendingPathComponent(name); try bytes.write(to: url)
                precondition(chmod(url.path, name == "vpn-helper" || name == "vpn-engine" ? 0o700 : 0o600) == 0)
            }
        }
        try populate(a[4], previous: ap, next: bp, edge: ab)
        try populate(a[5], previous: bp, next: cp, edge: bc)
        var journal: VPNUpdateJournalSnapshot?
        if !finalCase {
            let next = rotationCase ? cp : bp, transition = rotationCase ? bc : ab
            journal = try store.prepareUpdateJournal(payload: next, signature: signature(next), helper: helper,
                engine: engine, transitionPayload: transition, transitionSignature: edgeSignature(transition),
                expectedSequence: rotationCase ? 139 : 137)
            if operation != "active-prepared" {
                journal = try store.markUpdateReplacementPending(transactionID: journal!.transactionID, expectedRevision: 0)
            }
        }
        let inbox = try VPNUpdateBrokerInbox(trustedParent: broker)
        if operation.hasPrefix("active-") || operation.hasPrefix("backup-") || rotationCase || operation == "complete-inbox" || operation == "orphan-inbox" {
            let published = try inbox.ingest(sourceDirectory: operation == "active-foreign-inbox" || rotationCase ? cDirectory : bDirectory,
                checkpoint: { _ in })
            if operation != "orphan-inbox" {
                var transaction = try transactions.begin(identity: published.identity,
                    fromSequence: operation == "active-foreign-inbox" || rotationCase ? 139 : 137,
                    toSequence: operation == "active-foreign-inbox" || rotationCase ? 141 : 139)
                if operation != "active-accepted" {
                    let reference = VPNUpdateBrokerJournalReference(transactionID:
                        operation == "active-foreign-uuid" || operation == "rotation-invalid-ref" ? UUID() : (journal?.transactionID ?? UUID()),
                        revision: operation == "complete-inbox" ? 3 : 0,
                        phase: operation == "complete-inbox" ? .completed : .prepared)
                    transaction = try transactions.advance(identity: transaction.identity, expectedRevision: transaction.revision,
                        phase: .prepared, journal: reference, recovery: .journalRetained,
                        rotation: operation == "active-unarmed-pending" ? .notStarted : .pending)
                    if operation == "complete-inbox" {
                        _ = try transactions.advance(identity: transaction.identity, expectedRevision: transaction.revision,
                            phase: .complete, journal: reference, recovery: .complete, rotation: .complete)
                    } else if operation.hasPrefix("backup-") || rotationCase {
                        var current = try store.loadUpdateJournal()!
                        current = try store.selectUpdateCandidate(transactionID: current.transactionID, expectedRevision: 1)
                        current = try store.completeUpdateJournal(transactionID: current.transactionID, expectedRevision: 2)
                        let completed = VPNUpdateBrokerJournalReference(transactionID:
                            operation == "rotation-invalid-ref" ? transaction.journal!.transactionID : current.transactionID,
                            revision: 3, phase: .completed)
                        transaction = try transactions.advance(identity: transaction.identity, expectedRevision: transaction.revision,
                            phase: operation == "rotation-phase5" ? .handoffComplete : .rotatingBroker,
                            journal: completed, recovery: .executorCommitted,
                            rotation: operation == "rotation-phase5" ? .pending : .complete)
                        if operation == "backup-both" || operation == "backup-mismatched" {
                            try transactions.detachRescueRotation(transaction)
                            if operation == "backup-mismatched" {
                                let url = URL(fileURLWithPath: a[2]).appendingPathComponent("update.json")
                                var record = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
                                record["transactionID"] = UUID().uuidString
                                try JSONSerialization.data(withJSONObject: record, options: .sortedKeys).write(to: url)
                                precondition(chmod(url.path, 0o600) == 0)
                            } else {
                            let data = try Data(contentsOf: URL(fileURLWithPath: a[3]).appendingPathComponent(VPNUpdateBrokerTransactionStore.rescueRotationBackupName))
                            let normal = URL(fileURLWithPath: a[3]).appendingPathComponent(VPNUpdateBrokerTransactionStore.fileName)
                            try data.write(to: normal); precondition(chmod(normal.path, 0o600) == 0)
                            }
                        }
                    }
                }
            }
        }
        if operation == "orphan-preparing" {
            precondition(mkdirat(broker, ".inbox-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.preparing", 0o700) == 0)
        }
        var trace: [String] = [], ready = operation == "already-ready"
        var identityValid = true
        func makeCoordinator() throws -> VPNRescueBrokerCoordinator {
            try VPNRescueBrokerCoordinator.testCreate(service: service, broker: broker,
            authority: authority, first: first, second: second, final: cr,
            checkInputs: { if !identityValid { throw Injected.identityLost } },
            running: { _, _, _ in trace.append("probe"); if !ready { throw Injected.notRunning } },
            install: { _, _, _, beforeBootstrap in
                trace.append("install")
                // Service must already be released, while outer Broker stays held.
                let releasedService = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service); releasedService.release()
                do { let unexpected = try VPNLifecycleOwnership.acquire(inTrustedDirectory: broker); unexpected.release(); throw Injected.installFailed }
                catch VPNLifecycleOwnershipError.busy {}
                if operation == "install-failure" { throw Injected.installFailed }
                try beforeBootstrap()
                let releasedBroker = try VPNLifecycleOwnership.acquire(inTrustedDirectory: broker); releasedBroker.release()
                ready = true
            })
        }
        var coordinator = try makeCoordinator()
        func stored(_ name: String, in root: String) -> Data? {
            try? Data(contentsOf: URL(fileURLWithPath: root).appendingPathComponent(name))
        }
        let initialIndex = stored(VPNUpdateBrokerTransactionStore.fileName, in: a[3])
        let initialJournal = stored("update.json", in: a[2])
        do {
            if rotationCase {
                let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
                defer { lease.release() }
                let current = try store.loadUpdateJournal()!, before = try transactions.load()!
                let completion = try VPNUpdateBrokerRotation.testRotateIfRequired(
                    brokerDirectory: broker, store: store, lease: lease, journal: current, authority: authority,
                    installAndStart: { candidate in
                        precondition(candidate.release.isSameRelease(as: cr)); trace.append("rotate")
                    })
                let after = try transactions.load()!
                precondition(completion?.journal.transactionID == current.transactionID)
                precondition(after.phase == .rotatingBroker && after.rotation == .complete)
                if operation == "rotation-retry" { precondition(after == before) }
                else { precondition(after.revision == before.revision + 1) }
                precondition(stored("update.json", in: a[2]) == initialJournal)
                print("rotation-retried:trace=\(trace.joined(separator: ","))"); return
            }
            try coordinator.acquire()
            var lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
            defer { lease.release() }
            if operation == "lost-input" { identityValid = false }
            try coordinator.validateForRepair(serviceLease: lease)
            if operation.hasPrefix("backup-") {
                guard operation != "backup-both" else { throw Injected.installFailed }
                guard let detached = try transactions.loadRescueRotationBackup(), try transactions.load() == nil else { throw Injected.installFailed }
                let current = try store.loadUpdateJournal()!
                precondition(current.phase == .completed && current.revision == 3)
                if operation.contains("missing-inbox") { try inbox.retirePublished(identity: detached.identity) }
                if operation.contains("fresh") {
                    lease.release()
                    coordinator = try makeCoordinator()
                    try coordinator.acquire()
                    lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
                }
                try coordinator.validateForRepair(serviceLease: lease)
                try store.retireUpdateJournal(transactionID: current.transactionID, expectedRevision: 3)
                try coordinator.validateForRepair(serviceLease: lease)
                let absent = try transactions.loadRescueRotationBackup()
                let completedIndex = try transactions.load()
                let receipt = try store.loadUpdateCleanupReceipt()
                precondition(absent == nil && completedIndex?.phase == .complete)
                precondition(receipt?.transactionID == current.transactionID)
                print("backup-retired-after-service"); return
            }
            if operation.hasPrefix("active-") {
                let current = try transactions.load()!
                precondition(current.phase == (operation == "active-prepared" ? .prepared : .handoffStarted))
                let serviceJournal = try store.loadUpdateJournal()
                precondition(serviceJournal?.phase == (operation == "active-prepared" ? .prepared : .replacementPending))
                print("matching-active-bound"); return
            }
            lease.release()
            let outcome = try coordinator.reconcileFinal(deadline: DispatchTime.now().uptimeNanoseconds + 5_000_000_000)
            let finalLease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
            defer { finalLease.release() }
            try coordinator.requireFinalReady(serviceLease: finalLease,
                deadline: DispatchTime.now().uptimeNanoseconds + 5_000_000_000)
            let after = try budget.snapshot()
            precondition(after.desired == originalBudget.desired && after.failures == originalBudget.failures)
            print("\(outcome):trace=\(trace.joined(separator: ",")):desired=\(after.desired)")
        } catch {
            let after = try budget.snapshot()
            precondition(after.desired == originalBudget.desired && after.failures == originalBudget.failures)
            precondition(stored("update.json", in: a[2]) == initialJournal)
            precondition(stored(VPNUpdateBrokerTransactionStore.fileName, in: a[3]) == initialIndex)
            print("rejected:\(error):trace=\(trace.joined(separator: ","))"); exit(77)
        }
    }
}
