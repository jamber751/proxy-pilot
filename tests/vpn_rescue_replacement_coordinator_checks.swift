// Synthetic signed artifacts only. This fixture never starts a service.
import CryptoKit
import Darwin
import Foundation

@main enum VPNRescueReplacementCoordinatorChecks {
    enum Injected: Error { case interrupted }
    static func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    static func decode(_ value: String) -> Data {
        let bytes = Array(value.utf8)
        func nibble(_ c: UInt8) -> UInt8 { c <= 57 ? c - 48 : c - 87 }
        return Data(stride(from: 0, to: bytes.count, by: 2).map { nibble(bytes[$0]) * 16 + nibble(bytes[$0 + 1]) })
    }
    static func main() throws {
        let a = CommandLine.arguments
        guard a.count == 17 else { exit(64) }
        let operation = a[1]
        let service = open(a[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let update = open(a[3], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let source = open(a[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let candidateDirectory = open(a[5], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let rescue = open(a[6], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard min(service, update, source, candidateDirectory, rescue) >= 0 else { exit(65) }
        defer { close(service); close(update); close(source); close(candidateDirectory); close(rescue) }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
            minimumSequence: 1, supportedProtocol: 1)
        let helper = try Data(contentsOf: URL(fileURLWithPath: a[8]))
        let artifact = try Data(contentsOf: URL(fileURLWithPath: a[7]))
        func manifest(_ sequence: UInt64, _ version: String, _ arm: String, _ intel: String) -> Data {
            Data("""
            format=1
            product=kz.documentolog.proxypilot
            sequence=\(sequence)
            version=\(version)
            protocol=1
            app-arm64=\(arm)
            app-x86_64=\(intel)
            helper-arm64=\(a[15])
            helper-x86_64=\(a[16])
            helper-sha256=\(hex(Data(SHA256.hash(data: helper))))
            helper-bytes=\(helper.count)

            """.utf8)
        }
        let ap = manifest(139, "1.6.0", a[11], a[12])
        let bp = manifest(141, "1.7.0", a[13], a[14])
        func sign(_ bytes: Data) throws -> Data { try key.signature(for: VPNReleaseAuthority.signatureDomain + bytes) }
        let asig = try sign(ap), bsig = try sign(bp)
        let previous = try authority.verify(payload: ap, signature: asig, previous: nil)
        let candidate = try authority.verify(payload: bp, signature: bsig, previous: previous)
        func edge(_ payload: Data, _ sequence: UInt64) -> Data {
            Data("format=1\nproduct=kz.documentolog.proxypilot\nfrom-sequence=139\nfrom-sha256=\(hex(Data(SHA256.hash(data: ap))))\nto-sequence=\(sequence)\nto-sha256=\(hex(Data(SHA256.hash(data: payload))))\n".utf8)
        }
        let transitionPayload = edge(bp, 141)
        let transitionSignature = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + transitionPayload)
        let transition = try authority.verifyUpdateTransition(payload: transitionPayload,
            signature: transitionSignature, previous: previous, candidatePayload: bp, candidateSignature: bsig)
        let store = try VPNReleaseStore(trustedDirectoryDescriptor: service, authority: authority)
        if operation == "setup" {
            let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
            defer { lease.release() }
            _ = try store.bootstrapDeployment(payload: ap, signature: asig, helper: helper, trustedOwnerUserID: 501)
            print("setup"); return
        }
        func editJournal(_ transform: (inout [String: Any]) -> Void) throws {
            let url = URL(fileURLWithPath: a[2]).appendingPathComponent("update.json")
            var record = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
            transform(&record)
            try JSONSerialization.data(withJSONObject: record, options: .sortedKeys).write(to: url)
            precondition(chmod(url.path, 0o600) == 0)
        }
        if operation.hasPrefix("make-") {
            let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
            defer { lease.release() }
            let journal = try store.loadUpdateJournal()!
            if operation == "make-pending" {
                _ = try store.markUpdateReplacementPending(transactionID: journal.transactionID, expectedRevision: 0)
            } else if operation == "make-preparation" {
                let old = URL(fileURLWithPath: a[2]).appendingPathComponent("update.json")
                var record = try JSONSerialization.jsonObject(with: Data(contentsOf: old)) as! [String: Any]
                record.removeValue(forKey: "revision"); record["phase"] = "staging"
                let url = URL(fileURLWithPath: a[2]).appendingPathComponent("preparation.json")
                try JSONSerialization.data(withJSONObject: record, options: .sortedKeys).write(to: url)
                precondition(chmod(url.path, 0o600) == 0)
            } else if operation == "make-receipt" {
                _ = try store.markUpdateReplacementPending(transactionID: journal.transactionID, expectedRevision: 0)
                _ = try store.selectUpdateCandidate(transactionID: journal.transactionID, expectedRevision: 1)
                _ = try store.completeUpdateJournal(transactionID: journal.transactionID, expectedRevision: 2)
                try store.retireUpdateJournal(transactionID: journal.transactionID, expectedRevision: 3)
            } else if operation == "make-foreign-edge" {
                let foreign = manifest(142, "1.7.0", a[13], a[14])
                let foreignEdge = edge(foreign, 142)
                let foreignSignature = try sign(foreign)
                let foreignEdgeSignature = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + foreignEdge)
                try editJournal {
                    $0["candidatePayload"] = foreign.base64EncodedString()
                    $0["candidateSignature"] = foreignSignature.base64EncodedString()
                    $0["transitionPayload"] = foreignEdge.base64EncodedString()
                    $0["transitionSignature"] = foreignEdgeSignature.base64EncodedString()
                }
            }
            print("setup"); return
        }
        let finishPayload = try VPNRescueAuthorization.encode(previousManifest: ap, candidateManifest: bp,
            transitionPayload: transitionPayload, rescueArtifact: artifact,
            arm64CDHash: decode(a[9]), intelCDHash: decode(a[10]))
        let finish = try VPNRescueAuthorization.verify(payload: finishPayload,
            signature: key.signature(for: VPNReleaseAuthority.rescueAuthorizationDomain + finishPayload),
            authority: authority, previous: previous, previousPayload: ap, previousSignature: asig,
            candidatePayload: bp, candidateSignature: bsig,
            transitionPayload: transitionPayload, transitionSignature: transitionSignature)
        let startPayload = try VPNRescuePreparationAuthorization.encode(previousManifest: ap, candidateManifest: bp,
            transitionPayload: transitionPayload, rescueArtifact: artifact,
            arm64CDHash: decode(a[9]), intelCDHash: decode(a[10]))
        let start = try VPNRescuePreparationAuthorization.verify(payload: startPayload,
            signature: key.signature(for: VPNReleaseAuthority.rescuePreparationAuthorizationDomain + startPayload),
            authority: authority, previous: previous, previousPayload: ap, previousSignature: asig,
            candidatePayload: bp, candidateSignature: bsig,
            transitionPayload: transitionPayload, transitionSignature: transitionSignature)
        var trace: [String] = []
        do {
            let finishProof = try VPNRescueExecutor.testInspect(inTrustedDirectory: rescue, authorization: finish)
            let proof = try VPNRescuePreparationExecutor.testInspect(executor: finishProof, authorization: start,
                previous: previous, candidate: candidate, transition: transition)
            if operation == "prepare" {
                let payload = VPNJointUpdatePayload(previousManifest: ap, previousSignature: asig,
                    transitionPayload: transitionPayload, transitionSignature: transitionSignature,
                    candidate: VPNInstallationPayload(manifest: bp, signature: bsig, helper: helper, engine: nil, release: candidate),
                    previous: previous, transition: transition)
                let result = try VPNRescuePreparationCoordinator.testPrepare(service: service, update: update,
                    previousSource: source, candidateSource: candidateDirectory, payload: payload,
                    authority: authority, executor: proof)
                print("\(result.outcome):\(result.journal.revision)"); return
            }
            let leaseDirectory = operation == "foreign-lease" ? candidateDirectory : service
            let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: leaseDirectory)
            defer { lease.release() }
            if operation == "expired-lease" { lease.release() }
            let outcome = try VPNRescueReplacementCoordinator.testRun(
                service: service, update: update, destination: source, authority: authority,
                lease: lease, preparationExecutor: proof, executor: finishProof,
                armCandidateRecovery: { deployment in
                    precondition(deployment.release.isSameRelease(as: candidate))
                    trace.append("arm")
                    if operation == "arm-failure" { throw Injected.interrupted }
                }, drainPreviousService: {
                    trace.append("drain")
                    if operation == "drain-failure" { throw Injected.interrupted }
                }, checkpoint: { point in
                    if point == "afterPending" { trace.append("pending") }
                    if point == "protected:afterExchange" { trace.append("protected") }
                    if point == "afterDestinationStage" { trace.append("stage") }
                    if point == "destination:afterExchange" { trace.append("destination") }
                    if operation == "stale-after-arm", point == "afterArm" {
                        try editJournal { $0["transactionID"] = UUID().uuidString }
                    }
                    if operation == "lease-after-arm", point == "afterArm" { lease.release() }
                    if operation == "crash:" + point {
                        print("crash:\(point):trace=\(trace.joined(separator: ","))"); fflush(stdout); _exit(86)
                    }
                })
            print("\(outcome == .exchanged ? "exchanged" : "alreadyExchanged"):trace=\(trace.joined(separator: ","))")
        } catch { print("rejected:\(error):trace=\(trace.joined(separator: ","))"); exit(77) }
    }
}
