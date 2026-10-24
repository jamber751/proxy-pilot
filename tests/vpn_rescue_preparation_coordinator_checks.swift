// Synthetic signed artifacts only. This fixture never starts a service.
import CryptoKit
import Darwin
import Foundation

@main enum VPNRescuePreparationCoordinatorChecks {
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
        if operation.hasPrefix("setup") {
            let lease = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
            defer { lease.release() }
            if operation == "setup" {
                _ = try store.bootstrapDeployment(payload: ap, signature: asig, helper: helper, trustedOwnerUserID: 501)
            } else if operation == "setup-foreign" {
                let foreign = manifest(142, "1.7.0", a[13], a[14])
                let foreignEdge = edge(foreign, 142)
                _ = try store.beginUpdatePreparation(payload: foreign, signature: sign(foreign), helper: helper,
                    transitionPayload: foreignEdge,
                    transitionSignature: key.signature(for: VPNReleaseAuthority.updateTransitionDomain + foreignEdge),
                    expectedSequence: 139)
            } else {
                let journal = try store.prepareUpdateJournal(payload: bp, signature: bsig, helper: helper,
                    transitionPayload: transitionPayload, transitionSignature: transitionSignature, expectedSequence: 139)
                let pending = try store.markUpdateReplacementPending(transactionID: journal.transactionID, expectedRevision: 0)
                if operation == "setup-receipt" {
                    let selected = try store.selectUpdateCandidate(transactionID: pending.transactionID, expectedRevision: 1)
                    let completed = try store.completeUpdateJournal(transactionID: selected.transactionID, expectedRevision: 2)
                    try store.retireUpdateJournal(transactionID: completed.transactionID, expectedRevision: 3)
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
        do {
            let finishProof = try VPNRescueExecutor.testInspect(inTrustedDirectory: rescue, authorization: finish)
            let proof = try VPNRescuePreparationExecutor.testInspect(executor: finishProof, authorization: start,
                previous: previous, candidate: candidate, transition: transition)
            if operation == "interrupt:conversion" {
                VPNReleaseStore.checkpoint = { point in
                    if point == "preparation.json:after-journal" { _exit(86) }
                }
            }
            let payload = VPNJointUpdatePayload(previousManifest: ap, previousSignature: asig,
                transitionPayload: transitionPayload, transitionSignature: transitionSignature,
                candidate: VPNInstallationPayload(manifest: bp, signature: bsig, helper: helper, engine: nil, release: candidate),
                previous: previous, transition: transition)
            let result = try VPNRescuePreparationCoordinator.testPrepare(service: service, update: update,
                previousSource: source, candidateSource: candidateDirectory, payload: payload, authority: authority,
                executor: proof, checkpoint: { point in
                    if operation == "interrupt:" + point { throw Injected.interrupted }
                })
            print("\(result.outcome):\(result.journal.revision)")
        } catch { print("rejected:\(error)"); exit(77) }
    }
}
