import CryptoKit
import Darwin
import Foundation

@main enum VPNJointUpdatePreparationChecks {
    enum Injected: Error { case failure }

    static func main() throws {
        let a = CommandLine.arguments
        guard a.count == 13 else { exit(64) }
        let operation = a[1]
        let service = open(a[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let update = open(a[3], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let previousSource = open(a[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let candidateSource = open(a[5], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard service >= 0, update >= 0, previousSource >= 0, candidateSource >= 0 else {
            exit(65)
        }
        defer {
            close(service); close(update); close(previousSource); close(candidateSource)
        }
        let helper = try Data(contentsOf: URL(fileURLWithPath: a[6]))
        let key = try Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 0x42, count: 32))
        let authority = try VPNReleaseAuthority(
            trustedPublicKey: key.publicKey.rawRepresentation,
            minimumSequence: 1, supportedProtocol: 1)
        func manifest(_ sequence: UInt64, _ version: String,
                      _ arm: String, _ intel: String) -> Data {
            let sha = SHA256.hash(data: helper)
                .map { String(format: "%02x", $0) }.joined()
            return Data("""
            format=1
            product=kz.documentolog.proxypilot
            sequence=\(sequence)
            version=\(version)
            protocol=1
            app-arm64=\(arm)
            app-x86_64=\(intel)
            helper-arm64=\(a[11])
            helper-x86_64=\(a[12])
            helper-sha256=\(sha)
            helper-bytes=\(helper.count)

            """.utf8)
        }
        let previousManifest = manifest(10, "1.6.0", a[7], a[8])
        let candidateManifest = manifest(11, "1.7.0", a[9], a[10])
        let previousSignature = try key.signature(
            for: VPNReleaseAuthority.signatureDomain + previousManifest)
        let candidateSignatureURL = URL(fileURLWithPath: a[2]).appendingPathComponent("test-candidate.signature")
        let candidateSignature: Data
        if operation == "mismatch-signature" {
            candidateSignature = try key.signature(
                for: VPNReleaseAuthority.signatureDomain + candidateManifest)
        } else if let saved = try? Data(contentsOf: candidateSignatureURL) { candidateSignature = saved }
        else {
            candidateSignature = try key.signature(
                for: VPNReleaseAuthority.signatureDomain + candidateManifest)
            try candidateSignature.write(to: candidateSignatureURL, options: .atomic)
        }
        let previous = try authority.verify(
            payload: previousManifest, signature: previousSignature, previous: nil)
        let candidate = try authority.verify(
            payload: candidateManifest, signature: candidateSignature, previous: previous)
        func hex(_ value: Data) -> String {
            SHA256.hash(data: value).map { String(format: "%02x", $0) }.joined()
        }
        let edge = Data("format=1\nproduct=kz.documentolog.proxypilot\n"
            .appending("from-sequence=10\nfrom-sha256=\(hex(previousManifest))\n")
            .appending("to-sequence=11\nto-sha256=\(hex(candidateManifest))\n").utf8)
        let edgeSignatureURL = URL(fileURLWithPath: a[2]).appendingPathComponent("test-transition.signature")
        let edgeSignature: Data
        if let saved = try? Data(contentsOf: edgeSignatureURL) { edgeSignature = saved }
        else {
            edgeSignature = try key.signature(
                for: VPNReleaseAuthority.updateTransitionDomain + edge)
            try edgeSignature.write(to: edgeSignatureURL, options: .atomic)
        }
        let transition = try authority.verifyUpdateTransition(
            payload: edge, signature: edgeSignature, previous: previous,
            candidatePayload: candidateManifest,
            candidateSignature: candidateSignature)
        let candidatePayload = VPNInstallationPayload(
            manifest: candidateManifest, signature: candidateSignature,
            helper: helper, engine: nil, release: candidate)
        let joint = VPNJointUpdatePayload(
            previousManifest: previousManifest,
            previousSignature: previousSignature,
            transitionPayload: edge,
            transitionSignature: edgeSignature,
            candidate: candidatePayload, previous: previous,
            transition: transition)
        let store = try VPNReleaseStore(
            trustedDirectoryDescriptor: service, authority: authority)
        var marker = stat()
        if fstatat(service, "initialized", &marker, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { exit(65) }
            _ = try store.bootstrapDeployment(
                payload: previousManifest, signature: previousSignature,
                helper: helper, trustedOwnerUserID: geteuid())
        }
        var held: VPNLifecycleLease?
        if operation == "busy" {
            held = try VPNLifecycleOwnership.acquire(inTrustedDirectory: service)
        }
        defer { held?.release() }
        do {
            if operation == "crash-during-conversion" {
                VPNReleaseStore.checkpoint = { point in
                    if point == "preparation.json:after-journal" { _exit(86) }
                }
            }
            let result: VPNJointUpdatePreparation.Result
            if operation == "production" {
                result = try VPNJointUpdatePreparation.prepare(
                    candidateDirectory: candidateSource,
                    payload: joint, authority: authority)
            } else {
                result = try VPNJointUpdatePreparation.testPrepare(
                    service: service, update: update,
                    previousSource: previousSource,
                    candidateSource: candidateSource,
                    payload: joint, authority: authority) { point in
                    if operation == "throw-after-preparation",
                       point == "afterPreparation" { throw Injected.failure }
                    if operation == "throw-after-staging",
                       point == "afterApplicationStaging" { throw Injected.failure }
                    if operation == "throw-after-journal",
                       point == "afterJournal" { throw Injected.failure }
                }
            }
            let outcome: String
            if operation == "mark-pending" {
                let pending = try store.markUpdateReplacementPending(
                    transactionID: result.journal.transactionID,
                    expectedRevision: result.journal.revision)
                print("pending:\(pending.revision)")
                return
            }
            if operation == "swap-pending-and-retry" {
                let pending = try store.markUpdateReplacementPending(
                    transactionID: result.journal.transactionID,
                    expectedRevision: result.journal.revision)
                _ = try VPNProtectedApplicationSwap.testExchange(
                    inTrustedDirectory: update, previous: previous,
                    candidate: candidate, transition: transition)
                let retried = try VPNJointUpdatePreparation.testPrepare(
                    service: service, update: update,
                    previousSource: previousSource,
                    candidateSource: candidateSource,
                    payload: joint, authority: authority)
                print("postSwap:\(retried.journal.revision):\(pending.revision)")
                return
            }
            switch result.outcome {
            case .prepared: outcome = "prepared"
            case .resumed: outcome = "resumed"
            case .alreadyPrepared: outcome = "alreadyPrepared"
            }
            print("\(outcome):\(result.journal.revision)")
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
