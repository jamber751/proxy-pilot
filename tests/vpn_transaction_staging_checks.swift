import CryptoKit
import Darwin
import Foundation

@main enum VPNTransactionStagingChecks {
    enum Injected: Error { case failure }
    static let helper = Data("inert helper".utf8)

    static func releases(previousArm: String, previousIntel: String,
                         candidateArm: String, candidateIntel: String) throws
        -> (VerifiedVPNRelease, VerifiedVPNRelease, VerifiedVPNUpdateTransition) {
        let key = Curve25519.Signing.PrivateKey()
        let authority = try VPNReleaseAuthority(
            trustedPublicKey: key.publicKey.rawRepresentation,
            minimumSequence: 1, supportedProtocol: 1)

        func signedRelease(sequence: UInt64, version: String,
                           arm: String, intel: String) throws -> (Data, Data) {
            let sha = SHA256.hash(data: helper).map { String(format: "%02x", $0) }.joined()
            let payload = Data("""
            format=1
            product=kz.documentolog.proxypilot
            sequence=\(sequence)
            version=\(version)
            protocol=1
            app-arm64=\(arm)
            app-x86_64=\(intel)
            helper-arm64=\(String(repeating: "33", count: 20))
            helper-x86_64=\(String(repeating: "44", count: 20))
            helper-sha256=\(sha)
            helper-bytes=\(helper.count)

            """.utf8)
            let signature = try key.signature(
                for: VPNReleaseAuthority.signatureDomain + payload)
            return (payload, signature)
        }

        let oldRecord = try signedRelease(sequence: 10, version: "1.6.0",
                                          arm: previousArm, intel: previousIntel)
        let nextRecord = try signedRelease(sequence: 11, version: "1.7.0",
                                           arm: candidateArm, intel: candidateIntel)
        let previous = try authority.verify(payload: oldRecord.0,
                                            signature: oldRecord.1, previous: nil)
        let candidate = try authority.verify(payload: nextRecord.0,
                                             signature: nextRecord.1, previous: previous)
        func hex(_ data: Data) -> String {
            data.map { String(format: "%02x", $0) }.joined()
        }
        let edge = Data("""
        format=1
        product=kz.documentolog.proxypilot
        from-sequence=10
        from-sha256=\(hex(Data(SHA256.hash(data: oldRecord.0))))
        to-sequence=11
        to-sha256=\(hex(Data(SHA256.hash(data: nextRecord.0))))

        """.utf8)
        let edgeSignature = try key.signature(
            for: VPNReleaseAuthority.updateTransitionDomain + edge)
        let transition = try authority.verifyUpdateTransition(
            payload: edge, signature: edgeSignature, previous: previous,
            candidatePayload: nextRecord.0, candidateSignature: nextRecord.1)
        return (previous, candidate, transition)
    }

    static func main() throws {
        let arguments = CommandLine.arguments
        guard arguments.count == 9 else { exit(64) }
        let operation = arguments[1]
        let base = open(arguments[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let previousSource = open(arguments[3], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let candidateSource = open(arguments[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard base >= 0, previousSource >= 0, candidateSource >= 0 else { exit(65) }
        defer { close(base); close(previousSource); close(candidateSource) }
        let pair = try releases(previousArm: arguments[5], previousIntel: arguments[6],
                                candidateArm: arguments[7], candidateIntel: arguments[8])
        let transition = operation == "wrong-transition"
            ? try releases(previousArm: arguments[5], previousIntel: arguments[6],
                           candidateArm: arguments[7], candidateIntel: arguments[8]).2
            : pair.2
        var held: VPNLifecycleLease?
        if operation == "busy" {
            held = try VPNLifecycleOwnership.acquire(inTrustedDirectory: base)
        }
        defer { held?.release() }
        do {
            let outcome: VPNApplicationTransactionStager.Outcome
            if operation == "production" {
                outcome = try VPNApplicationTransactionStager.prepare(
                    candidateDirectory: candidateSource,
                    previousOwnerUserID: getuid(),
                    previous: pair.0, candidate: pair.1, transition: transition)
            } else {
                outcome = try VPNApplicationTransactionStager.testPrepare(
                    base: base, previousSource: previousSource,
                    candidateSource: candidateSource,
                    previous: pair.0, candidate: pair.1,
                    transition: transition) { point in
                    if operation == "throw-after-current", point == "afterPublish:current" {
                        throw Injected.failure
                    }
                    if operation == "throw-after-candidate-clone",
                       point == "afterClone:candidate" {
                        throw Injected.failure
                    }
                    if operation == "tamper-candidate-copy",
                       point == "afterClone:candidate" {
                        try Data("changed".utf8).write(to: URL(fileURLWithPath:
                            arguments[2] + "/.candidate.preparing/ProxyPilot.app/Contents/Resources/data.txt"))
                    }
                    if operation == "tamper-previous-source",
                       point == "beforePublish:current" {
                        try Data("changed".utf8).write(to: URL(fileURLWithPath:
                            arguments[3] + "/ProxyPilot.app/Contents/Resources/data.txt"))
                    }
                }
            }
            switch outcome {
            case .staged: print("staged")
            case .resumed: print("resumed")
            case .alreadyStaged: print("alreadyStaged")
            }
        } catch {
            print("rejected:\(error)")
            exit(77)
        }
    }
}
