import CryptoKit
import Foundation

/// Static fixture semantics only. Never launches an artifact or accesses a keychain.
@main enum VPNRescueSystemMaterialsChecks {
    static func main() throws {
        let args = CommandLine.arguments
        guard args.count == 3 else { exit(64) }
        let root = URL(fileURLWithPath: args[2], isDirectory: true)
        let candidate = root.appendingPathComponent("CandidateStage/Payload")
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                               minimumSequence: 1, supportedProtocol: 1)
        func read(_ base: URL, _ name: String) throws -> Data {
            try Data(contentsOf: base.appendingPathComponent(name))
        }
        func signature(_ base: URL, _ name: String) throws -> Data {
            let text = try String(contentsOf: base.appendingPathComponent(name), encoding: .utf8)
            guard let value = Data(base64Encoded: text.trimmingCharacters(in: .newlines)) else { exit(65) }
            return value
        }
        let aBytes = try read(root, "source-release.manifest")
        let bBytes = try read(candidate, "vpn-previous-release.manifest")
        let cBytes = try read(candidate, "vpn-release.manifest")
        let a = try authority.verify(payload: aBytes, signature: signature(root, "source-release.sig"), previous: nil)
        let b = try authority.verify(payload: bBytes, signature: signature(candidate, "vpn-previous-release.sig"), previous: a)
        let c = try authority.verify(payload: cBytes, signature: signature(candidate, "vpn-release.sig"), previous: b)
        guard a.engine != nil, b.engine != nil, c.engine != nil else { exit(77) }
        _ = try authority.verifyUpdateTransition(payload: read(root, "first-transition"),
            signature: signature(root, "first-transition.sig"), previous: a,
            candidatePayload: bBytes, candidateSignature: signature(candidate, "vpn-previous-release.sig"))
        _ = try authority.verifyUpdateTransition(payload: read(candidate, "vpn-update-transition"),
            signature: signature(candidate, "vpn-update-transition.sig"), previous: b,
            candidatePayload: cBytes, candidateSignature: signature(candidate, "vpn-release.sig"))

        switch args[1] {
        case "valid": break
        case "remove-engine", "rollback-crypto":
            var text = String(decoding: cBytes, as: UTF8.self)
            if args[1] == "remove-engine" {
                text = text.split(separator: "\n").filter { !$0.hasPrefix("engine-") }
                    .joined(separator: "\n").replacingOccurrences(of: "format=2\n", with: "format=1\n") + "\n"
            } else {
                text = text.replacingOccurrences(of: "engine-crypto-version=3.5.8\n", with: "engine-crypto-version=3.5.7\n")
            }
            let changed = Data(text.utf8)
            let signed = try key.signature(for: VPNReleaseAuthority.signatureDomain + changed)
            do {
                _ = try authority.verify(payload: changed, signature: signed, previous: b)
                exit(77)
            } catch VPNReleaseAuthorizationError.rollback { }
        case "wrong-first-binding":
            let old = try read(root, "first-transition")
            let text = String(decoding: old, as: UTF8.self)
                .replacingOccurrences(of: "from-sequence=\(a.sequence)\n", with: "from-sequence=999\n")
            let changed = Data(text.utf8)
            do {
                _ = try authority.verifyUpdateTransition(payload: changed,
                    signature: key.signature(for: VPNReleaseAuthority.updateTransitionDomain + changed), previous: a,
                    candidatePayload: bBytes, candidateSignature: signature(candidate, "vpn-previous-release.sig"))
                exit(77)
            } catch VPNReleaseAuthorizationError.invalidUpdateTransition { }
        default: exit(64)
        }
        print("Static production material verification passed")
    }
}
