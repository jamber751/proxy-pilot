import CryptoKit
import Darwin
import Foundation

/// Synthetic key only. This fixture never invokes storedKey, store, or Keychain.
@main enum VPNRescueReleaseKeyChecks {
    static func main() throws {
        let a = CommandLine.arguments
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        if a[1] == "fixture" {
            let root = URL(fileURLWithPath: a[2])
            func put(_ name: String, _ data: Data) throws {
                try data.write(to: root.appendingPathComponent(name))
            }
            func sign(_ name: String, _ domain: Data, _ payload: Data) throws {
                try put(name, Data((try key.signature(for: domain + payload).base64EncodedString() + "\n").utf8))
            }
            let ap = try Data(contentsOf: root.appendingPathComponent("previous"))
            let bp = try Data(contentsOf: root.appendingPathComponent("candidate"))
            let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                minimumSequence: 1, supportedProtocol: 1)
            let av = try authority.verify(payload: ap,
                signature: key.signature(for: VPNReleaseAuthority.signatureDomain + ap), previous: nil)
            let bv = try authority.verify(payload: bp,
                signature: key.signature(for: VPNReleaseAuthority.signatureDomain + bp), previous: av)
            let edge = VPNReleaseKeyTool.canonicalTransition(previousPayload: ap, previous: av,
                candidatePayload: bp, candidate: bv)
            let artifact = Data("synthetic rescue artifact".utf8)
            let payload = try VPNRescueAuthorization.encode(previousManifest: ap, candidateManifest: bp,
                transitionPayload: edge, rescueArtifact: artifact,
                arm64CDHash: Data(repeating: 1, count: 20), intelCDHash: Data(repeating: 2, count: 20))
            try put("transition", edge); try put("artifact", artifact); try put("description", payload)
            let preparation = try VPNRescuePreparationAuthorization.encode(previousManifest: ap,
                candidateManifest: bp, transitionPayload: edge, rescueArtifact: artifact,
                arm64CDHash: Data(repeating: 1, count: 20), intelCDHash: Data(repeating: 2, count: 20))
            try put("preparation-description", preparation)
            try put("public", Data((key.publicKey.rawRepresentation.base64EncodedString() + "\n").utf8))
            try sign("previous.sig", VPNReleaseAuthority.signatureDomain, ap)
            try sign("candidate.sig", VPNReleaseAuthority.signatureDomain, bp)
            try sign("transition.sig", VPNReleaseAuthority.updateTransitionDomain, edge)
        } else if a[1] == "raw-sign" {
            let payload = try Data(contentsOf: URL(fileURLWithPath: a[2]))
            let domain = a[4] == "release" ? VPNReleaseAuthority.signatureDomain
                : a[4] == "preparation" ? VPNReleaseAuthority.rescuePreparationAuthorizationDomain
                : VPNReleaseAuthority.rescueAuthorizationDomain
            let signature = try key.signature(for: domain + payload)
            try Data((signature.base64EncodedString() + "\n").utf8).write(to: URL(fileURLWithPath: a[3]))
        } else {
            do {
                guard a.count == 11, let inputs = VPNReleaseKeyTool.rescueInputs(a) else {
                    throw VPNRescueAuthorizationError.invalidAuthorization
                }
                let signed = try a[1] == "sign-preparation"
                    ? VPNReleaseKeyTool.validatedRescuePreparationSignature(inputs, key: key)
                    : VPNReleaseKeyTool.validatedRescueSignature(inputs, key: key)
                VPNReleaseKeyTool.write(signed.base64EncodedString() + "\n", to: a[10])
                print("signed synthetic rescue")
            } catch { print("rejected"); exit(77) }
        }
    }
}
