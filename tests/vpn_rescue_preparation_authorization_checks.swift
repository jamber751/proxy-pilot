import CryptoKit
import Foundation

@main enum VPNRescuePreparationAuthorizationChecks {
    static func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined() }
    static func reject(_ operation: () throws -> Void) {
        do { try operation(); fatalError("unexpected authorization") } catch { }
    }
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { fatalError("group required") }
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x42, count: 32))
        let otherKey = try Curve25519.Signing.PrivateKey(rawRepresentation: Data(repeating: 0x43, count: 32))
        let authority = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                minimumSequence: 1, supportedProtocol: 1)
        let foreign = try VPNReleaseAuthority(trustedPublicKey: otherKey.publicKey.rawRepresentation,
                                              minimumSequence: 1, supportedProtocol: 1)
        let helper = Data("helper fixture".utf8), artifact = Data("rescue fixture".utf8)
        let arm = Data(repeating: 0xab, count: 20), intel = Data(repeating: 0xcd, count: 20)
        func release(_ sequence: UInt64, _ version: String = "1.6.0") -> Data {
            Data("""
            format=1
            product=kz.documentolog.proxypilot
            sequence=\(sequence)
            version=\(version)
            protocol=1
            app-arm64=\(String(repeating: "11", count: 20))
            app-x86_64=\(String(repeating: "22", count: 20))
            helper-arm64=\(String(repeating: "33", count: 20))
            helper-x86_64=\(String(repeating: "44", count: 20))
            helper-sha256=\(hex(Data(SHA256.hash(data: helper))))
            helper-bytes=\(helper.count)

            """.utf8)
        }
        func signedRelease(_ payload: Data) throws -> Data {
            try key.signature(for: VPNReleaseAuthority.signatureDomain + payload)
        }
        func edge(_ previous: Data, _ next: Data, _ to: UInt64 = 141) -> Data {
            Data("format=1\nproduct=kz.documentolog.proxypilot\nfrom-sequence=139\nfrom-sha256=\(hex(Data(SHA256.hash(data: previous))))\nto-sequence=\(to)\nto-sha256=\(hex(Data(SHA256.hash(data: next))))\n".utf8)
        }
        let a = release(139), b = release(141), transition = edge(release(139), release(141))
        let aSignature = try signedRelease(a), bSignature = try signedRelease(b)
        let transitionSignature = try key.signature(for: VPNReleaseAuthority.updateTransitionDomain + transition)
        let previous = try authority.verify(payload: a, signature: aSignature, previous: nil)
        let candidate = try authority.verify(payload: b, signature: bSignature, previous: previous)
        let verifiedTransition = try authority.verifyUpdateTransition(payload: transition,
            signature: transitionSignature, previous: previous, candidatePayload: b, candidateSignature: bSignature)
        let payload = try VPNRescuePreparationAuthorization.encode(previousManifest: a, candidateManifest: b,
            transitionPayload: transition, rescueArtifact: artifact, arm64CDHash: arm, intelCDHash: intel)
        func sign(_ bytes: Data) throws -> Data {
            try key.signature(for: VPNReleaseAuthority.rescuePreparationAuthorizationDomain + bytes)
        }
        let signature = try sign(payload)
        func verify(_ bytes: Data, signature suppliedSignature: Data? = nil,
                    using suppliedAuthority: VPNReleaseAuthority? = nil,
                    source: VerifiedVPNRelease? = nil,
                    previousBytes: Data? = nil, previousSig: Data? = nil,
                    candidateBytes: Data? = nil, candidateSig: Data? = nil,
                    edgeBytes: Data? = nil, edgeSig: Data? = nil) throws -> VerifiedVPNRescuePreparationAuthorization {
            try VPNRescuePreparationAuthorization.verify(payload: bytes, signature: suppliedSignature ?? sign(bytes),
                authority: suppliedAuthority ?? authority, previous: source ?? previous,
                previousPayload: previousBytes ?? a, previousSignature: previousSig ?? aSignature,
                candidatePayload: candidateBytes ?? b, candidateSignature: candidateSig ?? bSignature,
                transitionPayload: edgeBytes ?? transition, transitionSignature: edgeSig ?? transitionSignature)
        }
        let text = String(decoding: payload, as: UTF8.self)
        func field(_ key: String, _ value: String) -> Data {
            Data(text.components(separatedBy: "\n").map {
                $0.hasPrefix(key + "=") ? key + "=" + value : $0
            }.joined(separator: "\n").utf8)
        }
        switch CommandLine.arguments[1] {
        case "valid":
            let token = try verify(payload)
            precondition(token.fromSequence == 139 && token.toSequence == 141)
            precondition(token.matchesSource(previous) && token.matchesDestination(candidate))
            precondition(token.matchesTransition(verifiedTransition))
            precondition(!token.matchesSource(candidate) && !token.matchesDestination(previous))
            precondition(token.hash(forArchitecture: "arm64") == arm)
            precondition(token.hash(forArchitecture: "x86_64") == intel)
            precondition(token.hash(forArchitecture: "unknown") == nil)
            precondition(token.artifactByteCount == artifact.count)
            try token.validateArtifact(artifact)
            let encodedAgain = try VPNRescuePreparationAuthorization.encode(previousManifest: a,
                candidateManifest: b, transitionPayload: transition, rescueArtifact: artifact,
                arm64CDHash: arm, intelCDHash: intel)
            precondition(payload == encodedAgain)
        case "signatures":
            reject { _ = try verify(payload, signature: Data()) }
            reject { _ = try verify(payload, signature: Data(repeating: 0, count: 64)) }
            reject { _ = try verify(payload, signature: signature + Data([0])) }
            reject { _ = try verify(payload, signature: otherKey.signature(for: VPNReleaseAuthority.rescuePreparationAuthorizationDomain + payload)) }
            reject { _ = try verify(payload + Data([32]), signature: signature) }
        case "domain":
            for domain in [VPNReleaseAuthority.signatureDomain, VPNReleaseAuthority.updateTransitionDomain, Data()] {
                reject { _ = try verify(payload, signature: key.signature(for: domain + payload)) }
            }
            reject { _ = try authority.verify(payload: payload, signature: signature, previous: nil) }
            precondition(!authority.verifyRescuePreparationSignature(payload: a, signature: aSignature))
            precondition(!authority.verifyRescuePreparationSignature(payload: transition, signature: transitionSignature))
        case "roles":
            let finish = try VPNRescueAuthorization.encode(previousManifest: a,
                candidateManifest: b, transitionPayload: transition, rescueArtifact: artifact,
                arm64CDHash: arm, intelCDHash: intel)
            let finishSignature = try key.signature(for: VPNReleaseAuthority.rescueAuthorizationDomain + finish)
            reject { _ = try verify(finish, signature: finishSignature) }
            reject { _ = try verify(finish) }
            reject { _ = try verify(payload, signature: key.signature(for: VPNReleaseAuthority.rescueAuthorizationDomain + payload)) }
            func verifyFinish(_ bytes: Data, _ sig: Data) throws {
                _ = try VPNRescueAuthorization.verify(payload: bytes, signature: sig,
                    authority: authority, previous: previous, previousPayload: a, previousSignature: aSignature,
                    candidatePayload: b, candidateSignature: bSignature,
                    transitionPayload: transition, transitionSignature: transitionSignature)
            }
            try verifyFinish(finish, finishSignature)
            reject { try verifyFinish(payload, signature) }
            reject { try verifyFinish(payload, key.signature(for: VPNReleaseAuthority.rescueAuthorizationDomain + payload)) }
            reject { try verifyFinish(finish, key.signature(for: VPNReleaseAuthority.rescuePreparationAuthorizationDomain + finish)) }
            precondition(!authority.verifyRescueSignature(payload: payload, signature: signature))
            precondition(!authority.verifyRescuePreparationSignature(payload: finish, signature: finishSignature))
        case "grammar":
            var lines = text.components(separatedBy: "\n"); lines.swapAt(3, 4)
            let malformed = [Data(text.replacingOccurrences(of: "\n", with: "\r\n").utf8),
                Data(payload.dropLast()), payload + Data([10]), Data((" " + text).utf8),
                Data(lines.joined(separator: "\n").utf8), payload + Data("operation=x\n".utf8),
                Data([0xff]), field("product", "other"), field("format", "01"),
                field("operation", "prepare-root-owned-update"),
                field("operation", "prepare-root-owned-update-and-cleanup "),
                field("operation", "*"), field("rescue-bytes", "13\0")]
            for bytes in malformed { reject { _ = try verify(bytes) } }
        case "fields":
            for value in ["", "0", "-1", "+1", "01", "1.0", " 1", "1 ", "１", "9223372036854775808", "33554433"] {
                reject { _ = try verify(field("rescue-bytes", value)) }
            }
            for name in ["previous-manifest-sha256", "candidate-manifest-sha256", "transition-sha256", "rescue-sha256"] {
                for value in ["*", String(repeating: "A", count: 64), String(repeating: "a", count: 63), String(repeating: "z", count: 64)] {
                    reject { _ = try verify(field(name, value)) }
                }
            }
            for name in ["rescue-arm64", "rescue-x86_64"] {
                for value in ["", "*", String(repeating: "A", count: 40), String(repeating: "a", count: 39)] {
                    reject { _ = try verify(field(name, value)) }
                }
            }
        case "edges":
            reject { _ = try verify(payload, previousBytes: b, previousSig: bSignature,
                candidateBytes: a, candidateSig: aSignature) }
            reject { _ = try verify(payload, previousSig: bSignature, candidateSig: aSignature) }
            for name in ["previous-manifest-sha256", "candidate-manifest-sha256", "transition-sha256"] {
                reject { _ = try verify(field(name, String(repeating: "0", count: 64))) }
            }
            let c = release(142), nextEdge = edge(a, release(142), 142)
            reject { _ = try verify(payload, candidateBytes: c, candidateSig: signedRelease(c),
                edgeBytes: nextEdge, edgeSig: key.signature(for: VPNReleaseAuthority.updateTransitionDomain + nextEdge)) }
            let changedA = release(139, "1.6.1")
            reject { _ = try verify(payload, previousBytes: changedA, previousSig: signedRelease(changedA)) }
            reject { _ = try verify(payload, edgeSig: Data(repeating: 0, count: 64)) }
            reject { _ = try verify(payload, candidateSig: Data(repeating: 0, count: 64)) }
            reject { _ = try verify(payload, previousSig: Data(repeating: 0, count: 64)) }
            let cVerified = try authority.verify(payload: c, signature: signedRelease(c), previous: previous)
            let cEdge = try authority.verifyUpdateTransition(payload: nextEdge,
                signature: key.signature(for: VPNReleaseAuthority.updateTransitionDomain + nextEdge),
                previous: previous, candidatePayload: c, candidateSignature: signedRelease(c))
            let token = try verify(payload)
            precondition(!token.matchesDestination(cVerified) && !token.matchesTransition(cEdge))
        case "limits":
            reject { _ = try verify(Data()) }
            reject { _ = try verify(Data(repeating: 65, count: VPNReleaseAuthority.maximumRescuePreparationAuthorizationBytes + 1)) }
            let boundary = try verify(field("rescue-bytes", String(VPNRescuePreparationAuthorization.maximumArtifactBytes)))
            precondition(boundary.artifactByteCount == VPNRescuePreparationAuthorization.maximumArtifactBytes)
        case "artifact":
            let token = try verify(payload)
            reject { try token.validateArtifact(Data()) }
            reject { try token.validateArtifact(artifact + Data([0])) }
            reject { try token.validateArtifact(Data(repeating: 0, count: artifact.count)) }
            let modified = try verify(field("rescue-sha256", String(repeating: "0", count: 64)))
            reject { try modified.validateArtifact(artifact) }
        case "authority":
            reject { _ = try verify(payload, using: foreign) }
            let otherSource = try foreign.verify(payload: a,
                signature: otherKey.signature(for: VPNReleaseAuthority.signatureDomain + a), previous: nil)
            reject { _ = try verify(payload, source: otherSource) }
            let token = try verify(payload)
            precondition(!token.matchesSource(otherSource))
            let floor = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                minimumSequence: 140, supportedProtocol: 1)
            reject { _ = try verify(payload, using: floor) }
        case "encoder":
            for hash in [Data(), Data(repeating: 0, count: 19), Data(repeating: 0, count: 21)] {
                reject { _ = try VPNRescuePreparationAuthorization.encode(previousManifest: a, candidateManifest: b,
                    transitionPayload: transition, rescueArtifact: artifact, arm64CDHash: hash, intelCDHash: intel) }
            }
            reject { _ = try VPNRescuePreparationAuthorization.encode(previousManifest: Data(), candidateManifest: b,
                transitionPayload: transition, rescueArtifact: artifact, arm64CDHash: arm, intelCDHash: intel) }
            reject { _ = try VPNRescuePreparationAuthorization.encode(previousManifest: a, candidateManifest: b,
                transitionPayload: transition, rescueArtifact: Data(), arm64CDHash: arm, intelCDHash: intel) }
            reject { _ = try VPNRescuePreparationAuthorization.encode(previousManifest: a, candidateManifest: b,
                transitionPayload: Data(repeating: 0, count: 513), rescueArtifact: artifact,
                arm64CDHash: arm, intelCDHash: intel) }
        default: fatalError("unknown group")
        }
        print("rescue authorization checks passed")
    }
}
