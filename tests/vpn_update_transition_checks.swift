import CryptoKit
import Foundation

@main
enum VPNUpdateTransitionChecks {
    static let key = Curve25519.Signing.PrivateKey()
    static let otherKey = Curve25519.Signing.PrivateKey()
    static let helper = Data("inert helper".utf8)
    static let engine = Data("inert engine".utf8)

    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    static func manifest(sequence: UInt64, version: String, protocolVersion: String = "1",
                         engineVersion: String = "2.7.7", cryptoVersion: String = "3.5.8",
                         appByte: String = "11") -> Data {
        let fields = [
            ("format", "2"), ("product", "kz.documentolog.proxypilot"), ("sequence", String(sequence)),
            ("version", version), ("protocol", protocolVersion),
            ("app-arm64", String(repeating: appByte, count: 20)),
            ("app-x86_64", String(repeating: "22", count: 20)),
            ("helper-arm64", String(repeating: "33", count: 20)),
            ("helper-x86_64", String(repeating: "44", count: 20)),
            ("helper-sha256", hex(Data(SHA256.hash(data: helper)))), ("helper-bytes", String(helper.count)),
            ("engine-version", engineVersion), ("engine-crypto-version", cryptoVersion),
            ("engine-arm64", String(repeating: "55", count: 20)),
            ("engine-x86_64", String(repeating: "66", count: 20)),
            ("engine-sha256", hex(Data(SHA256.hash(data: engine)))), ("engine-bytes", String(engine.count))
        ]
        return Data((fields.map { "\($0.0)=\($0.1)" }.joined(separator: "\n") + "\n").utf8)
    }

    static func releaseSignature(_ payload: Data, key signer: Curve25519.Signing.PrivateKey = key) throws -> Data {
        try signer.signature(for: VPNReleaseAuthority.signatureDomain + payload)
    }

    static func helperOnlyManifest(sequence: UInt64, version: String) -> Data {
        let lines = String(decoding: manifest(sequence: sequence, version: version), as: UTF8.self)
            .split(separator: "\n").prefix(11)
        return Data((lines.enumerated().map { index, line in index == 0 ? "format=1" : String(line) }
            .joined(separator: "\n") + "\n").utf8)
    }

    static func transition(from: Data, fromSequence: UInt64, to: Data, toSequence: UInt64,
                           changes: [String: String] = [:]) -> Data {
        let fields = [
            ("format", changes["format"] ?? "1"),
            ("product", changes["product"] ?? "kz.documentolog.proxypilot"),
            ("from-sequence", changes["from-sequence"] ?? String(fromSequence)),
            ("from-sha256", changes["from-sha256"] ?? hex(Data(SHA256.hash(data: from)))),
            ("to-sequence", changes["to-sequence"] ?? String(toSequence)),
            ("to-sha256", changes["to-sha256"] ?? hex(Data(SHA256.hash(data: to))))
        ]
        return Data((fields.map { "\($0.0)=\($0.1)" }.joined(separator: "\n") + "\n").utf8)
    }

    static func transitionSignature(_ payload: Data, key signer: Curve25519.Signing.PrivateKey = key) throws -> Data {
        try signer.signature(for: VPNReleaseAuthority.updateTransitionDomain + payload)
    }

    static func authority(key signer: Curve25519.Signing.PrivateKey = key, floor: UInt64 = 1) throws -> VPNReleaseAuthority {
        try VPNReleaseAuthority(trustedPublicKey: signer.publicKey.rawRepresentation,
                                minimumSequence: floor, supportedProtocol: 1)
    }

    static func rejects(_ expected: VPNReleaseAuthorizationError, _ body: () throws -> Void) {
        do { try body(); fatalError("unexpected authorization") }
        catch let error as VPNReleaseAuthorizationError {
            precondition(String(describing: error) == String(describing: expected), "unexpected error: \(error)")
        } catch { fatalError("unexpected error type: \(error)") }
    }

    static func check(_ verifier: VPNReleaseAuthority, previous: VerifiedVPNRelease,
                      edge: Data, edgeSignature: Data, candidate: Data, candidateSignature: Data) throws -> VerifiedVPNUpdateTransition {
        try verifier.verifyUpdateTransition(payload: edge, signature: edgeSignature, previous: previous,
                                             candidatePayload: candidate, candidateSignature: candidateSignature)
    }

    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        let verifier = try authority()
        let a = manifest(sequence: 10, version: "1.6.0")
        let b = manifest(sequence: 11, version: "1.7.0", appByte: "aa")
        let verifiedA = try verifier.verify(payload: a, signature: releaseSignature(a), previous: nil)
        let verifiedB = try verifier.verify(payload: b, signature: releaseSignature(b), previous: verifiedA)
        let edge = transition(from: a, fromSequence: 10, to: b, toSequence: 11)
        let edgeSignature = try transitionSignature(edge)

        switch CommandLine.arguments[1] {
        case "valid":
            let proof = try check(verifier, previous: verifiedA, edge: edge, edgeSignature: edgeSignature,
                                  candidate: b, candidateSignature: releaseSignature(b))
            precondition(proof.fromSequence == 10 && proof.toSequence == 11)
            precondition(proof.matchesSource(verifiedA) && proof.matchesDestination(verifiedB))
            precondition(!proof.matchesSource(verifiedB) && !proof.matchesDestination(verifiedA))
        case "signature":
            let wrongDomain = try key.signature(for: VPNReleaseAuthority.signatureDomain + edge)
            let raw = try key.signature(for: edge)
            let wrongKey = try transitionSignature(edge, key: otherKey)
            for bad in [Data(), Data(repeating: 0, count: 64), Data(edgeSignature.dropLast()),
                        edgeSignature + Data([0]), wrongDomain, raw, wrongKey] {
                rejects(.invalidSignature) { _ = try check(verifier, previous: verifiedA, edge: edge,
                    edgeSignature: bad, candidate: b, candidateSignature: try releaseSignature(b)) }
            }
            for bad in [Data(), Data(repeating: 97, count: VPNReleaseAuthority.maximumUpdateTransitionBytes + 1)] {
                rejects(.invalidSignature) { _ = try check(verifier, previous: verifiedA, edge: bad,
                    edgeSignature: try transitionSignature(bad), candidate: b, candidateSignature: try releaseSignature(b)) }
            }
            var tampered = edge; tampered[tampered.startIndex] ^= 1
            rejects(.invalidSignature) { _ = try check(verifier, previous: verifiedA, edge: tampered,
                edgeSignature: edgeSignature, candidate: b, candidateSignature: try releaseSignature(b)) }
        case "grammar":
            let text = String(decoding: edge, as: UTF8.self)
            var invalid = [
                Data(text.dropLast().utf8), edge + Data("extra=x\n".utf8), edge + Data([0]),
                Data(text.replacingOccurrences(of: "from-sequence=10\nfrom-sha256=",
                                               with: "from-sha256=")
                    .replacingOccurrences(of: "\nto-sequence=11",
                                          with: "\nfrom-sequence=10\nto-sequence=11").utf8),
                Data(text.replacingOccurrences(of: "to-sequence=11\n",
                                               with: "to-sequence=11\nto-sequence=11\n").utf8),
                Data(text.replacingOccurrences(of: "\n", with: "\r\n").utf8),
                Data(text.replacingOccurrences(of: "format=1", with: "format=2").utf8),
                Data(text.replacingOccurrences(of: "product=kz.documentolog.proxypilot", with: "product=other").utf8),
                Data(text.replacingOccurrences(of: "from-sequence=10", with: "from-sequence=010").utf8),
                Data(text.replacingOccurrences(of: "from-sha256=", with: "from-sha256=00").utf8),
                transition(from: a, fromSequence: 10, to: b, toSequence: 11,
                           changes: ["to-sha256": hex(Data(SHA256.hash(data: b))).uppercased()]),
                transition(from: a, fromSequence: 10, to: b, toSequence: 11,
                           changes: ["to-sequence": "011"])
            ]
            invalid.append(transition(from: a, fromSequence: 10, to: b, toSequence: 11,
                                      changes: ["to-sequence": "12"]))
            invalid.append(transition(from: a, fromSequence: 10, to: b, toSequence: 11,
                                      changes: ["from-sha256": String(repeating: "0", count: 64)]))
            for bad in invalid {
                rejects(.invalidUpdateTransition) { _ = try check(verifier, previous: verifiedA, edge: bad,
                    edgeSignature: try transitionSignature(bad), candidate: b, candidateSignature: try releaseSignature(b)) }
            }
        case "substitution":
            let x = manifest(sequence: 10, version: "1.6.0", appByte: "bb")
            let c = manifest(sequence: 12, version: "1.8.0", appByte: "cc")
            let bPrime = manifest(sequence: 11, version: "1.7.0", appByte: "dd")
            let verifiedX = try verifier.verify(payload: x, signature: releaseSignature(x), previous: nil)
            let verifiedC = try verifier.verify(payload: c, signature: releaseSignature(c), previous: verifiedA)
            rejects(.invalidUpdateTransition) { _ = try check(verifier, previous: verifiedX, edge: edge,
                edgeSignature: edgeSignature, candidate: b, candidateSignature: try releaseSignature(b)) }
            rejects(.invalidUpdateTransition) { _ = try check(verifier, previous: verifiedA, edge: edge,
                edgeSignature: edgeSignature, candidate: c, candidateSignature: try releaseSignature(c)) }
            rejects(.rollback) { _ = try check(verifier, previous: verifiedB, edge: edge,
                edgeSignature: edgeSignature, candidate: a, candidateSignature: try releaseSignature(a)) }
            // Even though B is an idempotently valid candidate relative to B,
            // the old A→B proof cannot be replayed after protected selection advances.
            rejects(.invalidUpdateTransition) { _ = try check(verifier, previous: verifiedB, edge: edge,
                edgeSignature: edgeSignature, candidate: b, candidateSignature: try releaseSignature(b)) }
            // A separately signed B' at the same destination sequence is valid
            // relative to A, but the exact A→B edge cannot authorize it.
            _ = try verifier.verify(payload: bPrime, signature: releaseSignature(bPrime), previous: verifiedA)
            rejects(.invalidUpdateTransition) { _ = try check(verifier, previous: verifiedA, edge: edge,
                edgeSignature: edgeSignature, candidate: bPrime, candidateSignature: try releaseSignature(bPrime)) }
            let edgeAC = transition(from: a, fromSequence: 10, to: c, toSequence: 12)
            let proofAC = try check(verifier, previous: verifiedA, edge: edgeAC,
                                    edgeSignature: transitionSignature(edgeAC), candidate: c,
                                    candidateSignature: releaseSignature(c))
            precondition(!proofAC.matchesDestination(verifiedB))
            precondition(verifiedC.sequence == 12)
        case "candidate":
            let candidates: [(Data, VPNReleaseAuthorizationError)] = [
                (manifest(sequence: 9, version: "1.7.0"), .rollback),
                (manifest(sequence: 11, version: "1.5.9"), .rollback),
                (manifest(sequence: 11, version: "1.7.0", protocolVersion: "2"), .incompatibleProtocol),
                (manifest(sequence: 11, version: "1.7.0", engineVersion: "2.7.6"), .rollback),
                (manifest(sequence: 11, version: "1.7.0", cryptoVersion: "3.5.7"), .rollback),
                (helperOnlyManifest(sequence: 11, version: "1.7.0"), .rollback),
                (manifest(sequence: 10, version: "1.6.1"), .conflictingRelease)
            ]
            for (candidate, error) in candidates {
                let signedEdge = transition(from: a, fromSequence: 10, to: candidate,
                                            toSequence: UInt64(String(decoding: candidate, as: UTF8.self)
                                                .split(separator: "\n")[2].split(separator: "=")[1])!)
                rejects(error) { _ = try check(verifier, previous: verifiedA, edge: signedEdge,
                    edgeSignature: try transitionSignature(signedEdge), candidate: candidate,
                    candidateSignature: try releaseSignature(candidate)) }
            }
            rejects(.invalidSignature) { _ = try check(verifier, previous: verifiedA, edge: edge,
                edgeSignature: edgeSignature, candidate: b, candidateSignature: try releaseSignature(b, key: otherKey)) }
            let retryEdge = transition(from: a, fromSequence: 10, to: a, toSequence: 10)
            rejects(.invalidUpdateTransition) { _ = try check(verifier, previous: verifiedA, edge: retryEdge,
                edgeSignature: try transitionSignature(retryEdge), candidate: a,
                candidateSignature: try releaseSignature(a)) }
        case "authority":
            let foreignAuthority = try authority(key: otherKey)
            let foreignA = try foreignAuthority.verify(payload: a, signature: releaseSignature(a, key: otherKey), previous: nil)
            rejects(.wrongAuthority) { _ = try check(verifier, previous: foreignA, edge: edge,
                edgeSignature: edgeSignature, candidate: b, candidateSignature: try releaseSignature(b)) }
            let highFloor = try authority(floor: 11)
            // Same key is the same authority identity, but its stricter local floor
            // is still applied independently to the candidate.
            _ = try check(highFloor, previous: verifiedA, edge: edge, edgeSignature: edgeSignature,
                          candidate: b, candidateSignature: releaseSignature(b))
            let belowFloor = manifest(sequence: 10, version: "1.7.0", appByte: "dd")
            let belowEdge = transition(from: a, fromSequence: 10, to: belowFloor, toSequence: 10)
            rejects(.rollback) { _ = try check(highFloor, previous: verifiedA, edge: belowEdge,
                edgeSignature: try transitionSignature(belowEdge), candidate: belowFloor,
                candidateSignature: try releaseSignature(belowFloor)) }
        default: exit(64)
        }
        print("update transition checks passed")
    }
}
