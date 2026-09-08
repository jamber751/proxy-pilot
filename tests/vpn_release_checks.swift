import CryptoKit
import Foundation

// Keys exist only in this process. Never accesses the production signing key,
// real VPN profile, installer, Keychain, launchd or network.
@main
enum VPNReleaseChecks {
    static let key = Curve25519.Signing.PrivateKey()
    static let otherKey = Curve25519.Signing.PrivateKey()
    static let helper = Data("inert synthetic helper bytes; never executed".utf8)
    static let engine = Data("inert synthetic engine bytes; never executed".utf8)

    static func fixture(_ changes: [String: String] = [:]) -> Data {
        var fields = [
            ("format", "1"), ("product", "kz.documentolog.proxypilot"), ("sequence", "10"),
            ("version", "1.6.0"), ("protocol", "1"),
            ("app-arm64", String(repeating: "11", count: 20)),
            ("app-x86_64", String(repeating: "22", count: 20)),
            ("helper-arm64", String(repeating: "33", count: 20)),
            ("helper-x86_64", String(repeating: "44", count: 20)),
            ("helper-sha256", SHA256.hash(data: helper).map { String(format: "%02x", $0) }.joined()),
            ("helper-bytes", String(helper.count))
        ]
        if changes["format"] == "2" {
            fields += [("engine-version", "2.7.7"), ("engine-crypto-version", "3.5.8"),
                       ("engine-arm64", String(repeating: "55", count: 20)),
                       ("engine-x86_64", String(repeating: "66", count: 20)),
                       ("engine-sha256", SHA256.hash(data: engine).map { String(format: "%02x", $0) }.joined()),
                       ("engine-bytes", String(engine.count))]
        }
        fields = fields.map { ($0.0, changes[$0.0] ?? $0.1) }
        return Data((fields.map { "\($0.0)=\($0.1)" }.joined(separator: "\n") + "\n").utf8)
    }

    static func signature(_ data: Data, using signer: Curve25519.Signing.PrivateKey = key) throws -> Data {
        try signer.signature(for: VPNReleaseAuthority.signatureDomain + data)
    }

    static func authority(floor: UInt64 = 1) throws -> VPNReleaseAuthority {
        try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                minimumSequence: floor, supportedProtocol: 1)
    }

    static func verified(_ changes: [String: String] = [:], previous: VerifiedVPNRelease? = nil) throws -> VerifiedVPNRelease {
        let payload = fixture(changes)
        return try authority().verify(payload: payload, signature: signature(payload), previous: previous)
    }

    static func engineAuthority() throws -> VPNReleaseAuthority {
        try VPNReleaseAuthority.engineCandidateAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                        minimumSequence: 1)
    }

    static func engineVerified(_ changes: [String: String] = [:], previous: VerifiedVPNRelease? = nil) throws -> VerifiedVPNRelease {
        let payload = fixture(changes.merging(["format": "2"]) { value, _ in value })
        return try engineAuthority().verify(payload: payload, signature: signature(payload), previous: previous)
    }

    static func rejects(_ expected: VPNReleaseAuthorizationError, _ body: () throws -> Void) {
        do {
            try body()
            fatalError("unexpected authorization")
        } catch let error as VPNReleaseAuthorizationError {
            precondition(String(describing: error) == String(describing: expected), "unexpected error: \(error)")
        } catch { fatalError("unexpected error type") }
    }

    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        let payload = fixture()
        let signed = try signature(payload)
        let verifier = try authority()
        switch CommandLine.arguments[1] {
        case "valid":
            let release = try verifier.verify(payload: payload, signature: signed, previous: nil)
            precondition(release.version == "1.6.0" && release.sequence == 10 && release.protocolVersion == 1)
            precondition(release.engine == nil)
            try release.validateHelperArtifact(helper)
            _ = try release.clientPolicy(forTrustedUserID: 501)
            do {
                _ = try release.clientPolicy(forTrustedUserID: 0)
                fatalError("root client policy was accepted")
            } catch VPNPeerAuthenticationError.invalidPolicy {}
        case "signatures":
            for invalid in [Data(), Data(repeating: 0, count: 64), signed.dropLast(), signed + Data([0])] {
                rejects(.invalidSignature) { _ = try verifier.verify(payload: payload, signature: Data(invalid), previous: nil) }
            }
            let wrong = try signature(payload, using: otherKey)
            rejects(.invalidSignature) { _ = try verifier.verify(payload: payload, signature: wrong, previous: nil) }
            rejects(.invalidSignature) { _ = try verifier.verify(payload: fixture(["sequence": "11"]), signature: signed, previous: nil) }
        case "domain":
            let signatures = [try key.signature(for: payload),
                              try key.signature(for: Data("another-domain\0".utf8) + payload)]
            for wrong in signatures {
                rejects(.invalidSignature) { _ = try verifier.verify(payload: payload, signature: wrong, previous: nil) }
            }
        case "grammar":
            let text = String(decoding: payload, as: UTF8.self)
            let invalid = [
                payload + Data("sequence=11\n".utf8), // duplicate/extra fields
                Data(text.replacingOccurrences(of: "sequence=10\n", with: "").utf8),
                Data(text.replacingOccurrences(of: "sequence=10", with: "unknown=10").utf8),
                Data(text.replacingOccurrences(of: "\n", with: "\r\n").utf8),
                Data(text.dropLast().utf8), payload + Data([0]), Data([0xff]),
                Data(text.replacingOccurrences(of: "format=1\nproduct=kz.documentolog.proxypilot",
                                              with: "product=kz.documentolog.proxypilot\nformat=1").utf8)
            ]
            for bad in invalid {
                let signature = try signature(bad)
                rejects(.invalidManifest) { _ = try verifier.verify(payload: bad, signature: signature, previous: nil) }
            }
        case "fields":
            let invalid = [
                ["format": "3"], ["product": "other.app"], ["sequence": "0"], ["sequence": "01"],
                ["sequence": "-1"], ["sequence": "+10"], ["sequence": "1e1"], ["sequence": " 10"],
                ["sequence": "9223372036854775808"], ["sequence": String(repeating: "9", count: 100)],
                ["version": "1.6"], ["version": "1.06.0"], ["version": "1.6.0-beta"],
                ["version": "1.6.0/../../test"], ["protocol": "01"],
                ["app-arm64": String(repeating: "a", count: 39)],
                ["app-x86_64": String(repeating: "AA", count: 20)],
                ["helper-arm64": String(repeating: "g", count: 40)],
                ["helper-x86_64": ""], ["helper-sha256": "abc"],
                ["helper-bytes": "0"], ["helper-bytes": "33554433"], ["helper-bytes": "1.0"]
            ]
            for fields in invalid {
                let bad = fixture(fields)
                let signature = try signature(bad)
                rejects(.invalidManifest) { _ = try verifier.verify(payload: bad, signature: signature, previous: nil) }
            }
        case "limits":
            for bad in [Data(), Data(repeating: 97, count: VPNReleaseAuthority.maximumPayloadBytes + 1)] {
                let signature = try signature(bad)
                rejects(.invalidSignature) { _ = try verifier.verify(payload: bad, signature: signature, previous: nil) }
            }
        case "protocol":
            for version in ["0", "2"] {
                let bad = fixture(["protocol": version])
                let signature = try signature(bad)
                rejects(.incompatibleProtocol) { _ = try verifier.verify(payload: bad, signature: signature, previous: nil) }
            }
        case "floor":
            let newerAuthority = try authority(floor: 11)
            rejects(.rollback) { _ = try newerAuthority.verify(payload: payload, signature: signed, previous: nil) }
        case "transitions":
            let old = try verified()
            let retry = try verified(previous: old)
            precondition(retry.sequence == old.sequence)
            let next = try verified(["sequence": "11", "version": "1.7.0"], previous: old)
            rejects(.rollback) { _ = try verified(previous: next) }
            rejects(.rollback) { _ = try verified(["sequence": "12", "version": "1.5.99"], previous: next) }
            let numeric = try verified(["sequence": "12", "version": "1.10.0"], previous: next)
            rejects(.rollback) { _ = try verified(["sequence": "13", "version": "1.9.99"], previous: numeric) }
            // A signed helper rebuild can retain the marketing version while
            // increasing the monotonic release sequence.
            _ = try verified(["sequence": "13", "version": "1.10.0"], previous: numeric)
        case "conflict":
            let old = try verified()
            for field in ["app-arm64", "app-x86_64", "helper-arm64", "helper-x86_64"] {
                rejects(.conflictingRelease) {
                    _ = try verified([field: String(repeating: "ab", count: 20)], previous: old)
                }
            }
            rejects(.conflictingRelease) { _ = try verified(["version": "1.6.1"], previous: old) }
        case "authority":
            let foreign = try VPNReleaseAuthority(trustedPublicKey: otherKey.publicKey.rawRepresentation,
                                                 minimumSequence: 1, supportedProtocol: 1)
            let foreignRelease = try foreign.verify(payload: payload, signature: signature(payload, using: otherKey), previous: nil)
            rejects(.wrongAuthority) { _ = try verifier.verify(payload: payload, signature: signed, previous: foreignRelease) }
        case "artifact":
            let release = try verified()
            var changed = helper
            changed[0] ^= 1
            for bad in [Data(), helper.dropLast(), helper + Data([0]), changed] {
                rejects(.invalidHelperArtifact) { try release.validateHelperArtifact(Data(bad)) }
            }
            try release.validateHelperArtifact(helper)
        case "trust":
            for bytes in [0, 31, 33] {
                rejects(.invalidTrustConfiguration) {
                    _ = try VPNReleaseAuthority(trustedPublicKey: Data(repeating: 0, count: bytes),
                                                minimumSequence: 1, supportedProtocol: 1)
                }
            }
            for floor in [UInt64(0), UInt64.max] {
                rejects(.invalidTrustConfiguration) { _ = try authority(floor: floor) }
            }
            rejects(.invalidTrustConfiguration) {
                _ = try VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                            minimumSequence: 1, supportedProtocol: 2)
            }
        case "engine-valid":
            let release = try engineVerified()
            guard let identity = release.engine else { fatalError("missing engine") }
            precondition(identity.version == "2.7.7" && identity.cryptoVersion == "3.5.8")
            precondition(identity.artifactName == "engine-" + SHA256.hash(data: engine).map { String(format: "%02x", $0) }.joined())
            precondition(identity.hash(forArchitecture: "arm64") == Data(repeating: 0x55, count: 20))
            precondition(identity.hash(forArchitecture: "x86_64") == Data(repeating: 0x66, count: 20))
            precondition(identity.hash(forArchitecture: "other") == nil)
            try identity.validateArtifact(engine)
            try release.validateHelperArtifact(helper)
            rejects(.invalidEngineArtifact) { try identity.validateArtifact(helper) }
            rejects(.invalidHelperArtifact) { try release.validateHelperArtifact(engine) }
        case "engine-production":
            let candidate = fixture(["format": "2"])
            let ordinary = try verifier.verify(payload: candidate, signature: signature(candidate), previous: nil)
            precondition(ordinary.engine != nil)
            try ordinary.validateArtifacts(helper: helper, engine: engine)
            rejects(.invalidEngineArtifact) { try ordinary.validateArtifacts(helper: helper, engine: nil) }
            // Verification still authenticates every byte before parsing.
            rejects(.invalidSignature) {
                _ = try verifier.verify(payload: candidate, signature: signed, previous: nil)
            }
        case "engine-grammar":
            let valid = String(decoding: fixture(["format": "2"]), as: UTF8.self)
            let invalid = [
                valid.replacingOccurrences(of: "format=2\n", with: "format=1\n"),
                String(decoding: payload, as: UTF8.self).replacingOccurrences(of: "format=1\n", with: "format=2\n"),
                valid + "engine-version=2.7.8\n", valid + "engine-path=/tmp/openvpn\n",
                valid.replacingOccurrences(of: "engine-version=2.7.7\n", with: ""),
                valid.replacingOccurrences(of: "engine-version=2.7.7\nengine-crypto-version=3.5.8\n",
                                            with: "engine-crypto-version=3.5.8\nengine-version=2.7.7\n"),
                valid.replacingOccurrences(of: "\n", with: "\r\n"), String(valid.dropLast())
            ]
            for text in invalid {
                let bad = Data(text.utf8)
                rejects(.invalidManifest) {
                    _ = try engineAuthority().verify(payload: bad, signature: signature(bad), previous: nil)
                }
            }
        case "engine-fields":
            for fields in [
                ["engine-version": "2.07.7"], ["engine-version": "2.7.7/evil"],
                ["engine-crypto-version": "3.5"], ["engine-crypto-version": "3.5.8-beta"],
                ["engine-arm64": ""], ["engine-x86_64": String(repeating: "AA", count: 20)],
                ["engine-sha256": String(repeating: "g", count: 64)],
                ["engine-bytes": "0"], ["engine-bytes": "01"], ["engine-bytes": "-1"],
                ["engine-bytes": "67108865"], ["engine-bytes": "9223372036854775808"]
            ] {
                rejects(.invalidManifest) { _ = try engineVerified(fields) }
            }
            _ = try engineVerified(["engine-bytes": "67108864"])
        case "engine-tamper":
            let release = try engineVerified()
            guard let identity = release.engine else { fatalError("missing engine") }
            var changed = engine; changed[0] ^= 1
            for bad in [Data(), engine.dropLast(), engine + Data([0]), changed] {
                rejects(.invalidEngineArtifact) { try identity.validateArtifact(Data(bad)) }
            }
            let original = fixture(["format": "2"])
            let replaced = fixture(["format": "2", "engine-bytes": "1"])
            rejects(.invalidSignature) {
                _ = try engineAuthority().verify(payload: replaced, signature: signature(original), previous: nil)
            }
        case "engine-transitions":
            let legacy = try verified()
            rejects(.conflictingRelease) { _ = try engineVerified(previous: legacy) }
            let upgraded = try engineVerified(["sequence": "11"], previous: legacy)
            let retry = try engineVerified(["sequence": "11"], previous: upgraded)
            precondition(retry.isSameRelease(as: upgraded))
            rejects(.rollback) { _ = try engineVerified(["format": "1", "sequence": "12"], previous: upgraded) }
            rejects(.rollback) { _ = try engineVerified(["sequence": "12", "engine-version": "2.7.6"], previous: upgraded) }
            rejects(.rollback) { _ = try engineVerified(["sequence": "12", "engine-crypto-version": "3.5.7"], previous: upgraded) }
            _ = try engineVerified(["sequence": "12", "engine-version": "2.7.8"], previous: upgraded)
            _ = try engineVerified(["sequence": "12", "engine-crypto-version": "3.5.9"], previous: upgraded)
            rejects(.rollback) { _ = try engineVerified(previous: upgraded) }
        case "engine-conflict":
            let release = try engineVerified()
            for fields in [
                ["engine-version": "2.7.8"], ["engine-crypto-version": "3.5.9"],
                ["engine-arm64": String(repeating: "aa", count: 20)],
                ["engine-x86_64": String(repeating: "bb", count: 20)],
                ["engine-sha256": String(repeating: "cc", count: 32)], ["engine-bytes": "1"]
            ] {
                rejects(.conflictingRelease) { _ = try engineVerified(fields, previous: release) }
            }
        case "engine-domain":
            let candidate = fixture(["format": "2"])
            for wrong in [try key.signature(for: candidate), try signature(candidate, using: otherKey)] {
                rejects(.invalidSignature) {
                    _ = try engineAuthority().verify(payload: candidate, signature: wrong, previous: nil)
                }
            }
        default: exit(64)
        }
        print("checks passed")
    }
}
