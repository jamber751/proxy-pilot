import CryptoKit
import Darwin
import Foundation
import Security

/// Release-signing tool for the VPN helper, mirroring how Sparkle's key is kept:
/// the private key lives in the Keychain and never touches disk, argv, output or
/// the repository. Only the public key is printed and committed. This signs a
/// release description; it does not build, install or activate anything.
@main
enum VPNReleaseKeyTool {
    static let service = "kz.documentolog.proxypilot.vpn-release"
    static let account = "kz.documentolog.proxypilot"

    static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data((message + "\n").utf8))
        exit(1)
    }

    static func usage() -> Never {
        fail("""
        Usage:
          vpn-release-key generate <public-key-file> [--keychain <path>] [--force]
          vpn-release-key public [--keychain <path>]
          vpn-release-key sign <manifest> <signature-file> [--keychain <path>]
          vpn-release-key verify <manifest> <signature> <public-key-file>
          vpn-release-key sign-transition <previous-manifest> <previous-signature> <candidate-manifest> <candidate-signature> <transition-file> <transition-signature-file> [--keychain <path>]
          vpn-release-key verify-transition <previous-manifest> <previous-signature> <candidate-manifest> <candidate-signature> <transition-file> <transition-signature> <public-key-file>
          vpn-release-key sign-companion <metadata> <signature-file> [--keychain <path>]
          vpn-release-key verify-companion <metadata> <signature> <public-key-file>
          vpn-release-key verify-companion-artifact <metadata> <signature> <public-key-file> <artifact>
        """)
    }

    /// The search list is what keeps tests off the developer's login keychain.
    static func keychain(_ arguments: [String]) -> SecKeychain? {
        guard let index = arguments.firstIndex(of: "--keychain"), index + 1 < arguments.count else { return nil }
        var found: SecKeychain?
        guard SecKeychainOpen(arguments[index + 1], &found) == errSecSuccess, let found = found else {
            fail("Cannot open keychain: \(arguments[index + 1])")
        }
        return found
    }

    static func storedKey(_ keychain: SecKeychain?) -> Curve25519.Signing.PrivateKey? {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrService as String: service,
                                    kSecAttrAccount as String: account,
                                    kSecReturnData as String: true]
        if let keychain = keychain { query[kSecMatchSearchList as String] = [keychain] }
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data, let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: data) else {
            return nil
        }
        return key
    }

    static func store(_ key: Curve25519.Signing.PrivateKey, in keychain: SecKeychain?, force: Bool) {
        if storedKey(keychain) != nil {
            guard force else { fail("A VPN release key already exists. Rotating it invalidates every earlier release; pass --force only deliberately.") }
            var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                        kSecAttrService as String: service,
                                        kSecAttrAccount as String: account]
            if let keychain = keychain { query[kSecMatchSearchList as String] = [keychain] }
            guard SecItemDelete(query as CFDictionary) == errSecSuccess else { fail("Cannot replace the existing key.") }
        }
        var attributes: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                         kSecAttrService as String: service,
                                         kSecAttrAccount as String: account,
                                         kSecAttrLabel as String: "ProxyPilot VPN release signing key",
                                         kSecAttrDescription as String: "Ed25519 private key",
                                         kSecValueData as String: key.rawRepresentation]
        if let keychain = keychain { attributes[kSecUseKeychain as String] = keychain }
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { fail("Cannot store the key in the Keychain: \(status)") }
    }

    static func write(_ text: String, to path: String) {
        let url = URL(fileURLWithPath: path)
        let temporary = url.deletingLastPathComponent()
            .appendingPathComponent(".vpn-release-key-\(UUID().uuidString).tmp")
        do {
            try Data(text.utf8).write(to: temporary, options: .atomic)
            _ = try FileManager.default.replaceItemAt(url, withItemAt: temporary)
        } catch {
            try? FileManager.default.removeItem(at: temporary)
            fail("Cannot write \(path)")
        }
    }

    static func file(_ path: String, limit: Int) -> Data? {
        guard let data = FileManager.default.contents(atPath: path),
              !data.isEmpty, data.count <= limit else { return nil }
        return data
    }

    static func signature(_ path: String) -> Data? {
        guard let data = file(path, limit: 89),
              let text = String(data: data, encoding: .utf8),
              text.count == 89, text.last == "\n",
              let decoded = Data(base64Encoded: String(text.dropLast())),
              decoded.count == 64,
              decoded.base64EncodedString() + "\n" == text else { return nil }
        return decoded
    }

    static func canonicalTransition(previousPayload: Data, previous: VerifiedVPNRelease,
                                    candidatePayload: Data, candidate: VerifiedVPNRelease) -> Data {
        func hex(_ data: Data) -> String {
            data.map { String(format: "%02x", $0) }.joined()
        }
        return Data(("format=1\nproduct=kz.documentolog.proxypilot\n"
            + "from-sequence=\(previous.sequence)\n"
            + "from-sha256=\(hex(Data(SHA256.hash(data: previousPayload))))\n"
            + "to-sequence=\(candidate.sequence)\n"
            + "to-sha256=\(hex(Data(SHA256.hash(data: candidatePayload))))\n").utf8)
    }

    static func main() {
        let arguments = CommandLine.arguments
        guard arguments.count >= 2 else { usage() }
        let chain = keychain(arguments)
        switch arguments[1] {
        case "generate":
            guard arguments.count >= 3 else { usage() }
            // Generated here and never seen again: the tool prints only the
            // public half, and nothing writes the private key to disk.
            let key = Curve25519.Signing.PrivateKey()
            store(key, in: chain, force: arguments.contains("--force"))
            let publicKey = key.publicKey.rawRepresentation.base64EncodedString()
            write(publicKey + "\n", to: arguments[2])
            print(publicKey)
        case "public":
            guard let key = storedKey(chain) else { fail("No VPN release key in the Keychain.") }
            print(key.publicKey.rawRepresentation.base64EncodedString())
        case "sign":
            guard arguments.count >= 4 else { usage() }
            guard let key = storedKey(chain) else { fail("No VPN release key in the Keychain.") }
            guard let payload = FileManager.default.contents(atPath: arguments[2]),
                  payload.count <= VPNReleaseAuthority.maximumPayloadBytes else {
                fail("Cannot read the release description: \(arguments[2])")
            }
            // Domain-separated, exactly as the helper verifies it: a signature
            // over an archive or an appcast can never authorize root code.
            guard let signature = try? key.signature(for: VPNReleaseAuthority.signatureDomain + payload) else {
                fail("Signing failed.")
            }
            // Refuse to publish a signature for malformed or unsupported code
            // authorization, using the same canonical parser as the installer.
            guard let authority = try? VPNReleaseAuthority(trustedPublicKey: key.publicKey.rawRepresentation,
                                                           minimumSequence: 1, supportedProtocol: 1),
                  (try? authority.verify(payload: payload, signature: signature, previous: nil)) != nil else {
                fail("Release description rejected; signature not written.")
            }
            write(signature.base64EncodedString() + "\n", to: arguments[3])
            print("Signed \(arguments[2])")
        case "verify":
            guard arguments.count >= 5 else { usage() }
            guard let payload = FileManager.default.contents(atPath: arguments[2]),
                  let signatureText = try? String(contentsOfFile: arguments[3], encoding: .utf8),
                  let signature = Data(base64Encoded: signatureText.trimmingCharacters(in: .whitespacesAndNewlines)),
                  let publicText = try? String(contentsOfFile: arguments[4], encoding: .utf8),
                  let publicKey = Data(base64Encoded: publicText.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                fail("Cannot read the release description, signature or public key.")
            }
            // The same verifier the helper uses: format, protocol, sequence and
            // pinned hashes are all checked, not just the signature bytes.
            guard let authority = try? VPNReleaseAuthority(trustedPublicKey: publicKey, minimumSequence: 1,
                                                           supportedProtocol: 1),
                  let release = try? authority.verify(payload: payload, signature: signature, previous: nil) else {
                fail("Release description or signature rejected.")
            }
            print("Verified sequence \(release.sequence) version \(release.version)")
        case "sign-transition":
            guard arguments.count >= 8,
                  let key = storedKey(chain),
                  let previousPayload = file(arguments[2], limit: VPNReleaseAuthority.maximumPayloadBytes),
                  let previousSignature = signature(arguments[3]),
                  let candidatePayload = file(arguments[4], limit: VPNReleaseAuthority.maximumPayloadBytes),
                  let candidateSignature = signature(arguments[5]),
                  let authority = try? VPNReleaseAuthority(
                    trustedPublicKey: key.publicKey.rawRepresentation,
                    minimumSequence: 1, supportedProtocol: 1),
                  let previous = try? authority.verify(
                    payload: previousPayload, signature: previousSignature, previous: nil),
                  let candidate = try? authority.verify(
                    payload: candidatePayload, signature: candidateSignature, previous: previous) else {
                fail("Release descriptions rejected; transition not written.")
            }
            let transition = canonicalTransition(
                previousPayload: previousPayload, previous: previous,
                candidatePayload: candidatePayload, candidate: candidate)
            guard let signed = try? key.signature(
                for: VPNReleaseAuthority.updateTransitionDomain + transition),
                  (try? authority.verifyUpdateTransition(
                    payload: transition, signature: signed, previous: previous,
                    candidatePayload: candidatePayload,
                    candidateSignature: candidateSignature)) != nil else {
                fail("Release transition rejected; transition not written.")
            }
            write(signed.base64EncodedString() + "\n", to: arguments[7])
            write(String(decoding: transition, as: UTF8.self), to: arguments[6])
            print("Signed transition \(previous.sequence) to \(candidate.sequence)")
        case "verify-transition":
            guard arguments.count >= 9,
                  let previousPayload = file(arguments[2], limit: VPNReleaseAuthority.maximumPayloadBytes),
                  let previousSignature = signature(arguments[3]),
                  let candidatePayload = file(arguments[4], limit: VPNReleaseAuthority.maximumPayloadBytes),
                  let candidateSignature = signature(arguments[5]),
                  let transition = file(arguments[6], limit: VPNReleaseAuthority.maximumUpdateTransitionBytes),
                  let transitionSignature = signature(arguments[7]),
                  let publicText = try? String(contentsOfFile: arguments[8], encoding: .utf8),
                  let publicKey = Data(base64Encoded:
                    publicText.trimmingCharacters(in: .whitespacesAndNewlines)),
                  let authority = try? VPNReleaseAuthority(
                    trustedPublicKey: publicKey, minimumSequence: 1, supportedProtocol: 1),
                  let previous = try? authority.verify(
                    payload: previousPayload, signature: previousSignature, previous: nil),
                  let edge = try? authority.verifyUpdateTransition(
                    payload: transition, signature: transitionSignature, previous: previous,
                    candidatePayload: candidatePayload,
                    candidateSignature: candidateSignature) else {
                fail("Release transition or signature rejected.")
            }
            print("Verified transition \(edge.fromSequence) to \(edge.toSequence)")
        case "sign-companion":
            guard arguments.count >= 4,
                  let key = storedKey(chain),
                  let payload = file(arguments[2], limit: VPNCompanionMetadataAuthority.maximumPayloadBytes),
                  let signed = try? key.signature(
                    for: VPNCompanionMetadataAuthority.signatureDomain + payload),
                  let authority = try? VPNCompanionMetadataAuthority(
                    trustedPublicKey: key.publicKey.rawRepresentation),
                  (try? authority.verify(payload: payload, signature: signed)) != nil else {
                fail("Companion metadata rejected; signature not written.")
            }
            write(signed.base64EncodedString() + "\n", to: arguments[3])
            print("Signed companion metadata")
        case "verify-companion":
            guard arguments.count >= 5,
                  let payload = file(arguments[2], limit: VPNCompanionMetadataAuthority.maximumPayloadBytes),
                  let signed = signature(arguments[3]),
                  let publicText = try? String(contentsOfFile: arguments[4], encoding: .utf8),
                  let publicKey = Data(base64Encoded:
                    publicText.trimmingCharacters(in: .whitespacesAndNewlines)),
                  let authority = try? VPNCompanionMetadataAuthority(
                    trustedPublicKey: publicKey),
                  let metadata = try? authority.verify(
                    payload: payload, signature: signed) else {
                fail("Companion metadata or signature rejected.")
            }
            print("Verified companion \(metadata.fromSequence) to \(metadata.toSequence)")
        case "verify-companion-artifact":
            guard arguments.count >= 6,
                  let payload = file(arguments[2], limit: VPNCompanionMetadataAuthority.maximumPayloadBytes),
                  let signed = signature(arguments[3]),
                  let publicText = try? String(contentsOfFile: arguments[4], encoding: .utf8),
                  let publicKey = Data(base64Encoded:
                    publicText.trimmingCharacters(in: .whitespacesAndNewlines)),
                  let authority = try? VPNCompanionMetadataAuthority(
                    trustedPublicKey: publicKey),
                  let metadata = try? authority.verify(
                    payload: payload, signature: signed) else {
                fail("Companion metadata or signature rejected.")
            }
            let descriptor = open(arguments[5], O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard descriptor >= 0 else { fail("Companion artifact rejected.") }
            defer { close(descriptor) }
            do { try metadata.validateArtifact(fileDescriptor: descriptor) }
            catch { fail("Companion artifact rejected.") }
            print("Verified companion artifact \(metadata.artifactName)")
        default:
            usage()
        }
    }
}
