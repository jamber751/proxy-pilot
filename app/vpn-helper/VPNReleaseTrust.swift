import Foundation

/// The one place the helper and installer learn whom to trust. The key is
/// compiled in on purpose: reading it from storage, preferences or the network
/// would let whoever controls that source authorize root code. It is the public
/// half only — the private key lives in the release engineer's Keychain and is
/// never in this repository. Rotation means shipping a new build with a new
/// constant; a release signed by an unknown key must simply fail to verify.
enum VPNReleaseTrust {
    /// Base64 of the 32-byte Ed25519 public key, matching
    /// `app/vpn-release-public-key.txt`. An empty value fails closed: without
    /// trust configured, no release can be authorized at all.
    static let publicKey = "5C3yVWgG5tJZBtcP/bYschpBqbtWCnz4dqRrqbNMWcM="

    /// Earliest release this build accepts. Raise it only to burn a compromised
    /// sequence; lowering it would re-enable a release that was already rejected.
    static let minimumSequence: UInt64 = 1
    static let supportedProtocol: UInt64 = 1

    static func authority() throws -> VPNReleaseAuthority {
        guard let key = Data(base64Encoded: publicKey), key.count == 32 else {
            throw VPNReleaseAuthorizationError.invalidTrustConfiguration
        }
        return try VPNReleaseAuthority(trustedPublicKey: key, minimumSequence: minimumSequence,
                                       supportedProtocol: supportedProtocol)
    }
}
