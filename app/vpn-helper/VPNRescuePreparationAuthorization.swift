import CryptoKit
import Foundation

enum VPNRescuePreparationAuthorizationError: Error {
    case invalidSignature, invalidAuthorization, wrongEdge, invalidArtifact
}

/// A signed, exact-edge rescue description, NOT a live process, journal lease,
/// root capability, installation proof or permission to skip ordinary A/B auth.
/// Never serialize this token as authority: persist/reverify the signed inputs.
/// UUID/revision are deliberately not signed; the eventual root coordinator must
/// capture and recheck selected source plus exact preparation/journal state under
/// its lifecycle lease. This type cannot substitute for a pending finish token.
struct VerifiedVPNRescuePreparationAuthorization {
    let fromSequence: UInt64
    let toSequence: UInt64
    let artifactByteCount: Int
    private let previous: VerifiedVPNRelease
    private let candidate: VerifiedVPNRelease
    private let artifactSHA256: Data
    private let hashes: [String: Data]

    fileprivate init(previous: VerifiedVPNRelease, candidate: VerifiedVPNRelease,
                     artifactSHA256: Data, artifactByteCount: Int,
                     arm64: Data, intel: Data) {
        self.previous = previous; self.candidate = candidate
        fromSequence = previous.sequence; toSequence = candidate.sequence
        self.artifactSHA256 = artifactSHA256; self.artifactByteCount = artifactByteCount
        hashes = ["arm64": arm64, "x86_64": intel]
    }

    func matchesSource(_ release: VerifiedVPNRelease) -> Bool { previous.isSameRelease(as: release) }
    func matchesDestination(_ release: VerifiedVPNRelease) -> Bool { candidate.isSameRelease(as: release) }
    func matchesTransition(_ transition: VerifiedVPNUpdateTransition) -> Bool {
        transition.matchesSource(previous) && transition.matchesDestination(candidate)
    }

    /// Exact bytes only. A future artifact checker must independently validate
    /// Mach-O architectures, hardened signature/CDHashes and descriptor identity.
    /// This method never launches a binary or authenticates the calling process.
    func validateArtifact(_ bytes: Data) throws {
        guard bytes.count == artifactByteCount,
              Data(SHA256.hash(data: bytes)) == artifactSHA256 else {
            throw VPNRescuePreparationAuthorizationError.invalidArtifact
        }
    }

    func hash(forArchitecture architecture: String) -> Data? { hashes[architecture] }
}

/// Pure canonical codec and verifier. No file IO, Keychain, process launch,
/// journal changes, peer-policy unions, exchange or cleanup entry is provided.
enum VPNRescuePreparationAuthorization {
    static let operation = "prepare-root-owned-update-and-authorize-replacement"
    static let maximumArtifactBytes = 32 * 1024 * 1024
    private static let keys = ["format", "product", "operation",
                               "previous-manifest-sha256", "candidate-manifest-sha256",
                               "transition-sha256", "rescue-sha256", "rescue-bytes",
                               "rescue-arm64", "rescue-x86_64"]

    /// `previous` and its signed bytes must come from authenticated protected
    /// state in production, never from worker IPC. A valid token alone does not
    /// prove source-selected or preparation state; that is a separate root boundary.
    static func verify(payload: Data, signature: Data, authority: VPNReleaseAuthority,
                       previous: VerifiedVPNRelease,
                       previousPayload: Data, previousSignature: Data,
                       candidatePayload: Data, candidateSignature: Data,
                       transitionPayload: Data, transitionSignature: Data) throws
        -> VerifiedVPNRescuePreparationAuthorization {
        guard authority.verifyRescuePreparationSignature(payload: payload, signature: signature) else {
            throw VPNRescuePreparationAuthorizationError.invalidSignature
        }
        let fields = try parse(payload)
        let checkedPrevious = try authority.verify(payload: previousPayload,
            signature: previousSignature, previous: previous)
        guard checkedPrevious.isSameRelease(as: previous) else {
            throw VPNRescuePreparationAuthorizationError.wrongEdge
        }
        let candidate = try authority.verify(payload: candidatePayload,
            signature: candidateSignature, previous: previous)
        let edge = try authority.verifyUpdateTransition(payload: transitionPayload,
            signature: transitionSignature, previous: previous,
            candidatePayload: candidatePayload, candidateSignature: candidateSignature)
        guard edge.matchesSource(previous), edge.matchesDestination(candidate),
              fields.previous == Data(SHA256.hash(data: previousPayload)),
              fields.candidate == Data(SHA256.hash(data: candidatePayload)),
              fields.transition == Data(SHA256.hash(data: transitionPayload)) else {
            throw VPNRescuePreparationAuthorizationError.wrongEdge
        }
        return VerifiedVPNRescuePreparationAuthorization(previous: previous, candidate: candidate,
            artifactSHA256: fields.artifact, artifactByteCount: fields.byteCount,
            arm64: fields.arm64, intel: fields.intel)
    }

    /// Produces unsigned bytes only. This does not authorize inputs or sign
    /// anything; the verifier independently checks both releases and their edge.
    static func encode(previousManifest: Data, candidateManifest: Data,
                       transitionPayload: Data, rescueArtifact: Data,
                       arm64CDHash: Data, intelCDHash: Data) throws -> Data {
        guard !previousManifest.isEmpty, previousManifest.count <= VPNReleaseAuthority.maximumPayloadBytes,
              !candidateManifest.isEmpty, candidateManifest.count <= VPNReleaseAuthority.maximumPayloadBytes,
              !transitionPayload.isEmpty,
              transitionPayload.count <= VPNReleaseAuthority.maximumUpdateTransitionBytes,
              !rescueArtifact.isEmpty, rescueArtifact.count <= maximumArtifactBytes,
              arm64CDHash.count == 20, intelCDHash.count == 20 else {
            throw VPNRescuePreparationAuthorizationError.invalidAuthorization
        }
        let values = ["1", "kz.documentolog.proxypilot", operation,
                      hex(Data(SHA256.hash(data: previousManifest))),
                      hex(Data(SHA256.hash(data: candidateManifest))),
                      hex(Data(SHA256.hash(data: transitionPayload))),
                      hex(Data(SHA256.hash(data: rescueArtifact))), String(rescueArtifact.count),
                      hex(arm64CDHash), hex(intelCDHash)]
        return Data(zip(keys, values).map { "\($0)=\($1)\n" }.joined().utf8)
    }

    private struct Fields {
        let previous: Data, candidate: Data, transition: Data, artifact: Data
        let byteCount: Int
        let arm64: Data, intel: Data
    }

    private static func parse(_ payload: Data) throws -> Fields {
        guard !payload.isEmpty, payload.count <= VPNReleaseAuthority.maximumRescuePreparationAuthorizationBytes,
              let text = String(data: payload, encoding: .utf8) else {
            throw VPNRescuePreparationAuthorizationError.invalidAuthorization
        }
        let lines = text.components(separatedBy: "\n")
        guard lines.count == keys.count + 1, lines.last == "" else {
            throw VPNRescuePreparationAuthorizationError.invalidAuthorization
        }
        var values: [String] = []
        for (key, line) in zip(keys, lines) {
            guard line.hasPrefix(key + "=") else { throw VPNRescuePreparationAuthorizationError.invalidAuthorization }
            values.append(String(line.dropFirst(key.count + 1)))
        }
        guard values[0] == "1", values[1] == "kz.documentolog.proxypilot", values[2] == operation,
              let previous = unhex(values[3], count: 32),
              let candidate = unhex(values[4], count: 32),
              let transition = unhex(values[5], count: 32),
              let artifact = unhex(values[6], count: 32),
              let bytes = number(values[7]), bytes > 0, bytes <= maximumArtifactBytes,
              let arm64 = unhex(values[8], count: 20),
              let intel = unhex(values[9], count: 20) else {
            throw VPNRescuePreparationAuthorizationError.invalidAuthorization
        }
        return Fields(previous: previous, candidate: candidate, transition: transition,
                      artifact: artifact, byteCount: bytes, arm64: arm64, intel: intel)
    }

    private static func number(_ text: String) -> Int? {
        guard !text.isEmpty, text.utf8.count <= 19,
              text.utf8.allSatisfy({ (48...57).contains($0) }),
              let value = Int(text), String(value) == text else { return nil }
        return value
    }

    private static func hex(_ bytes: Data) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func unhex(_ text: String, count: Int) -> Data? {
        let bytes = Array(text.utf8)
        guard bytes.count == count * 2,
              bytes.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { return nil }
        func nibble(_ value: UInt8) -> UInt8 { value <= 57 ? value - 48 : value - 87 }
        return Data(stride(from: 0, to: bytes.count, by: 2).map { nibble(bytes[$0]) * 16 + nibble(bytes[$0 + 1]) })
    }
}
