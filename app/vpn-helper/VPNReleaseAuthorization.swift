import CryptoKit
import Foundation

enum VPNReleaseAuthorizationError: Error {
    case invalidTrustConfiguration
    case invalidSignature
    case invalidManifest
    case incompatibleProtocol
    case rollback
    case conflictingRelease
    case wrongAuthority
    case invalidHelperArtifact
    case invalidEngineArtifact
}

/// A signed engine identity, not an executable path or permission to launch it.
/// Only the release authority can construct this after signature verification.
struct VerifiedVPNEngine {
    let version: String
    let cryptoVersion: String
    fileprivate let hashes: [String: Data]
    fileprivate let sha256: Data
    fileprivate let byteCount: Int

    fileprivate init(version: String, cryptoVersion: String, hashes: [String: Data],
                     sha256: Data, byteCount: Int) {
        self.version = version
        self.cryptoVersion = cryptoVersion
        self.hashes = hashes
        self.sha256 = sha256
        self.byteCount = byteCount
    }

    func validateArtifact(_ data: Data) throws {
        guard data.count == byteCount, Data(SHA256.hash(data: data)) == sha256 else {
            throw VPNReleaseAuthorizationError.invalidEngineArtifact
        }
    }

    var artifactName: String {
        "engine-" + sha256.map { String(format: "%02x", $0) }.joined()
    }

    func hash(forArchitecture architecture: String) -> Data? { hashes[architecture] }
}

/// An authenticated release description, not installation success or live VPN
/// state. Only VPNReleaseAuthority can construct this value after verification.
struct VerifiedVPNRelease {
    let sequence: UInt64
    let version: String
    let protocolVersion: UInt64
    let engine: VerifiedVPNEngine?
    fileprivate let appHashes: Set<Data>
    fileprivate let helperHashes: [String: Data]
    fileprivate let helperSHA256: Data
    fileprivate let helperByteCount: Int
    fileprivate let payloadDigest: Data
    fileprivate let authorityDigest: Data

    fileprivate init(sequence: UInt64, version: String, protocolVersion: UInt64,
                     appHashes: Set<Data>, helperHashes: [String: Data], helperSHA256: Data,
                     helperByteCount: Int, engine: VerifiedVPNEngine?, payloadDigest: Data, authorityDigest: Data) {
        self.sequence = sequence
        self.version = version
        self.protocolVersion = protocolVersion
        self.appHashes = appHashes
        self.helperHashes = helperHashes
        self.helperSHA256 = helperSHA256
        self.helperByteCount = helperByteCount
        self.engine = engine
        self.payloadDigest = payloadDigest
        self.authorityDigest = authorityDigest
    }

    /// The UID must come from trusted installation/session ownership, not IPC.
    func clientPolicy(forTrustedUserID userID: UInt32) throws -> VPNPeerPolicy {
        try VPNPeerPolicy(userID: userID, signingIdentifier: "kz.documentolog.proxypilot",
                          codeDirectoryHashes: appHashes)
    }

    func helperPolicy() throws -> VPNPeerPolicy {
        try VPNPeerPolicy.helper(codeDirectoryHashes: Set(helperHashes.values))
    }

    func installerPolicy() throws -> VPNPeerPolicy {
        try VPNPeerPolicy.installer(codeDirectoryHashes: appHashes)
    }

    #if VPN_HELPER_READINESS_TESTING
    func testHelperPolicy() throws -> VPNPeerPolicy {
        try VPNPeerPolicy.testHelper(codeDirectoryHashes: Set(helperHashes.values))
    }
    #endif

    func isSameRelease(as other: VerifiedVPNRelease) -> Bool {
        payloadDigest == other.payloadDigest && authorityDigest == other.authorityDigest
    }

    /// Checks the universal helper's exact bytes before staging. This does NOT
    /// check executable hardening, replace files, authenticate a running helper,
    /// or authorize extraction/execution of a path supplied by a client.
    func validateHelperArtifact(_ data: Data) throws {
        guard data.count == helperByteCount, Data(SHA256.hash(data: data)) == helperSHA256 else {
            throw VPNReleaseAuthorizationError.invalidHelperArtifact
        }
    }

    /// Exact component set: v1 never accepts stray engine bytes; v2 never
    /// degrades into a helper-only deployment when the engine is missing.
    func validateArtifacts(helper: Data, engine candidate: Data?) throws {
        try validateHelperArtifact(helper)
        if let engine = engine {
            guard let candidate = candidate else { throw VPNReleaseAuthorizationError.invalidEngineArtifact }
            try engine.validateArtifact(candidate)
        } else if candidate != nil {
            throw VPNReleaseAuthorizationError.invalidEngineArtifact
        }
    }

    // Content-addressed basename only; never accept an artifact path from IPC.
    var helperArtifactName: String {
        "helper-" + helperSHA256.map { String(format: "%02x", $0) }.joined()
    }

    func helperHash(forArchitecture architecture: String) -> Data? { helperHashes[architecture] }
}

/// Verification-only building block; not linked to the app or an installer.
/// Trust must be embedded in the helper/installer or read from protected state.
/// Never accept the public key, floor or previous release from a network request.
struct VPNReleaseAuthority {
    // Domain separation prevents a signature over an update archive, appcast or
    // arbitrary text from being interpreted as authorization for root code.
    static let signatureDomain = Data("kz.documentolog.proxypilot/vpn-release-authorization/v1\0".utf8)
    static let maximumPayloadBytes = 4096
    static let maximumHelperBytes = 32 * 1024 * 1024
    static let maximumEngineBytes = 64 * 1024 * 1024
    private let publicKey: Curve25519.Signing.PublicKey
    private let authorityDigest: Data
    private let minimumSequence: UInt64
    private let supportedProtocol: UInt64

    init(trustedPublicKey: Data, minimumSequence: UInt64, supportedProtocol: UInt64) throws {
        guard trustedPublicKey.count == 32, minimumSequence > 0,
              minimumSequence <= UInt64(Int64.max), supportedProtocol == 1,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: trustedPublicKey) else {
            throw VPNReleaseAuthorizationError.invalidTrustConfiguration
        }
        publicKey = key
        authorityDigest = Data(SHA256.hash(data: trustedPublicKey))
        self.minimumSequence = minimumSequence
        self.supportedProtocol = supportedProtocol
    }

    #if VPN_ENGINE_DELIVERY_TESTING
    /// Test convenience using exactly the production parser and rules.
    static func engineCandidateAuthority(trustedPublicKey: Data, minimumSequence: UInt64) throws -> VPNReleaseAuthority {
        try VPNReleaseAuthority(trustedPublicKey: trustedPublicKey,
                                minimumSequence: minimumSequence, supportedProtocol: 1)
    }
    #endif

    /// `previous == nil` is ONLY for a separately authorized first installation,
    /// never a fallback after corrupt/missing installed state. Production must
    /// reload the previously committed signed manifest from protected storage,
    /// serialize check+activation, and persist advancement atomically. This pure
    /// verifier intentionally does not claim durable rollback protection.
    func verify(payload: Data, signature: Data, previous: VerifiedVPNRelease?) throws -> VerifiedVPNRelease {
        guard !payload.isEmpty, payload.count <= Self.maximumPayloadBytes,
              signature.count == 64,
              publicKey.isValidSignature(signature, for: Self.signatureDomain + payload) else {
            throw VPNReleaseAuthorizationError.invalidSignature
        }
        // Fixed, canonical lines avoid duplicate keys, ambiguous JSON numbers,
        // ignored fields or differences between signing and parsing libraries.
        guard let text = String(data: payload, encoding: .utf8) else {
            throw VPNReleaseAuthorizationError.invalidManifest
        }
        let lines = text.components(separatedBy: "\n")
        let isEngineManifest = lines.first == "format=2"
        var keys = ["format", "product", "sequence", "version", "protocol", "app-arm64",
                    "app-x86_64", "helper-arm64", "helper-x86_64", "helper-sha256", "helper-bytes"]
        if isEngineManifest {
            keys += ["engine-version", "engine-crypto-version", "engine-arm64", "engine-x86_64",
                     "engine-sha256", "engine-bytes"]
        }
        guard lines.count == keys.count + 1, lines.last == "" else {
            throw VPNReleaseAuthorizationError.invalidManifest
        }
        var values: [String] = []
        for (line, key) in zip(lines, keys) {
            guard line.hasPrefix(key + "=") else { throw VPNReleaseAuthorizationError.invalidManifest }
            values.append(String(line.dropFirst(key.count + 1)))
        }
        guard values[0] == (isEngineManifest ? "2" : "1"), values[1] == "kz.documentolog.proxypilot",
              let sequence = Self.number(values[2]), sequence > 0,
              Self.versionParts(values[3]) != nil,
              let protocolVersion = Self.number(values[4]),
              let appARM = Self.hex(values[5], byteCount: 20),
              let appIntel = Self.hex(values[6], byteCount: 20),
              let helperARM = Self.hex(values[7], byteCount: 20),
              let helperIntel = Self.hex(values[8], byteCount: 20),
              let helperHash = Self.hex(values[9], byteCount: 32),
              let helperBytes = Self.number(values[10]), helperBytes > 0,
              helperBytes <= UInt64(Self.maximumHelperBytes) else {
            throw VPNReleaseAuthorizationError.invalidManifest
        }
        var engine: VerifiedVPNEngine?
        if isEngineManifest {
            guard Self.versionParts(values[11]) != nil, Self.versionParts(values[12]) != nil,
                  let arm = Self.hex(values[13], byteCount: 20),
                  let intel = Self.hex(values[14], byteCount: 20),
                  let hash = Self.hex(values[15], byteCount: 32),
                  let count = Self.number(values[16]), count > 0,
                  count <= UInt64(Self.maximumEngineBytes) else {
                throw VPNReleaseAuthorizationError.invalidManifest
            }
            engine = VerifiedVPNEngine(version: values[11], cryptoVersion: values[12],
                                       hashes: ["arm64": arm, "x86_64": intel], sha256: hash, byteCount: Int(count))
        }
        guard protocolVersion == supportedProtocol else {
            throw VPNReleaseAuthorizationError.incompatibleProtocol
        }
        guard sequence >= minimumSequence else { throw VPNReleaseAuthorizationError.rollback }
        let digest = Data(SHA256.hash(data: payload))
        if let previous = previous {
            guard previous.authorityDigest == authorityDigest else {
                throw VPNReleaseAuthorizationError.wrongAuthority
            }
            guard sequence >= previous.sequence,
                  !Self.versionIsOlder(values[3], than: previous.version) else {
                throw VPNReleaseAuthorizationError.rollback
            }
            // A higher app release must not silently drop the engine or roll
            // either embedded component back to an older signed version.
            if let old = previous.engine {
                guard let next = engine,
                      !Self.versionIsOlder(next.version, than: old.version),
                      !Self.versionIsOlder(next.cryptoVersion, than: old.cryptoVersion) else {
                    throw VPNReleaseAuthorizationError.rollback
                }
            }
            // Retry the same release idempotently, but never reuse its sequence
            // for different bytes (even if both descriptions were signed).
            guard sequence != previous.sequence || digest == previous.payloadDigest else {
                throw VPNReleaseAuthorizationError.conflictingRelease
            }
        }
        return VerifiedVPNRelease(
            sequence: sequence, version: values[3], protocolVersion: protocolVersion,
            appHashes: [appARM, appIntel], helperHashes: ["arm64": helperARM, "x86_64": helperIntel],
            helperSHA256: helperHash, helperByteCount: Int(helperBytes), engine: engine,
            payloadDigest: digest, authorityDigest: authorityDigest)
    }

    private static func number(_ value: String) -> UInt64? {
        guard !value.isEmpty, value.utf8.count <= 19,
              value == "0" || !value.hasPrefix("0"),
              value.utf8.allSatisfy({ (48...57).contains($0) }),
              let number = UInt64(value), number <= UInt64(Int64.max) else { return nil }
        return number
    }

    private static func versionParts(_ value: String) -> [UInt64]? {
        let parts = value.components(separatedBy: ".")
        guard parts.count == 3 else { return nil }
        let numbers = parts.compactMap(number)
        guard numbers.count == 3 else { return nil }
        return numbers
    }

    private static func versionIsOlder(_ value: String, than previous: String) -> Bool {
        // Both values have already passed the same strict version parser.
        guard let lhs = versionParts(value), let rhs = versionParts(previous) else { return true }
        return lhs.lexicographicallyPrecedes(rhs)
    }

    private static func hex(_ value: String, byteCount: Int) -> Data? {
        let bytes = Array(value.utf8)
        guard bytes.count == byteCount * 2,
              bytes.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { return nil }
        func nibble(_ byte: UInt8) -> UInt8 { byte <= 57 ? byte - 48 : byte - 87 }
        return Data(stride(from: 0, to: bytes.count, by: 2).map { nibble(bytes[$0]) * 16 + nibble(bytes[$0 + 1]) })
    }
}
