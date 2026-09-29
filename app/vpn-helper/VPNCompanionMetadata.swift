import CryptoKit
import Darwin
import Foundation

enum VPNCompanionMetadataError: Error {
    case invalidTrust, invalidSignature, invalidMetadata, invalidArtifact
}

struct VerifiedVPNCompanionMetadata {
    let version: String
    let fromSequence: UInt64
    let toSequence: UInt64
    let artifactBytes: UInt64
    private let artifactDigest: Data

    fileprivate init(version: String, fromSequence: UInt64, toSequence: UInt64,
                     artifactBytes: UInt64, artifactDigest: Data) {
        self.version = version
        self.fromSequence = fromSequence
        self.toSequence = toSequence
        self.artifactBytes = artifactBytes
        self.artifactDigest = artifactDigest
    }

    var artifactName: String { "ProxyPilot-\(version)-vpn-joint.dmg" }

    /// Location is derived from canonical signed version data. The metadata has
    /// no URL, host, path or redirect field that can select a download origin.
    var artifactURL: URL {
        URL(string: "https://github.com/jamber751/proxy-pilot/releases/download/v\(version)/\(artifactName)")!
    }

    func validateArtifact(fileDescriptor: Int32) throws {
        var info = stat()
        guard fileDescriptor >= 0, fstat(fileDescriptor, &info) == 0,
              info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1,
              info.st_size > 0, UInt64(info.st_size) == artifactBytes,
              lseek(fileDescriptor, 0, SEEK_SET) == 0 else {
            throw VPNCompanionMetadataError.invalidArtifact
        }
        var digest = SHA256()
        var buffer = [UInt8](repeating: 0, count: 1024 * 1024)
        while true {
            let count = buffer.withUnsafeMutableBytes {
                read(fileDescriptor, $0.baseAddress, $0.count)
            }
            if count == 0 { break }
            guard count > 0 else {
                if errno == EINTR { continue }
                throw VPNCompanionMetadataError.invalidArtifact
            }
            digest.update(data: Data(buffer.prefix(count)))
        }
        guard Data(digest.finalize()) == artifactDigest,
              lseek(fileDescriptor, 0, SEEK_SET) == 0 else {
            throw VPNCompanionMetadataError.invalidArtifact
        }
    }
}

struct VPNCompanionMetadataAuthority {
    static let signatureDomain = Data("kz.documentolog.proxypilot/vpn-companion-metadata/v1\0".utf8)
    static let maximumPayloadBytes = 512
    static let maximumArtifactBytes: UInt64 = 768 * 1024 * 1024
    private let publicKey: Curve25519.Signing.PublicKey

    init(trustedPublicKey: Data) throws {
        guard trustedPublicKey.count == 32,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: trustedPublicKey) else {
            throw VPNCompanionMetadataError.invalidTrust
        }
        publicKey = key
    }

    static func trusted() throws -> Self {
        guard let key = Data(base64Encoded: VPNReleaseTrust.publicKey) else {
            throw VPNCompanionMetadataError.invalidTrust
        }
        return try Self(trustedPublicKey: key)
    }

    func verify(payload: Data, signature: Data) throws
        -> VerifiedVPNCompanionMetadata {
        guard !payload.isEmpty, payload.count <= Self.maximumPayloadBytes,
              signature.count == 64,
              publicKey.isValidSignature(signature,
                  for: Self.signatureDomain + payload),
              let text = String(data: payload, encoding: .utf8) else {
            throw VPNCompanionMetadataError.invalidSignature
        }
        let keys = ["format", "product", "version", "from-sequence",
                    "to-sequence", "artifact-sha256", "artifact-bytes"]
        let lines = text.components(separatedBy: "\n")
        guard lines.count == keys.count + 1, lines.last == "" else {
            throw VPNCompanionMetadataError.invalidMetadata
        }
        var values: [String] = []
        for (line, key) in zip(lines, keys) {
            guard line.hasPrefix(key + "=") else {
                throw VPNCompanionMetadataError.invalidMetadata
            }
            values.append(String(line.dropFirst(key.count + 1)))
        }
        guard values[0] == "1", values[1] == "kz.documentolog.proxypilot",
              Self.version(values[2]),
              let from = Self.number(values[3]), from > 0,
              let to = Self.number(values[4]), to > from,
              let digest = Self.hex(values[5], bytes: 32),
              let count = Self.number(values[6]), count > 0,
              count <= Self.maximumArtifactBytes else {
            throw VPNCompanionMetadataError.invalidMetadata
        }
        return VerifiedVPNCompanionMetadata(
            version: values[2], fromSequence: from, toSequence: to,
            artifactBytes: count, artifactDigest: digest)
    }

    private static func number(_ value: String) -> UInt64? {
        guard !value.isEmpty, value.utf8.count <= 19,
              value == "0" || !value.hasPrefix("0"),
              value.utf8.allSatisfy({ (48...57).contains($0) }),
              let result = UInt64(value), result <= UInt64(Int64.max) else { return nil }
        return result
    }

    private static func version(_ value: String) -> Bool {
        let parts = value.components(separatedBy: ".")
        return parts.count == 3 && parts.allSatisfy { number($0) != nil }
    }

    private static func hex(_ value: String, bytes: Int) -> Data? {
        let source = Array(value.utf8)
        guard source.count == bytes * 2,
              source.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { return nil }
        func nibble(_ byte: UInt8) -> UInt8 { byte <= 57 ? byte - 48 : byte - 87 }
        return Data(stride(from: 0, to: source.count, by: 2).map {
            nibble(source[$0]) * 16 + nibble(source[$0 + 1])
        })
    }
}
