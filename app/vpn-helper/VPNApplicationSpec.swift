import Foundation

enum VPNApplicationSpecError: Error { case invalid, tooLarge }

/// The complete, non-secret configuration the owner asks the helper to apply.
/// Profile bytes are addressed by their SHA-256 digest and credentials are
/// deliberately absent. The helper decodes and validates this value again.
struct VPNApplicationSpec: Codable, Equatable {
    static let schema = 1
    static let maximumBytes = 128 * 1024

    let schemaVersion: Int
    let revision: UInt64
    let profileSHA256: String
    let resources: [VPNResource]
    let corporateDNS: [String]
    let authentication: VPNAuthentication

    init(revision: UInt64, profileSHA256: String, resources: [VPNResource],
         corporateDNS: [String], authentication: VPNAuthentication) throws {
        self.schemaVersion = Self.schema
        self.revision = revision
        self.profileSHA256 = profileSHA256
        self.resources = resources
        self.corporateDNS = corporateDNS
        self.authentication = authentication
        try validate()
    }

    func validate() throws {
        guard schemaVersion == Self.schema, revision > 0,
              profileSHA256.utf8.count == 64,
              profileSHA256.allSatisfy({ $0.isASCII && ($0.isNumber || ("a"..."f").contains(String($0))) }),
              !resources.isEmpty, resources.count <= 1000, corporateDNS.count <= 4,
              Set(resources.map { $0.id }).count == resources.count,
              Set(resources.map { $0.address }).count == resources.count
        else { throw VPNApplicationSpecError.invalid }
        for resource in resources { try resource.validate() }
        try authentication.validate()
        var dns = VPNConfiguration()
        try dns.setDNS(corporateDNS)
        guard dns.corporateDNS == corporateDNS else { throw VPNApplicationSpecError.invalid }
    }

    func encoded() throws -> Data {
        try validate()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(self)
        guard data.count <= Self.maximumBytes else { throw VPNApplicationSpecError.tooLarge }
        return data
    }

    static func decodeCanonical(_ data: Data) throws -> VPNApplicationSpec {
        guard !data.isEmpty, data.count <= maximumBytes else { throw VPNApplicationSpecError.tooLarge }
        let value = try JSONDecoder().decode(Self.self, from: data)
        try value.validate()
        guard try value.encoded() == data else { throw VPNApplicationSpecError.invalid }
        return value
    }
}

enum VPNCredentialKind: UInt8, Codable {
    case vpnPassword = 1
    case privateKeyPassword = 2
}

/// Public metadata for one credential request. It contains no credential.
struct VPNCredentialChallenge: Codable, Equatable {
    static let schema = 1
    let schemaVersion: Int
    let generation: UInt64
    let identifier: UUID
    let kind: VPNCredentialKind

    init(generation: UInt64, identifier: UUID = UUID(), kind: VPNCredentialKind) {
        schemaVersion = Self.schema
        self.generation = generation
        self.identifier = identifier
        self.kind = kind
    }

    func encoded() throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }

    static func decodeCanonical(_ data: Data) throws -> Self {
        guard data.count <= 1024 else { throw VPNApplicationSpecError.tooLarge }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.schemaVersion == schema, value.generation > 0,
              try value.encoded() == data else { throw VPNApplicationSpecError.invalid }
        return value
    }
}

/// A credential response is a bounded transient wire value. Callers must not
/// encode it through Codable or place it in a store. The helper consumes the
/// challenge before examining the secret, so retries and late replies fail.
struct VPNCredentialResponse {
    static let maximumSecretBytes = 4096
    let challenge: VPNCredentialChallenge
    var secret: Data

    func encoded() throws -> Data {
        guard !secret.isEmpty, secret.count <= Self.maximumSecretBytes else {
            throw VPNApplicationSpecError.invalid
        }
        let metadata = try challenge.encoded()
        guard metadata.count <= Int(UInt16.max) else { throw VPNApplicationSpecError.invalid }
        var result = Data([1, UInt8(metadata.count >> 8), UInt8(metadata.count & 0xff)])
        result.append(metadata)
        result.append(secret)
        return result
    }

    static func decode(_ data: Data) throws -> Self {
        guard data.count >= 4, data[0] == 1 else { throw VPNApplicationSpecError.invalid }
        let count = Int(data[1]) << 8 | Int(data[2])
        guard count > 0, data.count > 3 + count,
              data.count - 3 - count <= maximumSecretBytes else { throw VPNApplicationSpecError.invalid }
        let challenge = try VPNCredentialChallenge.decodeCanonical(data.subdata(in: 3..<(3 + count)))
        return Self(challenge: challenge, secret: data.subdata(in: (3 + count)..<data.count))
    }
}
