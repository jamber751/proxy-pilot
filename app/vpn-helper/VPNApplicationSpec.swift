import CryptoKit
import Foundation

enum VPNApplicationSpecError: Error { case invalid, tooLarge }

/// Complete listing of this ONE retained exact-host namespace. It is not the
/// inventory of legacy/static CIDR routes, an active-route proof, or permission
/// to start a bridge/release DNS answers. A new daemon has a different bootID.
struct VPNRetainedProtectionInventory: Codable, Equatable {
    static let maximumBytes = 256 * 1024
    static let maximumPrefixes = 4096
    static let namespace = "retained-exact-hosts-v1"
    let schemaVersion: Int
    let scope: String
    let bootID: UUID
    let prefixes: [String]

    init(bootID: UUID, prefixes: [String]) throws {
        schemaVersion=1;scope=Self.namespace;self.bootID=bootID;self.prefixes=prefixes
        try validate()
    }
    func validate() throws {
        guard schemaVersion==1,scope==Self.namespace,prefixes.count<=Self.maximumPrefixes,
              prefixes==prefixes.sorted(),Set(prefixes).count==prefixes.count else { throw VPNApplicationSpecError.invalid }
        for value in prefixes {
            let parts=value.split(separator:"/",omittingEmptySubsequences:false)
            guard parts.count==2 else { throw VPNApplicationSpecError.invalid }
            let resource=try VPNResource(address:String(parts[0]))
            guard resource.address==parts[0],
                  (resource.kind == .ipv4 && parts[1]=="32") || (resource.kind == .ipv6 && parts[1]=="128") else {
                throw VPNApplicationSpecError.invalid
            }
        }
    }
    func encoded() throws -> Data {
        try validate()
        let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys]
        let data=try encoder.encode(self)
        guard data.count<=Self.maximumBytes else { throw VPNApplicationSpecError.tooLarge }
        return data
    }
    static func decodeCanonical(_ data: Data) throws -> Self {
        guard !data.isEmpty,data.count<=maximumBytes else { throw VPNApplicationSpecError.tooLarge }
        let value=try JSONDecoder().decode(Self.self,from:data)
        try value.validate()
        guard try value.encoded()==data else { throw VPNApplicationSpecError.invalid }
        return value
    }
}

/// Complete observation of the CURRENT root bridge sources, including legacy
/// journal prefixes. It is not an active-route proof or a future-output lease.
struct VPNBridgeRootInventory: Codable, Equatable {
    static let maximumBytes = 512 * 1024
    static let maximumMatchers = 7200 // retained4096 + active/pending2008 + journal1004
    static let namespace = "root-bridge-sources-v1"
    let schemaVersion: Int
    let scope: String
    let bootID: UUID
    let stateSHA256: String
    let routeJournalSHA256: String?
    let matchers: [String]

    init(bootID: UUID, stateSHA256: String, routeJournalSHA256: String?, matchers: [String]) throws {
        schemaVersion=1;scope=Self.namespace;self.bootID=bootID
        self.stateSHA256=stateSHA256;self.routeJournalSHA256=routeJournalSHA256;self.matchers=matchers
        try validate()
    }
    static func canonical(_ address: String) throws -> String {
        let resource=try VPNResource(address:address)
        switch resource.kind {
        case .domain: throw VPNApplicationSpecError.invalid
        case .ipv4: return resource.address+"/32"
        case .ipv6: return resource.address+"/128"
        case .network4,.network6: return resource.address
        }
    }
    func validate() throws {
        func hash(_ value: String) -> Bool {
            value.utf8.count==64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
        }
        guard schemaVersion==1,scope==Self.namespace,hash(stateSHA256),
              routeJournalSHA256.map(hash) ?? true,matchers.count<=Self.maximumMatchers,
              matchers==matchers.sorted(),Set(matchers).count==matchers.count else { throw VPNApplicationSpecError.invalid }
        for value in matchers { guard try Self.canonical(value)==value else { throw VPNApplicationSpecError.invalid } }
    }
    func encoded() throws -> Data {
        try validate();let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys]
        let data=try encoder.encode(self)
        guard data.count<=Self.maximumBytes else { throw VPNApplicationSpecError.tooLarge };return data
    }
    static func decodeCanonical(_ data: Data) throws -> Self {
        guard !data.isEmpty,data.count<=maximumBytes else { throw VPNApplicationSpecError.tooLarge }
        let value=try JSONDecoder().decode(Self.self,from:data)
        guard try value.encoded()==data else { throw VPNApplicationSpecError.invalid };return value
    }
}

/// One bounded first-listen conversation. The nonce binds its acknowledgement
/// to this offer, even when the catalogue is identical to a previous boot.
struct VPNBridgeBootstrapOffer: Codable, Equatable {
    let nonce: UUID
    let inventory: VPNBridgeRootInventory
    init(inventory: VPNBridgeRootInventory) { nonce=UUID();self.inventory=inventory }
    func encoded() throws -> Data {
        try inventory.validate()
        let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys]
        let data=try encoder.encode(self)
        guard data.count<=VPNBridgeRootInventory.maximumBytes+256 else { throw VPNApplicationSpecError.tooLarge };return data
    }
    static func decodeCanonical(_ data: Data) throws -> Self {
        guard !data.isEmpty,data.count<=VPNBridgeRootInventory.maximumBytes+256 else { throw VPNApplicationSpecError.tooLarge }
        let value=try JSONDecoder().decode(Self.self,from:data)
        guard try value.encoded()==data else { throw VPNApplicationSpecError.invalid };return value
    }
    func acknowledgement() throws -> [UInt8] {
        Array("PPVNBR01".utf8)+Array(SHA256.hash(data:try encoded()))
    }
}

/// Root must hold its retained journal mutation lock throughout body, including
/// the final reply. verify checks this exact source catalogue inside that lock.
/// This is first-listen custody, not ongoing DNS answer/route authority.
protocol VPNBridgeBootstrapSource: AnyObject {
    func withInventory(deadline: DispatchTime,
                       body: (Data, () throws -> Void) throws -> Void) throws
}

/// Capabilities implemented by the currently shipped, route-only helper.
/// Domain resources require per-domain DNS selection and the complete protected
/// answer/route handoff. The native DNS building blocks are not yet wired into
/// that runtime, so domain configuration remains unavailable here.
enum VPNRuntimeCapabilityError: Error, Equatable {
    case splitDNSUnavailable
}

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

    /// Fails before OpenVPN is spawned when the saved intent needs a system
    /// capability that is not present in this build. Saving and editing such a
    /// configuration remains allowed, so a later Network Extension build can
    /// use it without migration or data loss.
    func validateCurrentRuntimeCapability() throws {
        guard corporateDNS.isEmpty,
              !resources.contains(where: { $0.kind == .domain }) else {
            throw VPNRuntimeCapabilityError.splitDNSUnavailable
        }
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
