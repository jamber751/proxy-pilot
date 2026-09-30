import Foundation

@main enum VPNRuntimeCapabilityChecks {
    static let digest = String(repeating: "a", count: 64)
    static let authentication = try! VPNAuthentication(mode: .certificate)

    static func spec(_ addresses: [String], dns: [String] = []) throws -> VPNApplicationSpec {
        try VPNApplicationSpec(revision: 1, profileSHA256: digest,
            resources: try addresses.map { try VPNResource(address: $0) },
            corporateDNS: dns, authentication: authentication)
    }

    static func accepted(_ addresses: [String]) throws {
        try spec(addresses).validateCurrentRuntimeCapability()
    }

    static func rejected(_ addresses: [String], dns: [String] = []) throws {
        do {
            try spec(addresses, dns: dns).validateCurrentRuntimeCapability()
            fatalError("unsupported runtime intent was accepted")
        } catch VPNRuntimeCapabilityError.splitDNSUnavailable {}
    }

    static func main() throws {
        try accepted(["10.24.0.8", "10.30.0.0/16", "2001:db8::5", "2001:db8:10::/64"])
        try rejected(["intranet.example.com"])
        try rejected(["10.24.0.8"], dns: ["10.24.0.53"])
        try rejected(["intranet.example.com", "10.24.0.0/16"], dns: ["10.24.0.53"])
        print("runtime capability gate passed")
    }
}
