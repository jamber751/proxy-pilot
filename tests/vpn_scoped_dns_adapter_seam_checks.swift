import Foundation

enum ScopedDNSSeamCheckError: Error { case failed(String) }

@main enum VPNScopedDNSAdapterSeamChecks {
    static func require(_ value: @autoclosure () -> Bool, _ message: String) throws {
        guard value() else { throw ScopedDNSSeamCheckError.failed(message) }
    }

    static func scope(_ domain: String = "corp.example") throws -> VPNDNSResolverScope {
        let binding = try JSONDecoder().decode(VPNTunnelRouteBinding.self,
            from: Data(#"{"interfaceIndex":42,"interfaceName":"utun7"}"#.utf8))
        return VPNDNSResolverScope(domain: domain,
            servers: [try VPNRoutePrefix(resource: VPNResource(address: "10.44.0.53"))],
            tunnelInterface: binding)
    }

    static func codec() throws {
        let value = try VPNScopedDNSCodec.record(scope: scope(), generation: 8,
                                                  revision: 13, index: 2)
        try require(value.dynamicStoreKey ==
            "State:/Network/Service/kz.documentolog.proxypilot.vpn.8.13.2/DNS", "key")
        try require(value.serverAddresses == ["10.44.0.53"], "servers")
        try require(value.supplementalMatchDomains == ["corp.example"], "domain")
        try require(value.supplementalMatchOrders == [120_002], "order")
        try require(value.interfaceName == "utun7", "interface")
        try value.validate(scope: scope(), generation: 8, revision: 13, index: 2)
        print("codec passed")
    }

    static func decisions() throws {
        let expected = try VPNScopedDNSCodec.record(scope: scope(), generation: 8,
                                                     revision: 13, index: 0)
        let fresh = try VPNScopedDNSControllerSeam.installDecision(
            expected: expected, observed: .absent)
        try require(fresh == .addExpected, "fresh add")
        let owned = VPNScopedDNSObservation(record: expected, ownedByThisSession: true)
        let resumed = try VPNScopedDNSControllerSeam.installDecision(
            expected: expected, observed: owned)
        try require(resumed == .alreadyInstalledByThisSession, "owned resume")
        let remove = try VPNScopedDNSControllerSeam.removeDecision(
            expected: expected, observed: owned)
        try require(remove == .removeExact, "owned remove")
        let absent = try VPNScopedDNSControllerSeam.removeDecision(
            expected: expected, observed: .absent)
        try require(absent == .alreadyAbsent, "crash cleanup")
        print("decisions passed")
    }

    static func rejected(_ mode: String) throws {
        let expected = try VPNScopedDNSCodec.record(scope: scope(), generation: 8,
                                                     revision: 13, index: 0)
        let other = try VPNScopedDNSCodec.record(scope: scope("other.example"), generation: 8,
                                                  revision: 13, index: 0)
        let observation: VPNScopedDNSObservation
        if mode == "equal-foreign" {
            observation = VPNScopedDNSObservation(record: expected, ownedByThisSession: false)
        } else if mode == "replacement" {
            observation = VPNScopedDNSObservation(record: other, ownedByThisSession: true)
        } else { exit(64) }
        do {
            _ = try VPNScopedDNSControllerSeam.removeDecision(expected: expected,
                                                               observed: observation)
            throw ScopedDNSSeamCheckError.failed("foreign state accepted")
        } catch VPNScopedDNSAdapterError.occupiedByForeignState {}
        print("\(mode) rejected")
    }

    static func main() throws {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        switch CommandLine.arguments[1] {
        case "codec": try codec()
        case "decisions": try decisions()
        default: try rejected(CommandLine.arguments[1])
        }
    }
}
