import Foundation

@main enum VPNBridgeBypassChecks {
    static func snapshot(_ addresses: [String], revision: UInt64 = 3,
                         generation: UInt64 = 7, phase: VPNTunnelPhase = .connected,
                         dns: [String] = []) throws -> VPNTunnelSnapshot {
        let spec = try VPNApplicationSpec(revision: revision,
            profileSHA256: String(repeating: "a", count: 64),
            resources: try addresses.map { try VPNResource(address: $0) },
            corporateDNS: dns, authentication: VPNAuthentication(mode: .certificate))
        let active = VPNValidatedApplication(spec: spec, requiresVPNCredentials: false,
                                             requiresPrivateKeyPassword: false)
        return VPNTunnelSnapshot(schemaVersion: 2, generation: generation,
            desiredEnabled: phase != .off, phase: phase, active: active, pending: nil,
            challenge: nil, attempt: phase == .connected
                ? VPNConnectAttemptBinding(generation: generation, application: active) : nil)
    }

    static func main() throws {
        switch CommandLine.arguments[1] {
        case "exact":
            let value = try VPNBridgeBypass(snapshot: snapshot([
                "198.51.100.7", "10.20.3.0/24", "2001:db8::7", "2001:db8:1::/64"]))
            precondition(value.generation == 7 && value.revision == 3)
            precondition(value.matchers == ["10.20.3.0/24", "198.51.100.7",
                "2001:db8:1::/64", "2001:db8::7"])
        case "merge":
            let value = try VPNBridgeBypass(snapshot: snapshot(["198.51.100.7", "10.20.0.0/16"]))
            let user = "localhost, .local,198.51.100.7,custom.example,"
            let merged = value.merging(with: user)
            precondition(merged == user + "10.20.0.0/16")
            precondition(value.merging(with: merged) == merged)
            precondition(value.merging(with: "") == "10.20.0.0/16,198.51.100.7")
        case "off":
            let value = try VPNBridgeBypass(snapshot: snapshot(["198.51.100.7"], phase: .off))
            precondition(value.matchers.isEmpty && value.revision == nil)
            precondition(value.merging(with: "unchanged.example") == "unchanged.example")
        case "failure":
            do {
                _ = try VPNBridgeBypass(snapshot: snapshot(["198.51.100.7"], phase: .failed))
                fatalError("failed state accepted as cleanup")
            } catch VPNBridgeBypassError.unavailable {}
        case "invalid":
            do {
                _ = try VPNBridgeBypass(snapshot: snapshot(["198.51.100.7"], generation: 0))
                fatalError("zero generation accepted")
            } catch VPNBridgeBypassError.invalidSnapshot {}
        case "unsupported":
            for (resources, dns) in [(["internal.example"], [String]()),
                                     (["198.51.100.7"], ["10.20.0.53"])] {
                do {
                    _ = try VPNBridgeBypass(snapshot: snapshot(resources, dns: dns))
                    fatalError("unsupported intent accepted")
                } catch VPNBridgeBypassError.unsupportedResources {}
            }
        case "replacement":
            let old = try VPNBridgeBypass(snapshot: snapshot(["198.51.100.7"]))
            let next = try VPNBridgeBypass(snapshot: snapshot(["203.0.113.8"], revision: 4,
                                                            generation: 8))
            precondition(old != next)
            precondition(next.merging(with: "custom.example") == "custom.example,203.0.113.8")
        default: fatalError("unknown case")
        }
        print("bridge bypass passed")
    }
}
