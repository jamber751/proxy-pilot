import Foundation

/// Opt-in local compatibility check. Outputs counts and booleans only; never
/// copies the profile, prints its contents, persists settings or connects.
/// Build with VPNConfiguration.swift and VPNProfileImporter.swift, then pass
/// the explicitly authorized file path as the sole argument.
@main struct CheckVPNProfile {
    static func main() {
        guard CommandLine.arguments.count == 2 else { print("Usage: check-vpn-profile <file.ovpn>"); exit(2) }
        let result: [String: Any]
        do {
            let profile = try VPNProfileImporter.inspect(files: [URL(fileURLWithPath: CommandLine.arguments[1])])
            result = ["structural_import_accepted": true,
                      "requires_credentials": profile.requiresCredentials,
                      "requires_key_password": profile.requiresKeyPassword,
                      "suggested_resource_count": profile.suggestedResources.count,
                      "suggested_dns_count": profile.suggestedDNS.count,
                      "routes_require_review": profile.hasIgnoredRoutes,
                      "network_connection_tested": false]
        } catch {
            result = ["structural_import_accepted": false, "error": "Profile rejected; private contents withheld.",
                      "network_connection_tested": false]
        }
        if let data = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]),
           let text = String(data: data, encoding: .utf8) { print(text) }
        else { exit(2) }
        if result["structural_import_accepted"] as? Bool != true { exit(1) }
    }
}
