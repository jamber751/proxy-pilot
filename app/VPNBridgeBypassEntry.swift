import Darwin
import Foundation

/// Ordinary-user, no-GUI entry used only by the CLI shipped in the same VPN
/// bundle. Mutual helper authentication remains the source of live authority.
enum VPNBridgeBypassEntry {
    static func runIfRequested(arguments: [String]) -> Int32? {
        guard arguments.dropFirst().first == "--vpn-bridge-bypass" else { return nil }
        guard arguments.count == 2, getuid() != 0, geteuid() != 0 else { return 64 }
        do {
            let session = try VPNFrontendHelperSession.open()
            defer { session.close() }
            let overlay = try VPNBridgeBypassReader.read {
                let (status, snapshot) = try session.tunnelStatus()
                guard status == .ok, let snapshot else {
                    throw VPNBridgeBypassError.unavailable
                }
                return snapshot
            }
            print(overlay.bridgeWire)
            return 0
        } catch {
            // Never interpolate peer errors, status payloads or profile data.
            return 69
        }
    }
}
