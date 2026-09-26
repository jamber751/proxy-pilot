import Darwin
import Foundation

@main enum VPNServiceMain {
    static func main() {
        #if VPN_RECOVERY_DAEMON_ENTRY
        if let status = VPNSelectedCandidateRecoveryDaemonEntry.runIfRequested(
            arguments: CommandLine.arguments) {
            exit(status)
        }
        #endif
        do { try VPNHelperDaemon.runSystem(arguments: CommandLine.arguments) }
        catch {
            // No payloads, keys, account names or personal paths in launchd logs.
            FileHandle.standardError.write(Data("ProxyPilot VPN support could not start.\n".utf8))
            exit(77)
        }
    }
}
