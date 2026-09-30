import Darwin
import Foundation

@main enum VPNServiceMain {
    static func main() {
        if let status = VPNEngineSupervisorEntry.runIfRequested(arguments: CommandLine.arguments) {
            exit(status)
        }
        #if VPN_RECOVERY_DAEMON_TESTING
        if let status = VPNRecoveryDaemonEntryTestHarness.runIfRequested(
            arguments: CommandLine.arguments) {
            exit(status)
        }
        #endif
        #if VPN_RECOVERY_DAEMON_ENTRY
        if let status = VPNSelectedCandidateRecoveryDaemonEntry.runIfRequested(
            arguments: CommandLine.arguments) {
            exit(status)
        }
        #endif
        #if !VPN_RECOVERY_DAEMON_TESTING
        if CommandLine.arguments.dropFirst().contains(
                VPNUpdateBrokerDaemon.entryArgument) {
            do {
                try VPNUpdateBrokerDaemon.runSystem(
                    arguments: CommandLine.arguments)
                exit(0)
            } catch {
                FileHandle.standardError.write(Data(
                    "ProxyPilot VPN update broker could not start.\n".utf8))
                exit(77)
            }
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
