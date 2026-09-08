import Darwin
import Foundation

@main enum VPNServiceMain {
    static func main() {
        do { try VPNHelperDaemon.runSystem(arguments: CommandLine.arguments) }
        catch {
            // No payloads, keys, account names or personal paths in launchd logs.
            FileHandle.standardError.write(Data("ProxyPilot VPN support could not start.\n".utf8))
            exit(77)
        }
    }
}
