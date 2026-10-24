#if VPN_RESCUE_SYSTEM_ENTRY && VPN_EXPLICIT_RESCUE && VPN_RESCUE_PREPARATION
import Darwin

@main enum VPNRescueMain {
    static func main() { exit(VPNRescueSystemEntry.run(arguments: CommandLine.arguments)) }
}
#endif
