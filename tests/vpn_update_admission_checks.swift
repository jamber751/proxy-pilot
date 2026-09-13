import Foundation

@main enum AdmissionChecks {
    static func main() {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        let base = URL(fileURLWithPath: CommandLine.arguments[1])
        let decision = VPNUpdateAdmission.inspect(applicationSupport: base.appendingPathComponent("support").path,
                                                   launchDaemons: base.appendingPathComponent("daemons").path)
        print(decision.rawValue)
        if let error = decision.error {
            precondition(error.domain == "kz.documentolog.proxypilot.update-admission")
            precondition(!error.localizedDescription.contains(base.path))
            precondition(error.localizedRecoverySuggestion != nil)
        }
    }
}
