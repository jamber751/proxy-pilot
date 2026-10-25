import Foundation

@main enum RescueFailureCategoryChecks {
    struct PrivateError: Error, CustomStringConvertible {
        var description: String { fatalError("Error descriptions must not be evaluated") }
    }
    static func main() {
        guard CommandLine.arguments.count == 2 else { exit(64) }
        let cases: [(Error, String)]
        switch CommandLine.arguments[1] {
        case "result":
            cases = [(VPNInstalledUpdateResultError.deadlineExceeded, "installedResultTimeout"),
                     (VPNInstalledUpdateResultError.changed, "installedResultChanged"),
                     (VPNInstalledUpdateResultError.childFailed, "installedResultChild"),
                     (VPNInstalledUpdateResultError.spawnFailed, "installedResultSpawn"),
                     (VPNInstalledUpdateResultError.invalidState, "installedResultState"),
                     (VPNInstalledUpdateResultError.requiresRoot, "installedResultState")]
        case "application":
            cases = [(VPNInstalledApplicationError.requiresRoot, "installedApplication"),
                     (VPNInstalledApplicationError.unsafeStorage, "installedApplication"),
                     (VPNInstalledApplicationError.wrongProcess, "installedApplication")]
        case "unknown": cases = [(PrivateError(), "other")]
        default: exit(64)
        }
        for (error, expected) in cases {
            guard VPNRescueSystemEntry.testFailureCategory(error) == expected else { exit(1) }
        }
        print("closed rescue failure categories passed")
    }
}
