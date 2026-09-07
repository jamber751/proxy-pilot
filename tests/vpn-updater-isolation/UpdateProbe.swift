import AppKit
import Sparkle

// Information-only worker for the disposable host. No install/download API.
final class ProbeDelegate: NSObject, SPUUpdaterDelegate {
    var found = false
    func updater(_ updater: SPUUpdater, didFindValidUpdate item: SUAppcastItem) { found = true }
    func updater(_ updater: SPUUpdater, didFinishUpdateCycleFor updateCheck: SPUUpdateCheck, error: Error?) {
        if found && error == nil { print("VALID_UPDATE_FOR_HOST"); exit(0) }
        print("REJECTED_OR_UNAVAILABLE"); exit(2)
    }
}

@main
enum UpdateProbe {
    static func main() throws {
        guard CommandLine.arguments.count == 1 else { exit(64) }
        // Resolve one fixed enclosing test bundle; callers cannot supply paths.
        let hostURL = Bundle.main.bundleURL.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        guard let host = Bundle(url: hostURL),
              host.bundleIdentifier?.hasPrefix("kz.documentolog.proxypilot.isolationtest.") == true,
              Bundle.main.bundleIdentifier == host.bundleIdentifier! + ".updater",
              let feed = host.object(forInfoDictionaryKey: "SUFeedURL") as? String,
              let url = URL(string: feed), url.scheme == "http", url.host == "127.0.0.1" else { exit(64) }
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let delegate = ProbeDelegate()
        let driver = SPUStandardUserDriver(hostBundle: host, delegate: nil)
        let updater = SPUUpdater(hostBundle: host, applicationBundle: host, userDriver: driver, delegate: delegate)
        try updater.start()
        updater.checkForUpdateInformation()
        DispatchQueue.main.asyncAfter(deadline: .now() + 12) { print("TIMEOUT"); exit(3) }
        withExtendedLifetime((updater, delegate, driver)) { app.run() }
    }
}
