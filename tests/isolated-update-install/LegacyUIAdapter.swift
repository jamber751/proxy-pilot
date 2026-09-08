import AppKit
import Sparkle

/// Only the native UI adapter is substituted in automated migration tests.
/// The UpdateModel itself is compiled from the pinned 1.5.1 release source;
/// the real SPUUpdater still runs inside that un-hardened frontend process.
final class LegacyUIAdapter {
    let updater: SPUUpdater
    private let driver: InstallDriver

    init(startingUpdater: Bool, updaterDelegate: SPUUpdaterDelegate, userDriverDelegate: SPUStandardUserDriverDelegate) {
        precondition(!startingUpdater)
        driver = InstallDriver(host: Bundle.main, delegate: userDriverDelegate)
        updater = SPUUpdater(hostBundle: Bundle.main, applicationBundle: Bundle.main, userDriver: driver, delegate: updaterDelegate)
    }

    func startUpdater() { try! updater.start() }
    func checkForUpdates(_ sender: Any?) { updater.checkForUpdates() }
}
