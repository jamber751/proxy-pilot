import AppKit
import Sparkle

// Automated choices are confined to this uniquely identified disposable host.
// The production worker never uses this driver or grants install consent itself.
final class InstallDriver: NSObject, SPUUserDriver {
    let directory: URL
    let mode: String
    weak var delegate: SPUStandardUserDriverDelegate?

    init(host: Bundle, delegate: SPUStandardUserDriverDelegate) {
        directory = URL(fileURLWithPath: host.object(forInfoDictionaryKey: "TestDirectory") as! String)
        mode = host.object(forInfoDictionaryKey: "TestMode") as! String
        self.delegate = delegate
        super.init()
        record("driver-start pid=\(getpid()) version=\(host.object(forInfoDictionaryKey: "CFBundleVersion")!)")
    }

    func record(_ event: String) {
        let url = directory.appendingPathComponent("worker.events")
        if !FileManager.default.fileExists(atPath: url.path) { FileManager.default.createFile(atPath: url.path, contents: nil) }
        let file = try! FileHandle(forWritingTo: url)
        file.seekToEndOfFile(); file.write(Data((event + "\n").utf8)); file.closeFile()
    }

    func show(_ request: SPUUpdatePermissionRequest, reply: @escaping (SUUpdatePermissionResponse) -> Void) {
        reply(SUUpdatePermissionResponse(automaticUpdateChecks: false, sendSystemProfile: false))
    }
    func showUserInitiatedUpdateCheck(cancellation: @escaping () -> Void) { record("checking") }
    func showUpdateFound(with appcastItem: SUAppcastItem, state: SPUUserUpdateState, reply: @escaping (SPUUserUpdateChoice) -> Void) {
        precondition(state.userInitiated)
        record("found \(appcastItem.displayVersionString)")
        delegate?.standardUserDriverWillHandleShowingUpdate?(true, forUpdate: appcastItem, state: state)
        if mode == "cancel-offer" { record("cancel-offer"); reply(.dismiss) }
        else { reply(.install) }
    }
    func showUpdateReleaseNotes(with downloadData: SPUDownloadData) { record("release-notes") }
    func showUpdateReleaseNotesFailedToDownloadWithError(_ error: Error) { record("release-notes-error") }
    func showUpdateNotFoundWithError(_ error: Error, acknowledgement: @escaping () -> Void) {
        record("not-found"); acknowledgement()
    }
    func showUpdaterError(_ error: Error, acknowledgement: @escaping () -> Void) {
        var current: NSError? = error as NSError
        while let value = current {
            record("error \(value.domain) \(value.code)")
            current = value.userInfo[NSUnderlyingErrorKey] as? NSError
        }
        acknowledgement()
    }
    func showDownloadInitiated(cancellation: @escaping () -> Void) { record("download") }
    func showDownloadDidReceiveExpectedContentLength(_ expectedContentLength: UInt64) {}
    func showDownloadDidReceiveData(ofLength length: UInt64) {}
    func showDownloadDidStartExtractingUpdate() { record("extract") }
    func showExtractionReceivedProgress(_ progress: Double) {}
    func showReady(toInstallAndRelaunch reply: @escaping (SPUUserUpdateChoice) -> Void) {
        record("ready")
        // Dismiss here would allow installation when the host quits. Skip is
        // Sparkle's documented cancellation at this stage, not deferred install.
        if mode == "cancel-ready" { record("cancel-ready"); reply(.skip) }
        else { reply(.install) }
    }
    func showInstallingUpdate(withApplicationTerminated applicationTerminated: Bool, retryTerminatingApplication: @escaping () -> Void) {
        record("installing terminated=\(applicationTerminated)")
    }
    func showUpdateInstalledAndRelaunched(_ relaunched: Bool, acknowledgement: @escaping () -> Void) {
        record("installed relaunched=\(relaunched)"); acknowledgement()
    }
    func dismissUpdateInstallation() {
        record("dismiss")
        delegate?.standardUserDriverWillFinishUpdateSession?()
    }
}

#if !LEGACY_UPDATER_TESTING
@main enum TestWorker {
    static func main() throws {
        guard geteuid() != 0, let host = UpdateWorker.enclosingHost(),
              let feed = host.object(forInfoDictionaryKey: "SUFeedURL") as? String,
              let url = URL(string: feed), url.scheme == "http", url.host == "127.0.0.1" else { exit(64) }
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let worker = UpdateWorker()
        try worker.start(host: host)
        let timeout = host.object(forInfoDictionaryKey: "TestMode") as? String == "native" ? 190.0 : 50.0
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { exit(3) }
        withExtendedLifetime(worker) { app.run() }
    }
}
#endif
