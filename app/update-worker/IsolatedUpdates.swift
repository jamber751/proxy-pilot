import AppKit
import SwiftUI
import Security

#if ISOLATED_UPDATER
/// Candidate frontend: no Sparkle import/linkage and no updater-to-VPN relay.
/// Enable only in a staging build until installation/relaunch is accepted.
final class UpdateModel: NSObject, ObservableObject {
    @Published private(set) var canCheck = false
    @Published private(set) var automaticChecks = true
    @Published private(set) var availableVersion: String?
    @Published private(set) var isPreview = false
    @Published private(set) var sessionInProgress = false
    @Published private(set) var jointUpdateAvailable = false
    let currentVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—"
    var onPresent: (() -> Void)?
    var onAbort: (() -> Void)?
    var prepareRelaunch: ((@escaping () -> Void) -> Void)?
    private var process: Process?
    private var channel: UpdateChannel?
    private var generation = UUID()
    private var relaunchToken: UUID?
    private var relaunchSent = false
    private var failed = false
    private var receivedState = false
    private var checkAfterStart = false
    var canChangeAutomaticChecks: Bool { !isPreview && !failed && receivedState }

    func start(preview: Bool) {
        isPreview = preview
        guard !preview, process == nil else { return }
        launchWorker()
    }

    private func launchWorker() {
        canCheck = false; failed = false; receivedState = false
        generation = UUID()
        let run = generation
        // No caller-supplied path, arguments, inherited DYLD_* or command shell.
        let worker = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/ProxyPilot Updater.app")
        var code: SecStaticCode?
        guard geteuid() != 0, getuid() == geteuid(),
              SecStaticCodeCreateWithPath(worker as CFURL, [], &code) == errSecSuccess,
              let code = code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures), nil) == errSecSuccess else {
            unavailable(run); return
        }
        let child = Process()
        child.executableURL = worker.appendingPathComponent("Contents/MacOS/ProxyPilotUpdater")
        child.arguments = []
        child.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        let incoming = Pipe(), outgoing = Pipe()
        child.standardInput = outgoing
        child.standardOutput = incoming
        child.standardError = FileHandle.nullDevice
        do {
            let connection = try UpdateChannel(read: incoming.fileHandleForReading.fileDescriptor,
                                               write: outgoing.fileHandleForWriting.fileDescriptor,
                                               receivesCommands: false, receive: { [weak self] message in
                DispatchQueue.main.async { self?.receive(message, run: run) }
            }, disconnected: { [weak self] in
                DispatchQueue.main.async { self?.unavailable(run) }
            })
            child.terminationHandler = { [weak self] _ in
                DispatchQueue.main.async { self?.unavailable(run) }
            }
            process = child; channel = connection
            try child.run()
            // Close every local original. The channel owns duplicates; the
            // child owns only its inherited stdin/stdout. EOF is meaningful.
            incoming.fileHandleForWriting.closeFile(); outgoing.fileHandleForReading.closeFile()
            incoming.fileHandleForReading.closeFile(); outgoing.fileHandleForWriting.closeFile()
            connection.start()
            DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
                guard let self = self, self.generation == run, !self.receivedState else { return }
                self.unavailable(run)
            }
        } catch {
            incoming.fileHandleForWriting.closeFile(); outgoing.fileHandleForReading.closeFile()
            incoming.fileHandleForReading.closeFile(); outgoing.fileHandleForWriting.closeFile()
            unavailable(run)
        }
    }

    func check() {
        guard canCheck, !isPreview else { return }
        if failed {
            checkAfterStart = true
            launchWorker()
            return
        }
        canCheck = false; sessionInProgress = true
        onPresent?()
        channel?.send(.check)
    }

    var checkTitle: String {
        if isPreview { return "Недоступно в превью" }
        if failed { return "Повторить проверку" }
        if !canCheck { return sessionInProgress ? "Проверяем…" : "Подождите…" }
        return availableVersion.map { "Обновить до \($0)" } ?? "Проверить обновления"
    }

    func setAutomaticChecks(_ enabled: Bool) {
        guard canChangeAutomaticChecks else { return }
        channel?.send(.automatic(enabled))
    }

    private func receive(_ message: UpdateMessage, run: UUID) {
        guard generation == run, !failed else { return }
        switch message {
        case .state(let state):
            receivedState = true
            canCheck = state.canCheck; automaticChecks = state.automatic
            sessionInProgress = state.inProgress; availableVersion = state.availableVersion
            jointUpdateAvailable = state.jointUpdate
            if checkAfterStart && canCheck { checkAfterStart = false; check() }
        case .present: onPresent?()
        case .aborted:
            relaunchToken = nil; relaunchSent = false; onAbort?()
        case .prepare(let token):
            guard relaunchToken == nil, !relaunchSent, receivedState, sessionInProgress else { unavailable(run); return }
            relaunchToken = token
            // Only quiesce this app's existing unprivileged update lifecycle.
            // Never add root/VPN actions to a message from this worker.
            let completion: () -> Void = { [weak self] in
                DispatchQueue.main.async {
                    guard let self = self, self.generation == run, self.relaunchToken == token, !self.relaunchSent, !self.failed else { return }
                    self.relaunchSent = true
                    self.channel?.send(.resume(token))
                }
            }
            if let prepareRelaunch = prepareRelaunch { prepareRelaunch(completion) }
            else { completion() }
        case .failed: unavailable(run)
        default: unavailable(run)
        }
    }

    private func unavailable(_ run: UUID) {
        guard generation == run, !failed else { return }
        failed = true; canCheck = true; sessionInProgress = false; availableVersion = nil
        jointUpdateAvailable = false
        relaunchToken = nil; relaunchSent = false; checkAfterStart = false
        channel?.close(); channel = nil
        if let child = process, child.isRunning { child.terminate() }
        process = nil
        onAbort?()
    }

    deinit {
        channel?.close()
        // EOF lets a worker finish an acknowledged Sparkle handoff. Killing it
        // unconditionally here would race installation when the host quits.
    }
}
#endif
