import AppKit
import Sparkle

final class UpdateWorker: NSObject, SPUUpdaterDelegate, SPUStandardUserDriverDelegate {
    static func enclosingHost() -> Bundle? {
        let ownURL = Bundle.main.bundleURL
        let hostURL = ownURL.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        guard ownURL == hostURL.appendingPathComponent("Contents/Helpers/ProxyPilot Updater.app"),
              let host = Bundle(url: hostURL), let identifier = host.bundleIdentifier,
              Bundle.main.bundleIdentifier == identifier + ".updater" else { return nil }
        #if UPDATE_WORKER_TESTING
        guard identifier.hasPrefix("kz.documentolog.proxypilot.workercheck.") else { return nil }
        #else
        guard identifier == "kz.documentolog.proxypilot" else { return nil }
        #endif
        return host
    }

    private var updater: SPUUpdater!
    private var driver: SPUStandardUserDriver!
    private var observations: [NSKeyValueObservation] = []
    private var channel: UpdateChannel!
    private var availableVersion: String?
    private var jointDiscovery = false
    private var jointReleaseID: String?
    private var pendingInstall: (UUID, () -> Void)?
    private var handingOff = false
    private var orphaned = false
    private var jointRelaunch: JointRelaunchSentinel!
    private let updateAdmission: () -> VPNUpdateAdmission.Decision = { VPNUpdateAdmission.inspectSystem() }

    func start(host: Bundle) throws {
        jointRelaunch = JointRelaunchSentinel(parentPID: getppid())
        channel = try UpdateChannel(read: STDIN_FILENO, write: STDOUT_FILENO, receivesCommands: true,
                                    receive: { [weak self] message in
            DispatchQueue.main.async { self?.receive(message) }
        }, disconnected: { [weak self] in
            DispatchQueue.main.async {
                guard let self = self else { exit(0) }
                self.orphaned = true
                if !self.handingOff { exit(0) }
                self.jointRelaunch.frontendEOF()
                // Let Sparkle complete the already acknowledged installation,
                // but never leave an orphan updater indefinitely.
                DispatchQueue.main.asyncAfter(deadline: .now() + 120) { exit(0) }
            }
        })
        // Only the channel retains these endpoints, with CLOEXEC. Do not leak
        // them to Sparkle's installer/downloader subprocesses.
        let null = open("/dev/null", O_RDWR | O_CLOEXEC)
        guard null >= 0 else { throw UpdateWire.Failure.malformed }
        guard dup2(null, STDIN_FILENO) >= 0, dup2(null, STDOUT_FILENO) >= 0 else {
            Darwin.close(null); throw UpdateWire.Failure.malformed
        }
        if null > STDOUT_FILENO { Darwin.close(null) }
        channel.start()
        driver = SPUStandardUserDriver(hostBundle: host, delegate: self)
        updater = SPUUpdater(hostBundle: host, applicationBundle: host, userDriver: driver, delegate: self)
        observations = [
            updater.observe(\.canCheckForUpdates, options: [.new]) { [weak self] _, _ in self?.publish() },
            updater.observe(\.automaticallyChecksForUpdates, options: [.new]) { [weak self] _, _ in self?.publish() },
            updater.observe(\.sessionInProgress, options: [.new]) { [weak self] _, _ in self?.publish() }
        ]
        try updater.start()
        publish()
    }

    private func publish() {
        guard let updater = updater else { return }
        channel.send(.state(UpdateSnapshot(canCheck: updater.canCheckForUpdates,
                                            automatic: updater.automaticallyChecksForUpdates,
                                            inProgress: updater.sessionInProgress,
                                            availableVersion: availableVersion,
                                            jointUpdate: jointDiscovery && availableVersion != nil && jointReleaseID != nil,
                                            jointReleaseID: jointReleaseID)))
    }

    private func receive(_ message: UpdateMessage) {
        switch message {
        case .check:
            guard updater.canCheckForUpdates, pendingInstall == nil else { publish(); return }
            switch updateAdmission() {
            case .allowed:
                jointDiscovery = false; jointReleaseID = nil
                channel.send(.present)
                NSApp.activate(ignoringOtherApps: true)
                updater.checkForUpdates()
            case .requiresCoordinatedUpdate:
                // Discovery and signed appcast parsing only. Never invoke the
                // Sparkle downloader/installer while Broker owns replacement.
                jointDiscovery = true
                availableVersion = nil; jointReleaseID = nil
                updater.checkForUpdateInformation()
            case .inspectionFailed:
                channel.send(.aborted); publish()
            }
        case .automatic(let enabled): updater.automaticallyChecksForUpdates = enabled; publish()
        case .resume(let token):
            guard let pending = pendingInstall, pending.0 == token else { exit(65) }
            pendingInstall = nil; handingOff = true
            pending.1()
        case .armJointRelaunch(let token):
            guard jointDiscovery, availableVersion != nil, jointReleaseID != nil,
                  pendingInstall == nil,
                  !handingOff, !orphaned, jointRelaunch.arm() else { exit(65) }
            handingOff = true
            channel.send(.jointRelaunchArmed(token))
        default: exit(65)
        }
    }

    var supportsGentleScheduledUpdateReminders: Bool { true }
    func standardUserDriverShouldHandleShowingScheduledUpdate(_ update: SUAppcastItem, andInImmediateFocus immediateFocus: Bool) -> Bool { false }
    func standardUserDriverWillHandleShowingUpdate(_ handleShowingUpdate: Bool, forUpdate update: SUAppcastItem, state: SPUUserUpdateState) {
        availableVersion = update.displayVersionString; publish()
        if handleShowingUpdate { channel.send(.present) }
    }
    func standardUserDriverWillShowModalAlert() { channel.send(.present) }
    func standardUserDriverWillFinishUpdateSession() {
        if !jointDiscovery { availableVersion = nil; jointReleaseID = nil }
        publish()
        if orphaned { exit(0) }
    }
    func updater(_ updater: SPUUpdater, didAbortWithError error: Error) {
        pendingInstall = nil; handingOff = false
        channel.send(.aborted); publish()
        if orphaned { exit(0) }
    }
    func updater(_ updater: SPUUpdater, didFindValidUpdate item: SUAppcastItem) {
        guard jointDiscovery else { return }
        guard item.signingValidationStatus == .succeeded,
              Self.canonicalVersion(item.versionString) else {
            availableVersion = nil; jointReleaseID = nil; publish(); return
        }
        availableVersion = item.displayVersionString
        jointReleaseID = item.versionString
        publish()
    }
    func updaterDidNotFindUpdate(_ updater: SPUUpdater) {
        guard jointDiscovery else { return }
        availableVersion = nil
        jointReleaseID = nil
        publish()
    }

    private static func canonicalVersion(_ value: String) -> Bool {
        let parts = value.components(separatedBy: ".")
        guard parts.count == 3 else { return false }
        return parts.allSatisfy { part in
            !part.isEmpty && part.utf8.count <= 19
                && (part == "0" || !part.hasPrefix("0"))
                && part.utf8.allSatisfy { (48...57).contains($0) }
                && UInt64(part).map { $0 <= UInt64(Int64.max) } == true
        }
    }
    func updater(_ updater: SPUUpdater, shouldProceedWithUpdate updateItem: SUAppcastItem, updateCheck: SPUUpdateCheck) throws {
        // Sparkle's supported veto occurs before showing/downloading the chosen
        // update. No helper command, policy change or administrative prompt.
        // This is only an early veto, not an atomic app/helper update protocol.
        if let error = updateAdmission().error { throw error }
    }
    func updater(_ updater: SPUUpdater, shouldPostponeRelaunchForUpdate item: SUAppcastItem, untilInvokingBlock installHandler: @escaping () -> Void) -> Bool {
        guard pendingInstall == nil, !handingOff, !orphaned else { exit(65) }
        let token = UUID()
        pendingInstall = (token, installHandler)
        publish(); channel.send(.prepare(token))
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) { [weak self] in
            if self?.pendingInstall?.0 == token { exit(70) }
        }
        return true
    }
}

#if !UPDATE_WORKER_TESTING
@main
enum UpdateWorkerMain {
    static func main() {
        guard CommandLine.arguments.count == 1, geteuid() != 0, getuid() == geteuid() else { exit(64) }
        guard let host = UpdateWorker.enclosingHost() else { exit(64) }
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let worker = UpdateWorker()
        do { try worker.start(host: host) } catch { exit(70) }
        withExtendedLifetime(worker) { app.run() }
    }
}
#endif
