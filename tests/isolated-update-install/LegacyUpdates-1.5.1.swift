// Regression snapshot: app/Updates.swift from ProxyPilot 1.5.1 (0518754).
// Excludes UpdatesView. Do not adapt this fixture to the current implementation.
// ORIGINAL_SOURCE
import AppKit
import SwiftUI
import Sparkle

/// Sparkle owns downloading, signature verification and installation. Never run
/// the DMG's first-install shell script as part of an update.
final class UpdateModel: NSObject, ObservableObject, SPUUpdaterDelegate, SPUStandardUserDriverDelegate {
    @Published private(set) var canCheck = false
    @Published private(set) var automaticChecks = true
    @Published private(set) var availableVersion: String?
    @Published private(set) var isPreview = false
    @Published private(set) var sessionInProgress = false
    let currentVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—"
    var onPresent: (() -> Void)?
    var onAbort: (() -> Void)?
    var prepareRelaunch: ((@escaping () -> Void) -> Void)?
    private var controller: SPUStandardUpdaterController?
    private var observations: [NSKeyValueObservation] = []

    func start(preview: Bool) {
        isPreview = preview
        guard !preview, controller == nil else { return }
        let controller = SPUStandardUpdaterController(startingUpdater: false, updaterDelegate: self, userDriverDelegate: self)
        self.controller = controller
        observations = [
            controller.updater.observe(\.canCheckForUpdates, options: [.initial, .new]) { [weak self] updater, _ in
                self?.canCheck = updater.canCheckForUpdates
            },
            controller.updater.observe(\.automaticallyChecksForUpdates, options: [.initial, .new]) { [weak self] updater, _ in
                self?.automaticChecks = updater.automaticallyChecksForUpdates
            },
            controller.updater.observe(\.sessionInProgress, options: [.initial, .new]) { [weak self] updater, _ in
                self?.sessionInProgress = updater.sessionInProgress
            }
        ]
        controller.startUpdater()
    }

    func check() {
        guard canCheck, let controller = controller else { return }
        onPresent?()
        NSApp.activate(ignoringOtherApps: true)
        controller.checkForUpdates(nil)
    }

    var checkTitle: String {
        if isPreview { return "Недоступно в превью" }
        if !canCheck { return sessionInProgress ? "Проверяем…" : "Подождите…" }
        return availableVersion.map { "Обновить до \($0)" } ?? "Проверить обновления"
    }

    func setAutomaticChecks(_ enabled: Bool) {
        controller?.updater.automaticallyChecksForUpdates = enabled
    }

    // A background menu-bar utility must not steal focus for scheduled checks.
    var supportsGentleScheduledUpdateReminders: Bool { true }
    func standardUserDriverShouldHandleShowingScheduledUpdate(_ update: SUAppcastItem, andInImmediateFocus immediateFocus: Bool) -> Bool { false }
    func standardUserDriverWillHandleShowingUpdate(_ handleShowingUpdate: Bool, forUpdate update: SUAppcastItem, state: SPUUserUpdateState) {
        availableVersion = update.displayVersionString
        if handleShowingUpdate { onPresent?() }
    }
    func standardUserDriverWillFinishUpdateSession() { availableVersion = nil }
    func standardUserDriverWillShowModalAlert() { onPresent?() }
    func updater(_ updater: SPUUpdater, didAbortWithError error: Error) { onAbort?() }

    func updater(_ updater: SPUUpdater, shouldPostponeRelaunchForUpdate item: SUAppcastItem, untilInvokingBlock installHandler: @escaping () -> Void) -> Bool {
        guard let prepareRelaunch = prepareRelaunch else { return false }
        prepareRelaunch(installHandler)
        return true
    }
}
