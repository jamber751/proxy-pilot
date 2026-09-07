import AppKit
import SwiftUI
import Sparkle

/// Sparkle owns downloading, signature verification and installation. Never run
/// the DMG's first-install shell script as part of an update.
final class UpdateModel: NSObject, ObservableObject, SPUUpdaterDelegate, SPUStandardUserDriverDelegate {
    @Published private(set) var canCheck = false
    @Published private(set) var automaticChecks = true
    @Published private(set) var availableVersion: String?
    let currentVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—"
    var onPresent: (() -> Void)?
    var onAbort: (() -> Void)?
    var prepareRelaunch: ((@escaping () -> Void) -> Void)?
    private var controller: SPUStandardUpdaterController?
    private var observations: [NSKeyValueObservation] = []

    func start(preview: Bool) {
        guard !preview, controller == nil else { return }
        let controller = SPUStandardUpdaterController(startingUpdater: false, updaterDelegate: self, userDriverDelegate: self)
        self.controller = controller
        observations = [
            controller.updater.observe(\.canCheckForUpdates, options: [.initial, .new]) { [weak self] updater, _ in
                self?.canCheck = updater.canCheckForUpdates
            },
            controller.updater.observe(\.automaticallyChecksForUpdates, options: [.initial, .new]) { [weak self] updater, _ in
                self?.automaticChecks = updater.automaticallyChecksForUpdates
            }
        ]
        controller.startUpdater()
    }

    func check() {
        guard canCheck else { return }
        onPresent?()
        controller?.checkForUpdates(nil)
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
    func standardUserDriverDidShowModalAlert() { onPresent?() }
    func updater(_ updater: SPUUpdater, didAbortWithError error: Error) { onAbort?() }

    func updater(_ updater: SPUUpdater, shouldPostponeRelaunchForUpdate item: SUAppcastItem, untilInvokingBlock installHandler: @escaping () -> Void) -> Bool {
        guard let prepareRelaunch = prepareRelaunch else { return false }
        prepareRelaunch(installHandler)
        return true
    }
}

struct UpdatesView: View {
    @ObservedObject var updates: UpdateModel
    let busy: Bool
    var body: some View {
        VStack(spacing: 8) {
            HStack {
                Text("Версия \(updates.currentVersion)").foregroundColor(.secondary)
                Spacer()
                Button(updates.availableVersion.map { "Обновить до \($0)" } ?? "Проверить обновления", action: updates.check)
                    .disabled(!updates.canCheck || busy)
            }
            Toggle("Проверять автоматически", isOn: Binding(get: { updates.automaticChecks }, set: updates.setAutomaticChecks))
                .toggleStyle(CheckboxToggleStyle()).frame(maxWidth: .infinity, alignment: .leading)
                .help("Раз в сутки. Установка и перезапуск — только после подтверждения.")
                .disabled(busy)
        }.font(.system(size: 10)).buttonStyle(PlainButtonStyle()).padding(.bottom, 12)
    }
}
