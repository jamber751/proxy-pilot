import AppKit
import Combine
import SwiftUI

enum VPNPanelNavigationRequest: Equatable {
    case applicationSettingsAfterVPNRemoval(UUID)
}

/// Main-thread presentation adapter around the synchronous authenticated VPN
/// controller. Helper work stays on one private queue so the menu never freezes.
final class VPNPanelModel: ObservableObject {
    @Published private(set) var liveState: VPNLiveState = .off
    @Published private(set) var working = false
    @Published private(set) var liveChecked = false
    @Published var settings = false
    @Published var editingResource = false
    @Published var editingAuthentication = false
    @Published var authenticationChoice: VPNAuthenticationMode?
    private struct PasswordPersistenceChoice {
        let login: String
        let enabled: Bool
    }
    @Published private var passwordPersistenceChoice: PasswordPersistenceChoice?
    @Published var login = ""
    @Published var resourceName = ""
    @Published var resourceAddress = ""
    @Published var secret = ""
    @Published var message = ""
    @Published var confirmLastResourceRemoval = false
    @Published var confirmVPNRemoval = false
    @Published var requestsPresentation = false
    @Published private(set) var navigationRequest: VPNPanelNavigationRequest?
    @Published private(set) var resourceRevealID: UUID?
    private(set) var topVisibleResourceID: UUID?

    let configuration: VPNModel
    var onAttention: (() -> Void)?
    private let controller: VPNLiveController?
    private let queue = DispatchQueue(label: "proxypilot.vpn.frontend")
    private var modelChanges: AnyCancellable?
    @Published private(set) var credentialPromptIdentifier: UUID?
    @Published private var passwordPersistenceEvent: VPNPasswordPersistenceEvent?

    init(preview: Bool = false) {
        if preview {
            configuration = VPNModel(previewConfiguration: VPNConfiguration())
            controller = nil
        } else {
            let base = FileManager.default.urls(for: .applicationSupportDirectory,
                                                in: .userDomainMask).first!
            let store = VPNStore(directory: base.appendingPathComponent("ProxyPilot/VPN",
                                                                         isDirectory: true))
            configuration = VPNModel(store: store)
            controller = VPNLiveController(store: store)
            do { try configuration.load() }
            catch { message = error.localizedDescription }
        }
        observeConfiguration()
    }

    #if VPN_PANEL_TESTING
    init(configuration: VPNModel, controller: VPNLiveController) {
        self.configuration = configuration
        self.controller = controller
        observeConfiguration()
    }
    #endif

    private func observeConfiguration() {
        modelChanges = configuration.objectWillChange.sink { [weak self] _ in
            self?.objectWillChange.send()
        }
        login = configuration.configuration.authentication?.login ?? ""
        authenticationChoice = configuration.configuration.authentication?.mode
        controller?.setPasswordPersistenceEventHandler { [weak self] event in
            // The persistence queue never reads or mutates presentation state.
            DispatchQueue.main.async { [weak self] in
                self?.receivePasswordPersistenceEvent(event)
            }
        }
    }

    private func receivePasswordPersistenceEvent(_ event: VPNPasswordPersistenceEvent) {
        guard controller?.isCurrentPasswordPersistenceEvent(event,
            configuration: configuration.configuration) == true else { return }
        passwordPersistenceEvent = event
    }

    var ready: Bool { configuration.connectionAvailability == .ready }
    var configured: Bool { configuration.profile != nil }
    var passwordPersistenceAvailable: Bool { controller?.passwordPersistenceAvailable ?? false }
    var passwordPersistenceSelected: Bool {
        guard (authenticationChoice ?? configuration.configuration.authentication?.mode) == .password,
              let draft = try? VPNAuthentication(mode: .password, login: login), let login = draft.login else { return false }
        if let choice = passwordPersistenceChoice, choice.login == login { return choice.enabled }
        guard let saved = configuration.configuration.authentication,
              saved.mode == .password, saved.login == login else { return false }
        return saved.credentialPersistence == .keychain
    }
    func choosePasswordPersistence(_ enabled: Bool) {
        guard passwordPersistenceAvailable, authenticationChoice == .password,
              let draft = try? VPNAuthentication(mode: .password, login: login), let login = draft.login else { return }
        passwordPersistenceChoice = PasswordPersistenceChoice(login: login, enabled: enabled)
    }
    var connected: Bool { liveState == .connected }
    var canImportProfile: Bool {
        !working && !connected && !needsCredential && liveState != .connecting
    }
    var mainStatus: String? {
        guard configured else { return nil }
        guard liveChecked else { return "VPN проверяется" }
        switch liveState {
        case .connected: return "VPN включён"
        case .off: return "VPN выключен"
        case .connecting, .needsCredential: return "VPN подключается"
        case .unavailable, .failed: return "VPN недоступен"
        }
    }
    var needsCredential: Bool {
        if case .needsCredential = liveState { return true }
        return false
    }
    var powerTitle: String {
        if working || liveState == .connecting { return "Подождите…" }
        if needsCredential { return "Подключение" }
        if connected { return "Выключить" }
        return "Включить"
    }
    var statusTitle: String {
        if !configured { return "Добавьте конфигурацию" }
        if !ready { return configuration.connectionAvailabilityLabel }
        return liveState.label
    }
    var statusDetail: String {
        switch liveState {
        case .connected:
            let detail = "Рабочие ресурсы открываются через VPN."
            return passwordPersistenceDetail.map { detail + "\n" + $0 } ?? detail
        case .needsCredential(.privateKeyPassword): return "Пароль нужен только для этой попытки подключения."
        case .needsCredential(.vpnPassword):
            if configuration.configuration.authentication?.mode == .oneTimePassword {
                return "Введите текущий код или комбинацию, которую выдал администратор."
            }
            if configuration.configuration.authentication?.mode == .password,
               passwordPersistenceEvent?.phase == .needsConfirmation,
               let detail = passwordPersistenceDetail {
                return "Введите пароль VPN.\n" + detail
            }
            return passwordPersistenceAvailable && configuration.configuration.authentication?.credentialPersistence == .keychain
                ? "Попробуем сохранить пароль после подключения."
                : "Введите пароль VPN. Он не сохраняется."
        case .unavailable: return "Компонент VPN недоступен. Проверьте установку и попробуйте ещё раз."
        default: return ready ? "Одно нажатие подключит выбранные ресурсы." : "Откройте настройки и завершите три шага."
        }
    }

    var passwordPersistenceDetail: String? {
        guard let event = passwordPersistenceEvent,
              controller?.isCurrentPasswordPersistenceEvent(event,
                  configuration: configuration.configuration) == true else { return nil }
        switch event.phase {
        case .saving: return "Сохраняем пароль…"
        case .saved: return "Пароль сохранён в Связке ключей."
        case .needsConfirmation: return "Сохранение пароля не подтверждено."
        }
    }

    func refresh() { run { $0.refresh() } }

    func restoreDesiredConnection() {
        dismissCredentialPrompt()
        let desired = configuration.configuration.desiredEnabled
        run({ controller in
            controller.refresh()
            guard desired else { return }
            switch controller.state {
            case .connected, .connecting, .unavailable: break
            case .needsCredential, .failed:
                controller.disconnect()
                if controller.state == .off { controller.connect() }
            case .off: controller.connect()
            }
        }, completion: { [weak self] state in
            guard let self else { return }
            if case .needsCredential = state {
                self.requestsPresentation = true
                self.onAttention?()
            }
        })
    }

    func reconnectAfterNetworkChange() {
        dismissCredentialPrompt()
        let desired = configuration.configuration.desiredEnabled
        run({ controller in
            controller.refresh()
            guard desired, controller.state != .unavailable else { return }
            controller.disconnect()
            if controller.state == .off { controller.connect() }
        }, completion: { [weak self] state in
            guard let self else { return }
            if case .needsCredential = state {
                self.requestsPresentation = true
                self.onAttention?()
            }
        })
    }
    func toggle() {
        dismissCredentialPrompt()
        guard ready else { settings = true; return }
        let shouldDisconnect = connected
        run { controller in shouldDisconnect ? controller.disconnect() : controller.connect() }
    }
    func submitCredential(expectedPromptIdentifier: UUID?) {
        guard !working, needsCredential, let prompt = credentialPromptIdentifier,
              expectedPromptIdentifier == prompt, !secret.isEmpty else { return }
        var bytes = Data(secret.utf8)
        secret = ""
        run { $0.submitCredential(&bytes, expectedPromptIdentifier: prompt) }
    }
    func cancelCredential(expectedPromptIdentifier: UUID?) {
        guard !working, needsCredential, let prompt = credentialPromptIdentifier,
              expectedPromptIdentifier == prompt else { return }
        dismissCredentialPrompt()
        run { $0.cancelCredential() }
    }

    /// Only the transient field is cleared. Login, password-saving consent and
    /// an authenticated connection are independent of a prompt's visibility.
    func dismissCredentialPrompt() { secret = "" }

    func dismissCredentialPrompt(ifMatching prompt: UUID?) {
        guard prompt == credentialPromptIdentifier else { return }
        dismissCredentialPrompt()
    }

    private func adoptLiveState(_ state: VPNLiveState, promptIdentifier: UUID?) {
        let next: UUID?
        if case .needsCredential = state { next = promptIdentifier }
        else { next = nil }
        if next == nil || next != credentialPromptIdentifier { dismissCredentialPrompt() }
        credentialPromptIdentifier = next
        liveState = state
    }

    /// Explicit app exit must stop the managed tunnel before the proxy and app
    /// are allowed to terminate. Failure keeps the app alive with a visible
    /// explanation instead of abandoning owned routes.
    func disconnectForQuit(completion: @escaping () -> Void) {
        dismissCredentialPrompt()
        guard let controller, configured else { completion(); return }
        working = true; message = "Выключаем VPN…"
        queue.async { [weak self] in
            controller.disconnect()
            let state = controller.state
            let promptIdentifier = controller.credentialPromptIdentifier
            DispatchQueue.main.async {
                guard let self else { return }
                self.adoptLiveState(state, promptIdentifier: promptIdentifier)
                self.liveChecked = true; self.working = false
                if state == .off {
                    do { try self.configuration.load() } catch { }
                    completion()
                } else {
                    self.message = "Не удалось безопасно выключить VPN. Попробуйте ещё раз."
                    self.settings = false
                    self.requestsPresentation = true
                }
            }
        }
    }

    func chooseProfile() {
        guard requireImportAvailability() else { return }
        let picker = NSOpenPanel()
        picker.title = "Выберите конфигурацию VPN"
        picker.prompt = "Добавить"
        picker.allowsMultipleSelection = false
        picker.canChooseDirectories = false
        picker.allowedFileTypes = ["ovpn"]
        guard picker.runModal() == .OK else { return }
        importProfiles(picker.urls)
    }

    @discardableResult
    func acceptDrop(_ providers: [NSItemProvider]) -> Bool {
        guard requireImportAvailability() else { return false }
        guard providers.count == 1,
              providers[0].hasItemConformingToTypeIdentifier("public.file-url") else {
            message = "Добавьте один файл .ovpn."
            return false
        }
        providers[0].loadItem(forTypeIdentifier: "public.file-url", options: nil) { [weak self] item, _ in
            let url: URL?
            if let data = item as? Data { url = URL(dataRepresentation: data, relativeTo: nil) }
            else if let candidate = item as? URL { url = candidate }
            else { url = nil }
            DispatchQueue.main.async {
                guard let self, let url else {
                    self?.message = "Не удалось прочитать файл VPN."
                    return
                }
                self.importProfiles([url])
            }
        }
        return true
    }

    func selectAuthentication(_ mode: VPNAuthenticationMode) {
        authenticationChoice = mode
        message = ""
    }

    func beginAuthentication() {
        passwordPersistenceChoice = nil
        login = configuration.configuration.authentication?.login ?? login
        authenticationChoice = configuration.configuration.authentication?.mode
        editingAuthentication = true; message = ""
    }

    func cancelAuthentication() {
        passwordPersistenceChoice = nil
        login = configuration.configuration.authentication?.login ?? ""
        authenticationChoice = configuration.configuration.authentication?.mode
        editingAuthentication = false; message = ""
    }

    func saveAuthentication() {
        guard let mode = authenticationChoice else {
            message = "Выберите пароль или код / 2FA."
            return
        }
        do {
            try persistAuthenticationChoice(mode)
            passwordPersistenceChoice = nil
            editingAuthentication = false; message = ""
        } catch { message = error.localizedDescription }
    }

    private func persistAuthenticationChoice(_ mode: VPNAuthenticationMode) throws {
        // A choice belongs to the normalized, case-sensitive login shown when
        // it was made. Editing another login never inherits that consent.
        let draft = try VPNAuthentication(mode: mode, login: mode == .certificate ? nil : login)
        var persistence: VPNCredentialPersistence = .none
        if passwordPersistenceAvailable, draft.mode == .password {
            persistence = passwordPersistenceSelected ? .keychain : .none
        } else if let previous = configuration.configuration.authentication,
           draft.mode == .password, previous.mode == draft.mode, previous.login == draft.login {
            persistence = previous.credentialPersistence
        }
        try configuration.setAuthentication(mode: draft.mode, login: draft.login,
                                            credentialPersistence: persistence)
    }

    func acceptSuggestions() {
        do { try configuration.acceptSupportedSuggestions(); message = "" }
        catch { message = error.localizedDescription }
    }

    func beginResource(_ resource: VPNResource? = nil) {
        do {
            if let resource { try configuration.beginEditingResource(id: resource.id) }
            else { configuration.beginAddingResource() }
            resourceName = resource?.name ?? ""
            resourceAddress = resource?.address ?? ""
            resourceRevealID = nil
            editingResource = true
            message = ""
        } catch { message = error.localizedDescription }
    }

    func saveResource() {
        guard var draft = configuration.resourceDraft else { return }
        let previousIDs = Set(configuration.configuration.resources.map(\.id))
        do {
            let candidate = try VPNResource(id: draft.id ?? UUID(), name: resourceName,
                                            address: resourceAddress)
            guard candidate.kind != .domain else {
                message = "Сейчас можно добавить IP-адрес или сеть. Доменные имена появятся позже."
                return
            }
        } catch { message = error.localizedDescription; return }
        draft.name = resourceName; draft.address = resourceAddress
        configuration.resourceDraft = draft
        do {
            try configuration.saveResourceDraft()
            resourceRevealID = draft.id ?? configuration.configuration.resources.first {
                !previousIDs.contains($0.id)
            }?.id
            editingResource = false; message = ""
        } catch { message = error.localizedDescription }
    }

    func cancelResource() {
        configuration.cancelResourceDraft(); editingResource = false; message = ""
    }

    func recordVisibleResource(_ id: UUID) {
        // A disappearing scroll view can still emit its final geometry. Freeze
        // the visible anchor when navigation leaves the list, before unmount.
        guard settings, !editingResource, !editingAuthentication,
              configuration.configuration.resources.contains(where: { $0.id == id }) else { return }
        topVisibleResourceID = id
    }

    func finishResourceReveal(_ id: UUID?) {
        if let id, resourceRevealID == id { resourceRevealID = nil }
    }

    func finishSettings() {
        do {
            if configuration.profile?.requiresCredentials == true {
                guard let mode = authenticationChoice ?? configuration.configuration.authentication?.mode else {
                    message = "Выберите пароль или код / 2FA."
                    return
                }
                try persistAuthenticationChoice(mode)
            }
            guard ready else { message = configuration.connectionAvailabilityLabel; return }
            settings = false; message = ""
        } catch { message = error.localizedDescription }
    }

    func requestResourceRemoval() {
        guard configuration.resourceDraft?.id != nil else { return }
        if configuration.configuration.resources.count == 1 {
            confirmLastResourceRemoval = true
        } else { removeDraftResource(confirmingVPNOff: false) }
    }

    func confirmResourceRemoval() { removeDraftResource(confirmingVPNOff: true) }

    func requestVPNRemoval() { confirmVPNRemoval = true }

    @discardableResult
    func consumeNavigationRequest(_ request: VPNPanelNavigationRequest) -> Bool {
        guard navigationRequest == request else { return false }
        navigationRequest = nil
        return true
    }

    func confirmRemoveVPN() {
        guard !working, let controller else { return }
        working = true; confirmVPNRemoval = false; message = "Выключаем и удаляем VPN…"
        queue.async { [weak self] in
            controller.disconnect()
            let state = controller.state
            let promptIdentifier = controller.credentialPromptIdentifier
            DispatchQueue.main.async {
                guard let self else { return }
                self.adoptLiveState(state, promptIdentifier: promptIdentifier)
                self.liveChecked = true; self.working = false
                guard state == .off else {
                    self.message = "Не удалось безопасно выключить VPN. Настройки не удалены."
                    return
                }
                do {
                    try self.configuration.load()
                    try self.configuration.removeProfile()
                    self.settings = false; self.login = ""; self.secret = ""; self.message = ""
                    self.requestsPresentation = false
                    self.navigationRequest = .applicationSettingsAfterVPNRemoval(UUID())
                } catch { self.message = error.localizedDescription }
            }
        }
    }

    private func removeDraftResource(confirmingVPNOff: Bool) {
        guard let id = configuration.resourceDraft?.id else { return }
        let index = configuration.configuration.resources.firstIndex(where: { $0.id == id }) ?? 0
        do {
            try configuration.removeResource(id: id, confirmingVPNOff: confirmingVPNOff)
            let remaining = configuration.configuration.resources
            resourceRevealID = remaining.isEmpty ? nil : remaining[min(index, remaining.count - 1)].id
            if remaining.isEmpty { topVisibleResourceID = nil }
            editingResource = false; confirmLastResourceRemoval = false; message = ""
        } catch { message = error.localizedDescription }
    }

    private func importProfiles(_ urls: [URL]) {
        // Item-provider delivery is asynchronous: state may have changed since
        // the drop was accepted. Check again before the transactional import.
        guard requireImportAvailability() else { return }
        do {
            try configuration.importProfile(files: urls)
            passwordPersistenceChoice = nil
            login = configuration.profile?.suggestedLogin ?? ""
            authenticationChoice = nil
            if configuration.profile?.requiresCredentials == false {
                try configuration.setAuthentication(mode: .certificate)
                authenticationChoice = .certificate
            }
            settings = true; message = ""
        } catch { message = error.localizedDescription }
    }

    private func requireImportAvailability() -> Bool {
        guard canImportProfile else {
            message = "Перед заменой файла завершите подключение или выключите VPN."
            return false
        }
        return true
    }

    private func run(_ operation: @escaping (VPNLiveController) -> Void,
                     completion: ((VPNLiveState) -> Void)? = nil) {
        guard !working, let controller else {
            if controller == nil { adoptLiveState(.unavailable, promptIdentifier: nil) }
            return
        }
        working = true; message = ""
        queue.async { [weak self] in
            operation(controller)
            let state = controller.state
            let promptIdentifier = controller.credentialPromptIdentifier
            var bridgeError = false
            #if VPN_INSTALLER_ENTRY
            // CLI takes the cross-process bridge lock, then obtains its own
            // fresh authenticated snapshot; never pass cached UI resources.
            if state == .connected || state == .off {
                if let proxy = CLI.state() {
                    if proxy.configured { bridgeError = !CLI.run(["ensure"]).succeeded }
                } else { bridgeError = true }
            }
            #endif
            let bridgeFailed = bridgeError
            DispatchQueue.main.async {
                guard let self else { return }
                self.adoptLiveState(state, promptIdentifier: promptIdentifier)
                self.liveChecked = true
                self.working = false
                do { try self.configuration.load() }
                catch { self.message = error.localizedDescription }
                // Enabling can advance the revision before an event reaches
                // this queue. Reconcile only after adopting the saved settings.
                if let event = controller.passwordPersistenceEvent {
                    self.receivePasswordPersistenceEvent(event)
                }
                if bridgeFailed {
                    self.message = "Не удалось обновить исключения VPN в локальном прокси. Откройте приложение и повторите проверку."
                }
                completion?(state)
            }
        }
    }
}

struct VPNPanelView: View {
    @ObservedObject var panel: VPNPanelModel
    let close: () -> Void
    @Environment(\.colorScheme) private var colorScheme
    @State private var dropTarget = false

    private var ink: Color { colorScheme == .dark ? Color(red: 0.92, green: 0.94, blue: 0.94) : Color(red: 0.12, green: 0.16, blue: 0.15) }
    private var accent: Color { PilotTheme.accent }
    private var background: Color { colorScheme == .dark ? Color(red: 0.10, green: 0.12, blue: 0.115) : Color(red: 0.98, green: 0.985, blue: 0.98) }

    var body: some View {
        VStack(spacing: 0) {
            header
            if panel.needsCredential { home }
            else if panel.editingResource { resourceEditor }
            else if panel.editingAuthentication { authenticationEditor }
            else if panel.settings { settings }
            else if panel.configured { home }
            else { importScreen }
        }
        .padding(.horizontal, 24).frame(width: 344, height: 432)
        .foregroundColor(ink).accentColor(accent).background(background)
        .onAppear { panel.refresh() }
        .onExitCommand(perform: goBack)
        .onReceive(NotificationCenter.default.publisher(for: NSPopover.didCloseNotification)) { _ in
            panel.dismissCredentialPrompt()
        }
    }

    private var header: some View {
        HStack(spacing: 7) {
            Button(action: goBack) {
                Image(systemName: "chevron.left").frame(width: 36, height: 36).contentShape(Rectangle())
            }.buttonStyle(PilotButtonStyle()).accessibilityLabel(panel.needsCredential ? "Отменить вход" : "Назад").accessibilityIdentifier("vpnBack")
                .disabled(panel.working)
            Text(panel.needsCredential ? "VPN" : panel.editingResource ? "Ресурс" : panel.editingAuthentication ? "Вход" : panel.settings ? "Настройки VPN" : "VPN")
                .font(.system(size: 14, weight: .semibold))
            Spacer()
            if panel.configured && !panel.needsCredential && !panel.settings && !panel.editingResource && !panel.editingAuthentication {
                Button { panel.settings = true } label: {
                    Image(systemName: "gearshape").frame(width: 36, height: 36).contentShape(Rectangle())
                }.buttonStyle(PilotButtonStyle()).accessibilityLabel("Настройки VPN")
                    .accessibilityIdentifier("vpnSettings").disabled(panel.working)
            }
        }.frame(height: 36).padding(.top, 12)
    }

    private var home: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 18)
            Button(action: panel.toggle) {
                VStack(spacing: 18) {
                    ZStack {
                        Circle().fill(panel.connected ? accent : ink)
                        if panel.working || panel.liveState == .connecting {
                            ProgressView().progressViewStyle(CircularProgressViewStyle(tint: colorScheme == .dark && !panel.connected ? .black : .white))
                        } else {
                            Image(systemName: "power").font(.system(size: 36, weight: .light))
                                .foregroundColor(colorScheme == .dark && !panel.connected ? .black : .white)
                        }
                    }.frame(width: 104, height: 104).shadow(color: .black.opacity(0.08), radius: 14, x: 0, y: 7)
                    Text(panel.powerTitle).font(.system(size: 13, weight: .medium)).foregroundColor(ink)
                }.frame(maxWidth: .infinity).contentShape(Rectangle())
            }.buttonStyle(PowerStyle()).disabled(panel.working || panel.needsCredential)
                .keyboardShortcut(.defaultAction)
                .accessibilityLabel(panel.powerTitle).accessibilityIdentifier("vpnPower")
            VStack(spacing: 8) {
                Text(panel.statusTitle).font(.system(size: 22, weight: .semibold)).tracking(-0.5)
                Text(panel.statusDetail).font(.system(size: 13)).foregroundColor(.secondary)
                    .multilineTextAlignment(.center).lineSpacing(3).fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("vpnStatusDetail")
            }.padding(.top, 22)
            if panel.needsCredential { credentialForm.padding(.top, 14) }
            else if !panel.ready {
                Button { panel.settings = true } label: {
                    Text("Завершить настройку").font(.system(size: 12, weight: .semibold))
                        .frame(maxWidth: .infinity, minHeight: 38).contentShape(Rectangle())
                        .background(accent).foregroundColor(.white).cornerRadius(9)
                }.buttonStyle(PilotButtonStyle(cornerRadius: 9)).padding(.top, 18)
            }
            if !panel.message.isEmpty {
                Text(panel.message).font(.system(size: 10)).foregroundColor(.secondary)
                    .multilineTextAlignment(.center).padding(.top, 10)
            }
            Spacer(minLength: 10)
            Divider().opacity(0.5)
            HStack {
                Text("Только выбранные ресурсы")
                Spacer()
                Text("\(panel.configuration.configuration.resources.count)")
            }.font(.system(size: 11)).foregroundColor(.secondary).frame(height: 46)
        }
    }

    private func goBack() {
        guard !panel.working else { return }
        if panel.needsCredential { panel.cancelCredential(expectedPromptIdentifier: panel.credentialPromptIdentifier) }
        else if panel.editingResource { panel.cancelResource() }
        else if panel.editingAuthentication { panel.cancelAuthentication() }
        else if panel.settings { panel.settings = false }
        else { close() }
    }

    private var credentialForm: some View {
        let displayedPrompt = panel.credentialPromptIdentifier
        return VStack(spacing: 9) {
            VPNSecretField(text: $panel.secret, prompt: panel.credentialPromptIdentifier,
                           enabled: !panel.working, label: panel.statusTitle,
                           submit: { panel.submitCredential(expectedPromptIdentifier: displayedPrompt) },
                           cancel: { panel.cancelCredential(expectedPromptIdentifier: displayedPrompt) })
                .frame(height: 28).accessibilityIdentifier("vpnCredential")
            HStack(spacing: 8) {
                Button(action: { panel.cancelCredential(expectedPromptIdentifier: displayedPrompt) }) {
                    Text("Отмена").frame(maxWidth: .infinity, minHeight: 36).contentShape(Rectangle())
                }.buttonStyle(PilotButtonStyle(cornerRadius: 8))
                    .accessibilityIdentifier("vpnCredentialCancel").keyboardShortcut(.cancelAction)
                Button(action: { panel.submitCredential(expectedPromptIdentifier: displayedPrompt) }) {
                    Text("Продолжить").frame(maxWidth: .infinity, minHeight: 36).contentShape(Rectangle())
                }.buttonStyle(PilotButtonStyle(cornerRadius: 8))
                    .accessibilityIdentifier("vpnCredentialSubmit").keyboardShortcut(.defaultAction)
                    .disabled(panel.secret.isEmpty)
            }.disabled(panel.working)
        }
        .onDisappear { panel.dismissCredentialPrompt(ifMatching: displayedPrompt) }
    }

    private var importScreen: some View {
        VStack(spacing: 0) {
            Text("Подключите VPN").font(.system(size: 25, weight: .semibold)).tracking(-0.6)
                .frame(maxWidth: .infinity, alignment: .leading).padding(.top, 34)
            Text("Добавьте файл .ovpn, который прислал администратор.")
                .font(.system(size: 12)).foregroundColor(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading).padding(.top, 8)
            Button(action: panel.chooseProfile) {
                VStack(spacing: 12) {
                    Image(systemName: "arrow.down.doc").font(.system(size: 29, weight: .light)).foregroundColor(accent)
                    Text(dropTarget ? "Отпустите файл здесь" : "Перетащите .ovpn сюда").font(.system(size: 14, weight: .semibold))
                    Text("или выберите файл").font(.system(size: 11)).foregroundColor(.secondary)
                }.frame(maxWidth: .infinity, minHeight: 154)
                    .background(dropTarget ? accent.opacity(0.12) : ink.opacity(0.025)).cornerRadius(14)
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(dropTarget ? accent : ink.opacity(0.10), style: StrokeStyle(lineWidth: 1, dash: [5])))
                    .contentShape(RoundedRectangle(cornerRadius: 14))
            }.buttonStyle(PilotButtonStyle(cornerRadius: 14)).accessibilityIdentifier("vpnImport")
                .accessibilityLabel("Добавить файл VPN")
                .disabled(!panel.canImportProfile)
                .onDrop(of: ["public.file-url"], isTargeted: $dropTarget, perform: panel.acceptDrop)
                .padding(.top, 24)
            if !panel.message.isEmpty {
                Text(panel.message).font(.system(size: 11)).foregroundColor(.secondary)
                    .multilineTextAlignment(.center).padding(.top, 12)
            }
            Spacer()
            Text("Файл хранится только на этом Mac. Одноразовые коды не сохраняются.")
                .font(.system(size: 10)).foregroundColor(.secondary).multilineTextAlignment(.center)
                .padding(.bottom, 16)
        }
    }

    private var settings: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                profileCard
                authenticationSummary
                resourcesCard
                if !panel.message.isEmpty {
                    Text(panel.message).font(.system(size: 10)).foregroundColor(.secondary)
                        .lineLimit(2).fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }.padding(.top, 8).padding(.bottom, 8).disabled(panel.connected || panel.working)
            Divider().opacity(0.5)
            HStack(spacing: 8) {
                Button(action: panel.requestVPNRemoval) {
                    Text("Удалить").font(.system(size: 11, weight: .medium))
                        .frame(minWidth: 64, minHeight: 38).contentShape(Rectangle())
                }.buttonStyle(PilotButtonStyle(cornerRadius: 9)).foregroundColor(.red)
                    .accessibilityIdentifier("vpnRemove")
                    .disabled(panel.connected || panel.working)
                Button(action: panel.finishSettings) {
                    Text(panel.ready ? "Готово" : "Продолжить")
                        .font(.system(size: 12, weight: .semibold)).frame(maxWidth: .infinity, minHeight: 38)
                        .background(panel.ready ? accent : ink.opacity(0.06))
                        .foregroundColor(panel.ready ? .white : ink).cornerRadius(9).contentShape(Rectangle())
                }.buttonStyle(PilotButtonStyle(cornerRadius: 9))
                    .accessibilityIdentifier("vpnSettingsDone")
            }.padding(.vertical, 10)
        }
        .alert(isPresented: $panel.confirmVPNRemoval) {
            Alert(title: Text("Удалить VPN?"),
                  message: Text("ProxyPilot выключит VPN и удалит сохранённую копию файла, вход и список ресурсов. Настройки прокси не изменятся."),
                  primaryButton: .destructive(Text("Удалить"), action: panel.confirmRemoveVPN),
                  secondaryButton: .cancel())
        }
    }

    private var profileCard: some View {
        Button(action: panel.chooseProfile) {
                HStack(spacing: 10) {
                    Image(systemName: "doc.badge.gearshape").foregroundColor(accent).frame(width: 24)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(panel.configuration.profile?.name ?? "Добавить .ovpn").font(.system(size: 12, weight: .semibold)).lineLimit(1)
                        Text(dropTarget ? "Отпустите файл здесь" : "Нажмите или перетащите .ovpn для замены")
                            .font(.system(size: 9)).foregroundColor(dropTarget ? accent : .secondary)
                    }
                    Spacer(); Image(systemName: "chevron.right").font(.system(size: 10)).foregroundColor(.secondary)
                }.padding(.horizontal, 11).frame(maxWidth: .infinity, minHeight: 48)
                    .background(dropTarget ? accent.opacity(0.12) : ink.opacity(0.035)).cornerRadius(10)
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(dropTarget ? accent : .clear).allowsHitTesting(false))
                    .contentShape(Rectangle())
        }.buttonStyle(PilotButtonStyle(cornerRadius: 10))
            .accessibilityIdentifier("vpnReplaceProfile")
            .disabled(!panel.canImportProfile)
            .onDrop(of: ["public.file-url"], isTargeted: $dropTarget, perform: panel.acceptDrop)
    }

    private var authenticationSummary: some View {
        Button(action: panel.beginAuthentication) {
            HStack(spacing: 10) {
                Image(systemName: "person.badge.key").foregroundColor(accent).frame(width: 24)
                VStack(alignment: .leading, spacing: 3) {
                    Text("Вход").font(.system(size: 12, weight: .semibold))
                    Text(authenticationSummaryText).font(.system(size: 9)).foregroundColor(.secondary).lineLimit(1)
                }
                Spacer(); Image(systemName: "chevron.right").font(.system(size: 10)).foregroundColor(.secondary)
            }.padding(.horizontal, 11).frame(maxWidth: .infinity, minHeight: 48)
                .background(ink.opacity(0.035)).cornerRadius(10).contentShape(Rectangle())
        }.buttonStyle(PilotButtonStyle(cornerRadius: 10))
    }

    private var authenticationSummaryText: String {
        guard panel.configuration.profile?.requiresCredentials == true else { return "Сертификат из файла" }
        guard let authentication = panel.configuration.configuration.authentication else { return "Выберите способ входа" }
        let mode = authentication.mode == .oneTimePassword ? "Код / 2FA" : "Пароль"
        return authentication.login.map { "\(mode) · \($0)" } ?? mode
    }

    private var authenticationEditor: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Как вы входите?").font(.system(size: 23, weight: .semibold)).tracking(-0.5).padding(.top, 24)
            if panel.configuration.profile?.requiresCredentials == true {
                Text("Логин").font(.system(size: 10, weight: .medium)).foregroundColor(.secondary)
                TextField("Логин", text: $panel.login).textFieldStyle(RoundedBorderTextFieldStyle())
                    .font(.system(size: 12))
                HStack(spacing: 6) {
                    authButton("Пароль", .password)
                    authButton("Код / 2FA", .oneTimePassword)
                }
                if panel.authenticationChoice == .password && panel.passwordPersistenceAvailable {
                    Toggle("Сохранять пароль на этом Mac", isOn: Binding(
                        get: { panel.passwordPersistenceSelected },
                        set: { panel.choosePasswordPersistence($0) }))
                        .toggleStyle(PilotCheckboxStyle(minimumHeight: 36))
                        .font(.system(size: 11))
                        .accessibilityIdentifier("vpnSavePassword")
                }
                Text(panel.authenticationChoice == .oneTimePassword ? "Одноразовый код не сохраняется." :
                     panel.passwordPersistenceSelected && panel.passwordPersistenceAvailable ?
                     "Попробуем сохранить пароль после подключения." : "Пароль вводится при подключении.")
                    .font(.system(size: 9)).foregroundColor(.secondary)
            } else {
                HStack(spacing: 9) {
                    Image(systemName: "checkmark.circle.fill").foregroundColor(accent)
                    Text("Сертификат из файла").font(.system(size: 12, weight: .medium))
                }.frame(minHeight: 32)
            }
            Button(action: panel.saveAuthentication) {
                Text("Сохранить").font(.system(size: 12, weight: .semibold)).frame(maxWidth: .infinity, minHeight: 40)
                    .background(accent).foregroundColor(.white).cornerRadius(9).contentShape(Rectangle())
            }.buttonStyle(PilotButtonStyle(cornerRadius: 9))
                .accessibilityIdentifier("vpnAuthenticationSave").keyboardShortcut(.defaultAction)
                .disabled(panel.configuration.profile?.requiresCredentials == true &&
                          (panel.login.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || panel.authenticationChoice == nil))
            if !panel.message.isEmpty { Text(panel.message).font(.system(size: 10)).foregroundColor(.secondary) }
            Spacer()
        }
    }

    private func authButton(_ title: String, _ mode: VPNAuthenticationMode) -> some View {
        let selected = panel.authenticationChoice == mode
        return Button { panel.selectAuthentication(mode) } label: {
            Text(title).font(.system(size: 11, weight: .medium)).frame(maxWidth: .infinity, minHeight: 34)
                .background(selected ? accent.opacity(0.15) : ink.opacity(0.04)).cornerRadius(8)
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(selected ? accent.opacity(0.7) : ink.opacity(0.08)))
                .contentShape(Rectangle())
        }.buttonStyle(PilotButtonStyle(cornerRadius: 8)).disabled(panel.login.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private var resourcesCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("РЕСУРСЫ ЧЕРЕЗ VPN").font(.system(size: 9, weight: .semibold)).tracking(0.8).foregroundColor(.secondary)
                Text("\(panel.configuration.configuration.resources.count)")
                    .font(.system(size: 10, weight: .medium, design: .monospaced)).foregroundColor(.secondary)
                    .accessibilityIdentifier("vpnResourceCount")
                Spacer()
                Button { panel.beginResource() } label: {
                    Image(systemName: "plus").frame(width: 36, height: 36).contentShape(Rectangle())
                }.buttonStyle(PilotButtonStyle()).accessibilityLabel("Добавить ресурс").accessibilityIdentifier("vpnAddResource")
            }
            let suggestions = panel.configuration.suggestedResources.filter { $0.kind != .domain }
            if !suggestions.isEmpty && panel.configuration.configuration.resources.isEmpty {
                Button(action: panel.acceptSuggestions) {
                    HStack {
                        Image(systemName: "sparkles"); Text("Добавить найденные в файле (\(suggestions.count))")
                        Spacer(); Image(systemName: "chevron.right").font(.system(size: 10))
                    }.font(.system(size: 11, weight: .medium)).padding(10)
                        .background(accent.opacity(0.10)).cornerRadius(9).contentShape(Rectangle())
                }.buttonStyle(PilotButtonStyle(cornerRadius: 9))
            }
            if panel.configuration.configuration.resources.isEmpty {
                Text("Добавьте IP-адрес или сеть, например 10.20.0.0/16.")
                    .font(.system(size: 10)).foregroundColor(.secondary).padding(.vertical, 8)
            } else {
                VPNResourceListView(panel: panel)
            }
        }
    }

    private var resourceEditor: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Рабочий ресурс").font(.system(size: 23, weight: .semibold)).tracking(-0.5).padding(.top, 24)
            Text("Через VPN будут идти только указанные адреса.").font(.system(size: 12)).foregroundColor(.secondary)
            Text("Название — необязательно").font(.system(size: 10, weight: .medium)).foregroundColor(.secondary)
            TextField("Например, CRM", text: $panel.resourceName).textFieldStyle(RoundedBorderTextFieldStyle())
            Text("IP-адрес или сеть").font(.system(size: 10, weight: .medium)).foregroundColor(.secondary)
            TextField("10.20.0.0/16", text: $panel.resourceAddress).textFieldStyle(RoundedBorderTextFieldStyle())
            Text("Доменные имена появятся после поддержки безопасного DNS через VPN.")
                .font(.system(size: 10)).foregroundColor(.secondary).fixedSize(horizontal: false, vertical: true)
            Button(action: panel.saveResource) {
                Text("Сохранить").font(.system(size: 12, weight: .semibold)).frame(maxWidth: .infinity, minHeight: 40)
                    .background(accent).foregroundColor(.white).cornerRadius(9).contentShape(Rectangle())
            }.buttonStyle(PilotButtonStyle(cornerRadius: 9))
                .accessibilityIdentifier("vpnResourceSave").keyboardShortcut(.defaultAction)
                .disabled(panel.resourceAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            if panel.configuration.resourceDraft?.id != nil {
                Button(action: panel.requestResourceRemoval) {
                    Text("Удалить ресурс").font(.system(size: 11, weight: .medium))
                        .frame(maxWidth: .infinity, minHeight: 36).contentShape(Rectangle())
                }.buttonStyle(PilotButtonStyle(cornerRadius: 8)).foregroundColor(.red)
                    .accessibilityIdentifier("vpnRemoveResource")
            }
            if !panel.message.isEmpty { Text(panel.message).font(.system(size: 10)).foregroundColor(.secondary) }
            Spacer()
        }
        .alert(isPresented: $panel.confirmLastResourceRemoval) {
            Alert(title: Text("Удалить последний ресурс?"),
                  message: Text("VPN будет выключен, а файл конфигурации останется."),
                  primaryButton: .destructive(Text("Удалить"), action: panel.confirmResourceRemoval),
                  secondaryButton: .cancel())
        }
    }
}


/// Local focus bridge for macOS 11. Prompt identity, not secret contents or the
/// credential kind, determines when a fresh field should receive keyboard focus.
private struct VPNSecretField: NSViewRepresentable {
    @Binding var text: String
    let prompt: UUID?
    let enabled: Bool
    let label: String
    let submit: () -> Void
    let cancel: () -> Void

    func makeCoordinator() -> Coordinator { Coordinator(self) }
    func makeNSView(context: Context) -> Field {
        let field = Field()
        field.placeholderString = "Пароль или код"
        field.bezelStyle = .roundedBezel
        field.font = .systemFont(ofSize: 13)
        field.delegate = context.coordinator
        field.target = context.coordinator
        field.action = #selector(Coordinator.commit)
        field.setAccessibilityIdentifier("vpnCredential")
        return field
    }
    func updateNSView(_ field: Field, context: Context) {
        context.coordinator.parent = self
        if field.stringValue != text { field.stringValue = text }
        if enabled && !field.isEnabled { field.focusedPrompt = nil }
        field.isEnabled = enabled
        if !enabled { field.cancelPendingFocus() }
        field.setAccessibilityLabel(label)
        field.prompt = prompt
        field.requestFocus()
    }
    static func dismantleNSView(_ field: Field, coordinator: Coordinator) {
        // Detach callbacks before ending editing or wiping this old native
        // control: neither operation may write a newer prompt's binding.
        field.delegate = nil; field.target = nil; field.action = nil
        field.stopObserving(); field.cancelPendingFocus(); field.prompt = nil
        if field.currentEditor() != nil { field.window?.makeFirstResponder(nil) }
        field.stringValue = ""
    }
    final class Coordinator: NSObject, NSTextFieldDelegate {
        var parent: VPNSecretField
        init(_ parent: VPNSecretField) { self.parent = parent }
        func controlTextDidChange(_ notification: Notification) {
            guard parent.enabled, let field = notification.object as? NSSecureTextField else { return }
            parent.text = field.stringValue
        }
        @objc func commit() { if parent.enabled { parent.submit() } }
        func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
            if selector == #selector(NSResponder.cancelOperation(_:)) {
                if parent.enabled { parent.cancel() }
                return true
            }
            return false
        }
    }
    final class Field: NSSecureTextField {
        var prompt: UUID?
        var focusedPrompt: UUID?
        private var observer: NSObjectProtocol?
        private var focusEpoch: UInt64 = 0
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            stopObserving()
            if let window {
                observer = NotificationCenter.default.addObserver(forName: NSWindow.didBecomeKeyNotification,
                    object: window, queue: .main) { [weak self] _ in self?.requestFocus() }
            }
            requestFocus()
        }
        func requestFocus() {
            guard let expectedPrompt = prompt, let expectedWindow = window else { return }
            let epoch = focusEpoch
            DispatchQueue.main.async { [weak self, weak expectedWindow] in
                guard let self, self.focusEpoch == epoch, self.isEnabled,
                      self.prompt == expectedPrompt, self.focusedPrompt != expectedPrompt,
                      let window = expectedWindow, self.window === window,
                      window.isVisible, window.isKeyWindow else { return }
                if window.makeFirstResponder(self) { self.focusedPrompt = expectedPrompt }
            }
        }
        func cancelPendingFocus() { focusEpoch &+= 1; focusedPrompt = nil }
        func stopObserving() {
            if let observer { NotificationCenter.default.removeObserver(observer) }
            observer = nil
        }
        deinit { stopObserving() }
    }
}

private struct VPNResourceRowsKey: PreferenceKey {
    static var defaultValue: [UUID: CGRect] = [:]
    static func reduce(value: inout [UUID: CGRect], nextValue: () -> [UUID: CGRect]) {
        value.merge(nextValue(), uniquingKeysWith: { _, new in new })
    }
}

private struct VPNResourceContentHeightKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}

private struct VPNResourceViewportHeightKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}

/// Only resource rows scroll. Stable row IDs survive editor navigation because
/// their anchor lives in the presentation model, outside this view's lifetime.
private struct VPNResourceListView: View {
    @ObservedObject var panel: VPNPanelModel
    @Environment(\.colorScheme) private var colorScheme
    @State private var initialTarget: UUID?
    @State private var revealTarget: Bool
    @State private var restoring = true
    @State private var restorationAttempts = 0
    @State private var coordinateSpace = UUID()
    @State private var contentHeight: CGFloat = 0
    @State private var viewportHeight: CGFloat = 0
    @State private var rowFrames: [UUID: CGRect] = [:]
    private let maximumViewportHeight: CGFloat = 144

    init(panel: VPNPanelModel) {
        self.panel = panel
        _initialTarget = State(initialValue: panel.resourceRevealID ?? panel.topVisibleResourceID)
        _revealTarget = State(initialValue: panel.resourceRevealID != nil)
    }

    private var resources: [VPNResource] { panel.configuration.configuration.resources }
    private var ink: Color {
        colorScheme == .dark ? Color(red: 0.92, green: 0.94, blue: 0.94) : Color(red: 0.12, green: 0.16, blue: 0.15)
    }
    private var viewportLimit: CGFloat {
        guard resources.count <= 3 else { return maximumViewportHeight }
        let estimate = CGFloat(resources.count) * 44 + CGFloat(max(0, resources.count - 1)) * 6
        return min(maximumViewportHeight, max(44, contentHeight > 0 ? contentHeight : estimate))
    }
    private var overflows: Bool {
        resources.count > 3 || (viewportHeight > 0 && contentHeight > viewportHeight + 0.5)
    }

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView(.vertical, showsIndicators: overflows) {
                Group {
                    if resources.count <= 3 {
                        // All short-list rows are measured, including wrapped text.
                        VStack(spacing: 6) { rows }
                    } else {
                        LazyVStack(spacing: 6) { rows }
                    }
                }
                .frame(maxWidth: .infinity)
                .background(GeometryReader { geometry in
                    Color.clear.preference(key: VPNResourceContentHeightKey.self, value: geometry.size.height)
                })
            }
            .coordinateSpace(name: coordinateSpace)
            .frame(minHeight: min(44, viewportLimit), idealHeight: viewportLimit, maxHeight: viewportLimit)
            .background(GeometryReader { geometry in
                Color.clear.preference(key: VPNResourceViewportHeightKey.self, value: geometry.size.height)
            })
            .accessibilityIdentifier("vpnResourceList")
            .onPreferenceChange(VPNResourceContentHeightKey.self) { contentHeight = $0 }
            .onPreferenceChange(VPNResourceViewportHeightKey.self) {
                viewportHeight = $0
                if restoring { restoreIfMeasured(using: proxy) }
            }
            .onPreferenceChange(VPNResourceRowsKey.self) { frames in
                rowFrames = frames
                if restoring { restoreIfMeasured(using: proxy) }
                else { recordTop(from: frames) }
            }
            .onChange(of: panel.resourceRevealID) { target in
                guard let target, panel.settings, !panel.editingResource, !panel.editingAuthentication else { return }
                initialTarget = target
                revealTarget = true
                restoring = true
                restorationAttempts = 0
                DispatchQueue.main.async {
                    guard restoring, initialTarget == target else { return }
                    restorationAttempts += 1
                    proxy.scrollTo(target, anchor: .center)
                    restoreIfMeasured(using: proxy)
                }
            }
            .onAppear {
                let target = initialTarget
                DispatchQueue.main.async {
                    guard restoring, initialTarget == target else { return }
                    if let target, resources.contains(where: { $0.id == target }) {
                        restorationAttempts += 1
                        proxy.scrollTo(target, anchor: revealTarget ? .center : .top)
                        restoreIfMeasured(using: proxy)
                    } else { finishRestoration() }
                }
            }
        }
    }

    private func restoreIfMeasured(using proxy: ScrollViewProxy) {
        guard restoring, viewportHeight > 0 else { return }
        guard let target = initialTarget, resources.contains(where: { $0.id == target }) else {
            finishRestoration(); return
        }
        guard let frame = rowFrames[target] else { return }
        let positioned = revealTarget
            ? frame.maxY > 0.5 && frame.minY < viewportHeight - 0.5
            : abs(frame.minY) <= 0.5
        if positioned || restorationAttempts >= 3 { finishRestoration() }
        else {
            // Lazy rows first provide estimated positions. Repeat only after
            // the target has a measured frame, using that same stable row ID.
            restorationAttempts += 1
            DispatchQueue.main.async {
                guard restoring, initialTarget == target else { return }
                proxy.scrollTo(target, anchor: revealTarget ? .center : .top)
            }
        }
    }

    private func finishRestoration() {
        restoring = false
        recordTop(from: rowFrames)
        panel.finishResourceReveal(initialTarget)
    }

    private func recordTop(from frames: [UUID: CGRect]) {
        guard viewportHeight > 0,
              let first = frames.filter({ $0.value.maxY > 0.5 && $0.value.minY < viewportHeight - 0.5 })
                .min(by: { $0.value.minY < $1.value.minY }) else { return }
        panel.recordVisibleResource(first.key)
    }

    private var rows: some View {
        ForEach(resources) { resource in
            Button { panel.beginResource(resource) } label: {
                HStack(spacing: 9) {
                    Image(systemName: "network").foregroundColor(PilotTheme.accent).frame(width: 22)
                    VStack(alignment: .leading, spacing: 2) {
                        if !resource.name.isEmpty {
                            Text(resource.name).font(.system(size: 10, weight: .medium))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Text(resource.address).font(.system(size: 11, design: .monospaced))
                            .fixedSize(horizontal: false, vertical: true)
                    }.frame(maxWidth: .infinity, alignment: .leading)
                    Image(systemName: "pencil").font(.system(size: 10)).foregroundColor(.secondary)
                }.padding(.horizontal, 10).padding(.vertical, 6)
                    .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                    .background(ink.opacity(0.035)).cornerRadius(9).contentShape(Rectangle())
            }.buttonStyle(PilotButtonStyle(cornerRadius: 9))
                .id(resource.id)
                .background(GeometryReader { geometry in
                    Color.clear.preference(key: VPNResourceRowsKey.self,
                        value: [resource.id: geometry.frame(in: .named(coordinateSpace))])
                })
        }
    }
}

/// Keeps the proxy home untouched. VPN is a separate destination reached from
/// Settings, so the existing large proxy button never changes its meaning.
struct VPNProductView: View {
    @ObservedObject var proxy: ProxyModel
    @ObservedObject var updates: UpdateModel
    @ObservedObject var vpn: VPNPanelModel
    @State private var showingVPN = false

    var body: some View {
        Group {
            if showingVPN {
                VPNPanelView(panel: vpn) { vpn.requestsPresentation = false; showingVPN = false }
            } else {
                PilotView(model: proxy, updates: updates, openVPN: { showingVPN = true },
                          vpnStatus: vpn.mainStatus)
            }
        }
        .onReceive(vpn.$requestsPresentation) { requested in
            if requested { showingVPN = true }
        }
        .onReceive(vpn.$navigationRequest.receive(on: DispatchQueue.main)) { request in
            // @Published emits before storage changes. Receiving on the main
            // queue lets consumption compare the fully committed request.
            guard let request, vpn.consumeNavigationRequest(request) else { return }
            switch request {
            case .applicationSettingsAfterVPNRemoval:
                vpn.requestsPresentation = false
                proxy.addingProxy = false
                proxy.choosingRoute = false
                proxy.manual = false
                proxy.editing = true
                showingVPN = false
            }
        }
    }
}
