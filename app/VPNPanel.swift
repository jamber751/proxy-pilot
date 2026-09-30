import AppKit
import Combine
import SwiftUI

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
    @Published var login = ""
    @Published var resourceName = ""
    @Published var resourceAddress = ""
    @Published var secret = ""
    @Published var message = ""
    @Published var confirmLastResourceRemoval = false
    @Published var confirmVPNRemoval = false
    @Published var requestsPresentation = false

    let configuration: VPNModel
    var onAttention: (() -> Void)?
    private let controller: VPNLiveController?
    private let queue = DispatchQueue(label: "proxypilot.vpn.frontend")
    private var modelChanges: AnyCancellable?

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
        modelChanges = configuration.objectWillChange.sink { [weak self] _ in
            self?.objectWillChange.send()
        }
        login = configuration.configuration.authentication?.login ?? ""
        authenticationChoice = configuration.configuration.authentication?.mode
    }

    var ready: Bool { configuration.connectionAvailability == .ready }
    var configured: Bool { configuration.profile != nil }
    var connected: Bool { liveState == .connected }
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
        case .connected: return "Рабочие ресурсы открываются через VPN."
        case .needsCredential(.privateKeyPassword): return "Пароль нужен только для этой попытки подключения."
        case .needsCredential(.vpnPassword):
            return configuration.configuration.authentication?.mode == .oneTimePassword
                ? "Введите текущий код или комбинацию, которую выдал администратор."
                : "Введите пароль VPN. Он не сохраняется."
        case .unavailable: return "Компонент VPN недоступен. Проверьте установку и попробуйте ещё раз."
        default: return ready ? "Одно нажатие подключит выбранные ресурсы." : "Откройте настройки и завершите три шага."
        }
    }

    func refresh() { run { $0.refresh() } }

    func restoreDesiredConnection() {
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
    func toggle() {
        guard ready else { settings = true; return }
        let shouldDisconnect = connected
        run { controller in shouldDisconnect ? controller.disconnect() : controller.connect() }
    }
    func submitCredential() {
        guard !secret.isEmpty else { return }
        var bytes = Data(secret.utf8)
        secret = ""
        run { $0.submitCredential(&bytes) }
    }
    func cancelCredential() { run { $0.cancelCredential() } }

    /// Explicit app exit must stop the managed tunnel before the proxy and app
    /// are allowed to terminate. Failure keeps the app alive with a visible
    /// explanation instead of abandoning owned routes.
    func disconnectForQuit(completion: @escaping () -> Void) {
        guard let controller, configured else { completion(); return }
        working = true; message = "Выключаем VPN…"
        queue.async { [weak self] in
            controller.disconnect()
            let state = controller.state
            DispatchQueue.main.async {
                guard let self else { return }
                self.liveState = state; self.liveChecked = true; self.working = false
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
        login = configuration.configuration.authentication?.login ?? login
        authenticationChoice = configuration.configuration.authentication?.mode
        editingAuthentication = true; message = ""
    }

    func cancelAuthentication() {
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
            try configuration.setAuthentication(mode: mode,
                                                login: mode == .certificate ? nil : login)
            editingAuthentication = false; message = ""
        } catch { message = error.localizedDescription }
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
            editingResource = true
            message = ""
        } catch { message = error.localizedDescription }
    }

    func saveResource() {
        guard var draft = configuration.resourceDraft else { return }
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
            editingResource = false; message = ""
        } catch { message = error.localizedDescription }
    }

    func cancelResource() {
        configuration.cancelResourceDraft(); editingResource = false; message = ""
    }

    func finishSettings() {
        do {
            if configuration.profile?.requiresCredentials == true {
                guard let mode = authenticationChoice ?? configuration.configuration.authentication?.mode else {
                    message = "Выберите пароль или код / 2FA."
                    return
                }
                try configuration.setAuthentication(mode: mode, login: login)
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

    func confirmRemoveVPN() {
        guard !working, let controller else { return }
        working = true; confirmVPNRemoval = false; message = "Выключаем и удаляем VPN…"
        queue.async { [weak self] in
            controller.disconnect()
            let state = controller.state
            DispatchQueue.main.async {
                guard let self else { return }
                self.liveState = state; self.liveChecked = true; self.working = false
                guard state == .off else {
                    self.message = "Не удалось безопасно выключить VPN. Настройки не удалены."
                    return
                }
                do {
                    try self.configuration.load()
                    try self.configuration.removeProfile()
                    self.settings = false; self.login = ""; self.secret = ""; self.message = ""
                } catch { self.message = error.localizedDescription }
            }
        }
    }

    private func removeDraftResource(confirmingVPNOff: Bool) {
        guard let id = configuration.resourceDraft?.id else { return }
        do {
            try configuration.removeResource(id: id, confirmingVPNOff: confirmingVPNOff)
            editingResource = false; confirmLastResourceRemoval = false; message = ""
        } catch { message = error.localizedDescription }
    }

    private func importProfiles(_ urls: [URL]) {
        do {
            try configuration.importProfile(files: urls)
            login = ""
            authenticationChoice = nil
            if configuration.profile?.requiresCredentials == false {
                try configuration.setAuthentication(mode: .certificate)
                authenticationChoice = .certificate
            }
            settings = true; message = ""
        } catch { message = error.localizedDescription }
    }

    private func run(_ operation: @escaping (VPNLiveController) -> Void,
                     completion: ((VPNLiveState) -> Void)? = nil) {
        guard !working, let controller else {
            if controller == nil { liveState = .unavailable }
            return
        }
        working = true; message = ""
        queue.async { [weak self] in
            operation(controller)
            let state = controller.state
            DispatchQueue.main.async {
                guard let self else { return }
                self.liveState = state
                self.liveChecked = true
                self.working = false
                do { try self.configuration.load() }
                catch { self.message = error.localizedDescription }
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
            if panel.editingResource { resourceEditor }
            else if panel.editingAuthentication { authenticationEditor }
            else if panel.settings { settings }
            else if panel.configured { home }
            else { importScreen }
        }
        .padding(.horizontal, 24).frame(width: 344, height: 432)
        .foregroundColor(ink).accentColor(accent).background(background)
        .onAppear { panel.refresh() }
    }

    private var header: some View {
        HStack(spacing: 7) {
            Button {
                if panel.editingResource { panel.cancelResource() }
                else if panel.editingAuthentication { panel.cancelAuthentication() }
                else if panel.settings { panel.settings = false }
                else { close() }
            } label: {
                Image(systemName: "chevron.left").frame(width: 36, height: 36).contentShape(Rectangle())
            }.buttonStyle(PilotButtonStyle()).accessibilityLabel("Назад").accessibilityIdentifier("vpnBack")
                .disabled(panel.working)
            Text(panel.editingResource ? "Ресурс" : panel.editingAuthentication ? "Вход" : panel.settings ? "Настройки VPN" : "VPN")
                .font(.system(size: 14, weight: .semibold))
            Spacer()
            if panel.configured && !panel.settings && !panel.editingResource {
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
            }.buttonStyle(PowerStyle()).disabled(panel.working)
                .accessibilityLabel(panel.powerTitle).accessibilityIdentifier("vpnPower")
            VStack(spacing: 8) {
                Text(panel.statusTitle).font(.system(size: 22, weight: .semibold)).tracking(-0.5)
                Text(panel.statusDetail).font(.system(size: 13)).foregroundColor(.secondary)
                    .multilineTextAlignment(.center).lineSpacing(3).fixedSize(horizontal: false, vertical: true)
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

    private var credentialForm: some View {
        VStack(spacing: 9) {
            SecureField("Пароль или код", text: $panel.secret)
                .textFieldStyle(RoundedBorderTextFieldStyle()).accessibilityIdentifier("vpnCredential")
            HStack(spacing: 8) {
                Button("Отмена", action: panel.cancelCredential)
                    .frame(maxWidth: .infinity, minHeight: 36).contentShape(Rectangle())
                    .buttonStyle(PilotButtonStyle(cornerRadius: 8)).accessibilityIdentifier("vpnCredentialCancel")
                Button("Продолжить", action: panel.submitCredential)
                    .frame(maxWidth: .infinity, minHeight: 36).contentShape(Rectangle())
                    .buttonStyle(PilotButtonStyle(cornerRadius: 8)).accessibilityIdentifier("vpnCredentialSubmit")
                    .disabled(panel.secret.isEmpty)
            }
        }
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
                    Text("Перетащите .ovpn сюда").font(.system(size: 14, weight: .semibold))
                    Text("или выберите файл").font(.system(size: 11)).foregroundColor(.secondary)
                }.frame(maxWidth: .infinity, minHeight: 154)
                    .background(dropTarget ? accent.opacity(0.12) : ink.opacity(0.025)).cornerRadius(14)
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(dropTarget ? accent : ink.opacity(0.10), style: StrokeStyle(lineWidth: 1, dash: [5])))
                    .contentShape(RoundedRectangle(cornerRadius: 14))
            }.buttonStyle(PilotButtonStyle(cornerRadius: 14)).accessibilityIdentifier("vpnImport")
                .accessibilityLabel("Добавить файл VPN")
                .onDrop(of: ["public.file-url"], isTargeted: $dropTarget, perform: panel.acceptDrop)
                .padding(.top, 24)
            if !panel.message.isEmpty {
                Text(panel.message).font(.system(size: 11)).foregroundColor(.secondary)
                    .multilineTextAlignment(.center).padding(.top, 12)
            }
            Spacer()
            Text("Файл хранится только на этом Mac. Пароли и коды не сохраняются.")
                .font(.system(size: 10)).foregroundColor(.secondary).multilineTextAlignment(.center)
                .padding(.bottom, 16)
        }
    }

    private var settings: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 10) {
                profileCard
                authenticationSummary
                resourcesCard
                if !panel.message.isEmpty {
                    Text(panel.message).font(.system(size: 10)).foregroundColor(.secondary)
                        .lineLimit(2).fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 4)
            }.padding(.top, 12).padding(.bottom, 8).disabled(panel.connected || panel.working)
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
                        Text("Нажмите, чтобы заменить файл").font(.system(size: 9)).foregroundColor(.secondary)
                    }
                    Spacer(); Image(systemName: "chevron.right").font(.system(size: 10)).foregroundColor(.secondary)
                }.padding(.horizontal, 11).frame(maxWidth: .infinity, minHeight: 48)
                    .background(ink.opacity(0.035)).cornerRadius(10).contentShape(Rectangle())
        }.buttonStyle(PilotButtonStyle(cornerRadius: 10))
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
                Text("Секрет вводится при каждом подключении и не сохраняется.")
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
                ScrollView(.vertical, showsIndicators: panel.configuration.configuration.resources.count > 3) {
                    LazyVStack(spacing: 6) {
                        ForEach(panel.configuration.configuration.resources) { resource in
                            Button { panel.beginResource(resource) } label: {
                                HStack(spacing: 9) {
                                    Image(systemName: "network").foregroundColor(accent).frame(width: 22)
                                    VStack(alignment: .leading, spacing: 2) {
                                        if !resource.name.isEmpty { Text(resource.name).font(.system(size: 10, weight: .medium)) }
                                        Text(resource.address).font(.system(size: 11, design: .monospaced)).lineLimit(1)
                                    }
                                    Spacer(); Image(systemName: "pencil").font(.system(size: 10)).foregroundColor(.secondary)
                                }.padding(.horizontal, 10).frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
                                    .background(ink.opacity(0.035)).cornerRadius(9).contentShape(Rectangle())
                            }.buttonStyle(PilotButtonStyle(cornerRadius: 9))
                        }
                    }
                }.frame(maxHeight: 144)
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
            }.buttonStyle(PilotButtonStyle(cornerRadius: 9)).disabled(panel.resourceAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
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
    }
}
