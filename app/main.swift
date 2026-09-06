// A menu-bar popover; gost inherits this app's Local Network permission.
import AppKit
import SwiftUI

struct ProxyState: Decodable {
    var configured: Bool
    var enabled: Bool
    var running: String
    var system_proxy: Bool
    var owns_system_proxy: Bool? = nil
    var selected: String? = nil
    var has_socks: Bool? = nil
    var has_http: Bool? = nil
    var socks_endpoint: String? = nil
    var http_endpoint: String? = nil
    func endpoint(for scheme: String) -> String {
        (scheme == "socks5" ? socks_endpoint : http_endpoint) ?? ""
    }
    static func routeName(_ mode: String) -> String {
        switch mode {
        case "socks": return "SOCKS5"
        case "http": return "HTTP"
        case "direct": return "Напрямую"
        default: return "Авто"
        }
    }
    var connected: Bool { enabled && running != "none" && system_proxy }
    var route: String {
        if !enabled && !system_proxy && owns_system_proxy != true { return "Напрямую" }
        guard connected else { return "Не определён" }
        switch running {
        case "direct": return "Напрямую"
        case "socks": return "SOCKS5"
        case "http": return "HTTP"
        default: return "Не определён"
        }
    }
}

struct CommandResult {
    let output: String
    let code: Int32
    var succeeded: Bool { code == 0 }
}

enum CLI {
    // Bundle and UI are versioned together, including source builds.
    static var path: String? {
        let bundled = Bundle.main.resourcePath.map { "\($0)/bin/proxypilot" }
        return ([bundled].compactMap { $0 } + [
            "\(NSHomeDirectory())/.local/bin/proxypilot",
            "/opt/homebrew/bin/proxypilot", "/usr/local/bin/proxypilot"
        ]).first { FileManager.default.isExecutableFile(atPath: $0) }
    }
    static func run(_ args: [String]) -> CommandResult {
        guard let path = path else { return CommandResult(output: "CLI not found", code: 127) }
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        var environment = ProcessInfo.processInfo.environment
        environment["TERM"] = "dumb"
        process.environment = environment
        // Drain both streams together; errors must not disappear or fill a pipe.
        process.standardOutput = pipe; process.standardError = pipe
        do { try process.run() }
        catch { return CommandResult(output: error.localizedDescription, code: 126) }
        let deadline = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 90, execute: deadline)
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit(); deadline.cancel()
        return CommandResult(output: String(data: data, encoding: .utf8) ?? "", code: process.terminationStatus)
    }
    static func state() -> ProxyState? {
        let result = run(["app-state"])
        guard result.succeeded, let data = result.output.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(ProxyState.self, from: data)
    }
}

final class ProxyModel: ObservableObject {
    @Published var state: ProxyState?
    @Published var busy = false
    @Published var loading = true
    @Published var operation = ""
    @Published var error = ""
    @Published var editing = false
    @Published var choosingRoute = false
    @Published var manual = false
    @Published var address = ""
    @Published var proxyHost = ""
    @Published var proxyPort = ""
    @Published var proxyScheme = "socks5"
    @Published var addingProxy = false
    let preview: Bool
    private let queue = DispatchQueue(label: "proxypilot.commands")
    private var refreshing = false
    var onChange: (() -> Void)?

    init(preview: Bool = false) {
        self.preview = preview
        if preview {
            loading = false
            state = ProxyState(configured: false, enabled: false, running: "none", system_proxy: false)
        }
    }
    var connected: Bool { state?.connected == true }
    var configured: Bool { state?.configured == true }
    var wantsOn: Bool { state?.enabled == true || state?.system_proxy == true || state?.owns_system_proxy == true }
    var setup: Bool { editing || (!configured && !loading) }
    var title: String {
        if loading { return "Проверяем подключение" }
        if busy { return operation }
        if !error.isEmpty { return wantsOn && !setup ? "Нужна проверка" : "Не удалось подключиться" }
        if setup { return manual ? "Укажите адрес прокси" : "Начнём с подключения" }
        return connected ? "Прокси включён" : "Прокси выключен"
    }
    var detail: String {
        if busy || loading { return "Это займёт несколько секунд" }
        if !error.isEmpty { return error }
        if setup { return manual ? "Вставьте адрес, который выдал\nадминистратор вашей сети." : "Найдём прокси в вашей сети\nи настроим всё автоматически." }
        if !connected { return "При включении: \(ProxyState.routeName(state?.selected ?? "auto"))." }
        if state?.running == "direct", let selected = state?.selected, ["socks", "http"].contains(selected) {
            return "\(ProxyState.routeName(selected)) недоступен — временно напрямую."
        }
        switch state?.running {
        case "socks": return "Через SOCKS5-прокси вашей сети."
        case "http": return "Через HTTP-прокси вашей сети."
        case "direct": return "Через локальный мост, без внешнего прокси."
        default: return "Не удалось определить маршрут."
        }
    }
    var actionTitle: String {
        if setup { return manual ? "Сохранить и включить" : "Найти автоматически" }
        if wantsOn { return "Выключить" }
        return error.isEmpty ? "Включить" : "Повторить"
    }
    static func endpoint(_ input: String) -> String? {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URLComponents(string: value),
              ["http", "socks5"].contains(url.scheme ?? ""),
              let host = url.host, !host.isEmpty,
              let port = url.port, (1...65535).contains(port),
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              url.path.isEmpty,
              host.range(of: "^[A-Za-z0-9][A-Za-z0-9.-]*$", options: .regularExpression) != nil,
              !["localhost", "0.0.0.0"].contains(host.lowercased()), !host.hasPrefix("127.")
        else { return nil }
        return value
    }
    func refresh() {
        guard !preview, !busy, !refreshing else { return }
        refreshing = true
        queue.async {
            var result = CLI.state()
            if result?.configured == true {
                _ = CLI.run(["ensure"])
                result = CLI.state()
            }
            let fresh = result
            DispatchQueue.main.async {
                self.refreshing = false
                guard !self.busy else { return }
                self.loading = false; self.state = fresh
                if self.error == "Не удалось прочитать состояние. Попробуйте открыть приложение заново." || self.error == "Подключение прервалось. Выключите прокси и попробуйте снова." {
                    self.error = ""
                }
                if fresh == nil { self.error = "Не удалось прочитать состояние. Попробуйте открыть приложение заново." }
                else if fresh!.enabled && !fresh!.connected {
                    self.error = "Подключение прервалось. Выключите прокси и попробуйте снова."
                }
                self.onChange?()
            }
        }
    }
    func perform() {
        guard !busy, !loading else { return }
        let args: [String]
        if setup {
            if manual {
                guard let endpoint = Self.endpoint(address) else { return }
                args = ["setup", endpoint]
            } else { args = ["detect"] }
        } else { args = wantsOn ? ["disable"] : ["route", state?.selected ?? "auto", "enable"] }
        execute(args)
    }
    func configure(manually: Bool) {
        manual = manually
        perform()
    }
    var formEndpoint: String? {
        let host = proxyHost.trimmingCharacters(in: .whitespacesAndNewlines)
        let port = proxyPort.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty, !port.isEmpty, port.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        return Self.endpoint("\(proxyScheme)://\(host):\(port)")
    }
    var replacesProxy: Bool { !(state?.endpoint(for: proxyScheme) ?? "").isEmpty }
    func openProxy(_ scheme: String? = nil) {
        proxyScheme = scheme ?? (state?.has_socks == true && state?.has_http != true ? "http" : "socks5")
        let value = scheme == nil ? "" : state?.endpoint(for: proxyScheme) ?? ""
        let pieces = value.split(separator: ":", omittingEmptySubsequences: false)
        proxyHost = pieces.count == 2 ? String(pieces[0]) : ""
        proxyPort = pieces.count == 2 ? String(pieces[1]) : ""
        error = ""; addingProxy = true
    }
    func saveProxy() {
        guard let endpoint = formEndpoint, !busy else { return }
        execute(["setup", endpoint])
    }
    func selectRoute(_ route: String) {
        guard !busy, !loading, configured else { return }
        execute(["route", route])
    }
    private func execute(_ args: [String], completion: (() -> Void)? = nil) {
        guard !busy else { return }
        busy = true; error = ""
        let off = args.first == "disable"
        operation = off ? "Выключаем прокси" : (args.first == "detect" ? "Ищем прокси" : "Подключаемся")
        onChange?()
        if preview {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                let choosing = args.first == "route"
                let enabled = choosing && args.count == 2 ? self.wantsOn : !off
                let previous = self.state
                let selected = args.first == "setup" ? (args[1].hasPrefix("socks5:") ? "socks" : "http") : choosing ? args[1] : self.state?.selected ?? "auto"
                self.state = ProxyState(configured: true, enabled: enabled, running: enabled ? (selected == "auto" ? "socks" : selected) : "direct", system_proxy: enabled, selected: selected, has_socks: true, has_http: true, socks_endpoint: previous?.socks_endpoint, http_endpoint: previous?.http_endpoint)
                if args.first == "setup", let url = URLComponents(string: args[1]), let host = url.host, let port = url.port {
                    if url.scheme == "socks5" { self.state?.socks_endpoint = "\(host):\(port)" }
                    else { self.state?.http_endpoint = "\(host):\(port)" }
                }
                self.busy = false; self.editing = args.first == "setup"; self.addingProxy = false; self.manual = false; self.choosingRoute = false
                self.onChange?(); completion?()
            }
            return
        }
        queue.async {
            let result = CLI.run(args)
            let fresh = CLI.state()
            let choosing = args.first == "route"
            let selectedOK = !choosing || fresh?.selected == args[1]
            let routeOK = !choosing || args[1] == "auto" || fresh?.enabled == false || fresh?.running == args[1]
            let offChoice = choosing && args.count == 2 && fresh?.enabled == false
            let verified = selectedOK && routeOK && (off ? (fresh?.enabled == false && fresh?.system_proxy == false && fresh?.owns_system_proxy != true) : (offChoice || fresh?.connected == true))
            DispatchQueue.main.async {
                self.busy = false; self.loading = false; self.state = fresh
                if result.succeeded && verified {
                    self.editing = args.first == "setup"; self.addingProxy = false; self.manual = false; self.choosingRoute = false; completion?()
                } else if args.first == "detect" && result.output.contains("прокси не найдены") {
                    self.error = "Прокси не найден. Подключитесь к рабочей сети или укажите адрес вручную."
                } else if choosing {
                    self.error = "Не удалось переключить маршрут. Проверьте адрес прокси и его доступность."
                } else if args.first == "setup" {
                    self.error = "Не удалось подключиться. Проверьте IP, порт, протокол и доступность сервера."
                } else {
                    self.error = off ? "Не удалось выключить прокси. Попробуйте ещё раз." : "Проверьте сеть и доступ ProxyPilot к локальной сети в настройках macOS."
                }
                self.onChange?()
            }
        }
    }
    func quit() {
        if preview { NSApp.terminate(nil); return }
        execute(["disable"]) { NSApp.terminate(nil) }
    }
}

struct PowerStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label.opacity(configuration.isPressed ? 0.65 : 1)
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
    }
}

struct RouteRow: View {
    let title: String
    let subtitle: String
    let symbol: String
    let selected: Bool
    let available: Bool
    let busy: Bool
    let ink: Color
    let accent: Color
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 11) {
                Image(systemName: symbol).font(.system(size: 16, weight: .medium))
                    .foregroundColor(selected ? accent : ink.opacity(0.65)).frame(width: 26)
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.system(size: 13, weight: .semibold))
                    Text(available ? subtitle : "Сначала настройте адрес прокси")
                        .font(.system(size: 10)).foregroundColor(.secondary)
                }
                Spacer(minLength: 4)
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 16, weight: .regular))
                    .foregroundColor(selected ? accent : ink.opacity(0.15))
            }.padding(.horizontal, 13).frame(height: 52)
                .background(selected ? accent.opacity(0.10) : ink.opacity(hovering && available ? 0.075 : 0.025))
                .cornerRadius(12)
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(selected ? accent.opacity(0.5) : ink.opacity(hovering ? 0.14 : 0.07), lineWidth: 1))
                .contentShape(RoundedRectangle(cornerRadius: 12))
        }.buttonStyle(PowerStyle()).disabled(!available || busy)
            .opacity(available ? 1 : 0.45)
            .onHover { hovering = $0 }
            .accessibilityLabel(title + (selected ? ", выбран" : "") + (available ? "" : ", не настроен"))
    }
}

struct PilotView: View {
    @ObservedObject var model: ProxyModel
    @Environment(\.colorScheme) private var colorScheme
    private var ink: Color { colorScheme == .dark ? Color(red: 0.92, green: 0.94, blue: 0.94) : Color(red: 0.12, green: 0.16, blue: 0.15) }
    private var accent: Color { Color(red: 0.12, green: 0.53, blue: 0.39) }
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 7) {
                if model.addingProxy || ((model.setup || model.choosingRoute) && model.configured) {
                    Button {
                        if model.addingProxy { model.addingProxy = false }
                        else { model.editing = false; model.choosingRoute = false; model.manual = false }
                        model.error = ""
                    } label: {
                        Image(systemName: "chevron.left").frame(width: 24, height: 28)
                    }.buttonStyle(PlainButtonStyle()).accessibilityLabel("Назад")
                        .disabled(model.busy)
                } else {
                    Image(systemName: "circle.hexagongrid.fill").font(.system(size: 14, weight: .medium))
                }
                Text(model.addingProxy ? "Адрес прокси" : model.choosingRoute ? "Маршрут" : model.setup ? "Настройки" : "ProxyPilot").font(.system(size: 14, weight: .semibold))
                Spacer()
                if model.preview { Text("ПРЕВЬЮ").font(.system(size: 9, weight: .medium)).foregroundColor(.secondary) }
                if model.setup && !model.addingProxy {
                    Button { model.openProxy() } label: {
                        Image(systemName: "plus").font(.system(size: 16, weight: .medium)).frame(width: 28, height: 28)
                    }.buttonStyle(PlainButtonStyle()).accessibilityLabel("Добавить прокси")
                        .disabled(model.busy || model.loading)
                }
                if !model.setup && !model.choosingRoute {
                    Button { model.editing = true; model.manual = false; model.error = "" } label: {
                        Image(systemName: "gearshape").font(.system(size: 16)).frame(width: 28, height: 28)
                    }.buttonStyle(PlainButtonStyle()).accessibilityLabel("Настройки")
                        .help("Настройки подключения").disabled(model.busy || model.loading)
                }
            }.padding(.top, 20)
            if model.setup {
                if model.addingProxy { proxyForm } else { settings }
            } else if model.choosingRoute {
                routePicker
            } else {
            Spacer(minLength: 12)
            Button(action: model.perform) {
                VStack(spacing: 18) {
                    ZStack {
                        Circle().fill(model.connected && !model.setup ? accent : ink)
                        if model.busy || model.loading {
                            ProgressView().progressViewStyle(CircularProgressViewStyle(tint: colorScheme == .dark && !model.connected ? .black : .white))
                        } else {
                            Image(systemName: "power").font(.system(size: 36, weight: .light))
                                .foregroundColor(colorScheme == .dark && !model.connected ? .black : .white)
                        }
                    }.frame(width: 104, height: 104).shadow(color: .black.opacity(0.08), radius: 14, x: 0, y: 7)
                    Text(model.busy ? "Подождите…" : model.actionTitle)
                        .font(.system(size: 13, weight: .medium)).foregroundColor(ink)
                }.frame(maxWidth: .infinity).contentShape(Rectangle())
            }
            .buttonStyle(PowerStyle())
            .disabled(model.busy || model.loading)
            .accessibilityLabel(model.actionTitle).keyboardShortcut(.defaultAction)
            VStack(spacing: 8) {
                Text(model.title).font(.system(size: 22, weight: .semibold)).tracking(-0.5)
                Text(model.detail).font(.system(size: 13)).foregroundColor(.secondary)
                    .multilineTextAlignment(.center).lineSpacing(3).fixedSize(horizontal: false, vertical: true)
            }.padding(.top, 24)
            Button { model.choosingRoute = true; model.error = "" } label: {
                HStack(spacing: 10) {
                    Image(systemName: "arrow.triangle.branch").font(.system(size: 16, weight: .medium)).foregroundColor(.secondary)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("МАРШРУТ").font(.system(size: 8, weight: .semibold)).tracking(1).foregroundColor(.secondary)
                        Text(model.loading || model.busy ? "Проверяем…" : model.state?.route ?? "Не определён")
                            .font(.system(size: 13, weight: .semibold))
                    }
                    Spacer(minLength: 8)
                    if (model.state?.selected ?? "auto") == "auto" {
                        Text("АВТО").font(.system(size: 8, weight: .semibold)).tracking(0.5)
                            .foregroundColor(accent).padding(.horizontal, 7).padding(.vertical, 4)
                            .background(accent.opacity(0.1)).cornerRadius(5)
                    }
                    Image(systemName: "chevron.down").font(.system(size: 10, weight: .semibold)).foregroundColor(.secondary)
                }.padding(.horizontal, 13).padding(.vertical, 10)
                    .background(ink.opacity(0.025)).cornerRadius(12)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(ink.opacity(0.09), lineWidth: 1))
                    .contentShape(RoundedRectangle(cornerRadius: 12))
            }.buttonStyle(PowerStyle())
                .disabled(model.busy || model.loading || !model.configured)
                .accessibilityLabel("Выбрать маршрут: \(model.state?.route ?? "Не определён")")
                .padding(.top, 18)
                .help("Маршрут ProxyPilot для приложений, использующих системный прокси. Другие VPN и прокси могут влиять на трафик отдельно.")
            }
            Spacer(minLength: 12)
            Divider().opacity(0.5)
            HStack {
                Text(model.setup ? "HTTP / SOCKS5" : "Маршрут системного прокси")
                Spacer()
                Button("Выйти", action: model.quit).disabled(model.busy || model.loading)
            }.buttonStyle(PlainButtonStyle()).font(.system(size: 11)).foregroundColor(.secondary).padding(.vertical, 16)
        }
        .padding(.horizontal, 24).frame(width: 344, height: 432)
        .foregroundColor(ink)
        .background(colorScheme == .dark ? Color(red: 0.10, green: 0.12, blue: 0.115) : Color(red: 0.98, green: 0.985, blue: 0.98))
    }
    private var routePicker: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text("Как подключаться?").font(.system(size: 22, weight: .semibold)).tracking(-0.5)
                .padding(.top, 16)
            Text(model.busy ? "Применяем маршрут…" : !model.error.isEmpty ? model.error : model.wantsOn ? "Выберите маршрут для обоих локальных мостов." : "Выбор применится при включении прокси.")
                .font(.system(size: 11)).foregroundColor(.secondary)
                .lineLimit(2).frame(height: 28, alignment: .topLeading)
            ForEach(["auto", "direct", "socks", "http"], id: \.self) { route in
                RouteRow(title: ProxyState.routeName(route), subtitle: routeSubtitle(route), symbol: routeSymbol(route),
                         selected: (model.state?.selected ?? "auto") == route,
                         available: route == "socks" ? model.state?.has_socks == true : route == "http" ? model.state?.has_http == true : true,
                         busy: model.busy, ink: ink, accent: accent) {
                    model.selectRoute(route)
                }
            }
        }
    }
    private func routeSubtitle(_ route: String) -> String {
        switch route {
        case "direct": return "Без внешнего прокси"
        case "socks": return "Через SOCKS5-прокси вашей сети"
        case "http": return "Через HTTP-прокси вашей сети"
        default: return "Подбирает маршрут по доступности"
        }
    }
    private func routeSymbol(_ route: String) -> String {
        switch route {
        case "direct": return "arrow.up.right"
        case "socks": return "network"
        case "http": return "globe"
        default: return "sparkles"
        }
    }
    private var settings: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Ваши прокси").font(.system(size: 22, weight: .semibold)).padding(.top, 20)
            Text(model.configured ? "Сохранённые адреса для подключения." : "Добавьте адрес через + или найдите автоматически.")
                .font(.system(size: 11)).foregroundColor(.secondary)
            ForEach(["socks5", "http"], id: \.self) { scheme in
                if !(model.state?.endpoint(for: scheme) ?? "").isEmpty {
                    proxyEntry(scheme)
                }
            }
            if !model.configured {
                VStack(spacing: 8) {
                    Image(systemName: "network").font(.system(size: 26)).foregroundColor(.secondary)
                    Text("Пока нет адресов").font(.system(size: 12, weight: .medium))
                }.frame(maxWidth: .infinity).padding(.vertical, 25)
                    .background(ink.opacity(0.025)).cornerRadius(12)
            }
            Divider().padding(.vertical, 4)
            Button { model.configure(manually: false) } label: {
                HStack(spacing: 8) {
                    Image(systemName: "sparkle.magnifyingglass")
                    Text("Найти автоматически").font(.system(size: 12, weight: .medium))
                    Spacer()
                    Image(systemName: "chevron.right").font(.system(size: 10))
                }.padding(12).background(ink.opacity(0.06)).cornerRadius(10)
            }.buttonStyle(PlainButtonStyle()).disabled(model.busy || model.loading)
            Text(model.busy ? model.operation : model.error)
                .font(.system(size: 10)).foregroundColor(.secondary).lineLimit(2)
        }
    }
    private func proxyEntry(_ scheme: String) -> some View {
        let mode = scheme == "socks5" ? "socks" : "http"
        let active = model.connected && model.state?.running == mode
        return Button { model.openProxy(scheme) } label: {
            HStack(spacing: 11) {
                Image(systemName: scheme == "socks5" ? "network" : "globe")
                    .font(.system(size: 17)).foregroundColor(active ? accent : .secondary).frame(width: 26)
                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 7) {
                        Text(scheme == "socks5" ? "SOCKS5" : "HTTP").font(.system(size: 12, weight: .semibold))
                        Text(active ? "Используется" : "Настроен").font(.system(size: 9, weight: .medium))
                            .foregroundColor(active ? accent : .secondary)
                    }
                    Text(model.state?.endpoint(for: scheme) ?? "")
                        .font(.system(size: 12, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                }
                Spacer(minLength: 2)
                Image(systemName: "pencil").font(.system(size: 12)).foregroundColor(.secondary)
            }.padding(13).frame(maxWidth: .infinity, alignment: .leading)
                .background(ink.opacity(0.025)).cornerRadius(12)
                .overlay(RoundedRectangle(cornerRadius: 12).stroke(active ? accent.opacity(0.4) : ink.opacity(0.08), lineWidth: 1))
                .contentShape(RoundedRectangle(cornerRadius: 12))
        }.buttonStyle(PowerStyle()).disabled(model.busy)
            .accessibilityLabel("Изменить \(scheme == "socks5" ? "SOCKS5" : "HTTP"): \(model.state?.endpoint(for: scheme) ?? ""), \(active ? "используется" : "настроен")")
    }
    private var proxyForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Настроить подключение").font(.system(size: 21, weight: .semibold)).tracking(-0.5).padding(.top, 16)
            VStack(alignment: .leading, spacing: 7) {
                Text("Протокол").font(.system(size: 11, weight: .medium)).foregroundColor(.secondary)
                Picker("Протокол", selection: $model.proxyScheme) {
                    Text("SOCKS5").tag("socks5")
                    Text("HTTP").tag("http")
                }.pickerStyle(SegmentedPickerStyle()).labelsHidden()
            }
            HStack(alignment: .top, spacing: 10) {
                VStack(alignment: .leading, spacing: 7) {
                    Text("IP / хост").font(.system(size: 11, weight: .medium)).foregroundColor(.secondary)
                    TextField("192.168.1.2", text: $model.proxyHost).accessibilityLabel("IP или хост")
                }
                VStack(alignment: .leading, spacing: 7) {
                    Text("Порт").font(.system(size: 11, weight: .medium)).foregroundColor(.secondary)
                    TextField(model.proxyScheme == "socks5" ? "1080" : "3128", text: $model.proxyPort).accessibilityLabel("Порт")
                }.frame(width: 72)
            }.textFieldStyle(RoundedBorderTextFieldStyle()).font(.system(size: 13))
            Text(model.replacesProxy ? "Адрес \(model.proxyScheme == "socks5" ? "SOCKS5" : "HTTP") будет обновлён. Другой протокол останется без изменений." : "Только IP или имя сервера — без http:// и socks5://.")
                .font(.system(size: 11)).foregroundColor(.secondary).frame(height: 32, alignment: .topLeading)
            Button(action: model.saveProxy) {
                Text(model.busy ? "Подключаемся…" : model.replacesProxy ? "Обновить и подключить" : "Добавить и подключить").font(.system(size: 12, weight: .semibold))
                    .frame(maxWidth: .infinity).padding(.vertical, 10)
                    .background(accent).foregroundColor(.white).cornerRadius(9)
            }.buttonStyle(PlainButtonStyle())
                .disabled(model.busy || model.loading || model.formEndpoint == nil)
                .opacity(model.formEndpoint == nil || model.busy ? 0.4 : 1)
            Text(model.error).font(.system(size: 11)).foregroundColor(.secondary).lineLimit(2).frame(height: 28, alignment: .topLeading)
        }.disabled(model.busy)
    }
}

final class App: NSObject, NSApplicationDelegate {
    private var item: NSStatusItem!
    private var popover: NSPopover!
    private var timer: Timer?
    private var activity: NSObjectProtocol?
    private let model = ProxyModel(preview: Bundle.main.bundleIdentifier?.hasSuffix(".preview") == true)
    func applicationDidFinishLaunching(_ notification: Notification) {
        if model.preview, let appearance = Bundle.main.object(forInfoDictionaryKey: "PreviewAppearance") as? String {
            NSApp.appearance = NSAppearance(named: appearance == "light" ? .aqua : .darkAqua)
        }
        let bundleID = Bundle.main.bundleIdentifier ?? "kz.documentolog.proxypilot"
        if NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
            .contains(where: { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }) {
            NSApp.terminate(nil); return
        }
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.target = self; item.button?.action = #selector(toggleWindow)
        let host = NSHostingController(rootView: PilotView(model: model))
        popover = NSPopover()
        popover.contentViewController = host
        popover.contentSize = NSSize(width: 344, height: 432)
        popover.behavior = .transient
        popover.animates = true
        model.onChange = { [weak self] in self?.renderStatus() }
        activity = ProcessInfo.processInfo.beginActivity(options: [.userInitiatedAllowingIdleSystemSleep], reason: "Proxy connection")
        let t = Timer(timeInterval: 5, repeats: true) { [weak self] _ in self?.model.refresh() }
        RunLoop.main.add(t, forMode: .common); timer = t
        renderStatus(); model.refresh()
        DispatchQueue.main.async { [weak self] in self?.showWindow() }
    }
    private func renderStatus() {
        // Keep the same brand mark as the popover header in every state.
        let image = NSImage(systemSymbolName: "circle.hexagongrid.fill", accessibilityDescription: "ProxyPilot: \(model.title)")?
            .withSymbolConfiguration(NSImage.SymbolConfiguration(pointSize: 16, weight: .medium))
        image?.isTemplate = true; item.button?.image = image
        item.button?.alphaValue = model.busy || model.loading ? 0.7 : (model.connected ? 1 : 0.45)
        item.button?.toolTip = "\(model.title) · \(model.state?.route ?? "Проверяем маршрут")"
    }
    @objc private func toggleWindow() {
        if popover.isShown { popover.performClose(nil) } else { showWindow(); model.refresh() }
    }
    private func showWindow() {
        guard let button = item.button, button.window != nil else { return }
        NSApp.activate(ignoringOtherApps: true)
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        if let window = popover.contentViewController?.view.window {
            window.title = "ProxyPilot"
            window.setAccessibilityRole(.window)
            window.setAccessibilitySubrole(.standardWindow)
            window.setAccessibilityLabel("ProxyPilot")
            window.makeKey()
        }
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        showWindow(); return true
    }
}

let app = NSApplication.shared
let delegate = App()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
