// ProxyPilot — переключатель апстрима прокси в меню-баре macOS.
//
// Приложение НЕ реализует прокси само: оно управляет CLI `proxypilot`
// и показывает его состояние. Мост (gost) запускается как дочерний процесс
// ЭТОГО приложения и наследует его разрешение Local Network (macOS 15+);
// у launchd-агента такого разрешения нет ("no route to host") — поэтому
// мост сознательно не вынесен в LaunchAgent.
//
// Всё редактирование конфига идёт через `proxypilot set` — знание о формате
// файла живёт в CLI, приложение конфиг только читает.

import AppKit
import SwiftUI
import Combine

// ── состояние от CLI ─────────────────────────────────────────────────────────
struct State: Decodable {
    let mode: String          // сохранённый режим: auto|socks|http|direct
    let effective: String     // во что разворачивается auto
    let running: String       // фактический апстрим моста, либо "none"
    let port: Int
    let socks: String
    let socks_up: Bool
    let http: String
    let http_up: Bool
    let gateway: String
    let configured: Bool

    // Сетевой профиль. Опциональные: приложение может стоять рядом с CLI,
    // который этих полей ещё не отдаёт — тогда секция просто не показывается.
    let in_office: Bool?
    let net_service: String?
    let office_ip: String?
    let net_daemon: Bool?
    let vpn_profile: String?
    let vpn_installed: Bool?
    let vpn_up: Bool?
    let vpn_auto: Bool?
    let vpn_foreign: Bool?
    let system_proxy: Bool?
}

// Автозапуск. SMAppService появился только в macOS 13, а планка у нас 11 —
// поэтому через System Events, тем же способом, что и установщик из DMG.
// Без автозапуска после перезагрузки нет моста: gost живёт дочерним процессом
// этого приложения (см. шапку файла), так что «выключено» = сломанная машина.
enum LoginItem {
    private static func osa(_ script: String) -> String {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", script]
        let pipe = Pipe()
        proc.standardOutput = pipe; proc.standardError = Pipe()
        do { try proc.run() } catch { return "" }
        let d = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        return String(data: d, encoding: .utf8) ?? ""
    }
    static func enabled() -> Bool {
        osa("tell application \"System Events\" to get the name of every login item")
            .contains("ProxyPilot")
    }
    static func set(_ on: Bool) {
        if on {
            let path = Bundle.main.bundlePath
            _ = osa("tell application \"System Events\" to make login item at end with properties {path:\"\(path)\", hidden:true}")
        } else {
            _ = osa("tell application \"System Events\" to delete login item \"ProxyPilot\"")
        }
    }
}

enum CLI {
    // Установленный CLI ищем раньше вложенного: у разработчика ~/.local/bin —
    // симлинк на репо (всегда свежий), а копия в бандле отстаёт от правок.
    // Вложенный (Contents/Resources/bin, кладёт make-dmg.sh) — для машин,
    // куда приложение попало через DMG без install.sh.
    static var candidates: [String] {
        var list = [
            "\(NSHomeDirectory())/.local/bin/proxypilot",
            "/opt/homebrew/bin/proxypilot",
            "/usr/local/bin/proxypilot",
        ]
        if let res = Bundle.main.resourcePath {
            list.append("\(res)/bin/proxypilot")
        }
        return list
    }
    static var path: String? {
        candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    @discardableResult
    static func run(_ args: [String]) -> String {
        guard let exe = path else { return "" }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: exe)
        proc.arguments = args
        var env = ProcessInfo.processInfo.environment
        env["TERM"] = "dumb"   // без ANSI-раскраски в выводе для GUI
        proc.environment = env
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = Pipe()
        do { try proc.run() } catch { return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        return String(data: data, encoding: .utf8) ?? ""
    }

    // Профиль сети и туннель — это root (смена IPv4 в macOS доступна только ему).
    // Пароль спрашивает система своим диалогом; сами мы его не видим и не храним.
    // XDG_CONFIG_HOME передаём явно: у root свой $HOME, а конфиг лежит у
    // пользователя.
    static func runAdmin(_ args: [String]) -> String {
        guard let exe = path else { return "CLI не найден" }
        let home = "\(NSHomeDirectory())/.config"
        let parts = ["/usr/bin/env", "XDG_CONFIG_HOME=\(home)", exe] + args
        let cmd = parts.map(shQuote).joined(separator: " ")
        let script = "do shell script \(asQuote(cmd)) with administrator privileges"

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", script]
        let out = Pipe(), err = Pipe()
        proc.standardOutput = out; proc.standardError = err
        do { try proc.run() } catch { return "не удалось запустить osascript" }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        let edata = err.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        let stdout = String(data: data, encoding: .utf8) ?? ""
        if proc.terminationStatus != 0 {
            let e = String(data: edata, encoding: .utf8) ?? ""
            // -128 — пользователь нажал «Отмена» в диалоге пароля
            if e.contains("-128") { return "отменено" }
            return e.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return stdout
    }

    private static func shQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
    private static func asQuote(_ s: String) -> String {
        "\"" + s.replacingOccurrences(of: "\\", with: "\\\\")
                 .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    static func state() -> State? {
        let out = run(["json"])
        guard let data = out.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(State.self, from: data)
    }
}

func stripANSI(_ s: String) -> String {
    s.replacingOccurrences(of: "\u{1B}\\[[0-9;]*[A-Za-z]",
                           with: "", options: .regularExpression)
}

let appLog = URL(fileURLWithPath: "\(NSHomeDirectory())/Library/Logs/proxypilot-app.log")
func log(_ s: String) {
    let line = "\(ISO8601DateFormatter().string(from: Date()))  \(s)\n"
    guard let d = line.data(using: .utf8) else { return }
    if let fh = try? FileHandle(forWritingTo: appLog) {
        defer { try? fh.close() }
        _ = try? fh.seekToEnd()
        try? fh.write(contentsOf: d)
    } else {
        try? d.write(to: appLog)
    }
}

// ── модель настроек (для окна Settings) ──────────────────────────────────────
enum Probe { case unknown, checking, up, down }

final class ConfigStore: ObservableObject {
    @Published var socks = ""
    @Published var http = ""
    @Published var port = "3129"
    @Published var gateways = ""

    // сетевой профиль
    // Пусто — и CLI выведет сам: сервис по дефолтному маршруту, маску с
    // интерфейса. Прежние значения "Wi-Fi" и "255.255.255.0" сохранение
    // записывало в конфиг, заново прибивая то, что должно определяться.
    @Published var netService = ""
    @Published var officeIP = ""
    @Published var officeMask = ""
    @Published var officeDNS = ""
    @Published var vpnProfile = ""
    @Published var vpnRoutes = ""
    @Published var vpnAuto = false

    // Тумблеры не ждут «Сохранить»: это не поля конфига, а состояние системы.
    @Published var systemProxyOn = false
    @Published var loginItemOn = false

    @Published var socksProbe: Probe = .unknown
    @Published var httpProbe: Probe = .unknown
    @Published var busy = false
    @Published var message = ""

    var configPath: String {
        "\(NSHomeDirectory())/.config/proxypilot/config"
    }

    // читаем конфиг напрямую (KEY=VALUE); пишем — только через `proxypilot set`
    func load() {
        guard let text = try? String(contentsOfFile: configPath, encoding: .utf8) else { return }
        for raw in text.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.hasPrefix("#"), let eq = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<eq])
            // Значения с пробелами (список DNS, несколько маршрутов) лежат в
            // кавычках — так их пишет `proxypilot set` и разбирает CLI.
            let value = Self.unquote(String(line[line.index(after: eq)...]))
            switch key {
            case "SOCKS_UPSTREAM":  socks = value
            case "HTTP_UPSTREAM":   http = value
            case "BRIDGE_PORT":     port = value
            case "OFFICE_GATEWAYS": gateways = value
            case "NET_SERVICE":     netService = value
            case "OFFICE_IP":       officeIP = value
            case "OFFICE_MASK":     officeMask = value
            case "OFFICE_DNS":      officeDNS = value
            case "VPN_PROFILE":     vpnProfile = value
            case "VPN_ROUTES":      vpnRoutes = value
            case "VPN_AUTO":        vpnAuto = (value == "on")
            default: break
            }
        }
        savedFields = fields
    }

    static func unquote(_ s: String) -> String {
        guard s.count >= 2, s.hasPrefix("\""), s.hasSuffix("\"") else { return s }
        return String(s.dropFirst().dropLast())
    }

    private static let hostPort = try! NSRegularExpression(pattern: "^[A-Za-z0-9_.-]+:[0-9]{1,5}$")
    private static let ipv4 = try! NSRegularExpression(pattern: "^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$")
    static func validIPv4(_ s: String, allowEmpty: Bool = true) -> Bool {
        if s.isEmpty { return allowEmpty }
        return ipv4.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }
    static func validDNSList(_ s: String) -> Bool {
        s.split(separator: " ").allSatisfy { validIPv4(String($0), allowEmpty: false) }
    }
    static func validUpstream(_ s: String) -> Bool {
        s.isEmpty || hostPort.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }
    var valid: Bool {
        Self.validUpstream(socks) && Self.validUpstream(http)
            && Int(port).map { (1024...65535).contains($0) } == true
            && !(socks.isEmpty && http.isEmpty)
            && Self.validIPv4(officeIP) && Self.validIPv4(officeMask)
            && Self.validDNSList(officeDNS)
    }

    // Адрес не из офисной подсети — почти всегда скопированный пример: в офисе
    // он не поднимется, сработает откат в DHCP, и профиль будет дёргаться.
    var officeIPMismatch: Bool {
        guard !officeIP.isEmpty, !gateways.isEmpty else { return false }
        let prefixes = gateways.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        return !prefixes.contains { officeIP.hasPrefix($0) }
    }
    // При статике DNS от DHCP не приедут — пустое поле оставит резолвер как был.
    var officeDNSMissing: Bool { !officeIP.isEmpty && officeDNS.isEmpty }

    func refreshSwitches() {
        DispatchQueue.global().async {
            let sp = CLI.state()?.system_proxy == true
            let li = LoginItem.enabled()
            DispatchQueue.main.async { self.systemProxyOn = sp; self.loginItemOn = li }
        }
    }
    func setSystemProxy(_ on: Bool) {
        systemProxyOn = on
        DispatchQueue.global().async {
            CLI.run(["system", on ? "on" : "off"])
            let now = CLI.state()?.system_proxy == true
            DispatchQueue.main.async { self.systemProxyOn = now }
        }
    }
    func setLoginItem(_ on: Bool) {
        loginItemOn = on
        DispatchQueue.global().async {
            LoginItem.set(on)
            let now = LoginItem.enabled()
            DispatchQueue.main.async { self.loginItemOn = now }
        }
    }
    func setVpnAuto(_ on: Bool) {
        vpnAuto = on
        DispatchQueue.global().async { CLI.run(["vpn", "auto", on ? "on" : "off"]) }
    }

    // Профиль кладут перетаскиванием: путь к .ovpn руками не набирают.
    // Сразу за приёмом собираем split-tunnel — иначе файл лежал бы без дела.
    func adoptOVPN(_ path: String, completion: @escaping () -> Void) {
        vpnProfile = path
        busy = true; message = "Принимаю профиль и собираю туннель…"
        DispatchQueue.global().async {
            CLI.run(["set", "VPN_PROFILE", path])
            let out = stripANSI(CLI.runAdmin(["vpn", "install"]))
                .trimmingCharacters(in: .whitespacesAndNewlines)
            DispatchQueue.main.async {
                self.busy = false
                self.message = out.isEmpty ? "Туннель собран." : out
                self.load()
                completion()
            }
        }
    }

    func probeAll() {
        probe(\.socksProbe, socks)
        probe(\.httpProbe, http)
    }
    private func probe(_ key: ReferenceWritableKeyPath<ConfigStore, Probe>, _ upstream: String) {
        guard !upstream.isEmpty else { self[keyPath: key] = .unknown; return }
        self[keyPath: key] = .checking
        DispatchQueue.global().async {
            let ok = CLI.run(["probe", upstream]).contains("up")
            DispatchQueue.main.async { self[keyPath: key] = ok ? .up : .down }
        }
    }

    // detect пишет конфиг сам — потом просто перечитываем
    func detect(completion: @escaping () -> Void) {
        busy = true; message = "Ищу прокси в текущей сети…"
        DispatchQueue.global().async {
            let out = stripANSI(CLI.run(["detect"]))
            DispatchQueue.main.async {
                self.load()
                self.probeAll()
                self.busy = false
                self.message = out.contains("конфиг записан")
                    ? "Найдено и записано. Проверь поля и нажми «Сохранить»."
                    : out.trimmingCharacters(in: .whitespacesAndNewlines)
                completion()
            }
        }
    }

    // Действия, требующие root: установка демонов, сборка туннеля, ручной
    // подъём/останов. Диалог пароля показывает система.
    func admin(_ args: [String], note: String, completion: @escaping () -> Void) {
        busy = true; message = note
        DispatchQueue.global().async {
            let out = stripANSI(CLI.runAdmin(args)).trimmingCharacters(in: .whitespacesAndNewlines)
            DispatchQueue.main.async {
                self.busy = false
                self.message = out.isEmpty ? "Готово." : out
                self.load()
                completion()
            }
        }
    }

    // Снимок значений, прочитанных из файла: с ним сравниваем при сохранении.
    private var savedFields: [String: String] = [:]
    private var fields: [String: String] {
        ["SOCKS_UPSTREAM": socks, "HTTP_UPSTREAM": http,
         "BRIDGE_PORT": port, "OFFICE_GATEWAYS": gateways,
         "NET_SERVICE": netService, "OFFICE_IP": officeIP,
         "OFFICE_MASK": officeMask, "OFFICE_DNS": officeDNS,
         "VPN_PROFILE": vpnProfile, "VPN_ROUTES": vpnRoutes,
         "VPN_AUTO": vpnAuto ? "on" : "off"]
    }

    // сохранить через CLI set; мост трогаем, только если поменялось то, что на него влияет
    func save(mode: String, completion: @escaping () -> Void) {
        let now = fields
        let changed = now.filter { savedFields[$0.key] != $0.value }
        guard !changed.isEmpty else {
            message = "Ничего не изменилось."
            completion()
            return
        }
        // Раньше «Сохранить» всегда звал switch, а это stop_bridge + start_bridge:
        // открыл настройки посмотреть, нажал кнопку — и живые соединения оборваны.
        let restartKeys: Set<String> = ["SOCKS_UPSTREAM", "HTTP_UPSTREAM", "BRIDGE_PORT"]
        let needsRestart = !restartKeys.isDisjoint(with: changed.keys)
        busy = true
        message = needsRestart ? "Сохраняю и перезапускаю мост…" : "Сохраняю…"
        DispatchQueue.global().async {
            // состояние системного прокси снимаем ДО правок: после смены порта
            // json сравнивал бы старый порт в системе с новым в конфиге
            let sysWasOn = CLI.state()?.system_proxy == true
            for (k, v) in changed { CLI.run(["set", k, v]) }
            if needsRestart {
                CLI.run([mode])
                // порт мог смениться — системный прокси должен смотреть на новый
                if sysWasOn { CLI.run(["system", "on"]) }
            }
            DispatchQueue.main.async {
                self.savedFields = now
                self.busy = false
                self.message = needsRestart ? "Готово — мост перезапущен." : "Готово."
                self.probeAll()
                completion()
            }
        }
    }
}

// ── окно настроек (SwiftUI) ──────────────────────────────────────────────────
struct ProbeDot: View {
    let state: Probe
    var body: some View {
        switch state {
        case .unknown:  Circle().fill(.gray.opacity(0.35)).frame(width: 9, height: 9)
        case .checking: ProgressView().controlSize(.small)
        case .up:       Circle().fill(.green).frame(width: 9, height: 9)
        case .down:     Circle().fill(.red).frame(width: 9, height: 9)
        }
    }
}

// TextField с подсказкой: параметр prompt появился только в macOS 12,
// на Big Sur подставляем placeholder заголовком — визуально то же самое.
struct HintField: View {
    let title: String
    @Binding var text: String
    let hint: String

    var body: some View {
        if #available(macOS 12.0, *) {
            TextField(title, text: $text, prompt: Text(hint))
        } else {
            TextField(hint, text: $text)
        }
    }
}

// Зона приёма .ovpn. Путь к профилю руками не набирают — его перетаскивают.
struct DropZone: View {
    let current: String
    let targeted: Bool
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [5, 4]))
                .foregroundColor(targeted ? Color.accentColor : Color.gray.opacity(0.45))
            if current.isEmpty {
                Text("Перетащи сюда файл .ovpn")
                    .font(.callout).foregroundColor(.secondary)
            } else {
                VStack(spacing: 2) {
                    Text((current as NSString).lastPathComponent).font(.callout)
                    Text("перетащи другой, чтобы заменить")
                        .font(.caption).foregroundColor(.secondary)
                }
            }
        }
        .frame(height: 62)
    }
}

struct SettingsView: View {
    @ObservedObject var store: ConfigStore
    let currentMode: () -> String
    let onApplied: () -> Void

    // Всё, что можно вывести, выведено: адреса прокси, порт, префиксы шлюзов,
    // сетевой сервис, маска, DNS. Здесь остаётся то, что вывести нельзя —
    // офисный адрес выдают, а профиль приносят файлом.
    @SwiftUI.State private var showAdvanced = false
    @SwiftUI.State private var dropTargeted = false

    @ViewBuilder private var fields: some View {
        Section {
            HStack {
                Text("SOCKS5").frame(width: 70, alignment: .leading)
                Text(store.socks.isEmpty ? "не найден" : store.socks)
                    .foregroundColor(store.socks.isEmpty ? .secondary : .primary)
                Spacer()
                ProbeDot(state: store.socksProbe)
            }
            HStack {
                Text("HTTP").frame(width: 70, alignment: .leading)
                Text(store.http.isEmpty ? "не найден" : store.http)
                    .foregroundColor(store.http.isEmpty ? .secondary : .primary)
                Spacer()
                ProbeDot(state: store.httpProbe)
            }
        } header: {
            Text("Прокси — найдены сами")
        } footer: {
            Text("Мост слушает 127.0.0.1:\(store.port), и клиенты всегда ходят на него. Адреса, порт и префиксы офисных шлюзов правятся в «Дополнительно».")
                .font(.caption).foregroundColor(.secondary)
        }

        Section {
            Toggle("Системный прокси — браузер и остальные GUI", isOn: Binding(
                get: { store.systemProxyOn }, set: { store.setSystemProxy($0) }))
            Toggle("Запускать при входе", isOn: Binding(
                get: { store.loginItemOn }, set: { store.setLoginItem($0) }))
        } header: {
            Text("Переключатели")
        } footer: {
            Text("Оба действуют сразу, «Сохранить» для них не нужен. Без автозапуска после перезагрузки моста не будет: он живёт дочерним процессом приложения.")
                .font(.caption).foregroundColor(.secondary)
        }

        Section {
            HintField(title: "Адрес в офисе", text: $store.officeIP,
                      hint: "пусто — адресом не управляем")
            if store.officeIPMismatch {
                Text("Адрес не из офисной подсети (\(store.gateways)) — там он не поднимется.")
                    .font(.caption).foregroundColor(.orange)
            }
            HStack {
                Button("Применить сейчас") {
                    store.admin(["net", "apply"], note: "Применяю профиль…") { onApplied() }
                }
                .disabled(store.officeIP.isEmpty)
                Button("Применять автоматически") {
                    store.admin(["net", "install"], note: "Ставлю демон профиля…") { onApplied() }
                }
                .disabled(store.officeIP.isEmpty)
                Spacer()
            }
        } header: {
            Text("Офисный адрес")
        } footer: {
            Text("Единственное, что нельзя угадать: фиксированный адрес выдают вам. Маску, сетевой сервис и офисные DNS приложение определяет само. Пусто — сетью не управляем, везде DHCP. Требует пароль администратора.")
                .font(.caption).foregroundColor(.secondary)
        }

        Section {
            DropZone(current: store.vpnProfile, targeted: dropTargeted)
                .onDrop(of: ["public.file-url"], isTargeted: $dropTargeted) { providers in
                    guard let p = providers.first else { return false }
                    p.loadItem(forTypeIdentifier: "public.file-url", options: nil) { item, _ in
                        guard let d = item as? Data,
                              let url = URL(dataRepresentation: d, relativeTo: nil),
                              url.pathExtension.lowercased() == "ovpn" else { return }
                        DispatchQueue.main.async { store.adoptOVPN(url.path) { onApplied() } }
                    }
                    return true
                }
            Toggle("Поднимать вне офиса, гасить в офисе", isOn: Binding(
                get: { store.vpnAuto }, set: { store.setVpnAuto($0) }))
                .disabled(store.vpnProfile.isEmpty)
            HStack {
                Button("Поднять") {
                    store.admin(["vpn", "up"], note: "Поднимаю туннель…") { onApplied() }
                }
                .disabled(store.vpnProfile.isEmpty)
                Button("Опустить") {
                    store.admin(["vpn", "down"], note: "Опускаю туннель…") { onApplied() }
                }
                .disabled(store.vpnProfile.isEmpty)
                Spacer()
            }
        } header: {
            Text("Туннель — по желанию")
        } footer: {
            Text("Из профиля собирается конфиг со split-tunnel: в туннель уходят только офисные сети, а не весь трафик. Маршруты выводятся из офисной подсети. Файл копируется под root с правами 600 — внутри приватный ключ.")
                .font(.caption).foregroundColor(.secondary)
        }

        Section {
            DisclosureGroup("Дополнительно", isExpanded: $showAdvanced) {
                HintField(title: "SOCKS5", text: $store.socks, hint: "192.168.1.2:9999")
                HintField(title: "HTTP", text: $store.http, hint: "192.168.1.2:3128")
                TextField("Порт моста", text: $store.port)
                HintField(title: "Шлюзы офиса", text: $store.gateways, hint: "192.168.1.")
                HintField(title: "Сетевой сервис", text: $store.netService,
                          hint: "пусто — по дефолтному маршруту")
                HintField(title: "Маска", text: $store.officeMask,
                          hint: "пусто — как на интерфейсе")
                HintField(title: "DNS в офисе", text: $store.officeDNS,
                          hint: "пусто — как выдал роутер при поиске")
                HintField(title: "В туннель", text: $store.vpnRoutes,
                          hint: "пусто — /16 вокруг офиса")
            }
        } footer: {
            Text("Заполненные значения перекрывают автоопределение. Порт менять не стоит: на него смотрят системный прокси и shellenv.")
                .font(.caption).foregroundColor(.secondary)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            if #available(macOS 13.0, *) {
                Form { fields }.formStyle(.grouped)
            } else {
                Form { fields }
            }

            Divider()
            HStack {
                Button {
                    store.detect { onApplied() }
                } label: {
                    Label("Найти заново", systemImage: "antenna.radiowaves.left.and.right")
                }
                Button("Проверить") { store.probeAll() }
                Spacer()
                if store.busy { ProgressView().controlSize(.small) }
                Button("Сохранить") {
                    store.save(mode: currentMode()) { onApplied() }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!store.valid || store.busy)
            }
            .padding(12)

            if !store.message.isEmpty {
                let msg = Text(store.message)
                    .font(.caption).foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 12).padding(.bottom, 8)
                if #available(macOS 12.0, *) {
                    msg.textSelection(.enabled)
                } else {
                    msg
                }
            }
        }
        .frame(width: 470, height: 700)
        .onAppear {
            store.load()
            store.probeAll()
            store.refreshSwitches()
        }
    }
}

// ── приложение ───────────────────────────────────────────────────────────────
final class App: NSObject, NSApplicationDelegate {
    private var item: NSStatusItem!
    private var timer: Timer?
    private var state: State?
    private var busy = false
    private var loginItemOn = false
    private var napBlocker: NSObjectProtocol?
    private let store = ConfigStore()
    private var settingsWC: NSWindowController?

    func applicationDidFinishLaunching(_ n: Notification) {
        // Один экземпляр на систему: запуск второго (например, прямо из DMG
        // при уже установленном) молча выходит, не плодя вторую иконку в баре.
        let selfPID = ProcessInfo.processInfo.processIdentifier
        let twins = NSRunningApplication.runningApplications(
            withBundleIdentifier: Bundle.main.bundleIdentifier ?? "kz.documentolog.proxypilot")
            .filter { $0.processIdentifier != selfPID }
        if !twins.isEmpty {
            log("уже запущен (pid \(twins[0].processIdentifier)) — второй экземпляр выходит")
            NSApp.terminate(nil)
            return
        }

        log("старт; CLI=\(CLI.path ?? "НЕ НАЙДЕН")")
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.autosaveName = "ProxyPilot"
        item.isVisible = true
        item.menu = NSMenu()
        item.menu?.delegate = self

        guard CLI.path != nil else {
            item.button?.title = "PP!"
            fatalAlert("Не найден CLI `proxypilot`.\n\nОжидается в ~/.local/bin/proxypilot.\nЗапусти install.sh из проекта proxy-pilot.")
            return
        }

        store.load()   // адреса апстримов — из конфига, а не из дефолтов

        // Без activity macOS усыпляет фоновое приложение (App Nap), и таймер
        // перестаёт тикать — иконка застывает в старом режиме.
        // ВАЖНО: именно ...AllowingIdleSystemSleep — обычный .userInitiated
        // включает idleSystemSleepDisabled и вешает PreventUserIdleSystemSleep,
        // из-за чего ноут не засыпал, пока ProxyPilot запущен.
        napBlocker = ProcessInfo.processInfo.beginActivity(
            options: [.userInitiatedAllowingIdleSystemSleep],
            reason: "опрос состояния прокси")

        // Первый запуск без конфига: detect сам находит прокси, пишет конфиг и
        // выставляет системный прокси. Раньше следом открывалась форма на 11
        // полей, и пользователь жал «Сохранить» те же самые значения — шаг был
        // ритуальный. Теперь просто включаемся; форму показываем, только когда
        // искать было нечего.
        if CLI.state()?.configured != true {
            log("нет конфига — запускаю автопоиск")
            store.detect { [weak self] in
                guard let self = self else { return }
                if let st = CLI.state(), st.configured {
                    DispatchQueue.global().async {
                        CLI.run(["auto"])
                        DispatchQueue.main.async { self.refresh() }
                    }
                    self.firstRunSummary(st)
                } else {
                    self.openSettings()
                }
                self.refresh()
            }
        } else {
            // поднять мост в сохранённом режиме; gost — дочерний процесс app
            DispatchQueue.global().async {
                CLI.run(["ensure"])
                DispatchQueue.main.async { self.refresh() }
            }
        }

        DispatchQueue.global().async {
            let on = LoginItem.enabled()
            DispatchQueue.main.async { self.loginItemOn = on }
        }

        // .common, а не дефолтный режим: иначе таймер замирает при открытом меню
        let t = Timer(timeInterval: 5, repeats: true) { [weak self] _ in self?.refresh() }
        RunLoop.main.add(t, forMode: .common)
        timer = t
        refresh()
    }

    // Единственное, что пользователь видит после установки: что нашлось и что
    // включилось. Одна кнопка вместо формы на 11 полей.
    private func firstRunSummary(_ s: State) {
        var lines: [String] = []
        if !s.socks.isEmpty { lines.append("SOCKS5: \(s.socks)") }
        if !s.http.isEmpty  { lines.append("HTTP: \(s.http)") }
        lines.append("Мост: 127.0.0.1:\(s.port)")
        if s.system_proxy == true { lines.append("Системный прокси: включён") }
        let a = NSAlert()
        a.messageText = "ProxyPilot настроен"
        a.informativeText = lines.joined(separator: "\n")
            + "\n\nРежим «Авто» — путь выбирается по сети. Всё остальное в меню-баре."
        a.addButton(withTitle: "Готово")
        NSApp.activate(ignoringOtherApps: true)
        a.runModal()
    }

    // ── обновление состояния ─────────────────────────────────────────────────
    private func refresh() {
        guard !busy else { return }
        DispatchQueue.global().async {
            let s = CLI.state()
            // ensure идемпотентен и сам решает, надо ли перезапускать мост:
            // и когда auto разошёлся с фактическим режимом, и когда сменилась
            // сеть (режим тот же, но у gost остаётся DNS-кэш от старой сети)
            if s?.configured == true {
                CLI.run(["ensure"])
            }
            let fresh = CLI.state() ?? s
            DispatchQueue.main.async {
                self.state = fresh
                // конфиг могли поменять из CLI (`proxypilot set …`) — перечитываем,
                // но не пока открыты Настройки: затёрли бы правки пользователя
                if self.settingsWC?.window?.isVisible != true {
                    self.store.load()
                }
                self.render()
            }
        }
    }

    private func render() {
        let mode = (state?.configured == false) ? "unconfigured" : (state?.running ?? "error")
        let (symbol, fallback): (String, String) = {
            if busy { return ("hourglass", "…") }
            switch mode {
            case "socks":        return ("bolt.horizontal.circle.fill", "PP⚡")
            case "http":         return ("tortoise.fill", "PP~")
            case "direct":       return ("arrow.right.circle", "PP→")
            case "unconfigured": return ("gearshape", "PP?")
            default:             return ("exclamationmark.triangle.fill", "PP!")
            }
        }()
        if let img = NSImage(systemSymbolName: symbol, accessibilityDescription: "ProxyPilot") {
            img.isTemplate = true
            item.button?.image = img
            item.button?.imagePosition = .imageOnly
        } else {
            item.button?.image = nil
            item.button?.title = fallback
        }
        item.button?.toolTip = state.map {
            "proxypilot — 127.0.0.1:\($0.port) (\(human($0.running)))"
        } ?? "proxypilot — состояние недоступно"
    }

    private func human(_ mode: String) -> String {
        switch mode {
        case "socks":  return "SOCKS5, быстро"
        case "http":   return "HTTP-прокси, медленно"
        case "direct": return "без прокси"
        case "none":   return "мост не запущен"
        default:       return mode
        }
    }

    // ── меню ─────────────────────────────────────────────────────────────────
    private func menuItem(_ title: String, symbol: String, action: Selector?,
                          key: String = "") -> NSMenuItem {
        let mi = NSMenuItem(title: title, action: action, keyEquivalent: key)
        mi.target = self
        mi.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
        return mi
    }

    fileprivate func buildMenu(_ menu: NSMenu) {
        menu.removeAllItems()
        guard let s = state else {
            menu.addItem(withTitle: "Состояние недоступно", action: nil, keyEquivalent: "")
            menu.addItem(.separator())
            menu.addItem(menuItem("Настройки…", symbol: "gearshape", action: #selector(openSettingsAction), key: ","))
            menu.addItem(menuItem("Выйти", symbol: "power", action: #selector(quit), key: "q"))
            return
        }

        // шапка: адрес моста + текущий канал
        let head = NSMenuItem()
        // Когда выбранный режим недоступен, мы молча работаем в обход —
        // без этой строки пользователь не понял бы, почему галочка на socks,
        // а трафик идёт напрямую.
        var headLine = s.running == "none" ? "не запущен" : human(s.running)
        if s.mode != "auto", s.effective != s.mode {
            headLine = "\(human(s.mode)) недоступен → \(human(s.effective))"
        }
        head.attributedTitle = NSAttributedString(
            string: "Мост 127.0.0.1:\(s.port)\n\(headLine)",
            attributes: [
                .font: NSFont.menuFont(ofSize: NSFont.smallSystemFontSize),
                .foregroundColor: NSColor.secondaryLabelColor,
            ])
        head.isEnabled = false
        menu.addItem(head)
        menu.addItem(.separator())

        if !s.configured {
            menu.addItem(withTitle: "Нет конфига — открой Настройки", action: nil, keyEquivalent: "")
        } else {
            addMode(menu, "Авто (по сети)", symbol: "sparkles", mode: "auto", s: s,
                    note: s.mode == "auto" ? "→ \(human(s.effective))" : nil, enabled: true)
            addMode(menu, "SOCKS5 — быстро", symbol: "bolt.fill", mode: "socks", s: s,
                    note: s.socks.isEmpty ? "не настроен" : s.socks,
                    dot: s.socks.isEmpty ? nil : s.socks_up,
                    enabled: !s.socks.isEmpty && s.socks_up)
            addMode(menu, "HTTP — запасной", symbol: "tortoise.fill", mode: "http", s: s,
                    note: s.http.isEmpty ? "не настроен" : s.http,
                    dot: s.http.isEmpty ? nil : s.http_up,
                    enabled: !s.http.isEmpty && s.http_up)
            addMode(menu, "Без прокси", symbol: "arrow.right", mode: "direct", s: s,
                    note: nil, enabled: true)
        }

        // ── сеть ─────────────────────────────────────────────────────────────
        // Показываем, только когда это кем-то настроено: иначе меню разрастается
        // без пользы у тех, кому нужен один прокси.
        if let inOffice = s.in_office, s.office_ip?.isEmpty == false {
            menu.addItem(.separator())
            var lines = [inOffice ? "Сеть: офис" : "Сеть: вне офиса"]
            if let ip = s.office_ip, !ip.isEmpty {
                lines.append(inOffice ? "адрес \(ip)" : "адрес по DHCP")
            }
            if s.net_daemon != true {
                lines.append("применяется только вручную")
            }
            menu.addItem(noteItem(lines.joined(separator: "\n")))
        }

        // ── туннель ──────────────────────────────────────────────────────────
        // Отдельный пункт, не привязанный к офисному адресу: VPN настраивают и без
        // статики, а его состояние должно читаться с одного взгляда на меню.
        let vpnConfigured = s.vpn_installed == true || (s.vpn_profile?.isEmpty == false)
        if vpnConfigured {
            menu.addItem(.separator())
            let installed = s.vpn_installed == true
            let up = s.vpn_up == true
            let foreign = s.vpn_foreign == true
            var lines = [foreign ? "VPN: туннель поднят другим клиентом"
                                 : (up ? "VPN: туннель поднят" : "VPN: туннель опущен")]
            if !installed {
                lines.append("не установлен — собрать из профиля: «Установить туннель…»")
            }
            menu.addItem(noteItem(lines.joined(separator: "\n")))

            if installed {
                let mi = NSMenuItem(title: up ? "Опустить туннель" : "Поднять туннель",
                                    action: foreign ? nil : #selector(toggleVPN), keyEquivalent: "")
                mi.target = self
                mi.isEnabled = !foreign
                mi.image = NSImage(systemSymbolName: up ? "bolt.horizontal.fill" : "bolt.horizontal",
                                   accessibilityDescription: nil)
                menu.addItem(mi)
            } else {
                // `vpn up` без установленного туннеля молча ничего не делает — предлагать
                // его нельзя: пользователь введёт пароль и не получит ни туннеля, ни ошибки.
                let mi = NSMenuItem(title: "Установить туннель…",
                                    action: #selector(installVPN), keyEquivalent: "")
                mi.target = self
                mi.image = NSImage(systemSymbolName: "bolt.horizontal.circle", accessibilityDescription: nil)
                menu.addItem(mi)
            }

            let auto = NSMenuItem(title: "Поднимать вне офиса",
                                  action: #selector(toggleVPNAuto), keyEquivalent: "")
            auto.target = self
            auto.state = (s.vpn_auto == true) ? .on : .off
            auto.isEnabled = installed
            menu.addItem(auto)
        }

        menu.addItem(.separator())
        menu.addItem(menuItem("Замерить скорость…", symbol: "speedometer", action: #selector(bench), key: "b"))
        menu.addItem(menuItem("Диагностика…", symbol: "stethoscope", action: #selector(doctor), key: "d"))
        menu.addItem(menuItem("Скопировать адрес прокси", symbol: "doc.on.doc", action: #selector(copyAddr), key: "c"))
        menu.addItem(.separator())
        // Системный прокси — то, ради чего раньше ходили в System Settings.
        // Держим тумблером: включается само при detect, но выключить надо уметь.
        let sysItem = menuItem("Системный прокси (браузер и GUI)", symbol: "globe",
                               action: #selector(toggleSystemProxy))
        sysItem.state = (s.system_proxy == true) ? .on : .off
        menu.addItem(sysItem)
        // Без автозапуска после перезагрузки нет моста: gost — дочерний процесс
        // этого приложения. Поэтому тумблер, а не «поставьте сами в Login Items».
        let loginMI = menuItem("Запускать при входе", symbol: "power.circle",
                               action: #selector(toggleLoginItem))
        loginMI.state = loginItemOn ? .on : .off
        menu.addItem(loginMI)
        menu.addItem(menuItem("Найти прокси в сети", symbol: "antenna.radiowaves.left.and.right", action: #selector(detectAction)))
        menu.addItem(menuItem("Настройки…", symbol: "gearshape", action: #selector(openSettingsAction), key: ","))
        menu.addItem(.separator())
        menu.addItem(menuItem("Выйти", symbol: "power", action: #selector(quit), key: "q"))
    }

    // Серая подпись-состояние в меню (не кликается).
    private func noteItem(_ text: String) -> NSMenuItem {
        let item = NSMenuItem()
        item.attributedTitle = NSAttributedString(
            string: text,
            attributes: [
                .font: NSFont.menuFont(ofSize: NSFont.smallSystemFontSize),
                .foregroundColor: NSColor.secondaryLabelColor,
            ])
        item.isEnabled = false
        return item
    }

    private func addMode(_ menu: NSMenu, _ title: String, symbol: String, mode: String,
                         s: State, note: String?, dot: Bool? = nil, enabled: Bool) {
        let mi = NSMenuItem(title: title, action: #selector(switchMode(_:)), keyEquivalent: "")
        mi.target = self
        mi.representedObject = mode
        mi.state = (s.mode == mode) ? .on : .off
        mi.isEnabled = enabled
        mi.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
        if note != nil || dot != nil {
            let text = NSMutableAttributedString(
                string: title, attributes: [.font: NSFont.menuFont(ofSize: 0)])
            if let note = note {
                text.append(NSAttributedString(
                    string: "   \(note)",
                    attributes: [
                        .font: NSFont.menuFont(ofSize: NSFont.smallSystemFontSize),
                        .foregroundColor: NSColor.secondaryLabelColor,
                    ]))
            }
            if let dot = dot {
                text.append(NSAttributedString(
                    string: "  ●",
                    attributes: [
                        .font: NSFont.menuFont(ofSize: 9),
                        .foregroundColor: dot ? NSColor.systemGreen : NSColor.systemRed,
                    ]))
            }
            mi.attributedTitle = text
        }
        menu.addItem(mi)
    }

    // ── действия ─────────────────────────────────────────────────────────────

    // Подъём и останов туннеля — root, поэтому через диалог пароля системы.
    @objc private func toggleVPN() {
        guard let s = state else { return }
        let up = s.vpn_up == true
        busy = true; render()
        DispatchQueue.global().async {
            let out = stripANSI(CLI.runAdmin(["vpn", up ? "down" : "up"]))
            log("vpn \(up ? "down" : "up"): \(out.trimmingCharacters(in: .whitespacesAndNewlines))")
            DispatchQueue.main.async { self.busy = false; self.refresh() }
        }
    }

    // Собрать split-tunnel из профиля (VPN_PROFILE) и поставить демон — нужен root.
    @objc private func installVPN() {
        busy = true; render()
        DispatchQueue.global().async {
            let out = stripANSI(CLI.runAdmin(["vpn", "install"]))
            log("vpn install: \(out.trimmingCharacters(in: .whitespacesAndNewlines))")
            DispatchQueue.main.async {
                self.busy = false; self.refresh()
                self.show("Туннель", out.isEmpty ? "Готово." : out)
            }
        }
    }

    // networksetup правит системный прокси без root — диалог пароля не нужен.
    @objc private func toggleSystemProxy() {
        guard let s = state else { return }
        let on = s.system_proxy == true
        busy = true; render()
        DispatchQueue.global().async {
            let out = stripANSI(CLI.run(["system", on ? "off" : "on"]))
            log("system \(on ? "off" : "on"): \(out.trimmingCharacters(in: .whitespacesAndNewlines))")
            DispatchQueue.main.async { self.busy = false; self.refresh() }
        }
    }

    @objc private func toggleLoginItem() {
        let on = loginItemOn
        DispatchQueue.global().async {
            LoginItem.set(!on)
            let now = LoginItem.enabled()
            DispatchQueue.main.async { self.loginItemOn = now; self.render() }
        }
    }

    // Тумблер автоматики пишет в пользовательский конфиг — root не нужен.
    @objc private func toggleVPNAuto() {
        guard let s = state else { return }
        let on = s.vpn_auto == true
        DispatchQueue.global().async {
            CLI.run(["vpn", "auto", on ? "off" : "on"])
            DispatchQueue.main.async { self.refresh() }
        }
    }

    @objc private func switchMode(_ sender: NSMenuItem) {
        guard let mode = sender.representedObject as? String else { return }
        busy = true; render()
        DispatchQueue.global().async {
            CLI.run([mode])
            DispatchQueue.main.async { self.busy = false; self.refresh() }
        }
    }

    @objc private func bench() {
        busy = true; render()
        DispatchQueue.global().async {
            let out = stripANSI(CLI.run(["bench"]))
            DispatchQueue.main.async {
                self.busy = false; self.render()
                self.show("Скорость каналов", out)
            }
        }
    }

    @objc private func doctor() {
        DispatchQueue.global().async {
            let out = stripANSI(CLI.run(["doctor"]))
            DispatchQueue.main.async { self.show("Диагностика", out) }
        }
    }

    @objc private func copyAddr() {
        guard let s = state else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString("http://127.0.0.1:\(s.port)", forType: .string)
    }

    @objc private func detectAction() {
        busy = true; render()
        store.detect { [weak self] in
            self?.busy = false
            self?.refresh()
            self?.show("Автопоиск прокси", self?.store.message ?? "")
        }
    }

    @objc private func openSettingsAction() { openSettings() }

    private func openSettings() {
        if settingsWC == nil {
            let view = SettingsView(
                store: store,
                currentMode: { [weak self] in self?.state?.mode ?? "auto" },
                onApplied: { [weak self] in self?.refresh() })
            let host = NSHostingController(rootView: view)
            let win = NSWindow(contentViewController: host)
            win.title = "ProxyPilot — Настройки"
            win.styleMask = [.titled, .closable, .miniaturizable]
            settingsWC = NSWindowController(window: win)
        }
        NSApp.activate(ignoringOtherApps: true)
        settingsWC?.window?.center()
        settingsWC?.showWindow(nil)
        settingsWC?.window?.makeKeyAndOrderFront(nil)
    }

    @objc private func quit() {
        CLI.run(["stop"])
        NSApp.terminate(nil)
    }

    // ── алерты ───────────────────────────────────────────────────────────────
    private func show(_ title: String, _ body: String) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = title
        a.alertStyle = .informational
        let tv = NSTextView(frame: NSRect(x: 0, y: 0, width: 460, height: 190))
        tv.string = body.trimmingCharacters(in: .whitespacesAndNewlines)
        tv.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        tv.isEditable = false
        tv.drawsBackground = false
        a.accessoryView = tv
        a.addButton(withTitle: "ОК")
        a.runModal()
    }

    private func fatalAlert(_ text: String) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = "ProxyPilot"
        a.informativeText = text
        a.alertStyle = .critical
        a.runModal()
    }
}

extension App: NSMenuDelegate {
    func menuNeedsUpdate(_ menu: NSMenu) { buildMenu(menu) }
    func menuWillOpen(_ menu: NSMenu) { refresh() }
}

let app = NSApplication.shared
let delegate = App()
app.delegate = delegate
app.setActivationPolicy(.accessory)   // только меню-бар, без иконки в Dock
app.run()
