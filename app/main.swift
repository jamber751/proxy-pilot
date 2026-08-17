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
            let value = String(line[line.index(after: eq)...])
            switch key {
            case "SOCKS_UPSTREAM":  socks = value
            case "HTTP_UPSTREAM":   http = value
            case "BRIDGE_PORT":     port = value
            case "OFFICE_GATEWAYS": gateways = value
            default: break
            }
        }
    }

    private static let hostPort = try! NSRegularExpression(pattern: "^[A-Za-z0-9_.-]+:[0-9]{1,5}$")
    static func validUpstream(_ s: String) -> Bool {
        s.isEmpty || hostPort.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }
    var valid: Bool {
        Self.validUpstream(socks) && Self.validUpstream(http)
            && Int(port).map { (1024...65535).contains($0) } == true
            && !(socks.isEmpty && http.isEmpty)
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

    // сохранить через CLI set + перезапустить мост в сохранённом режиме
    func save(mode: String, completion: @escaping () -> Void) {
        busy = true; message = "Сохраняю и перезапускаю мост…"
        let fields = [("SOCKS_UPSTREAM", socks), ("HTTP_UPSTREAM", http),
                      ("BRIDGE_PORT", port), ("OFFICE_GATEWAYS", gateways)]
        DispatchQueue.global().async {
            for (k, v) in fields { CLI.run(["set", k, v]) }
            CLI.run([mode])   // switch: остановит и поднимет мост с новыми апстримами
            DispatchQueue.main.async {
                self.busy = false
                self.message = "Готово — мост перезапущен."
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

struct SettingsView: View {
    @ObservedObject var store: ConfigStore
    let currentMode: () -> String
    let onApplied: () -> Void

    // содержимое формы отдельно: обёртку выбираем по версии системы
    @ViewBuilder private var fields: some View {
        Section {
            HStack {
                HintField(title: "SOCKS5 (быстрый)", text: $store.socks,
                          hint: "192.168.1.2:9999")
                ProbeDot(state: store.socksProbe)
            }
            HStack {
                HintField(title: "HTTP (запасной)", text: $store.http,
                          hint: "192.168.1.2:3128")
                ProbeDot(state: store.httpProbe)
            }
        } header: {
            Text("Реальные прокси (апстримы)")
        } footer: {
            Text("host:port. Пустое поле выключает режим. Хотя бы один должен быть задан.")
                .font(.caption).foregroundColor(.secondary)
        }

        Section {
            TextField("Порт моста", text: $store.port)
            HintField(title: "Шлюзы офиса (префиксы)", text: $store.gateways,
                      hint: "192.168.1.")
        } header: {
            Text("Мост и авторежим")
        } footer: {
            Text("Клиенты всегда ходят на http://127.0.0.1:\(store.port). Если менять порт — обнови системный прокси и shellenv. «Авто» включает прокси, когда шлюз сети начинается с одного из префиксов (через запятую).")
                .font(.caption).foregroundColor(.secondary)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            // .formStyle(.grouped) — macOS 13+; на 11–12 Form и так рисуется
            // сгруппированной, отличий по виду почти нет
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
                    Label("Найти в сети", systemImage: "antenna.radiowaves.left.and.right")
                }
                Button("Проверить") { store.probeAll() }
                Spacer()
                if store.busy { ProgressView().controlSize(.small) }
                Button("Сохранить и применить") {
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
                // выделение текста мышью — macOS 12+; на Big Sur просто без него
                if #available(macOS 12.0, *) {
                    msg.textSelection(.enabled)
                } else {
                    msg
                }
            }
        }
        .frame(width: 470, height: 420)
        .onAppear { store.load(); store.probeAll() }
    }
}

// ── приложение ───────────────────────────────────────────────────────────────
final class App: NSObject, NSApplicationDelegate {
    private var item: NSStatusItem!
    private var timer: Timer?
    private var state: State?
    private var busy = false
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

        // первый запуск без конфига: сами находим прокси и открываем настройки
        if CLI.state()?.configured != true {
            log("нет конфига — запускаю автопоиск")
            store.detect { [weak self] in
                self?.openSettings()
                self?.refresh()
            }
        } else {
            // поднять мост в сохранённом режиме; gost — дочерний процесс app
            DispatchQueue.global().async {
                CLI.run(["ensure"])
                DispatchQueue.main.async { self.refresh() }
            }
        }

        // .common, а не дефолтный режим: иначе таймер замирает при открытом меню
        let t = Timer(timeInterval: 5, repeats: true) { [weak self] _ in self?.refresh() }
        RunLoop.main.add(t, forMode: .common)
        timer = t
        refresh()
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
        head.attributedTitle = NSAttributedString(
            string: "Мост 127.0.0.1:\(s.port)\n\(s.running == "none" ? "не запущен" : human(s.running))",
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

        menu.addItem(.separator())
        menu.addItem(menuItem("Замерить скорость…", symbol: "speedometer", action: #selector(bench), key: "b"))
        menu.addItem(menuItem("Диагностика…", symbol: "stethoscope", action: #selector(doctor), key: "d"))
        menu.addItem(menuItem("Скопировать адрес прокси", symbol: "doc.on.doc", action: #selector(copyAddr), key: "c"))
        menu.addItem(.separator())
        menu.addItem(menuItem("Найти прокси в сети", symbol: "antenna.radiowaves.left.and.right", action: #selector(detectAction)))
        menu.addItem(menuItem("Настройки…", symbol: "gearshape", action: #selector(openSettingsAction), key: ","))
        menu.addItem(.separator())
        menu.addItem(menuItem("Выйти", symbol: "power", action: #selector(quit), key: "q"))
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
