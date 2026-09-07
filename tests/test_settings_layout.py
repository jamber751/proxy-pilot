"""Check real SwiftUI geometry and scroll only when settings actually overflow."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FRAMEWORKS = ROOT / 'vendor/sparkle-2.9.6/Sparkle.xcframework/macos-arm64_x86_64'


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc') and FRAMEWORKS.exists(), 'macOS Swift and Sparkle required')
class SettingsLayoutTests(unittest.TestCase):
    def test_footer_bounds_and_scroll_only_on_overflow(self):
        source = (ROOT / 'app/main.swift').read_text().split('\nfinal class App:', 1)[0]
        target = 'Text(model.setup ? "HTTP / SOCKS5" : "Маршрут системного прокси")'
        self.assertEqual(source.count(target), 1)
        source = source.replace(target, target + '''
                    .background(GeometryReader { geometry in
                        Color.clear.preference(key: FooterBounds.self, value: geometry.frame(in: .named("testPopover")))
                    })''')
        scroll_target = 'ScrollView(.vertical) { measuredSettings }'
        self.assertEqual(source.count(scroll_target), 1)
        source = source.replace(scroll_target, scroll_target + '.preference(key: SettingsScrollEnabled.self, value: true)')
        viewport_target = '}.onPreferenceChange(SettingsHeightKey.self)'
        self.assertEqual(source.count(viewport_target), 1)
        source = source.replace(viewport_target, '''}.background(GeometryReader { geometry in
            Color.clear.preference(key: SettingsViewportHeight.self, value: geometry.size.height)
        }).onPreferenceChange(SettingsHeightKey.self)''')
        checks = '''
struct FooterBounds: PreferenceKey {
    static var defaultValue = CGRect.null
    static func reduce(value: inout CGRect, nextValue: () -> CGRect) { value = nextValue() }
}
struct SettingsScrollEnabled: PreferenceKey {
    static var defaultValue = false
    static func reduce(value: inout Bool, nextValue: () -> Bool) { value = value || nextValue() }
}
struct SettingsViewportHeight: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}
let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
for scenario in ["configured", "empty", "error", "busy", "main", "form", "routes"] {
    let model = ProxyModel(preview: true)
    model.state = ProxyState(configured: true, enabled: true, running: "socks", system_proxy: true,
        selected: "socks", has_socks: true, has_http: true,
        socks_endpoint: "proxy.example:1080", http_endpoint: "proxy.example:3128")
    model.editing = true
    if scenario == "empty" { model.state = ProxyState(configured: false, enabled: false, running: "none", system_proxy: false) }
    if scenario == "error" { model.error = "Не удалось найти прокси в этой сети. Проверьте подключение, доступ к локальной сети в настройках macOS и повторите попытку." }
    if scenario == "busy" { model.busy = true; model.operation = "Ищем прокси…" }
    if scenario == "main" { model.editing = false }
    if scenario == "form" { model.openProxy("http") }
    if scenario == "routes" { model.editing = false; model.choosingRoute = true }
    var footer = CGRect.null
    var scrolling = false
    var contentHeight: CGFloat = 0
    var viewportHeight: CGFloat = 0
    let root = PilotView(model: model, updates: UpdateModel())
        .coordinateSpace(name: "testPopover")
        .onPreferenceChange(FooterBounds.self) { footer = $0 }
        .onPreferenceChange(SettingsScrollEnabled.self) { scrolling = $0 }
        .onPreferenceChange(SettingsHeightKey.self) { contentHeight = $0 }
        .onPreferenceChange(SettingsViewportHeight.self) { viewportHeight = $0 }
    let host = NSHostingView(rootView: root)
    host.frame = NSRect(x: 0, y: 0, width: 344, height: 432)
    let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
    window.contentView = host
    // GeometryReader defers its children in an unordered window. Order the
    // fixture off-screen without activating it so adaptive content lays out.
    window.setFrameOrigin(NSPoint(x: -10000, y: -10000))
    window.orderBack(nil)
    for _ in 0..<4 {
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))
    }
    precondition(!footer.isNull, "No layout for \\(scenario)")
    precondition(footer.minX >= 23 && footer.maxX <= 321, "Horizontal overflow: \\(scenario) \\(footer)")
    precondition(footer.maxY <= 416.5, "Missing bottom inset: \\(scenario) \\(footer)")
    precondition(footer.minY >= 390, "Footer moved up: \\(scenario) \\(footer)")
    if ["configured", "empty", "error", "busy"].contains(scenario) {
        precondition(contentHeight > 0 && viewportHeight > 0, "Settings were not measured: \\(scenario)")
    }
    if scenario == "error" {
        precondition(scrolling, "Long error must remain accessible: content=\\(contentHeight), viewport=\\(viewportHeight)")
    } else if scenario != "busy" {
        precondition(!scrolling, "Unnecessary scroll view: \\(scenario)")
    }
    precondition(scrolling == (contentHeight > viewportHeight + 0.5), "Scroll must match actual overflow: \\(scenario)")
    print("\\(scenario): footer=\\(footer), scrolling=\\(scrolling), content=\\(contentHeight), viewport=\\(viewportHeight)")
    if scenario == "configured" {
        for error in [String(repeating: "Длинная ошибка подключения. ", count: 20), ""] {
            model.error = error
            for _ in 0..<4 {
                host.layoutSubtreeIfNeeded()
                RunLoop.main.run(until: Date().addingTimeInterval(0.05))
            }
            precondition(scrolling == !error.isEmpty, "Scroll must follow content changes")
            precondition(scrolling == (contentHeight > viewportHeight + 0.5), "Stale settings measurement")
            precondition(footer.maxY <= 416.5, "Dynamic content moved the footer")
        }
    }
    window.orderOut(nil)
    window.contentView = nil
}
'''
        with tempfile.TemporaryDirectory(prefix='proxypilot-layout-') as directory:
            script, binary = Path(directory) / 'main.swift', Path(directory) / 'layout-test'
            script.write_text(source + checks)
            built = subprocess.run(['swiftc', '-module-cache-path', str(ROOT / 'app/build/ModuleCache'),
                                    '-F', str(FRAMEWORKS), '-framework', 'Sparkle',
                                    '-Xlinker', '-rpath', '-Xlinker', str(FRAMEWORKS),
                                    str(script), str(ROOT / 'app/Updates.swift'), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.count('footer='), 7)
