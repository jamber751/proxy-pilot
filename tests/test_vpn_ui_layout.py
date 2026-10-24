"""Render the real VPN SwiftUI views in an isolated preview model."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNUILayoutTests(unittest.TestCase):
    def test_vpn_states_fit_popover_and_keep_accessible_hit_targets(self):
        panel = (ROOT / 'app/VPNPanel.swift').read_text().split(
            '\n/// Keeps the proxy home untouched.', 1)[0]
        # Presentation-only state injection; production view/control code is unchanged.
        panel = panel.replace('@Published private(set) var liveState:', '@Published var liveState:')
        panel = panel.replace('@Published private(set) var credentialPromptIdentifier:', '@Published var credentialPromptIdentifier:')
        # Presentation-only capability injection; no driver or Keychain is used.
        panel = panel.replace('var passwordPersistenceAvailable: Bool { controller?.passwordPersistenceAvailable ?? false }',
                              'var passwordPersistenceAvailable: Bool { true }')
        identifiers = (
            'vpnBack', 'vpnSettings', 'vpnPower', 'vpnImport', 'vpnReplaceProfile',
            'vpnCredential', 'vpnCredentialSubmit', 'vpnCredentialCancel',
            'vpnAddResource', 'vpnRemoveResource', 'vpnRemove',
            'vpnSettingsDone', 'vpnAuthenticationSave', 'vpnResourceSave',
            'vpnSavePassword',
        )
        for name in identifiers:
            marker = f'.accessibilityIdentifier("{name}")'
            self.assertEqual(panel.count(marker), 1, name)
            panel = panel.replace(marker, marker + f'''.background(GeometryReader {{ geometry in
                Color.clear.preference(key: VPNHitBounds.self,
                    value: ["{name}": geometry.frame(in: .named("vpnPopover"))])
            }})''')

        for title, name in (('Отмена', 'cancelLabel'), ('Продолжить', 'submitLabel')):
            label = f'Text("{title}").frame(maxWidth: .infinity, minHeight: 36).contentShape(Rectangle())'
            self.assertEqual(panel.count(label), 1)
            panel = panel.replace(label, label + f'''.background(GeometryReader {{ geometry in
                Color.clear.preference(key: VPNHitBounds.self,
                    value: ["{name}": geometry.frame(in: .named("vpnPopover"))])
            }})''')

        harness = r'''
enum VPNCredentialKind: Equatable { case privateKeyPassword, vpnPassword }
enum VPNLiveState: Equatable {
    case unavailable, off, connecting, needsCredential(VPNCredentialKind), connected, failed(String)
    var label: String {
        switch self {
        case .unavailable: return "VPN недоступен"
        case .off: return "VPN выключен"
        case .connecting: return "Подключаемся…"
        case .needsCredential(.privateKeyPassword): return "Введите пароль ключа"
        case .needsCredential(.vpnPassword): return "Введите пароль или код"
        case .connected: return "VPN включён"
        case .failed(let message): return message
        }
    }
}
final class VPNLiveController: ObservableObject {
    @Published private(set) var state: VPNLiveState = .off
    var credentialPromptIdentifier: UUID? { nil }
    init(store: VPNStore) {}
    func refresh() { state = .off }
    func connect() { state = .connected }
    func disconnect() { state = .off }
    var passwordPersistenceAvailable: Bool { true }
    func submitCredential(_ secret: inout Data, expectedPromptIdentifier: UUID?) { secret.removeAll(); state = .connected }
    func cancelCredential() { state = .off }
}
struct PowerStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        PilotButtonStyle(highlightsSurface: false).makeBody(configuration: configuration)
    }
}
'''
        checks = r'''
struct VPNHitBounds: PreferenceKey {
    static var defaultValue: [String: CGRect] = [:]
    static func reduce(value: inout [String: CGRect], nextValue: () -> [String: CGRect]) {
        value.merge(nextValue(), uniquingKeysWith: { _, new in new })
    }
}

let certificateProfile = """
client
dev tun
proto udp
remote vpn.company.example 1194
remote-cert-tls server
<ca>
-----BEGIN CERTIFICATE-----
QUJDRA==
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
QUJDRA==
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
QUJDRA==
-----END PRIVATE KEY-----
</key>
"""
let credentialProfile = """
client
dev tun
proto udp
remote vpn.company.example 1194
remote-cert-tls server
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
QUJDRA==
-----END CERTIFICATE-----
</ca>
"""

func configure(_ panel: VPNPanelModel, resources: Int, credentials: Bool = false) throws {
    let profile = credentials ? credentialProfile : certificateProfile
    try panel.configuration.importProfile(data: Data(profile.utf8), name: "company.ovpn")
    if credentials {
        panel.login = "employee"
        panel.authenticationChoice = .password
    } else {
        try panel.configuration.setAuthentication(mode: .certificate)
        panel.authenticationChoice = .certificate
    }
    for index in 0..<resources {
        panel.configuration.beginAddingResource()
        panel.configuration.resourceDraft?.name = "Resource \(index + 1)"
        panel.configuration.resourceDraft?.address = "10.44.\(index).1"
        try panel.configuration.saveResourceDraft()
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
// Prohibited offscreen processes never activate another app. Only this owned
// fixture window supplies a controlled key-state for native responder tests.
final class OwnCredentialWindow: NSWindow {
    override var canBecomeKey: Bool { true }
    override var isKeyWindow: Bool { true }
}
private func secureField(_ view: NSView) -> VPNSecretField.Field? {
    if let field = view as? VPNSecretField.Field { return field }
    return view.subviews.lazy.compactMap { secureField($0) }.first
}
for scenario in ["import", "settings0", "settings3", "settings18", "resource", "auth", "auth-save", "auth-otp", "credential-settings", "credential-resource"] {
    let panel = VPNPanelModel(preview: true)
    if scenario != "import" {
        try configure(panel, resources: scenario == "settings18" ? 18 : scenario == "settings3" ? 3 : 0,
                      credentials: scenario.hasPrefix("auth"))
        panel.settings = true
    }
    if scenario == "resource" {
        panel.beginResource(); panel.resourceAddress = "10.55.0.0/16"
    }
    if scenario.hasPrefix("auth") {
        panel.beginAuthentication(); panel.authenticationChoice = .password
        if scenario == "auth-save" { panel.choosePasswordPersistence(true) }
        if scenario == "auth-otp" { panel.selectAuthentication(.oneTimePassword) }
    }

    var bounds: [String: CGRect] = [:]
    let root = VPNPanelView(panel: panel, close: {})
        .coordinateSpace(name: "vpnPopover")
        .onPreferenceChange(VPNHitBounds.self) { bounds = $0 }
    let host = NSHostingView(rootView: root)
    host.frame = NSRect(x: 0, y: 0, width: 344, height: 432)
    let window = OwnCredentialWindow(contentRect: host.frame, styleMask: [.borderless],
                          backing: .buffered, defer: false)
    window.contentView = host
    window.setFrameOrigin(NSPoint(x: -10000, y: -10000)); window.orderBack(nil)
    for _ in 0..<5 {
        host.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))
    }
    if scenario.hasPrefix("credential-") {
        if scenario == "credential-resource" { panel.beginResource() }
        panel.liveState = .needsCredential(.vpnPassword)
        panel.credentialPromptIdentifier = UUID()
        panel.secret = "synthetic"
        window.makeKey()
        for _ in 0..<6 { host.layoutSubtreeIfNeeded(); RunLoop.main.run(until: Date().addingTimeInterval(0.03)) }
        guard let field = secureField(host) else { fatalError("Prompt hidden behind nested settings") }
        precondition(field.currentEditor() != nil, "Native secure field did not become first responder")
        precondition(field.focusedPrompt == panel.credentialPromptIdentifier, "Fresh prompt did not focus own field")
        let prior = field.focusedPrompt
        panel.credentialPromptIdentifier = UUID()
        for _ in 0..<6 { host.layoutSubtreeIfNeeded(); RunLoop.main.run(until: Date().addingTimeInterval(0.03)) }
        precondition(field.focusedPrompt == panel.credentialPromptIdentifier && field.focusedPrompt != prior,
                     "Same-kind fresh prompt did not drive focus")
        field.requestFocus(); field.cancelPendingFocus(); field.prompt = nil
        RunLoop.main.run(until: Date().addingTimeInterval(0.03))
        precondition(field.focusedPrompt == nil, "Cancelled queued focus ran after invalidation")
    }
    var required = ["vpnBack"]
    switch scenario {
    case "credential-settings", "credential-resource": required += ["vpnCredential", "vpnCredentialCancel", "vpnCredentialSubmit", "cancelLabel", "submitLabel"]
    case "import": required += ["vpnImport"]
    case "resource": required += ["vpnResourceSave"]
    case "auth", "auth-save": required += ["vpnAuthenticationSave", "vpnSavePassword"]
    case "auth-otp":
        required += ["vpnAuthenticationSave"]
        precondition(bounds["vpnSavePassword"] == nil, "OTP offered password saving")
    default: required += ["vpnReplaceProfile", "vpnAddResource", "vpnRemove", "vpnSettingsDone"]
    }
    for name in required {
        guard let frame = bounds[name] else { fatalError("Missing \(name) in \(scenario)") }
        let minimum: CGFloat = name == "vpnImport" ? 100 : name == "vpnCredential" ? 28 : 36
        precondition(frame.width >= 36 && frame.height >= minimum,
                     "Small target \(name) in \(scenario): \(frame)")
        precondition(frame.minX >= -0.5 && frame.maxX <= 344.5 &&
                     frame.minY >= -0.5 && frame.maxY <= 432.5,
                     "Overflow \(name) in \(scenario): \(frame)")
    }
    let rendered = required.map { "\($0)=\(bounds[$0]!)" }.joined(separator: ", ")
    print("\(scenario): \(rendered)")
    if scenario.hasPrefix("credential-") {
        guard let field = secureField(host), let editor = field.currentEditor() as? NSTextView else {
            fatalError("Native credential control missing")
        }
        if scenario == "credential-settings" {
            guard let action = field.action else { fatalError("Missing secure-field Return action") }
            precondition(field.sendAction(action, to: field.target), "Native Return target/action not handled")
        } else {
            guard let delegate = field.delegate as? VPNSecretField.Coordinator else { fatalError("Missing native delegate") }
            precondition(delegate.control(field, textView: editor, doCommandBy: #selector(NSResponder.cancelOperation(_:))),
                         "Native Esc delegate command not handled")
        }
        precondition(panel.secret.isEmpty, "Credential action did not clear draft")
        precondition(panel.settings && (scenario != "credential-resource" || panel.editingResource),
                     "Credential presentation discarded nested return destination")
        if let delegate = field.delegate as? VPNSecretField.Coordinator {
            panel.credentialPromptIdentifier = UUID(); panel.secret = "new synthetic draft"
            VPNSecretField.dismantleNSView(field, coordinator: delegate)
            precondition(field.stringValue.isEmpty && panel.secret == "new synthetic draft",
                         "Old native teardown overwrote a newer draft")
        }
    }
    window.orderOut(nil); window.contentView = nil
}
'''
        with tempfile.TemporaryDirectory(prefix='proxypilot-vpn-layout-') as directory:
            main = Path(directory) / 'main.swift'
            binary = Path(directory) / 'vpn-layout'
            main.write_text(harness + panel + checks)
            sources = [ROOT / 'app' / name for name in (
                'Controls.swift', 'VPNConfiguration.swift', 'VPNProfileImporter.swift',
                'VPNStore.swift', 'VPNModel.swift',
            )]
            target = ('arm64-apple-macosx11.0' if platform.machine() == 'arm64'
                      else 'x86_64-apple-macosx11.0')
            built = subprocess.run([
                'swiftc', '-target', target, *map(str, sources), str(main), '-o', str(binary)
            ], capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.count(': vpnBack='), 10, result.stdout)


if __name__ == '__main__':
    unittest.main()
