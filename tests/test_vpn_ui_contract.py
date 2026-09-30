"""Static gates for the production VPN screen and its build graph."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class VPNUIContractTests(unittest.TestCase):
    def test_vpn_sources_are_appended_after_base_source_initialization(self):
        build = (ROOT / 'app/build.sh').read_text()
        base = build.index('SOURCES=("$HERE/main.swift"')
        model = build.index('SOURCES+=("$HERE/VPNModel.swift"')
        self.assertGreater(model, base)
        for name in ('VPNModel.swift', 'VPNLiveController.swift', 'VPNPanel.swift'):
            self.assertIn(name, build[model:])

    def test_vpn_is_a_settings_destination_with_accessible_controls(self):
        main = (ROOT / 'app/main.swift').read_text()
        panel = (ROOT / 'app/VPNPanel.swift').read_text()
        self.assertIn('.accessibilityIdentifier("vpnSettingsRow")', main)
        self.assertIn('PilotView(model: proxy, updates: updates, openVPN:', panel)
        for identifier in ('vpnBack', 'vpnSettings', 'vpnPower', 'vpnImport',
                           'vpnCredential', 'vpnCredentialSubmit',
                           'vpnCredentialCancel', 'vpnAddResource', 'vpnRemoveResource',
                           'vpnRemove'):
            self.assertEqual(panel.count(f'.accessibilityIdentifier("{identifier}")'), 1)
        self.assertIn('SecureField("Пароль или код"', panel)
        self.assertIn('.onDrop(of: ["public.file-url"]', panel)
        self.assertIn('configuration.importProfile(files: urls)', panel)
        self.assertIn('func disconnectForQuit(completion:', panel)
        self.assertIn('func restoreDesiredConnection()', panel)
        self.assertIn('NSWorkspace.didWakeNotification', main)

    def test_long_resource_list_is_bounded_and_lazy(self):
        panel = (ROOT / 'app/VPNPanel.swift').read_text()
        self.assertIn('LazyVStack(spacing: 6)', panel)
        self.assertIn('.frame(maxHeight: 144)', panel)
        self.assertIn('showsIndicators: panel.configuration.configuration.resources.count > 3', panel)

    def test_ui_does_not_offer_unimplemented_secret_persistence(self):
        panel = (ROOT / 'app/VPNPanel.swift').read_text()
        self.assertNotIn('keychain', panel.lower())
        self.assertIn('Пароли и коды не сохраняются', panel)
        self.assertIn('candidate.kind != .domain', panel)


if __name__ == '__main__':
    unittest.main()
