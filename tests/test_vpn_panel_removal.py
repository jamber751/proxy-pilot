"""Real ProductView navigation with fake proxy content/helper and synthetic VPN store."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]

@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNPanelRemovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-removal-build-')
        cls.addClassCleanup(cls.temp.cleanup); folder = Path(cls.temp.name)
        panel = (ROOT / 'app/VPNPanel.swift').read_text()
        marker = '.accessibilityIdentifier("vpnBack")'
        if panel.count(marker) != 1: raise AssertionError('VPN header marker changed')
        panel = panel.replace(marker, marker + '''.background(Color.clear.preference(key: RemovalDestinationKey.self,
            value: RemovalDestination(screen: "vpn", vpnStatus: panel.mainStatus)))''')
        source = folder / 'VPNPanel.swift'; source.write_text(panel)
        sources = [ROOT / name for name in ('app/Controls.swift', 'app/VPNConfiguration.swift',
            'app/VPNProfileImporter.swift', 'app/VPNStore.swift', 'app/VPNModel.swift', 'app/VPNPasswordRuntime.swift', 'app/VPNPasswordCleanupCoordinator.swift',
            'app/VPNPasswordPersistenceCoordinator.swift', 'app/VPNLiveController.swift', 'app/vpn-helper/VPNHelperProtocol.swift',
            'app/vpn-helper/VPNApplicationSpec.swift', 'app/vpn-helper/VPNTunnelStateStore.swift')]
        checks = (ROOT / 'tests/vpn_panel_removal_checks.swift').read_text()
        main = (ROOT / 'app/main.swift').read_text()
        row = main.split('            if let openVPN {',1)[1].split('            ForEach(["socks5", "http"]',1)[0]
        row = row.replace('.accessibilityIdentifier("vpnSettingsRow")', '.accessibilityIdentifier("vpnSettingsRow").background(GeometryReader { geometry in Color.clear.preference(key: RemovalRowBoundsKey.self, value: geometry.frame(in: .global)) })')
        checks = checks.replace('// ACTUAL_VPN_SETTINGS_ROW', 'if let openVPN {' + row)
        check_source = folder / 'checks.swift'; check_source.write_text(checks)
        cls.binary = folder / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        built = subprocess.run(['swiftc', '-D', 'VPN_PANEL_TESTING', '-D', 'VPN_LIVE_CONTROLLER_TESTING',
            '-target', arch + '-apple-macosx11.0', *map(str, sources), str(source),
            str(check_source), '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=120)
        if built.returncode: raise AssertionError(built.stdout + built.stderr)

    def run_case(self, case):
        with tempfile.TemporaryDirectory(prefix='pp-removal-') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), case, folder], capture_output=True, text=True, timeout=12)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('flow passed', result.stdout)
            self.assertNotIn('Publishing changes from within view updates', result.stderr)

    def test_unknown_password_cleanup_warning_survives_real_product_removal_navigation(self): self.run_case('cleanup-warning')

    def test_success_returns_to_settings_and_preserves_proxy(self): self.run_case('success')
    def test_vpn_only_returns_to_settings_without_proxy_configuration(self): self.run_case('vpn-only')
    def test_failed_stop_keeps_vpn_and_proxy_navigation(self): self.run_case('failed-stop')
    def test_failed_deletion_keeps_vpn_and_proxy_navigation(self): self.run_case('failed-delete')
    def test_cancel_keeps_vpn_and_proxy_navigation(self): self.run_case('cancel')
    def test_request_identity_and_duplicate_consumption(self): self.run_case('consume')
    def test_pending_request_is_consumed_when_product_mounts(self): self.run_case('pending-on-mount')

if __name__ == '__main__': unittest.main()
