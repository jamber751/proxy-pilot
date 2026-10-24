"""Real saved-state/adapter recovery; synthetic profiles, no GUI/helper/Keychain."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def build_fixture(folder, panel_source=None):
    folder = Path(folder)
    adapter = folder / 'VPNPanelModel.swift'
    adapter.write_text((panel_source or ROOT / 'app/VPNPanel.swift').read_text().split('\nstruct VPNPanelView:', 1)[0])
    sources = [ROOT / name for name in ('app/VPNConfiguration.swift', 'app/VPNProfileImporter.swift',
        'app/VPNStore.swift', 'app/VPNModel.swift', 'app/VPNPasswordRuntime.swift', 'app/VPNPasswordCleanupCoordinator.swift',
        'app/VPNPasswordPersistenceCoordinator.swift', 'app/VPNLiveController.swift',
        'app/vpn-helper/VPNHelperProtocol.swift', 'app/vpn-helper/VPNApplicationSpec.swift', 'app/vpn-helper/VPNTunnelStateStore.swift')]
    binary = folder / 'checks'
    arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
    built = subprocess.run(['swiftc', '-D', 'VPN_PANEL_TESTING', '-D', 'VPN_LIVE_CONTROLLER_TESTING',
        '-target', arch + '-apple-macosx11.0', *map(str, sources), str(adapter),
        str(ROOT / 'tests/vpn_panel_certificate_recovery_checks.swift'), '-o', str(binary)],
        capture_output=True, text=True, timeout=120)
    if built.returncode: raise AssertionError(built.stdout + built.stderr)
    return binary


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift model required')
class CertificateRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-certificate-recovery-build-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = build_fixture(cls.temp.name)

    def run_case(self, case):
        with tempfile.TemporaryDirectory(prefix='pp-certificate-recovery-') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), case, folder], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), 'certificate recovery check passed')

    def test_reopened_partial_import_can_save_certificate_authentication(self): self.run_case('save')
    def test_reopened_partial_import_can_continue_without_selecting_password_mode(self): self.run_case('continue')
    def test_missing_resources_still_requests_resources_after_certificate_recovery(self): self.run_case('resources')
    def test_failed_save_or_continue_stays_open_and_can_recover_after_reopen(self):
        for case in ('save-error', 'continue-error'):
            with self.subTest(case=case): self.run_case(case)
    def test_password_profile_still_requires_explicit_mode_and_preserves_existing_consent(self): self.run_case('password')
    def test_missing_profile_never_creates_certificate_authentication(self): self.run_case('missing')
    def test_stale_certificate_editor_cannot_overwrite_replacement_password_profile(self): self.run_case('stale')


if __name__ == '__main__': unittest.main()
