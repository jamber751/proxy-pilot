"""One-button frontend orchestration against an in-memory helper session."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNLiveControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-live-controller-build-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        sources = [ROOT / 'app/VPNConfiguration.swift', ROOT / 'app/VPNProfileImporter.swift',
            ROOT / 'app/VPNStore.swift', ROOT / 'app/vpn-helper/VPNHelperProtocol.swift',
            ROOT / 'app/vpn-helper/VPNApplicationSpec.swift',
            ROOT / 'app/vpn-helper/VPNTunnelStateStore.swift',
            ROOT / 'app/VPNLiveController.swift', ROOT / 'tests/vpn_live_controller_checks.swift']
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run(['swiftc', '-D', 'VPN_LIVE_CONTROLLER_TESTING',
            '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, name):
        with tempfile.TemporaryDirectory(prefix='pp-live-controller-', dir='/tmp') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), name, folder], capture_output=True,
                                    text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('flow passed', result.stdout)

    def test_certificate_one_button_connect(self): self.run_case('certificate')
    def test_password_or_otp_prompt_and_secret_wipe(self): self.run_case('credential')
    def test_sequential_prompts_keep_session_and_wipe_each_secret(self):
        self.run_case('multi-credential')
    def test_cancel_persists_off(self): self.run_case('cancel')
    def test_disconnect_proves_cleanup_before_persisting_off(self): self.run_case('disconnect')
    def test_domain_intent_never_opens_helper(self): self.run_case('unsupported')


if __name__ == '__main__':
    unittest.main()
