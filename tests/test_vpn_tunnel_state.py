"""Inert Stage-A VPN application transaction and durable-state checks."""
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
class VPNTunnelStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-tunnel-state-build-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        sources = [ROOT / 'app/VPNConfiguration.swift',
                   ROOT / 'app/vpn-helper/VPNApplicationSpec.swift',
                   ROOT / 'app/vpn-helper/VPNTunnelStateStore.swift',
                   ROOT / 'app/vpn-helper/VPNProfileVault.swift',
                   ROOT / 'tests/vpn_tunnel_state_checks.swift']
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0',
                                 *map(str, sources), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, name):
        with tempfile.TemporaryDirectory(prefix='pp-tunnel-state-', dir='/tmp') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), name, folder], capture_output=True,
                                    text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('passed' if name in ('transactions', 'canonical', 'vault') else 'rejected',
                          result.stdout)

    def test_canonical_bounds(self): self.run_case('canonical')
    def test_active_pending_and_one_shot_challenge(self): self.run_case('transactions')
    def test_content_addressed_profile_vault(self): self.run_case('vault')
    def test_corruption_rejected(self): self.run_case('corrupt')
    def test_wrong_mode_rejected(self): self.run_case('mode')
    def test_symlink_rejected(self): self.run_case('link')
