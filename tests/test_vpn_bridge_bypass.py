"""Pure effective bypass projection; no real profile, helper or network access."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNBridgeBypassTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-vpn-bypass-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        sources = ['app/VPNConfiguration.swift', 'app/vpn-helper/VPNApplicationSpec.swift',
                   'app/vpn-helper/VPNTunnelStateStore.swift', 'app/VPNBridgeBypass.swift',
                   'tests/vpn_bridge_bypass_checks.swift']
        built = subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0',
                                *[str(ROOT / source) for source in sources],
                                '-o', str(cls.binary)], capture_output=True, text=True, timeout=90)
        if built.returncode:
            raise AssertionError(built.stderr)

    def run_case(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('bridge bypass passed', result.stdout)

    def test_exact_public_ip_cidr_and_ipv6(self): self.run_case('exact')
    def test_user_list_preserved_and_merge_idempotent(self): self.run_case('merge')
    def test_off_removes_only_overlay(self): self.run_case('off')
    def test_failure_does_not_imply_cleanup(self): self.run_case('failure')
    def test_zero_generation_rejected(self): self.run_case('invalid')
    def test_domains_and_dns_not_implicitly_supported(self): self.run_case('unsupported')
    def test_new_active_revision_replaces_old_overlay(self): self.run_case('replacement')
