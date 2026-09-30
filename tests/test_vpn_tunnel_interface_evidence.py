"""Read-only kernel interface evidence and pure resolver checks."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNTunnelInterfaceEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-interface-evidence-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        sources = [ROOT / 'app/vpn-helper/OpenVPNManagementEvent.swift',
                   ROOT / 'app/vpn-helper/OpenVPNStateEvidence.swift',
                   ROOT / 'app/vpn-helper/OpenVPNManagementParser.swift',
                   ROOT / 'app/vpn-helper/VPNKernelInterfaceSnapshot.swift',
                   ROOT / 'app/vpn-helper/VPNTunnelInterfaceResolver.swift',
                   ROOT / 'tests/vpn_tunnel_interface_evidence_checks.swift']
        result = subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0',
                                 *map(str, sources), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, case):
        result = subprocess.run([str(self.binary), case], capture_output=True,
                                text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('passed', result.stdout)

    def test_ipv4_ipv6_and_dual_stack(self): self.run_case('families')
    def test_ambiguity_address_flags_and_identity_rejected(self): self.run_case('rejections')
    def test_explicit_production_snapshot_is_read_only(self): self.run_case('capture')


if __name__ == '__main__':
    unittest.main()
