"""Bounded, redacted OpenVPN management client and parser checks."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class OpenVPNManagementClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-management-build-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        sources = [ROOT / 'app/vpn-helper/OpenVPNManagementEvent.swift',
                   ROOT / 'app/vpn-helper/OpenVPNManagementParser.swift',
                   ROOT / 'app/vpn-helper/OpenVPNManagementClient.swift',
                   ROOT / 'tests/vpn_management_client_checks.swift']
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0',
                                 *map(str, sources), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True,
                                text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('passed', result.stdout)

    def test_strict_redacted_parser(self): self.run_case('parser')
    def test_bounded_stream_and_fixed_command(self): self.run_case('stream')
    def test_length_flood_and_deadline_limits(self): self.run_case('limits')
    def test_explicit_loopback_endpoint(self): self.run_case('loopback')
    def test_owned_unix_socket_endpoint(self): self.run_case('unix')


if __name__ == '__main__':
    unittest.main()
