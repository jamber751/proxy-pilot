"""Deterministic Darwin routing-socket adapter tests; no network mutation."""
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
class VPNDarwinRouteSocketTests(unittest.TestCase):
    def test_fake_transport_and_codec(self):
        with tempfile.TemporaryDirectory(prefix='pp-route-socket-build-', dir='/tmp') as build:
            binary = Path(build) / 'checks'
            arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
            sources = [ROOT / 'app/VPNConfiguration.swift',
                       ROOT / 'app/vpn-helper/VPNRoutePlan.swift',
                       ROOT / 'app/vpn-helper/VPNRouteJournal.swift',
                       ROOT / 'app/vpn-helper/VPNDarwinRouteSocket.swift',
                       ROOT / 'tests/vpn_darwin_route_socket_checks.swift']
            compiled = subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0',
                                       *map(str, sources), '-o', str(binary)],
                                      capture_output=True, text=True, timeout=90)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            journal = Path(build) / 'journal'; journal.mkdir(mode=0o700)
            checked = subprocess.run([str(binary), str(journal)], capture_output=True,
                                     text=True, timeout=20)
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
            self.assertIn('route socket checks passed', checked.stdout)

    def test_adapter_uses_no_shell_or_network_configuration_tools(self):
        source = (ROOT / 'app/vpn-helper/VPNDarwinRouteSocket.swift').read_text()
        for forbidden in ('Process(', 'posix_spawn', 'system(', '/sbin/route',
                          'networksetup', 'scutil', 'releaseHold', 'case connected'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
