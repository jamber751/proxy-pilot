"""Read-only PF_ROUTE best-route evidence tests; all kernel replies are fake."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNPeerRouteEvidenceTests(unittest.TestCase):
    def test_fake_transport_ipv4_ipv6_and_fail_closed_validation(self):
        with tempfile.TemporaryDirectory(prefix='pp-peer-route-build-', dir='/tmp') as build:
            binary = Path(build) / 'checks'
            arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
            sources = [ROOT / 'app/VPNConfiguration.swift',
                       ROOT / 'app/vpn-helper/OpenVPNManagementEvent.swift',
                       ROOT / 'app/vpn-helper/OpenVPNStateEvidence.swift',
                       ROOT / 'app/vpn-helper/VPNKernelInterfaceSnapshot.swift',
                       ROOT / 'app/vpn-helper/VPNTunnelInterfaceResolver.swift',
                       ROOT / 'app/vpn-helper/VPNRoutePlan.swift',
                       ROOT / 'app/vpn-helper/VPNRouteJournal.swift',
                       ROOT / 'app/vpn-helper/VPNDarwinRouteSocket.swift',
                       ROOT / 'app/vpn-helper/VPNPeerRouteEvidenceResolver.swift',
                       ROOT / 'tests/vpn_peer_route_evidence_checks.swift']
            compiled = subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0',
                                       *map(str, sources), '-o', str(binary)],
                                      capture_output=True, text=True, timeout=90)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            checked = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
            self.assertIn('peer route evidence checks passed', checked.stdout)

    def test_slice_is_read_only(self):
        source = (ROOT / 'app/vpn-helper/VPNPeerRouteEvidenceResolver.swift').read_text()
        self.assertIn('RTM_GET', source)
        for forbidden in ('RTM_ADD', 'RTM_DELETE', 'Process(', 'posix_spawn', 'system(',
                          '/sbin/route', 'networksetup', 'scutil', 'releaseHold',
                          'VPNDarwinRouteSocket.production'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
