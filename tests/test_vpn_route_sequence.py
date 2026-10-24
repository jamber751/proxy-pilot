"""Same-process PF_ROUTE correlation; fake broadcast transports only."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [
    'app/VPNConfiguration.swift', 'app/vpn-helper/OpenVPNManagementEvent.swift',
    'app/vpn-helper/OpenVPNStateEvidence.swift', 'app/vpn-helper/VPNKernelInterfaceSnapshot.swift',
    'app/vpn-helper/VPNTunnelInterfaceResolver.swift', 'app/vpn-helper/VPNRoutePlan.swift',
    'app/vpn-helper/VPNRouteJournal.swift', 'app/vpn-helper/VPNDarwinRouteSocket.swift',
    'app/vpn-helper/VPNPeerRouteEvidenceResolver.swift', 'tests/vpn_route_sequence_checks.swift',
]

@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class RouteSequenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-route-sequence-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.build = Path(cls.temp.name)
        files = []
        for relative in SOURCES:
            target = cls.build / Path(relative).name
            target.write_bytes((ROOT / relative).read_bytes())
            files.append(target)
        cls.binary = cls.build / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0',
                                 *map(str, files), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, case):
        result = subprocess.run([str(self.binary), case], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'PASS route-sequence\n')

    def test_two_default_route_controllers_ignore_each_others_broadcasts(self): self.run_case('route-route')
    def test_route_then_peer_share_namespace(self): self.run_case('route-peer')
    def test_peer_then_route_share_namespace(self): self.run_case('peer-route')
    def test_stale_wrong_type_is_not_current_response(self): self.run_case('stale-type')
    def test_stale_error_is_not_current_response(self): self.run_case('stale-error')
    def test_stale_wrong_address_is_not_current_response(self): self.run_case('stale-address')
    def test_matching_wrong_type_still_refused(self): self.run_case('matching-type')
    def test_explicit_inputs_and_no_wrap(self): self.run_case('explicit')
    def test_allocator_concurrent_uniqueness(self): self.run_case('concurrent')

if __name__ == '__main__': unittest.main()
