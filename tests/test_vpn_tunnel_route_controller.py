"""The tunnel route controller is tested only with a fake route kernel."""
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
class VPNTunnelRouteControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-tunnel-routes-build-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        sources = [
            ROOT / 'app/VPNConfiguration.swift',
            ROOT / 'app/vpn-helper/VPNApplicationSpec.swift',
            ROOT / 'app/vpn-helper/VPNTunnelStateStore.swift',
            ROOT / 'app/vpn-helper/OpenVPNManagementEvent.swift',
            ROOT / 'app/vpn-helper/OpenVPNStateEvidence.swift',
            ROOT / 'app/vpn-helper/VPNKernelInterfaceSnapshot.swift',
            ROOT / 'app/vpn-helper/VPNTunnelInterfaceResolver.swift',
            ROOT / 'app/vpn-helper/VPNRoutePlan.swift',
            ROOT / 'app/vpn-helper/VPNRouteJournal.swift',
            ROOT / 'app/vpn-helper/VPNDarwinRouteSocket.swift',
            ROOT / 'app/vpn-helper/VPNRouteTransaction.swift',
            ROOT / 'app/vpn-helper/VPNTunnelRouteController.swift',
            ROOT / 'tests/vpn_tunnel_route_controller_test_types.swift',
            ROOT / 'tests/vpn_tunnel_route_controller_checks.swift',
        ]
        result = subprocess.run([
            'swiftc', '-D', 'VPN_ROUTE_TRANSACTION_TESTING',
            '-D', 'VPN_TUNNEL_ROUTE_CONTROLLER_TESTING',
            '-D', 'VPN_TUNNEL_COORDINATOR_TESTING',
            '-target', f'{arch}-apple-macosx11.0', *map(str, sources),
            '-o', str(cls.binary),
        ], capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise RuntimeError(result.stderr)

    def run_case(self, mode):
        with tempfile.TemporaryDirectory(prefix='pp-tunnel-routes-', dir='/tmp') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), mode, folder],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('passed', result.stdout)

    def test_install_verify_and_cleanup_before_process_stop(self):
        self.run_case('lifecycle')

    def test_generation_is_bound_before_route_lookup(self):
        self.run_case('stale-generation')

    def test_exact_active_application_is_required(self):
        self.run_case('stale-application')

    def test_peer_best_route_cannot_use_new_tunnel(self):
        self.run_case('peer-tunnel')

    def test_intent_change_before_mutation_is_rejected(self):
        self.run_case('intent-race-before')

    def test_intent_change_after_mutation_is_rolled_back(self):
        self.run_case('intent-race-after')

    def test_lost_runtime_authority_blocks_mutation(self):
        self.run_case('authority')

    def test_controller_has_no_dns_ui_or_process_authority(self):
        source = (ROOT / 'app/vpn-helper/VPNTunnelRouteController.swift').read_text()
        for forbidden in ('markConnected', 'scutil', 'networksetup',
                          'OpenVPNManagementClient', 'VPNEngineProcess', 'VPNDNS'):
            self.assertNotIn(forbidden, source)
        self.assertIn('prepareForProcessStop', source)
        self.assertIn('runtimeLease: VPNLifecycleLease', source)


if __name__ == '__main__':
    unittest.main()
