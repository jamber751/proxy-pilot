"""Held OpenVPN process + management protocol integration checks."""
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
class VPNTunnelCoordinatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-tunnel-coordinator-build-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        sources = [ROOT / 'app/vpn-helper/VPNProfileVault.swift',
                   ROOT / 'app/vpn-helper/VPNEngineProcess.swift',
                   ROOT / 'app/vpn-helper/OpenVPNManagementEvent.swift',
                   ROOT / 'app/vpn-helper/OpenVPNStateEvidence.swift',
                   ROOT / 'app/vpn-helper/OpenVPNManagementParser.swift',
                   ROOT / 'app/vpn-helper/OpenVPNManagementClient.swift',
                   ROOT / 'app/vpn-helper/VPNManagementSocketReservation.swift',
                   ROOT / 'app/vpn-helper/VPNTunnelCoordinator.swift',
                   ROOT / 'tests/vpn_tunnel_coordinator_checks.swift']
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run([
            'swiftc', '-D', 'VPN_ENGINE_PROCESS_TESTING', '-D', 'VPN_TUNNEL_COORDINATOR_TESTING',
            '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(cls.binary)
        ], capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, name, word):
        with tempfile.TemporaryDirectory(prefix='pp-tunnel-coordinator-', dir='/tmp') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), name, folder], capture_output=True,
                                    text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(word, result.stdout)

    def test_serialized_held_lifecycle(self): self.run_case('lifecycle', 'passed')
    def test_connected_is_only_internal_management_evidence(self): self.run_case('internal-connected', 'passed')
    def test_serialized_management_state_observation(self): self.run_case('observe', 'passed')
    def test_runtime_credential_prompt_is_explicitly_blocked(self): self.run_case('credential', 'blocked')
    def test_saved_credential_requirement_never_spawns(self): self.run_case('plan-blocked', 'blocked')
    def test_management_rejection_fails_closed(self): self.run_case('reject', 'rejected')
    def test_management_socket_deadline_stops_child(self): self.run_case('timeout', 'timed out')

    def test_coordinator_never_releases_hold_or_claims_connected(self):
        source = (ROOT / 'app/vpn-helper/VPNTunnelCoordinator.swift').read_text()
        self.assertNotIn('.releaseHold', source)
        self.assertNotIn('case connected', source)
        self.assertNotIn('route(', source)
        self.assertNotIn('scutil', source)


if __name__ == '__main__':
    unittest.main()
