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
        sources = [ROOT / 'app/VPNConfiguration.swift',
                   ROOT / 'app/vpn-helper/VPNApplicationSpec.swift',
                   ROOT / 'app/vpn-helper/VPNTunnelStateStore.swift',
                   ROOT / 'app/vpn-helper/OpenVPNTransientCredential.swift',
                   ROOT / 'app/vpn-helper/OpenVPNHeldCredentialExchange.swift',
                   ROOT / 'app/vpn-helper/OpenVPNManagementCredentialTransport.swift',
                   ROOT / 'app/vpn-helper/VPNProfileVault.swift',
                   ROOT / 'app/vpn-helper/VPNEngineProcess.swift',
                   ROOT / 'app/vpn-helper/VPNEngineSupervisor.swift',
                   ROOT / 'app/vpn-helper/OpenVPNManagementEvent.swift',
                   ROOT / 'app/vpn-helper/OpenVPNStateEvidence.swift',
                   ROOT / 'app/vpn-helper/OpenVPNManagementParser.swift',
                   ROOT / 'app/vpn-helper/OpenVPNManagementClient.swift',
                   ROOT / 'app/vpn-helper/VPNManagementSocketReservation.swift',
                   ROOT / 'app/vpn-helper/VPNKernelInterfaceSnapshot.swift',
                   ROOT / 'app/vpn-helper/VPNTunnelInterfaceResolver.swift',
                   ROOT / 'app/vpn-helper/VPNTunnelCoordinator.swift',
                   ROOT / 'tests/vpn_tunnel_coordinator_checks.swift']
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run([
            'swiftc', '-D', 'VPN_ENGINE_PROCESS_TESTING', '-D', 'VPN_TUNNEL_COORDINATOR_TESTING',
            '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(cls.binary)
        ], capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, name, word, behavior=None):
        with tempfile.TemporaryDirectory(prefix='pp-tunnel-coordinator-', dir='/tmp') as folder:
            os.chmod(folder, 0o700)
            arguments = [str(self.binary), name, folder]
            if behavior is not None:
                arguments.append(behavior)
            result = subprocess.run(arguments, capture_output=True,
                                    text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(word, result.stdout)

    def test_serialized_held_lifecycle(self): self.run_case('lifecycle', 'passed')
    def test_startup_diagnostics_never_interpolate_unknown_errors(self):
        self.run_case('redacted-diagnostics', 'diagnostics redacted')
    def test_routes_are_installed_and_removed_around_the_process(self):
        self.run_case('route-lifecycle', 'routes ordered')
    def test_unproven_route_cleanup_blocks_explicit_stop(self):
        self.run_case('route-cleanup-blocked', 'cleanup blocked safely')
    def test_route_install_failure_cleans_before_process_stop(self):
        self.run_case('route-install-failure', 'install rolled back')
    def test_any_non_connected_state_after_bootstrap_fails_closed(self):
        for behavior in ('observe', 'observe-wait'):
            with self.subTest(behavior=behavior):
                self.run_case('observe-state', 'failed closed', behavior)
    def test_runtime_credential_prompt_is_explicitly_blocked(self): self.run_case('credential', 'blocked')
    def test_private_key_and_auth_prompts_are_sequential_in_either_order(self):
        for behavior in ('multi-key-auth', 'multi-auth-key', 'multi-auth-key-after-hold'):
            with self.subTest(behavior=behavior):
                self.run_case('multi-credential', 'multi prompt passed', behavior)

    def test_static_challenge_fails_before_hold_release_and_cleans_routes_first(self):
        self.run_case('static-credential', 'static rejected')
    def test_stale_credential_wipes_and_stops_before_hold_release(self):
        self.run_case('stale-credential', 'stale rejected')
    def test_saved_credential_requirement_never_spawns(self): self.run_case('plan-blocked', 'blocked')
    def test_management_rejection_fails_closed(self): self.run_case('reject', 'rejected')
    def test_management_socket_deadline_stops_child(self): self.run_case('timeout', 'timed out')

    def test_post_release_credential_hold_exit_and_timeout_fail_closed(self):
        for behavior in ('credential-after', 'hold-after', 'reconnect', 'exiting', 'timeout-after'):
            with self.subTest(behavior=behavior):
                self.run_case('post-release-failure', 'failed closed', behavior)

    def test_missing_or_ambiguous_new_utun_fails_closed(self):
        for behavior in ('missing-interface', 'ambiguous-interface'):
            with self.subTest(behavior=behavior):
                self.run_case('interface-failure', 'failed closed', behavior)

    def test_missing_initial_hold_or_pre_release_reconnect_never_releases(self):
        for behavior in ('no-hold', 'pre-reconnect'):
            with self.subTest(behavior=behavior):
                self.run_case('precondition-failure', 'failed closed', behavior)

    def test_coordinator_bootstrap_never_claims_route_dns_or_ui_connected(self):
        source = (ROOT / 'app/vpn-helper/VPNTunnelCoordinator.swift').read_text()
        self.assertEqual(source.count('client.send(.releaseHold'), 1)
        self.assertNotIn('route(', source)
        self.assertNotIn('scutil', source)
        self.assertNotIn('VPNRouteTransaction', source)
        self.assertNotIn('VPNDNS', source)


if __name__ == '__main__':
    unittest.main()
