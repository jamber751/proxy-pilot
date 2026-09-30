"""Recoverable route transaction tests use only an in-memory fake kernel."""
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
class VPNRouteTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-route-transaction-build-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        sources = [ROOT / 'app/VPNConfiguration.swift',
                   ROOT / 'app/vpn-helper/OpenVPNManagementEvent.swift',
                   ROOT / 'app/vpn-helper/OpenVPNStateEvidence.swift',
                   ROOT / 'app/vpn-helper/VPNKernelInterfaceSnapshot.swift',
                   ROOT / 'app/vpn-helper/VPNTunnelInterfaceResolver.swift',
                   ROOT / 'app/vpn-helper/VPNRoutePlan.swift',
                   ROOT / 'app/vpn-helper/VPNRouteJournal.swift',
                   ROOT / 'app/vpn-helper/VPNDarwinRouteSocket.swift',
                   ROOT / 'app/vpn-helper/VPNRouteTransaction.swift',
                   ROOT / 'tests/vpn_route_transaction_checks.swift']
        result = subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0',
                                 *map(str, sources), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise RuntimeError(result.stderr)

    def run_case(self, mode):
        with tempfile.TemporaryDirectory(prefix='pp-route-transaction-', dir='/tmp') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), mode, folder], capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('passed', result.stdout)

    def test_install_verify_and_reverse_cleanup(self): self.run_case('lifecycle')
    def test_fresh_identical_route_is_never_claimed(self): self.run_case('preexisting')
    def test_crash_before_mutation_recovers_to_idle(self): self.run_case('crash-before')
    def test_crash_after_mutation_uses_checkpoint_and_rolls_back(self): self.run_case('crash-after')
    def test_missing_owned_route_is_reconciled(self): self.run_case('missing')
    def test_foreign_replacement_is_never_deleted(self): self.run_case('foreign')

    def test_transaction_has_no_hold_dns_or_connected_authority(self):
        source = (ROOT / 'app/vpn-helper/VPNRouteTransaction.swift').read_text()
        for forbidden in ('releaseHold', 'scutil', 'networksetup', 'markConnected',
                          'VPNTunnelStateStore', 'OpenVPNManagementClient'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
