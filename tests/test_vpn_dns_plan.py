"""Pure scoped-DNS plan and durable journal; never mutates DNS or networking."""
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
class VPNDNSPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-dns-plan-build-', dir='/tmp')
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
                   ROOT / 'app/vpn-helper/VPNDNSPlan.swift',
                   ROOT / 'app/vpn-helper/VPNDNSJournal.swift',
                   ROOT / 'tests/vpn_dns_plan_checks.swift']
        result = subprocess.run(['swiftc', '-D', 'VPN_ROUTE_TRANSACTION_TESTING',
                                 '-target', f'{arch}-apple-macosx11.0',
                                 *map(str, sources), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, name, word=None):
        with tempfile.TemporaryDirectory(prefix='pp-dns-plan-', dir='/tmp') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), name, folder], capture_output=True,
                                    text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(word or ('passed' if name in ('planning', 'journal') else 'rejected'),
                          result.stdout)

    def test_deterministic_scoped_plan(self): self.run_case('planning')
    def test_requires_domain_scope(self): self.run_case('no-domain')
    def test_overlapping_domains_rejected(self): self.run_case('overlap')
    def test_unproved_dns_server_rejected(self): self.run_case('unproved')
    def test_foreign_dns_route_rejected(self): self.run_case('foreign-route')
    def test_stale_route_proof_rejected(self): self.run_case('stale-proof')
    def test_global_scope_rejected(self): self.run_case('global')
    def test_durable_ordered_checkpoints_and_retirement(self): self.run_case('journal')
    def test_generation_revision_binding(self): self.run_case('stale')
    def test_wrong_file_mode_rejected(self): self.run_case('mode')
    def test_symlink_rejected(self): self.run_case('link')
    def test_corrupt_record_rejected(self): self.run_case('corrupt')
    def test_shared_directory_rejected(self): self.run_case('directory')

    def test_source_is_inert(self):
        source = ''.join((ROOT / path).read_text() for path in (
            'app/vpn-helper/VPNDNSPlan.swift', 'app/vpn-helper/VPNDNSJournal.swift'))
        for forbidden in ('scutil', 'networksetup', 'SCDynamicStore', 'Process(', 'posix_spawn',
                          'system(', 'releaseHold', 'case connected'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
