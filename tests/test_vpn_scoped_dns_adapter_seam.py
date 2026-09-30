"""Inert scoped-DNS adapter codec and exact ownership decisions."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNScopedDNSAdapterSeamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-dns-seam-build-', dir='/tmp')
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
                   ROOT / 'app/vpn-helper/VPNScopedDNSAdapterSeam.swift',
                   ROOT / 'tests/vpn_scoped_dns_adapter_seam_checks.swift']
        result = subprocess.run(['swiftc', '-D', 'VPN_ROUTE_TRANSACTION_TESTING',
                                 '-target', f'{arch}-apple-macosx11.0',
                                 *map(str, sources), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, name, word='passed'):
        result = subprocess.run([str(self.binary), name], capture_output=True,
                                text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(word, result.stdout)

    def test_canonical_systemconfiguration_entity(self): self.run_case('codec')
    def test_owned_exact_decisions(self): self.run_case('decisions')
    def test_equal_foreign_record_is_not_adopted(self): self.run_case('equal-foreign', 'rejected')
    def test_foreign_replacement_is_not_deleted(self): self.run_case('replacement', 'rejected')

    def test_source_is_inert(self):
        source = (ROOT / 'app/vpn-helper/VPNScopedDNSAdapterSeam.swift').read_text()
        for forbidden in ('import SystemConfiguration', 'SCDynamicStoreCreate',
                          'SCDynamicStoreSetValue', 'SCDynamicStoreRemoveValue',
                          'scutil', 'networksetup', 'Process(', 'posix_spawn', 'system('):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
