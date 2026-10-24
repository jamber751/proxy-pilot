"""Predicted IPv6 direct-host profile: fake transport/kernel/interfaces only."""
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
class IPv6DirectRouteProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(prefix='pp-scoped-dns-route-build-')
        cls.addClassCleanup(cls.folder.cleanup)
        cls.binary = Path(cls.folder.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        names = ['OpenVPNManagementEvent.swift', 'OpenVPNStateEvidence.swift',
                 'VPNKernelInterfaceSnapshot.swift', 'VPNTunnelInterfaceResolver.swift',
                 'VPNRoutePlan.swift', 'VPNRouteJournal.swift', 'VPNDarwinRouteSocket.swift',
                 'VPNRouteTransaction.swift', 'VPNDNSPlan.swift', 'VPNDomainNetworkPlan.swift']
        sources = [ROOT/'app/VPNConfiguration.swift', *[ROOT/'app/vpn-helper'/name for name in names],
                   ROOT/'tests/vpn_ipv6_direct_route_profile_checks.swift']
        result = subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-D', 'VPN_ROUTE_TRANSACTION_TESTING',
                                 '-target', arch+'-apple-macosx11.0', *map(str, sources), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise AssertionError(result.stderr)

    def case(self, name):
        with tempfile.TemporaryDirectory(prefix='pp-scoped-dns-route-state-') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), name, folder], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertIn('pure IPv6 route profile passed\n', result.stdout)
            return result.stdout

    def test_domain_proof(self): self.case('domain-proof')
    def test_journal_unneeded(self): self.case('journal-unneeded')
    def test_factory(self): self.case('factory')
    def test_identity_negative(self): self.case('identity-negative')
    def test_wire(self): self.case('wire')
    def test_link_empty_name(self): self.case('link-empty-name')
    def test_link_missing(self): self.case('link-missing')
    def test_link_numeric(self): self.case('link-numeric')
    def test_link_wrong_index(self): self.case('link-wrong-index')
    def test_link_wrong_name(self): self.case('link-wrong-name')
    def test_link_address(self): self.case('link-address')
    def test_link_selector(self): self.case('link-selector')
    def test_journal3(self): self.case('journal3')
    def test_journal_invalid(self): self.case('journal-invalid')
    def test_legacy_goldens(self): self.case('legacy-goldens')
    def test_adapter(self): self.case('adapter')
    def test_adapter_missing_llinfo(self): self.case('adapter-missing-llinfo')
    def test_preexisting_adapter(self): self.case('preexisting-adapter')
    def test_legacy_pending(self): self.case('legacy-pending')
    def test_legacy_applied(self): self.case('legacy-applied')
    def test_preexisting_transaction(self): self.case('preexisting-transaction')
    def test_recovery_before(self): self.case('recovery-before')
    def test_recovery_after(self): self.case('recovery-after')
    def test_foreign_missing_llinfo(self): self.case('foreign-missing-llinfo')
    def test_foreign_missing_owner(self): self.case('foreign-missing-owner')
    def test_foreign_interface(self): self.case('foreign-interface')
    def test_lifecycle(self): self.case('lifecycle')

if __name__ == "__main__": unittest.main()
