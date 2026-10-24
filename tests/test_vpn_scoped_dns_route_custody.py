"""Scope-aware custody uses private fake interfaces/transports/kernel only."""
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
class ScopedDNSRouteCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(prefix='pp-scoped-dns-route-build-')
        cls.addClassCleanup(cls.folder.cleanup)
        cls.binary = Path(cls.folder.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        names = ['OpenVPNManagementEvent.swift', 'OpenVPNStateEvidence.swift',
                 'VPNKernelInterfaceSnapshot.swift', 'VPNTunnelInterfaceResolver.swift',
                 'VPNRoutePlan.swift', 'VPNRouteJournal.swift', 'VPNDarwinRouteSocket.swift',
                 'VPNRouteTransaction.swift']
        sources = [ROOT/'app/VPNConfiguration.swift', *[ROOT/'app/vpn-helper'/name for name in names],
                   ROOT/'tests/vpn_scoped_dns_route_custody_checks.swift']
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
            self.assertIn('scoped DNS route custody passed\n', result.stdout)
            return result.stdout

    def test_ipv4_ipv6_scope_codec_and_missing_table_fallback(self): self.case('codec')
    def test_scope_is_used_for_all_adapter_lookup_add_delete_and_postchecks(self): self.case('adapter')
    def test_scoped_eexist_race_is_never_fresh_install(self): self.case('race')
    def test_adapter_foreign_same_scope_is_not_deleted(self): self.case('adapter-foreign')
    def test_adapter_wrong_scope_response_cannot_acknowledge_or_delete(self): self.case('adapter-wrong-scope')
    def test_actual_adapter_wrong_scope_recovery_response_retains_checkpoint(self): self.case('wrong-scope-recovery')
    def test_actual_adapter_wrong_scope_delete_recovery_retains_checkpoint(self): self.case('wrong-scope-delete-recovery')
    def test_roles_versions_scopes_and_flags_cannot_be_downgraded(self): self.case('validation')
    def test_same_destination_other_tables_survive_full_lifecycle(self): self.case('coexist')
    def test_crash_before_scoped_mutation_recovers_only_owned_routes(self): self.case('crash-before')
    def test_crash_after_scoped_mutation_uses_exact_checkpoint(self): self.case('crash-after')
    def test_crash_after_scoped_delete_retains_and_recovers_exact_checkpoint(self): self.case('crash-delete')
    def test_missing_scoped_route_preserves_other_tables(self): self.case('missing')
    def test_uncertain_install_foreign_replacement_retains_checkpoint(self): self.case('foreign')
    def test_foreign_delete_replacement_retains_ledger_and_table(self): self.case('foreign-delete')
    def test_identical_preexisting_scoped_route_is_never_claimed(self): self.case('preexisting')
    def test_legacy_format_and_crash_recovery(self): self.case('legacy')
    def test_legacy_controller_cannot_drop_scope_or_issue_mutation(self): self.case('unsupported')


if __name__ == '__main__':
    unittest.main()
