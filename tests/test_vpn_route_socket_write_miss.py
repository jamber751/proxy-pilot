"""Real route adapter with synthetic interface names and fake transport ONLY."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [ROOT/'app/VPNConfiguration.swift'] + [ROOT/'app/vpn-helper'/name for name in (
    'OpenVPNManagementEvent.swift', 'OpenVPNStateEvidence.swift', 'VPNKernelInterfaceSnapshot.swift',
    'VPNTunnelInterfaceResolver.swift', 'VPNRoutePlan.swift', 'VPNRouteJournal.swift',
    'VPNDarwinRouteSocket.swift', 'VPNRouteTransaction.swift', 'VPNLifecycleOwnership.swift')]

@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS SDK required')
class RouteWriteMissTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-route-write-miss-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name)/'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-target', arch+'-apple-macosx11.0',
            *map(str,SOURCES), str(ROOT/'tests/vpn_route_socket_write_miss_checks.swift'), '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=120)
        if result.returncode: raise AssertionError(result.stderr)

    def case(self, mode):
        with tempfile.TemporaryDirectory(prefix='pp-route-write-ledger-') as folder:
            result = subprocess.run([str(self.binary),mode,folder], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(result.stdout,'pure route write-miss checks passed\n')

    def test_send_esrch_is_absence(self): self.case('absence')
    def test_receive_esrch_is_not_absence(self): self.case('receive')
    def test_send_enoent_is_not_broadened(self): self.case('enoent')
    def test_other_send_errors_remain_failures(self): self.case('permission')
    def test_matching_kernel_esrch_reply_unchanged(self): self.case('kernel')
    def test_add_esrch_does_not_claim_installation(self): self.case('add')
    def test_delete_esrch_does_not_claim_removal(self): self.case('delete')
    def test_queued_own_error_and_foreign_success_are_skipped(self): self.case('stale')
    def test_stale_success_cannot_authorize_mutation_receipt(self): self.case('stale-add')
    def test_response_limit_and_deadline_unchanged(self): self.case('limit')
    def test_repeated_miss_backlog_is_bounded_and_conservative(self): self.case('repeated')
    def test_read_uncertainty_preserves_pending_and_applied_journal(self): self.case('recovery')

if __name__ == '__main__': unittest.main()
