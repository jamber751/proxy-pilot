"""Contradictory fake replies, not a reproduction of kernel route selection."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class OrdinaryLookupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-ordinary-lookup-build-')
        cls.addClassCleanup(cls.temp.cleanup); cls.binary = Path(cls.temp.name)/'checks'
        names = ['OpenVPNManagementEvent.swift','OpenVPNStateEvidence.swift','VPNKernelInterfaceSnapshot.swift',
            'VPNTunnelInterfaceResolver.swift','VPNRoutePlan.swift','VPNRouteJournal.swift','VPNDarwinRouteSocket.swift','VPNRouteTransaction.swift']
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        r = subprocess.run(['swiftc','-parse-as-library','-D','VPN_ROUTE_TRANSACTION_TESTING','-target',arch+'-apple-macosx11.0',
            str(ROOT/'app/VPNConfiguration.swift'),*[str(ROOT/'app/vpn-helper'/n) for n in names],
            str(ROOT/'tests/vpn_ordinary_route_lookup_checks.swift'),'-o',str(cls.binary)],capture_output=True,text=True,timeout=120)
        if r.returncode: raise AssertionError(r.stderr)
    def case(self, mode):
        with tempfile.TemporaryDirectory(prefix='pp-ordinary-lookup-') as folder:
            r = subprocess.run([str(self.binary),mode,folder],capture_output=True,text=True,timeout=15)
            self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            self.assertEqual(r.stdout.strip(),'ordinary route evidence passed')
    def test_exact_reply_unchanged(self): self.case('exact')
    def test_broader_host_fallback_unchanged(self): self.case('broader')
    def test_broader_cidr_containment_unchanged(self): self.case('broader-cidr')
    def test_default_echo_destination_with_zero_mask_unchanged(self): self.case('default')
    def test_default_link_gateway_unchanged(self): self.case('default-link')
    def test_esrch_absence_unchanged(self): self.case('absent')
    def test_enoent_absence_unchanged(self): self.case('enoent')
    def test_scoped_same_interface_fallback_and_default_behavior_unchanged(self): self.case('scoped')
    def test_narrower_contradiction_refused(self): self.case('narrower')
    def test_noncontaining_broader_refused(self): self.case('unrelated')
    def test_other_family_refused(self): self.case('family')
    def test_default_other_family_refused(self): self.case('default-family')
    def test_success_without_destination_is_not_absence(self): self.case('missing')
    def test_recovery_narrower_keeps_inflight_and_applied_journal_bytes(self): self.case('recovery-narrower')
    def test_recovery_noncontaining_keeps_inflight_and_applied_journal_bytes(self): self.case('recovery-unrelated')
    def test_recovery_other_family_keeps_inflight_and_applied_journal_bytes(self): self.case('recovery-family')
    def test_recovery_default_other_family_keeps_inflight_and_applied_journal_bytes(self): self.case('recovery-default-family')
    def test_recovery_missing_destination_keeps_inflight_and_applied_journal_bytes(self): self.case('recovery-missing')
if __name__ == '__main__': unittest.main()
