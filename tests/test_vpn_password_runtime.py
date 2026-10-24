"""Explicit lifecycle owner with synthetic workers and ordinary private Store only."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-password-runtime-build-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        names = ('VPNConfiguration.swift','VPNProfileImporter.swift','VPNStore.swift','VPNModel.swift',
            'VPNLiveController.swift','VPNPasswordPersistenceCoordinator.swift','VPNPasswordCleanupCoordinator.swift',
            'VPNPasswordRuntime.swift','vpn-helper/VPNHelperProtocol.swift','vpn-helper/VPNApplicationSpec.swift',
            'vpn-helper/VPNTunnelStateStore.swift')
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        r = subprocess.run(['swiftc','-D','VPN_LIVE_CONTROLLER_TESTING','-target',arch+'-apple-macosx11.0',
            *[str(ROOT/'app'/n) for n in names],str(ROOT/'tests/vpn_password_runtime_checks.swift'),'-o',str(cls.binary)],
            capture_output=True,text=True,timeout=120)
        if r.returncode: raise AssertionError(r.stderr)
    def run_case(self, mode):
        r = subprocess.run([str(self.binary),mode],capture_output=True,text=True,timeout=15)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(r.stdout.strip(),'runtime checks passed')
    def test_default_constructor_and_requests_are_inert(self): self.run_case('inert')
    def test_explicit_startup_cleans_residual_once(self): self.run_case('startup')
    def test_revoke(self): self.run_case('revoke')
    def test_login_change(self): self.run_case('login')
    def test_authentication_mode_change(self): self.run_case('mode')
    def test_same_name_changed_profile_import(self): self.run_case('import')
    def test_profile_removal(self): self.run_case('remove')
    def test_committed_save_hook_precedes_failed_adoption_outside_store_lock(self): self.run_case('adopt-failed')
    def test_failed_stale_save_does_not_request_cleanup(self): self.run_case('stale-save')
    def test_noop_does_not_request_cleanup(self): self.run_case('noop')
    def test_revoke_clears_candidate_held_through_private_key_prompt(self): self.run_case('capture-revoke')
    def test_new_verified_save_cleans_old_item_with_fresh_sessions(self): self.run_case('new-save')
    def test_unknown_add_never_deletes(self): self.run_case('unknown-add')
    def test_unknown_delete_stays_visible_and_cannot_retry(self): self.run_case('unknown-delete')
    def test_partial_cleanup_never_claims_all_removed(self): self.run_case('partial')
if __name__ == '__main__': unittest.main()
