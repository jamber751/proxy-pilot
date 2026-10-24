"""Read-only exact selected-source preparation gate in unprivileged temporary storage."""
import json
import shutil
import subprocess
import sys
import unittest

import test_vpn_update_journal as journal


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNRescuePreparationContextTests(unittest.TestCase):
    cmd = staticmethod(journal.VPNUpdateJournalTests.cmd)
    run_journal = journal.VPNUpdateJournalTests.run_journal
    prepare = journal.VPNUpdateJournalTests.prepare

    @classmethod
    def setUpClass(cls):
        journal.VPNUpdateJournalTests.setUpClass.__func__(cls)
        cls.context_binary = cls.work / 'rescue-context'
        sources = [journal.ROOT / 'app/vpn-helper' / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperArtifact.swift',
            'VPNReleaseStore.swift', 'VPNLifecycleOwnership.swift', 'VPNRescuePreparationAuthorization.swift',
            'VPNRescuePreparationContext.swift')]
        cls.cmd(['swiftc', *map(str, sources),
                 str(journal.ROOT / 'tests/vpn_rescue_preparation_context_checks.swift'), '-o', str(cls.context_binary)])

    def setUp(self):
        journal.VPNUpdateJournalTests.setUp(self)
        self.other = self.dir.parent / 'other'; self.other.mkdir(mode=0o700)
        (self.dir / 'lifecycle.lock').touch(mode=0o600)

    def pending(self):
        tid = self.prepare()
        self.run_journal('pending', tid=tid, rev=0, ok=True)
        return tid

    def check(self, operation='capture', accepted=False):
        result = subprocess.run([str(self.context_binary), operation, str(self.dir), str(self.other),
                                 str(self.man[0]), str(self.man[1]), str(self.helpers[1]), str(self.helpers[2])],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0 if accepted else 77, result.stdout + result.stderr)
        self.assertIn('validated' if accepted else 'rejected:', result.stdout)
        return result

    def test_clean_selected_source_is_readonly(self):
        self.assertEqual(self.check(accepted=True).stdout.strip(), 'validated:clean')
    def test_matching_staging_is_readonly(self):
        self.assertEqual(self.check('staging', accepted=True).stdout.strip(), 'validated:staging')
    def test_matching_prepared_is_readonly(self):
        self.prepare()
        self.assertEqual(self.check(accepted=True).stdout.strip(), 'validated:prepared')
    def test_exact_conversion_window_is_readonly(self):
        self.assertEqual(self.check('conversion', accepted=True).stdout.strip(), 'validated:conversionPending')
    def test_mismatched_conversion_uuid_is_refused(self): self.check('conversion-mismatched-id')
    def test_foreign_preparation_owner_is_refused(self): self.check('staging-foreign-owner')
    def test_gc_preparation_is_refused(self): self.check('staging-gc')
    def test_pending_requires_separate_context(self): self.pending(); self.check()
    def test_cancelled_is_refused(self):
        tid = self.prepare(); self.run_journal('cancel', tid=tid, rev=0, ok=True); self.check()
    def test_selected_is_refused(self):
        tid = self.pending(); self.run_journal('select', tid=tid, rev=1, ok=True); self.check()
    def test_receipt_is_not_clean_state(self):
        tid = self.pending(); self.run_journal('select', tid=tid, rev=1, ok=True)
        self.run_journal('complete', tid=tid, rev=2, ok=True)
        self.run_journal('retire', tid=tid, rev=3, ok=True); self.check()
    def test_foreign_signed_edge_is_refused(self): self.prepare(); self.check('wrong-edge')
    def test_wrong_store_lease_is_refused(self): self.check('foreign-lease')
    def test_runtime_lease_is_refused(self): self.check('runtime-lease')
    def test_released_lease_is_refused(self): self.check('released-before')
    def test_expired_context_is_refused(self): self.check('release-after')
    def test_replaced_lease_is_refused(self): self.check('replace-lease')
    def test_missing_store_lock_not_created(self): self.check('missing-store-lock')
    def test_clean_to_staging_invalidates_context(self): self.check('advance-clean')
    def test_staging_uuid_change_invalidates_context(self): self.check('staging-new-id')
    def test_staging_removal_invalidates_context(self): self.check('staging-delete')
    def test_conversion_completion_invalidates_context(self): self.check('conversion-finish')
    def test_conversion_uuid_change_invalidates_context(self): self.check('conversion-new-id')
    def test_prepared_removal_invalidates_context(self): self.prepare(); self.check('delete-journal')
    def test_prepared_revision_change_invalidates_context(self): self.prepare(); self.check('new-revision')
    def test_prepared_uuid_change_invalidates_context(self): self.prepare(); self.check('new-transaction')
    def test_owner_change_invalidates_context(self): self.prepare(); self.check('new-owner')
    def test_prepared_to_pending_invalidates_context(self): self.prepare(); self.check('select-after')
    def test_storage_mode_change_invalidates_context(self): self.check('unsafe-directory')

if __name__ == '__main__':
    unittest.main()
