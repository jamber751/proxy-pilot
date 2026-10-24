"""Read-only exact pending-journal gate in unprivileged temporary storage."""
import json
import shutil
import subprocess
import sys
import unittest

import test_vpn_update_journal as journal


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNRescueJournalContextTests(unittest.TestCase):
    cmd = staticmethod(journal.VPNUpdateJournalTests.cmd)
    run_journal = journal.VPNUpdateJournalTests.run_journal
    prepare = journal.VPNUpdateJournalTests.prepare

    @classmethod
    def setUpClass(cls):
        journal.VPNUpdateJournalTests.setUpClass.__func__(cls)
        cls.context_binary = cls.work / 'rescue-context'
        sources = [journal.ROOT / 'app/vpn-helper' / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperArtifact.swift',
            'VPNReleaseStore.swift', 'VPNLifecycleOwnership.swift', 'VPNRescueAuthorization.swift',
            'VPNRescueJournalContext.swift')]
        cls.cmd(['swiftc', *map(str, sources),
                 str(journal.ROOT / 'tests/vpn_rescue_journal_context_checks.swift'), '-o', str(cls.context_binary)])

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

    def test_pending_source_selected_context_is_readonly(self):
        self.pending(); self.check(accepted=True)

    def test_missing_journal_is_rejected(self): self.check()

    def test_prepared_is_rejected(self): self.prepare(); self.check()

    def test_cancelled_is_rejected(self):
        tid = self.prepare(); self.run_journal('cancel', tid=tid, rev=0, ok=True); self.check()

    def test_selected_is_rejected(self):
        tid = self.pending(); self.run_journal('select', tid=tid, rev=1, ok=True); self.check()

    def test_completed_is_rejected(self):
        tid = self.pending()
        self.run_journal('select', tid=tid, rev=1, ok=True)
        self.run_journal('complete', tid=tid, rev=2, ok=True)
        self.check()

    def test_wrong_signed_edge_is_rejected(self): self.pending(); self.check('wrong-edge')

    def test_different_directory_lease_is_rejected(self):
        self.pending()
        self.assertIn('mismatchedStorage', self.check('foreign-lease').stdout)

    def test_expired_lease_before_capture_is_rejected(self): self.pending(); self.check('released-before')
    def test_missing_store_lock_is_not_recreated(self): self.pending(); self.check('missing-store-lock')
    def test_runtime_lease_cannot_replace_lifecycle_lease(self): self.pending(); self.check('runtime-lease')
    def test_expired_lease_after_capture_is_rejected(self): self.pending(); self.check('release-after')
    def test_rebound_lease_after_capture_is_rejected(self): self.pending(); self.check('replace-lease')
    def test_new_transaction_with_same_edge_is_rejected(self): self.pending(); self.check('new-transaction')
    def test_stale_revision_is_rejected(self): self.pending(); self.check('new-revision')
    def test_owner_change_is_rejected(self): self.pending(); self.check('new-owner')
    def test_selection_change_is_rejected(self): self.pending(); self.check('select-after')
    def test_deleted_journal_is_rejected(self): self.pending(); self.check('delete-journal')
    def test_unsafe_storage_after_capture_is_rejected(self): self.pending(); self.check('unsafe-directory')

    def test_invalid_or_inconsistent_owner_is_rejected(self):
        self.pending()
        path = self.dir / 'update.json'
        original = json.loads(path.read_text())
        for owner in (0, 499, 2**32 - 1, 502):
            with self.subTest(owner=owner):
                record = dict(original); record['owner'] = owner
                path.write_text(json.dumps(record)); path.chmod(0o600)
                self.check()


if __name__ == '__main__':
    unittest.main()
