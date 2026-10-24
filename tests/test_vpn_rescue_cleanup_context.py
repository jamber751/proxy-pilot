"""Read-only cleanup receipt binding; no host root or installed application work."""
import json
import shutil
import subprocess
import sys
import unittest

import test_vpn_update_journal as journal


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNRescueCleanupContextTests(unittest.TestCase):
    cmd = staticmethod(journal.VPNUpdateJournalTests.cmd)
    run_journal = journal.VPNUpdateJournalTests.run_journal
    prepare = journal.VPNUpdateJournalTests.prepare

    @classmethod
    def setUpClass(cls):
        journal.VPNUpdateJournalTests.setUpClass.__func__(cls)
        cls.context_binary = cls.work / 'rescue-cleanup-context'
        sources = [journal.ROOT / 'app/vpn-helper' / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperArtifact.swift',
            'VPNReleaseStore.swift', 'VPNLifecycleOwnership.swift', 'VPNRescueAuthorization.swift',
            'VPNRescueCleanupContext.swift')]
        cls.cmd(['swiftc', *map(str, sources),
                 str(journal.ROOT / 'tests/vpn_rescue_cleanup_context_checks.swift'), '-o', str(cls.context_binary)])

    def setUp(self):
        journal.VPNUpdateJournalTests.setUp(self)
        self.source_selection = (self.dir / 'release.json').read_bytes()
        self.other = self.dir.parent / 'other'; self.other.mkdir(mode=0o700)
        (self.dir / 'lifecycle.lock').touch(mode=0o600)

    def receipt(self):
        tid = self.prepare()
        self.prepared = (self.dir / 'update.json').read_bytes()
        self.run_journal('pending', tid=tid, rev=0, ok=True)
        self.pending = (self.dir / 'update.json').read_bytes()
        self.run_journal('select', tid=tid, rev=1, ok=True)
        self.run_journal('complete', tid=tid, rev=2, ok=True)
        self.run_journal('retire', tid=tid, rev=3, ok=True)
        return tid

    def write(self, name, value):
        path = self.dir / name
        # Match the store's canonical JSONEncoder representation so rejection
        # exercises semantic checks, rather than incidental whitespace.
        path.write_bytes(value if isinstance(value, bytes) else
                         json.dumps(value, sort_keys=True, separators=(',', ':')).replace('/', '\\/').encode())
        path.chmod(0o600)

    def check(self, operation='capture', accepted=False):
        result = subprocess.run([str(self.context_binary), operation, str(self.dir), str(self.other),
                                 str(self.man[0]), str(self.man[1]), str(self.helpers[1]), str(self.helpers[2])],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0 if accepted else 77, result.stdout + result.stderr)
        self.assertIn('validated' if accepted else 'rejected:', result.stdout)
        return result

    def test_valid_receipt_is_readonly(self): self.receipt(); self.check(accepted=True)
    def test_valid_later_phase_can_be_captured(self):
        tid = self.receipt()
        self.run_journal('cleanup-app', tid=tid, ok=True)
        self.run_journal('cleanup-update', tid=tid, ok=True)
        self.check(accepted=True)
    def test_unsigned_receipt_edge_tampering_rejected(self):
        self.receipt()
        record = json.loads((self.dir / 'cleanup.json').read_bytes())
        record['journal']['transitionSignature'] = 'AA=='
        self.write('cleanup.json', record); self.check()
    def test_no_receipt_requires_separate_completion_proof(self):
        self.receipt(); (self.dir / 'cleanup.json').unlink()
        self.assertIn('needsSeparateCompletionProof', self.check().stdout)
    def test_source_selected_rejected(self):
        self.receipt(); self.write('release.json', self.source_selection); self.check()
    def test_prepared_journal_rejected(self):
        self.receipt(); self.write('update.json', self.prepared); self.check()
    def test_pending_journal_rejected(self):
        self.receipt(); self.write('update.json', self.pending); self.check()
    def test_preparation_rejected(self):
        self.receipt()
        record = json.loads(self.prepared)
        record.pop('revision'); record['phase'] = 'staging'
        self.write('preparation.json', record); self.check()
    def test_wrong_edge(self): self.receipt(); self.check('wrong-edge')
    def test_foreign_lease(self): self.receipt(); self.check('foreign-lease')
    def test_expired_lease_before(self): self.receipt(); self.check('released-before')
    def test_expired_lease_after(self): self.receipt(); self.check('release-after')
    def test_replaced_lease(self): self.receipt(); self.check('replace-lease')
    def test_runtime_lease(self): self.receipt(); self.check('runtime-lease')
    def test_missing_lock_not_created(self): self.receipt(); self.check('missing-store-lock')
    def test_new_uuid(self): self.receipt(); self.check('new-transaction')
    def test_new_revision(self): self.receipt(); self.check('new-revision')
    def test_new_common_owner(self): self.receipt(); self.check('new-owner')
    def test_new_terminal_phase(self): self.receipt(); self.check('terminal-phase')
    def test_phase_advance_invalidates_context(self): self.receipt(); self.check('advance-phase')
    def test_phase_advance_requires_recapture(self): self.receipt(); self.check('advance-recapture', accepted=True)
    def test_receipt_disappears(self): self.receipt(); self.check('delete-receipt')
    def test_directory_becomes_unsafe(self): self.receipt(); self.check('unsafe-directory')
    def test_gc_roots_bound_to_context(self):
        self.receipt()
        record = json.loads((self.dir / 'cleanup.json').read_bytes())
        record['phase'] = 'gcAuthorized'
        record['gcRoots'] = [dict(name=name, device=1, inode=i + 1) for i, name in
                             enumerate(['application', 'candidate', 'current', 'executor'])]
        self.write('cleanup.json', record)
        self.check(accepted=True); self.check('new-roots')
    def test_invalid_or_inconsistent_owner(self):
        self.receipt()
        record = json.loads((self.dir / 'cleanup.json').read_bytes())
        for owner in (0, 499, 2**32 - 1, 502):
            with self.subTest(owner=owner):
                record['journal']['owner'] = owner
                self.write('cleanup.json', record); self.check()


if __name__ == '__main__':
    unittest.main()
