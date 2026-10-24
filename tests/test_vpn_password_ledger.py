"""Real user-store transactions and injected silent callbacks; no password backend."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNPasswordLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-password-ledger-build-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        sources = [ROOT / 'app' / name for name in
                   ('VPNConfiguration.swift', 'VPNProfileImporter.swift', 'VPNStore.swift')]
        result = subprocess.run(['swiftc', '-D', 'VPN_PASSWORD_LEDGER_TESTING', '-target', arch + '-apple-macosx11.0',
                                 *map(str, sources), str(ROOT / 'tests/vpn_password_ledger_checks.swift'),
                                 '-o', str(cls.binary)], capture_output=True, text=True, timeout=120)
        if result.returncode: raise AssertionError(result.stderr)

    def run_case(self, case, folder=None, expected=0):
        if folder is None:
            with tempfile.TemporaryDirectory(prefix='pp-password-ledger-') as temporary:
                return self.run_case(case, temporary, expected)
        os.chmod(folder, 0o700)
        result = subprocess.run([str(self.binary), case, str(folder)], capture_output=True,
                                text=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        if expected == 0: self.assertIn('ledger checks passed', result.stdout)

    def test_authenticated_add_receipt_is_exact_idempotent_and_never_recreates_missing_ref(self): self.run_case('receipt-add')
    def test_authenticated_no_io_receipt_requires_pending_and_exact_terminal_match(self): self.run_case('receipt-noio')
    def test_only_real_receipt_lock_busy_is_retryable_not_postrename_error(self): self.run_case('receipt-lock')
    def test_positive_delete_receipt_cannot_drop_changed_locator(self): self.run_case('receipt-delete-changed')
    def test_positive_delete_cannot_treat_same_uuid_different_scope_as_absence(self): self.run_case('receipt-delete-scope')
    def test_explicit_grant_and_exact_binding(self): self.run_case('grant')
    def test_revocation_survives_restart_and_denied_delete(self): self.run_case('revoke')
    def test_regrant_same_binding_cannot_be_deleted_by_old_reference(self): self.run_case('regrant')
    def test_stale_write_and_forged_reference_never_call_backend(self): self.run_case('stale')
    def test_login_and_mode_changes_revoke(self): self.run_case('identity')
    def test_profile_replace_and_remove_queue_old_binding(self): self.run_case('profile')
    def test_acknowledgements_preserve_ledger_and_applied_never_grants(self): self.run_case('ack')
    def test_locked_callback_prevents_competing_process_store_update(self): self.run_case('lock')
    def test_schema1_and_2_migration_and_malformed_state_fail_closed(self): self.run_case('schema')
    def test_schema3_every_write_state_migrates_to_unknown(self): self.run_case('schema3')
    def test_locator_bounds_and_redacted_descriptions(self): self.run_case('locator')
    def test_invalid_or_replayed_completion_does_not_settle_unknown_add(self): self.run_case('invalid-completion')
    def test_definitely_no_io_is_unreadable_and_retires_without_backend(self): self.run_case('no-item')
    def test_late_no_io_completion_only_retires_old_queued_reference(self): self.run_case('late-no-io')
    def test_delete_not_found_and_unavailable_retain_exact_locator(self): self.run_case('delete-outcomes')
    def test_malformed_state_locator_combinations_and_8mb_limit(self): self.run_case('malformed-slot')
    def test_completion_error_after_atomic_rename_preserves_valid_locator(self): self.run_case('rename-error')
    def test_full_queue_rejects_without_losing_obligations(self): self.run_case('capacity')
    def test_callback_errors_do_not_lose_durable_state(self): self.run_case('errors')
    def test_one_add_per_uuid_and_fresh_save_rejects_stale_editor(self): self.run_case('once')
    def test_unknown_add_retains_obligation_until_exact_definite_receipt(self): self.run_case('unknown')
    def test_late_definite_receipt_resolves_active_after_resource_revision(self): self.run_case('late-active')
    def test_unissued_grant_retirement_never_calls_backend(self): self.run_case('unissued')
    def test_pending_directory_sync_error_never_dispatches_add(self): self.run_case('pending-sync')

    def test_process_exit_after_pending_before_add_stays_unknown(self):
        with tempfile.TemporaryDirectory(prefix='pp-password-ledger-') as folder:
            self.run_case('prepare-add-crash', folder)
            self.run_case('add-crash', folder, expected=43)
            self.run_case('resume-add-crash', folder)

    def test_process_exit_after_delete_before_ack_keeps_not_found_pending(self):
        with tempfile.TemporaryDirectory(prefix='pp-password-ledger-') as folder:
            self.run_case('prepare-crash', folder)
            self.run_case('delete-crash', folder, expected=42)
            self.run_case('resume-crash', folder)


if __name__ == '__main__': unittest.main()
