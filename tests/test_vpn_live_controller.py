"""One-button frontend orchestration against an in-memory helper session."""
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
class VPNLiveControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-live-controller-build-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        sources = [ROOT / 'app/VPNConfiguration.swift', ROOT / 'app/VPNProfileImporter.swift',
            ROOT / 'app/VPNStore.swift', ROOT / 'app/vpn-helper/VPNHelperProtocol.swift',
            ROOT / 'app/vpn-helper/VPNApplicationSpec.swift',
            ROOT / 'app/vpn-helper/VPNTunnelStateStore.swift',
            ROOT / 'app/VPNPasswordPersistenceCoordinator.swift', ROOT / 'app/VPNLiveController.swift', ROOT / 'tests/vpn_live_controller_checks.swift']
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run(['swiftc', '-D', 'VPN_LIVE_CONTROLLER_TESTING', '-D', 'VPN_PASSWORD_LEDGER_TESTING',
            '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, name):
        with tempfile.TemporaryDirectory(prefix='pp-live-controller-', dir='/tmp') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), name, folder], capture_output=True,
                                    text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('flow passed', result.stdout)

    def test_certificate_one_button_connect(self): self.run_case('certificate')
    def test_password_or_otp_prompt_and_secret_wipe(self): self.run_case('credential')
    def test_sequential_prompts_keep_session_and_wipe_each_secret(self):
        self.run_case('multi-credential')
    def test_cancel_persists_off(self): self.run_case('cancel')
    def test_disconnect_proves_cleanup_before_persisting_off(self): self.run_case('disconnect')
    def test_domain_intent_never_opens_helper(self): self.run_case('unsupported')

    def test_manual_save_is_bound_to_verified_connection_and_not_helper_inout_buffer(self): self.run_case('cache-manual')
    def test_manual_candidate_survives_exact_private_key_sequence(self): self.run_case('cache-private-sequence')
    def test_private_key_prompt_from_different_attempt_wipes_candidate(self): self.run_case('cache-private-attempt-changed')
    def test_helper_expiry_on_private_key_exchange_wipes_candidate(self): self.run_case('cache-private-expired')
    def test_hide_reopen_preserves_owned_prompt_and_exact_eight_request_flow(self): self.run_case('held-refresh')
    def test_new_vpn_password_prompt_replaces_candidate(self): self.run_case('cache-new-vpn')
    def test_cancel_wipes_candidate(self): self.run_case('cache-cancel-candidate')
    def test_new_session_wipes_candidate(self): self.run_case('cache-reconnect')
    def test_otp_never_calls_cache(self): self.run_case('cache-otp')
    def test_private_key_never_calls_cache(self): self.run_case('cache-key-only')
    def test_unavailable_default_does_not_capture_or_prepare(self): self.run_case('cache-inert')
    def test_cache_add_unknown_keeps_connected_vpn_and_pending_obligation(self): self.run_case('cache-add-unknown')
    def test_wrong_attempt_cannot_save(self): self.run_case('cache-bad-attempt')
    def test_unproven_routes_cannot_save(self): self.run_case('cache-unproven')
    def test_failed_helper_cannot_save(self): self.run_case('cache-failed')
    def test_stale_prompt_cannot_submit(self): self.run_case('cache-stale-prompt')
    def test_cached_success_never_adds_again(self): self.run_case('cache-auto')
    def test_failed_cached_submission_is_suppressed_on_reconnect_for_manual_recovery(self): self.run_case('cache-auto-failed')
    def test_cached_failure_falls_back_to_manual(self): self.run_case('cache-read-fallback')
    def test_cached_credential_retried_at_most_once_per_attempt(self): self.run_case('cache-auto-reprompt')
    def test_revocation_after_cache_read_discards_result(self): self.run_case('cache-read-revoked')
    def test_new_verified_save_precedes_old_claimed_add_and_stale_callback_is_refused(self): self.run_case('cache-claim-new-first')
    def test_old_claimed_add_then_new_verified_save_keeps_new_password_and_old_obligation(self): self.run_case('cache-claim-old-first')
    def test_new_connection_invalidates_older_queued_password(self): self.run_case('cache-queued-replaced')
    def test_disconnect_invalidates_queued_password(self): self.run_case('cache-queued-disconnect')
    def test_worker_prepare_holds_neither_store_nor_cancellation_lock(self): self.run_case('cache-prepare-cancel')
    def test_queued_save_revalidates_fresh_store(self):
        for change in ('revoke', 'login', 'mode', 'profile', 'grant'):
            with self.subTest(change=change): self.run_case('cache-stale-' + change)

    def test_feedback_saved_requires_positive_add_and_store_ack(self): self.run_case('feedback-saved')
    def test_feedback_positive_ack_tolerates_brief_late_store_lock(self): self.run_case('feedback-saved-busy')
    def test_feedback_prepare_nil_is_confirmation_without_vpn_failure(self): self.run_case('feedback-prepare-nil')
    def test_feedback_superseded_during_prepare_invalidates_old_saving_event(self): self.run_case('feedback-prepare-superseded')
    def test_feedback_prepare_throw_is_confirmation_without_vpn_failure(self): self.run_case('feedback-prepare-throw')
    def test_feedback_unknown_add_is_confirmation_without_vpn_failure(self): self.run_case('feedback-unknown')
    def test_feedback_known_no_io_needs_confirmation(self): self.run_case('feedback-no-io')
    def test_feedback_postrename_ack_failure_is_not_inferred_saved(self): self.run_case('feedback-ack-failed')
    def test_feedback_capture_failure_keeps_no_secret_and_waits_for_connected(self): self.run_case('feedback-capture-failed')
    def test_feedback_empty_marker_survives_private_key_without_saving_key(self): self.run_case('feedback-capture-private')
    def test_feedback_empty_marker_is_quiet_after_user_revokes_consent(self): self.run_case('feedback-capture-revoked')
    def test_feedback_unproven_capture_failure_emits_nothing(self): self.run_case('feedback-capture-unproven')
    def test_feedback_cache_read_failure_offers_manual_confirmation(self): self.run_case('feedback-read-failed')
    def test_feedback_cache_read_success_never_adds_or_invents_saved_event(self): self.run_case('feedback-read-success')
    def test_feedback_revoked_cache_read_is_quiet(self): self.run_case('feedback-read-revoked')
    def test_feedback_revoked_queued_save_is_quiet(self): self.run_case('feedback-stale-revoke')
    def test_feedback_changed_revision_queued_save_is_quiet(self): self.run_case('feedback-stale-revision')
    def test_feedback_new_input_supersedes_older_queued_events(self): self.run_case('feedback-stale-input')
    def test_feedback_ui_guard_rejects_old_phase_old_intent_and_revoked_consent(self): self.run_case('feedback-stale-delivery')
    def test_feedback_ineligible_or_inert_credential_has_zero_events(self):
        for mode in ('feedback-inert', 'feedback-otp', 'feedback-private-key'):
            with self.subTest(mode=mode): self.run_case(mode)


if __name__ == '__main__':
    unittest.main()
