"""Cleanup core: fake prepared workers and ordinary private Store files only."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNPasswordCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-cleanup-build-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        sources = [ROOT / 'app' / name for name in ('VPNConfiguration.swift', 'VPNProfileImporter.swift',
                                                    'VPNStore.swift', 'VPNPasswordCleanupCoordinator.swift')]
        result = subprocess.run(['swiftc', '-D', 'VPN_PASSWORD_CLEANUP_TESTING', '-target', arch + '-apple-macosx11.0', *map(str, sources),
                                 str(ROOT / 'tests/vpn_password_cleanup_checks.swift'), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=120)
        if result.returncode: raise AssertionError(result.stderr)

    def run_case(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'cleanup checks passed')

    def test_positive_delete_acknowledges_exact_queue_item(self): self.run_case('positive')
    def test_positive_ack_survives_brief_late_worker_store_contention(self): self.run_case('positive-busy')
    def test_positive_ack_observation_retry_is_bounded_without_another_go(self): self.run_case('positive-busy-held')
    def test_positive_observation_expired_before_retry_does_not_ack_or_repeat_go(self): self.run_case('positive-expire')
    def test_positive_observation_oversleep_cannot_reset_budget_or_repeat_go(self): self.run_case('positive-oversleep')
    def test_post_positive_malformed_store_is_not_retried_as_busy(self): self.run_case('positive-malformed')
    def test_not_found_retains_obligation(self): self.run_case('not-found')
    def test_known_unavailable_retains_obligation(self): self.run_case('known-unavailable')
    def test_indeterminate_is_never_reissued_in_process(self): self.run_case('indeterminate')
    def test_first_unknown_stops_pass_but_later_explicit_request_handles_other_ref(self): self.run_case('stop-unknown')
    def test_first_unknown_throw_stops_pass(self): self.run_case('stop-throw')
    def test_positive_ack_ambiguity_stops_pass(self): self.run_case('stop-ack')
    def test_busy_store_retains_metadata_without_automatic_retry(self): self.run_case('store-busy')
    def test_recreating_coordinator_cannot_retry_unknown_ref_in_process(self): self.run_case('recreated')
    def test_throw_after_possible_go_is_never_reissued(self): self.run_case('throw')
    def test_positive_result_without_store_ack_is_not_accepted(self): self.run_case('false-positive')
    def test_missing_queue_after_throw_is_not_a_positive_receipt(self): self.run_case('post-delete-throw')
    def test_profile_removal_still_allows_exact_queued_item_cleanup(self): self.run_case('profile-removed')
    def test_mixed_refs_preserve_new_active_and_skip_unknown_adds(self): self.run_case('mixed')
    def test_unknown_add_has_zero_driver_calls(self): self.run_case('pending')
    def test_no_item_and_not_issued_retire_without_driver(self): self.run_case('no-io')
    def test_failed_preparation_retains_metadata(self): self.run_case('prepare-throw')
    def test_unavailable_preparation_retains_metadata(self): self.run_case('prepare-nil')
    def test_locator_changed_during_preparation_never_reaches_worker(self): self.run_case('changed-locator')
    def test_prestart_requests_coalesce_without_retrying_retained_refs(self): self.run_case('coalesced-same')
    def test_concurrent_request_processes_only_new_refs_once(self): self.run_case('coalesced-new')
    def test_quarantine_limit_never_evicts_unknown_history(self): self.run_case('bounds')
    def test_oversized_stored_queue_fails_closed(self): self.run_case('malformed-bounds')
    def test_default_unavailable_does_not_schedule_or_prepare(self): self.run_case('unavailable')


if __name__ == '__main__': unittest.main()
