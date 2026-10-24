"""Credential-draft lifecycle using real adapter/controller and synthetic helper responses."""
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
class VPNPanelCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-panel-credential-build-')
        cls.addClassCleanup(cls.temp.cleanup)
        folder = Path(cls.temp.name)
        adapter = folder / 'VPNPanelModel.swift'
        # Compile the production adapter, without constructing any SwiftUI views.
        adapter.write_text((ROOT / 'app/VPNPanel.swift').read_text().split('\nstruct VPNPanelView:', 1)[0])
        sources = [ROOT / name for name in ('app/VPNConfiguration.swift', 'app/VPNProfileImporter.swift',
            'app/VPNStore.swift', 'app/VPNModel.swift', 'app/VPNPasswordRuntime.swift', 'app/VPNPasswordCleanupCoordinator.swift', 'app/VPNPasswordPersistenceCoordinator.swift', 'app/VPNLiveController.swift',
            'app/vpn-helper/VPNHelperProtocol.swift', 'app/vpn-helper/VPNApplicationSpec.swift',
            'app/vpn-helper/VPNTunnelStateStore.swift')]
        cls.binary = folder / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        built = subprocess.run(['swiftc', '-D', 'VPN_PANEL_TESTING', '-D', 'VPN_LIVE_CONTROLLER_TESTING',
            '-target', arch + '-apple-macosx11.0', *map(str, sources), str(adapter),
            str(ROOT / 'tests/vpn_panel_credentials_checks.swift'), '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=120)
        if built.returncode: raise AssertionError(built.stdout + built.stderr)

    def run_case(self, case):
        with tempfile.TemporaryDirectory(prefix='pp-panel-credential-') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), case, folder], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('credential presentation flow passed', result.stdout)

    def test_revoked_consent_keeps_cleanup_warning_visible_in_vpn_settings(self): self.run_case('cleanup-revoke')

    def test_cancel_and_next_attempt_clear_old_otp(self): self.run_case('cancel-new-attempt')
    def test_busy_buttons_do_not_discard_entered_draft(self): self.run_case('busy-preserves-draft')
    def test_stale_view_does_not_wipe_newer_prompt_draft(self): self.run_case('stale-view-does-not-wipe-new-prompt')
    def test_stale_submit_and_cancel_cannot_act_on_new_prompt(self): self.run_case('stale-actions')
    def test_same_prompt_refresh_keeps_current_draft(self): self.run_case('same-prompt-refresh')
    def test_new_request_of_same_kind_clears_old_otp(self): self.run_case('same-kind-new-request')
    def test_expired_prompt_is_rejected_on_exchange_and_clears_draft(self): self.run_case('prompt-disappeared')
    def test_unavailable_prompt_clears_draft(self): self.run_case('status-failed')
    def test_reconnect_clears_before_new_attempt(self): self.run_case('network-new-attempt')
    def test_hide_reopen_keeps_challenge_but_not_secret(self): self.run_case('hide-reopen')
    def test_password_persistence_consent_is_not_erased(self): self.run_case('password-consent')
    def test_submit_clears_field_and_completed_identity(self): self.run_case('submit')

    def test_save_feedback_uses_latest_phase_and_does_not_change_vpn_state(self):
        for scenario in ('saved', 'saving', 'unconfirmed', 'inert', 'revoke', 'disconnect', 'read-fallback'):
            with self.subTest(scenario=scenario): self.run_case('feedback-' + scenario)

    def test_explicit_save_choice_is_bound_to_login_and_only_changes_metadata(self):
        for scenario in ('opt-in', 'revoke', 'cancel', 'login', 'case', 'whitespace', 'otp', 'unavailable'):
            with self.subTest(scenario=scenario): self.run_case('consent-' + scenario)

    def test_save_authentication_preserves_only_the_same_normalized_binding(self):
        for scenario in ('unchanged', 'login', 'case', 'mode', 'invalid', 'default'):
            with self.subTest(scenario=scenario): self.run_case('auth-save-' + scenario)

    def test_finish_settings_preserves_only_the_same_normalized_binding(self):
        for scenario in ('unchanged', 'login', 'case', 'mode', 'invalid', 'default'):
            with self.subTest(scenario=scenario): self.run_case('auth-finish-' + scenario)

    def test_view_visibility_hooks_are_wired_source_contract(self):
        # Wiring only; this does not prove a native popover lifecycle or focus behavior.
        panel = (ROOT / 'app/VPNPanel.swift').read_text()
        credential_view = panel.split('private var credentialForm:', 1)[1].split('private var importScreen:', 1)[0]
        self.assertIn('.onDisappear { panel.dismissCredentialPrompt(ifMatching: displayedPrompt) }', credential_view)
        self.assertIn('.publisher(for: NSPopover.didCloseNotification)', panel)
        self.assertIn('panel.dismissCredentialPrompt()', panel.split('NSPopover.didCloseNotification', 1)[1].split('\n    }', 1)[0])

if __name__ == '__main__': unittest.main()
