"""Exact-prompt, one-shot held OpenVPN credential exchange checks."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNHeldCredentialExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-held-credential-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        sources = [ROOT / 'app/VPNConfiguration.swift',
                   ROOT / 'app/vpn-helper/VPNApplicationSpec.swift',
                   ROOT / 'app/vpn-helper/VPNTunnelStateStore.swift',
                   ROOT / 'app/vpn-helper/OpenVPNManagementEvent.swift',
                   ROOT / 'app/vpn-helper/OpenVPNStateEvidence.swift',
                   ROOT / 'app/vpn-helper/OpenVPNTransientCredential.swift',
                   ROOT / 'app/vpn-helper/OpenVPNHeldCredentialExchange.swift',
                   ROOT / 'tests/vpn_held_credential_exchange_checks.swift']
        result = subprocess.run([
            'swiftc', '-D', 'VPN_TRANSIENT_CREDENTIAL_TESTING',
            '-D', 'VPN_HELD_CREDENTIAL_EXCHANGE_TESTING',
            '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(cls.binary)
        ], capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, name, word):
        result = subprocess.run([str(self.binary), name], capture_output=True,
                                text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(word, result.stdout)

    def test_password_is_bound_to_observed_prompt(self): self.run_case('password', 'passed')
    def test_private_key_challenge(self): self.run_case('private-key', 'passed')
    def test_otp_code_only_challenge(self): self.run_case('otp', 'passed')
    def test_secret_before_prompt_is_burned(self): self.run_case('no-prompt', 'rejected')
    def test_wrong_prompt_closes_exchange(self): self.run_case('mismatch', 'rejected')
    def test_duplicate_prompt_closes_exchange(self): self.run_case('duplicate', 'rejected')
    def test_transport_failure_is_terminal(self): self.run_case('transport-failure', 'passed')
    def test_combined_static_challenge_is_not_guessed(self): self.run_case('otp-policy', 'passed')
    def test_engine_rejection_aborts_transport(self): self.run_case('rejection', 'passed')

    def test_exchange_has_no_hold_release_or_persistence_surface(self):
        source = (ROOT / 'app/vpn-helper/OpenVPNHeldCredentialExchange.swift').read_text()
        self.assertNotIn('releaseHold', source)
        self.assertNotIn('String(data:', source)
        self.assertNotIn('String(decoding:', source)
        self.assertNotIn('UserDefaults', source)
        self.assertNotIn('write(to:', source)
        self.assertNotIn('print(', source)


if __name__ == '__main__':
    unittest.main()
