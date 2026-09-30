"""One-attempt byte-only OpenVPN credential primitive checks."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNTransientCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-credential-build-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        sources = [ROOT / 'app/VPNConfiguration.swift',
                   ROOT / 'app/vpn-helper/VPNApplicationSpec.swift',
                   ROOT / 'app/vpn-helper/VPNTunnelStateStore.swift',
                   ROOT / 'app/vpn-helper/OpenVPNManagementEvent.swift',
                   ROOT / 'app/vpn-helper/OpenVPNStateEvidence.swift',
                   ROOT / 'app/vpn-helper/OpenVPNTransientCredential.swift',
                   ROOT / 'tests/vpn_transient_credential_checks.swift']
        result = subprocess.run([
            'swiftc', '-D', 'VPN_TRANSIENT_CREDENTIAL_TESTING',
            '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(cls.binary)
        ], capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, name, word):
        result = subprocess.run([str(self.binary), name], capture_output=True,
                                text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(word, result.stdout)

    def test_password_escaping_zeroization_and_replay(self): self.run_case('password', 'passed')
    def test_otp_is_code_only_and_static_challenge_fails(self): self.run_case('otp', 'passed')
    def test_private_key_passphrase_command(self): self.run_case('private-key', 'passed')
    def test_stale_and_application_mismatch_burn_attempt(self): self.run_case('mismatch', 'rejected')
    def test_empty_control_and_oversized_secret_rejected(self): self.run_case('bounds', 'rejected')
    def test_sink_failure_and_deinit_zeroize(self): self.run_case('failure', 'passed')

    def test_source_never_turns_secret_into_string_or_description(self):
        source = (ROOT / 'app/vpn-helper/OpenVPNTransientCredential.swift').read_text()
        self.assertNotIn('String(decoding:', source)
        self.assertNotIn('String(data:', source)
        self.assertNotIn('CustomStringConvertible', source)
        self.assertNotIn('print(', source)
        self.assertIn('memset_s', source)


if __name__ == '__main__':
    unittest.main()
