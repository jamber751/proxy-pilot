"""Synthetic-key rescue codec only: no production key, root or installer access."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNRescueAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = tempfile.TemporaryDirectory(prefix='pp-rescue-auth-')
        cls.addClassCleanup(build.cleanup)
        directory = Path(build.name)
        sources = [ROOT / 'app/vpn-helper' / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNRescueAuthorization.swift')]
        sources.append(ROOT / 'tests/vpn_rescue_authorization_checks.swift')
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = directory / arch
            result = subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0',
                                     *map(str, sources), '-o', str(output)],
                                    capture_output=True, text=True, timeout=90)
            if result.returncode:
                raise AssertionError(result.stderr)
            slices.append(str(output))
        cls.binary = directory / 'checks'
        subprocess.run(['lipo', '-create', *slices, '-output', str(cls.binary)], check=True,
                       capture_output=True, timeout=10)

    def check(self, group):
        result = subprocess.run([str(self.binary), group], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('checks passed', result.stdout)

    def test_canonical_roundtrip_and_exact_identity(self): self.check('valid')
    def test_mutation_wrong_key_and_signature_lengths(self): self.check('signatures')
    def test_release_transition_and_rescue_signature_domains_are_separate(self): self.check('domain')
    def test_noncanonical_records_and_wrong_operation_are_rejected(self): self.check('grammar')
    def test_strict_numbers_hashes_and_architecture_fields(self): self.check('fields')
    def test_exact_signed_endpoint_and_transition_binding(self): self.check('edges')
    def test_bounded_authorization_and_artifact_sizes(self): self.check('limits')
    def test_artifact_bytes_and_length_are_exact(self): self.check('artifact')
    def test_existing_authority_and_floor_are_enforced(self): self.check('authority')
    def test_unsigned_encoder_rejects_invalid_inputs(self): self.check('encoder')


if __name__ == '__main__':
    unittest.main()
