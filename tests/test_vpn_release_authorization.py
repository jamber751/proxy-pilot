"""Real Ed25519 verification with ephemeral keys; no signing key or installer access."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNReleaseAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='proxypilot-vpn-release-')
        cls.addClassCleanup(cls.build.cleanup)
        directory = Path(cls.build.name)
        sources = [ROOT / 'app/vpn-helper/VPNPeerAuthentication.swift',
                   ROOT / 'app/vpn-helper/VPNReleaseAuthorization.swift',
                   ROOT / 'tests/vpn_release_checks.swift']
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = directory / arch
            result = subprocess.run(['swiftc', '-D', 'VPN_ENGINE_DELIVERY_TESTING', '-target', f'{arch}-apple-macosx11.0',
                                     *map(str, sources), '-o', str(output)],
                                    capture_output=True, text=True, timeout=90)
            if result.returncode:
                raise AssertionError(result.stderr)
            slices.append(str(output))
        cls.binary = directory / 'release-checks'
        subprocess.run(['lipo', '-create', *slices, '-output', str(cls.binary)],
                       check=True, capture_output=True, timeout=10)
        subprocess.run(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                        '--identifier', 'kz.documentolog.proxypilot.release-checks', str(cls.binary)],
                       check=True, capture_output=True, timeout=10)

    def check(self, group):
        result = subprocess.run([str(self.binary), group], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('checks passed', result.stdout)

    def test_valid_release_and_owner_policy(self): self.check('valid')
    def test_bad_signatures_keys_and_tampering(self): self.check('signatures')
    def test_cross_protocol_signature_reuse(self): self.check('domain')
    def test_canonical_format_and_duplicate_fields(self): self.check('grammar')
    def test_malformed_values_and_overflows(self): self.check('fields')
    def test_bounded_input(self): self.check('limits')
    def test_incompatible_protocol(self): self.check('protocol')
    def test_embedded_minimum_sequence(self): self.check('floor')
    def test_upgrade_retry_and_rollback(self): self.check('transitions')
    def test_sequence_cannot_be_reused_for_different_release(self): self.check('conflict')
    def test_previous_release_must_have_same_authority(self): self.check('authority')
    def test_exact_helper_artifact_bytes(self): self.check('artifact')
    def test_invalid_trust_configuration(self): self.check('trust')
    def test_engine_candidate_binds_separate_component_identity(self): self.check('engine-valid')
    def test_production_authority_requires_complete_engine_set(self): self.check('engine-production')
    def test_engine_format_is_exact_and_has_no_executable_paths(self): self.check('engine-grammar')
    def test_engine_values_and_limits(self): self.check('engine-fields')
    def test_engine_bytes_and_manifest_tampering(self): self.check('engine-tamper')
    def test_engine_upgrade_retry_and_component_rollback(self): self.check('engine-transitions')
    def test_engine_changes_require_new_sequence(self): self.check('engine-conflict')
    def test_engine_requires_release_authority_and_signature_domain(self): self.check('engine-domain')
