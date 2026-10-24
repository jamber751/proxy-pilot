"""Two exact roles on one real live rescue; disposable root VM execution only."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
import test_vpn_rescue_executor as identity

ROOT, HELPER = identity.ROOT, identity.HELPER

@unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() == 0
                     and os.environ.get('PROXYPILOT_VM_ROOT_TESTS') == '1',
                     'explicit disposable macOS root VM fixture')
class VPNRescuePreparationExecutorRootTests(identity.RescueBuild, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='pp-rescue-identity-build-', dir='/tmp')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.build = Path(cls.temporary.name)
        sources = [HELPER / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
            'VPNRescueAuthorization.swift', 'VPNRescuePreparationAuthorization.swift',
            'VPNHelperArtifact.swift', 'VPNRescueExecutor.swift', 'VPNRescuePreparationExecutor.swift')]
        sources.append(ROOT / 'tests/vpn_rescue_preparation_executor_checks.swift')
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.build / arch
            cls.command(['swiftc', '-D', 'VPN_RESCUE_EXECUTOR_TESTING', '-D', 'VPN_RESCUE_PREPARATION', '-target',
                         arch + '-apple-macosx11.0', *map(str, sources), '-o', str(output)])
            slices.append(str(output))
        cls.binary = cls.build / 'checks'
        cls.command(['lipo', '-create', *slices, '-output', str(cls.binary)])
        cls.binary.chmod(0o700)
        cls.sign(cls.binary)
        cls.code_hashes = cls.pins(cls.binary)

    def run_live(self, operation='live', expected=77):
        result = self.invoke(operation, runner=self.artifact)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_same_live_bytes_prove_both_roles(self):
        self.assertEqual(self.run_live(expected=0).stdout.strip(), 'live-start-and-finish')

    def test_another_copy_is_not_the_live_executor(self):
        result = self.invoke('live')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn('wrongProcess', result.stdout)

    def test_start_digest_must_match_actual_live_bytes(self): self.run_live('wrong-sha')
    def test_start_size_must_match_actual_live_bytes(self): self.run_live('wrong-size')
    def test_start_arm_hash_must_match_actual_live_signature(self): self.run_live('wrong-arm')
    def test_start_intel_hash_must_match_actual_live_signature(self): self.run_live('wrong-intel')
    def test_start_edge_must_match_finish_edge(self): self.run_live('wrong-edge')
    def test_changed_mode_invalidates_both_roles(self): self.run_live('chmod-after')
    def test_rebound_file_invalidates_both_roles(self): self.run_live('rebind-after')
    def test_unknown_sibling_invalidates_both_roles(self):
        self.run_live('unknown-after')
        self.assertEqual((self.directory / 'unknown').read_text(), 'keep')

if __name__ == '__main__':
    unittest.main()
