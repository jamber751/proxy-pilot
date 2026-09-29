"""Pure route planning and durable ownership journal; never mutates networking."""
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
class VPNRoutePlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-route-plan-build-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        sources = [ROOT / 'app/VPNConfiguration.swift',
                   ROOT / 'app/vpn-helper/VPNRoutePlan.swift',
                   ROOT / 'app/vpn-helper/VPNRouteJournal.swift',
                   ROOT / 'tests/vpn_route_plan_checks.swift']
        result = subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0',
                                 *map(str, sources), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, name, word=None):
        with tempfile.TemporaryDirectory(prefix='pp-route-plan-', dir='/tmp') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), name, folder], capture_output=True,
                                    text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(word or ('passed' if name in ('planning', 'journal') else 'rejected'),
                          result.stdout)

    def test_normalized_deterministic_plan(self): self.run_case('planning')
    def test_domain_is_deferred(self): self.run_case('domain')
    def test_duplicate_is_rejected(self): self.run_case('duplicate')
    def test_overlap_is_rejected(self): self.run_case('overlap')
    def test_resource_cannot_capture_vpn_peer(self): self.run_case('peer')
    def test_default_route_is_rejected(self): self.run_case('default')
    def test_durable_checkpoints_and_retirement(self): self.run_case('journal')
    def test_generation_revision_binding_is_fail_closed(self): self.run_case('stale')
    def test_corrupt_record_is_rejected(self): self.run_case('corrupt')
    def test_wrong_mode_is_rejected(self): self.run_case('mode')
    def test_symlink_is_rejected(self): self.run_case('link')
    def test_shared_directory_is_rejected(self): self.run_case('directory')

    def test_source_contains_no_network_mutator_or_connected_claim(self):
        source = ''.join((ROOT / path).read_text() for path in (
            'app/vpn-helper/VPNRoutePlan.swift', 'app/vpn-helper/VPNRouteJournal.swift'))
        for forbidden in ('/sbin/route', 'networksetup', 'scutil', 'Process(', 'posix_spawn',
                          'system(', 'case connected', 'hold release'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
