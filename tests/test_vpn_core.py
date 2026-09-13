"""Compile real VPN core and exercise it in disposable directories, without networking."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='proxypilot-vpn-build-')
        cls.binary = Path(cls.build.name) / 'vpn-checks'
        sources = [ROOT / 'app' / name for name in
                   ['VPNConfiguration.swift', 'VPNProfileImporter.swift', 'VPNStore.swift',
                    'VPNLegacyMigration.swift']]
        built = subprocess.run(['swiftc', '-target', 'arm64-apple-macosx11.0' if
                                platform.machine() == 'arm64' else 'x86_64-apple-macosx11.0',
                                *map(str, sources), str(ROOT / 'tests/vpn_core_checks.swift'),
                                '-o', str(cls.binary)], capture_output=True, text=True, timeout=90)
        if built.returncode:
            cls.build.cleanup()
            raise AssertionError(built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def run_group(self, group):
        with tempfile.TemporaryDirectory(prefix='proxypilot-vpn-test-') as directory:
            result = subprocess.run([str(self.binary), group, directory],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('checks passed', result.stdout)

    def test_resources(self): self.run_group('resources')
    def test_configuration(self): self.run_group('configuration')
    def test_authentication_metadata_and_migration(self): self.run_group('authentication')
    def test_import(self): self.run_group('import')
    def test_reject_unsafe_profiles(self): self.run_group('unsafe')
    def test_picker_and_drop_files(self): self.run_group('files')
    def test_atomic_store_and_pending_revisions(self): self.run_group('store')
    def test_store_security_and_corruption(self): self.run_group('store-security')
    def test_legacy_route_migration(self): self.run_group('migration')
