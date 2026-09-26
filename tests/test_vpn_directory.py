"""Fixed private directory provisioning below a disposable trusted base; no root writes."""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNDirectoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='proxypilot-directory-build-')
        cls.addClassCleanup(cls.build.cleanup)
        directory = Path(cls.build.name)
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = directory / arch
            result = subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0',
                                     '-D', 'VPN_DIRECTORY_TESTING',
                                     str(ROOT / 'app/vpn-helper/VPNDirectoryProvisioner.swift'),
                                     str(ROOT / 'tests/vpn_directory_checks.swift'), '-o', str(output)],
                                    capture_output=True, text=True, timeout=60)
            if result.returncode:
                raise AssertionError(result.stderr)
            slices.append(str(output))
        cls.binary = directory / 'directory-checks'
        subprocess.run(['lipo', '-create', *slices, '-output', str(cls.binary)], check=True, capture_output=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='proxypilot-directory-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.app = self.base / 'ProxyPilot'

    def expect(self, operation, output):
        result = subprocess.run([str(self.binary), operation, str(self.base)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0 if output == 'private-directory-ready' else 77, result.stdout + result.stderr)
        self.assertIn(output, result.stdout)

    def test_create_repeat_and_read_preserve_existing_contents(self):
        self.expect('create', 'private-directory-ready')
        for path in (self.app, self.app / 'VPN'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            self.assertEqual(path.stat().st_uid, os.geteuid())
        existing = self.app / 'VPN/untouched'
        existing.write_bytes(b'unchanged')
        self.expect('create', 'private-directory-ready')
        self.expect('read', 'private-directory-ready')
        self.assertEqual(existing.read_bytes(), b'unchanged')

    def test_read_does_not_create_missing_directories(self):
        self.expect('read', 'rejected:unavailable')
        self.assertFalse(self.app.exists())

    def test_update_namespace_is_a_separate_fixed_private_sibling(self):
        self.expect('create', 'private-directory-ready')
        self.expect('create-update', 'private-directory-ready')
        update = self.app / 'Update'
        self.assertEqual(stat.S_IMODE(update.stat().st_mode), 0o700)
        self.assertEqual(update.stat().st_uid, os.geteuid())
        (update / 'untouched').write_bytes(b'update')
        (self.app / 'VPN/untouched').write_bytes(b'vpn')
        self.expect('read-update', 'private-directory-ready')
        self.assertEqual((update / 'untouched').read_bytes(), b'update')
        self.assertEqual((self.app / 'VPN/untouched').read_bytes(), b'vpn')

    def test_update_read_does_not_create_missing_directories(self):
        self.expect('read-update', 'rejected:unavailable')
        self.assertFalse(self.app.exists())

    def test_writable_base_rejected_before_creation(self):
        self.base.chmod(0o770)
        self.expect('create', 'rejected:unsafeDirectory')
        self.assertFalse(self.app.exists())

    def test_unsafe_existing_directory_not_repaired(self):
        self.app.mkdir(mode=0o755)
        self.expect('create', 'rejected:unsafeDirectory')
        self.assertEqual(stat.S_IMODE(self.app.stat().st_mode), 0o755)
        self.assertFalse((self.app / 'VPN').exists())

    def test_symlink_component_is_not_followed(self):
        other = self.base / 'other'
        other.mkdir(mode=0o700)
        self.app.symlink_to(other)
        self.expect('create', 'rejected:unavailable')
        self.assertEqual(list(other.iterdir()), [])
        self.app.unlink()
        self.app.mkdir(mode=0o700)
        (self.app / 'VPN').symlink_to(other)
        self.expect('create', 'rejected:unavailable')
        self.assertEqual(list(other.iterdir()), [])

    def test_acl_on_base_or_existing_child_rejected(self):
        for path in (self.base, self.app):
            if path == self.app:
                self.app.mkdir(mode=0o700)
            subprocess.run(['chmod', '+a', 'everyone allow read', str(path)], check=True, capture_output=True)
            try:
                self.expect('create', 'rejected:unsafeDirectory')
            finally:
                subprocess.run(['chmod', '-N', str(path)], check=True, capture_output=True)
        self.assertFalse((self.app / 'VPN').exists())

    @unittest.skipIf(os.geteuid() == 0, 'must never call production provisioning from an elevated test')
    def test_production_entry_requires_root_before_any_write(self):
        self.expect('root-guard', 'rejected:requiresRoot')
        self.expect('root-update-guard', 'rejected:requiresRoot')
        self.assertEqual(list(self.base.iterdir()), [])
