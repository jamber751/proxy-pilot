"""Read-only update preflight in disposable directories; never inspect system VPN state."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNUpdateAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='pp-admission-build-')
        cls.addClassCleanup(cls.build.cleanup)
        slices = []
        for arch in ('arm64', 'x86_64'):
            binary = str(Path(cls.build.name) / arch)
            compiled = subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0',
                            '-module-cache-path', str(Path(cls.build.name) / 'ModuleCache'),
                            str(ROOT / 'app/update-worker/VPNUpdateAdmission.swift'),
                            str(ROOT / 'tests/vpn_update_admission_checks.swift'), '-o', binary],
                           capture_output=True, text=True, timeout=120)
            if compiled.returncode:
                raise AssertionError(compiled.stdout + compiled.stderr)
            slices.append(binary)
        cls.binary = str(Path(cls.build.name) / 'check')
        subprocess.run(['lipo', '-create', *slices, '-output', cls.binary], check=True, capture_output=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pp-admission-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.support = self.base / 'support'; self.support.mkdir()
        self.daemons = self.base / 'daemons'; self.daemons.mkdir()

    def expect(self, decision):
        result = subprocess.run([self.binary, str(self.base)], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), decision)

    def test_absent_does_not_create_anything(self):
        self.expect('allowed')
        self.assertEqual(list(self.support.iterdir()), [])
        self.assertEqual(list(self.daemons.iterdir()), [])

    def test_each_partial_installation_vetoes(self):
        for marker in (self.support / 'ProxyPilot', self.support / 'kz.documentolog.proxypilot.vpn',
                       self.daemons / 'kz.documentolog.proxypilot.vpn-helper.plist',
                       self.daemons / 'kz.documentolog.proxypilot.vpn-recovery.plist'):
            with self.subTest(marker=marker.name):
                marker.write_bytes(b'untouched')
                self.expect('requiresCoordinatedUpdate')
                self.assertEqual(marker.read_bytes(), b'untouched')
                marker.unlink()

    def test_private_directory_is_not_entered_or_repaired(self):
        marker = self.support / 'ProxyPilot'; marker.mkdir()
        (marker / 'profile').write_bytes(b'private fixture')
        marker.chmod(0)
        try:
            self.expect('requiresCoordinatedUpdate')
            self.assertEqual(marker.stat().st_mode & 0o777, 0)
        finally:
            marker.chmod(0o700)
        self.assertEqual((marker / 'profile').read_bytes(), b'private fixture')

    def test_dangling_marker_is_not_absence(self):
        (self.support / 'ProxyPilot').symlink_to(self.base / 'missing')
        self.expect('requiresCoordinatedUpdate')
        self.assertFalse((self.base / 'missing').exists())

    def test_fifo_marker_never_blocks(self):
        os.mkfifo(self.support / 'ProxyPilot')
        self.expect('requiresCoordinatedUpdate')

    def test_missing_parent_is_not_a_clean_installation(self):
        self.daemons.rmdir()
        self.expect('inspectionFailed')
        self.assertFalse(self.daemons.exists())

    def test_symlink_parent_is_not_followed(self):
        other = self.base / 'other'; other.mkdir()
        self.daemons.rmdir(); self.daemons.symlink_to(other)
        self.expect('inspectionFailed')
        self.assertEqual(list(other.iterdir()), [])

    def test_file_parent_is_rejected(self):
        self.daemons.rmdir(); self.daemons.write_bytes(b'untouched')
        self.expect('inspectionFailed')
        self.assertEqual(self.daemons.read_bytes(), b'untouched')

    @unittest.skipIf(os.geteuid() == 0, 'readability test requires an ordinary user')
    def test_unreadable_parent_is_not_absence(self):
        self.daemons.chmod(0)
        try: self.expect('inspectionFailed')
        finally: self.daemons.chmod(0o700)

    def test_no_cached_allow_after_state_changes(self):
        self.expect('allowed')
        marker = self.support / 'ProxyPilot'; marker.mkdir()
        self.expect('requiresCoordinatedUpdate')
        marker.rmdir()
        self.expect('allowed')
