"""Policy persistence, process crashes and hostile files in private temporary dirs.

No root/elevation, service registration, real profiles or production signing key.
The store checks the fixture owner's UID; production provisioning must use root.
"""
import fcntl
import json
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
class VPNReleaseStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='proxypilot-release-store-build-')
        cls.addClassCleanup(cls.build.cleanup)
        directory = Path(cls.build.name)
        sources = [ROOT / 'app/vpn-helper' / file for file in
                   ('VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperArtifact.swift', 'VPNReleaseStore.swift')]
        sources.append(ROOT / 'tests/vpn_release_store_checks.swift')
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = directory / arch
            result = subprocess.run(['swiftc', '-D', 'VPN_RELEASE_STORE_TESTING',
                                     '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(output)],
                                    capture_output=True, text=True, timeout=90)
            if result.returncode:
                raise AssertionError(result.stderr)
            slices.append(str(output))
        cls.binary = directory / 'store-checks'
        subprocess.run(['lipo', '-create', *slices, '-output', str(cls.binary)],
                       check=True, capture_output=True, timeout=10)
        subprocess.run(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill', str(cls.binary)],
                       check=True, capture_output=True, timeout=10)
        # Release compilation excludes the forced-crash hooks entirely.
        result = subprocess.run(['swiftc', '-typecheck', *map(str, sources[:-1])],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='proxypilot-release-store-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'policy'
        self.directory.mkdir(mode=0o700)

    def run_store(self, operation, sequence=10, expected=10, checkpoint='none', directory=None):
        return subprocess.run([str(self.binary), operation, str(directory or self.directory),
                               str(sequence), str(expected), checkpoint],
                              capture_output=True, text=True, timeout=10)

    def expect(self, operation, output, **kwargs):
        result = self.run_store(operation, **kwargs)
        self.assertEqual(result.returncode, 0 if output.startswith('sequence=') else 77,
                         result.stdout + result.stderr)
        self.assertIn(output, result.stdout)
        return result

    def seed(self):
        self.expect('bootstrap', 'sequence=10 owner=501')

    def test_bootstrap_load_restart_and_private_modes(self):
        self.expect('load', 'rejected:invalidState')
        self.seed()
        self.expect('load', 'sequence=10 owner=501')
        self.assertEqual(sorted(p.name for p in self.directory.iterdir()), ['initialized', 'release.json', 'release.lock'])
        for path in self.directory.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_uid, os.geteuid())

    def test_upgrade_persists_floor_across_processes(self):
        self.seed()
        self.expect('upgrade', 'sequence=20 owner=501', sequence=20)
        self.expect('load', 'sequence=20 owner=501')
        self.expect('upgrade', 'rejected:rollback', sequence=10, expected=20)
        self.expect('load', 'sequence=20 owner=501')

    def test_retry_stale_writer_and_sequence_conflict(self):
        self.seed()
        before = (self.directory / 'release.json').read_bytes()
        self.expect('upgrade', 'sequence=10 owner=501')
        self.assertEqual((self.directory / 'release.json').read_bytes(), before)
        self.expect('upgrade', 'sequence=20 owner=501', sequence=20)
        self.expect('upgrade', 'rejected:staleRevision', sequence=30, expected=10)
        self.expect('conflict', 'rejected:conflictingRelease', sequence=20, expected=20)
        self.expect('load', 'sequence=20 owner=501')

    def test_bad_signature_keeps_previous_bytes(self):
        self.seed()
        before = (self.directory / 'release.json').read_bytes()
        self.expect('invalid-update', 'rejected:invalidSignature', sequence=20)
        self.assertEqual((self.directory / 'release.json').read_bytes(), before)
        self.expect('wrong-key', 'rejected:invalidState')
        self.expect('load', 'sequence=10 owner=501')

    def test_no_reinitialization_or_owner_replacement(self):
        self.seed()
        self.expect('bootstrap', 'rejected:alreadyInitialized', sequence=1)
        self.expect('upgrade', 'sequence=20 owner=501', sequence=20)

    def test_missing_and_corrupt_state_never_reset(self):
        self.seed()
        record = self.directory / 'release.json'
        record.unlink()
        self.expect('load', 'rejected:invalidState')
        self.expect('bootstrap', 'rejected:alreadyInitialized', sequence=1)
        record.write_bytes(b'corrupt')
        record.chmod(0o600)
        self.expect('upgrade', 'rejected:invalidState', sequence=20)
        self.assertEqual(record.read_bytes(), b'corrupt')

    def test_missing_marker_fails_closed(self):
        self.seed()
        (self.directory / 'initialized').unlink()
        self.expect('load', 'rejected:invalidState')
        self.expect('bootstrap', 'rejected:alreadyInitialized')

    def test_envelope_rejects_extra_fields_and_oversize(self):
        self.seed()
        record = self.directory / 'release.json'
        data = json.loads(record.read_bytes())
        data['unknown'] = 'unexpected'
        record.write_text(json.dumps(data, sort_keys=True, separators=(',', ':')))
        self.expect('load', 'rejected:invalidState')
        record.write_bytes(b'a' * 8193)
        self.expect('load', 'rejected:invalidState')

    def test_nonblocking_cross_process_lock(self):
        self.seed()
        with (self.directory / 'release.lock').open('r+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.expect('load', 'rejected:busy')
            self.expect('upgrade', 'rejected:busy', sequence=20)
        self.expect('load', 'sequence=10 owner=501')

    def test_links_and_fifo_cannot_redirect_record(self):
        self.seed()
        record = self.directory / 'release.json'
        other = Path(self.temp.name) / 'untouched'
        other.write_bytes(b'unchanged')
        record.unlink()
        record.symlink_to(other)
        self.expect('load', 'rejected:unsafeStorage')
        self.expect('upgrade', 'rejected:unsafeStorage', sequence=20)
        self.assertEqual(other.read_bytes(), b'unchanged')
        record.unlink()
        os.mkfifo(record, 0o600)
        self.expect('load', 'rejected:unsafeStorage')
        record.unlink()
        other.chmod(0o600)
        os.link(other, record)
        self.expect('load', 'rejected:unsafeStorage')

    def test_unsafe_directory_file_and_lock_modes(self):
        self.seed()
        self.directory.chmod(0o755)
        self.expect('load', 'rejected:unsafeStorage')
        self.directory.chmod(0o700)
        for name in ('release.json', 'initialized', 'release.lock'):
            with self.subTest(name=name):
                path = self.directory / name
                path.chmod(0o644)
                self.expect('load', 'rejected:unsafeStorage')
                path.chmod(0o600)

    def test_lock_symlink_cannot_touch_another_file(self):
        self.seed()
        lock = self.directory / 'release.lock'
        lock.unlink()
        other = Path(self.temp.name) / 'other-file'
        other.write_bytes(b'untouched')
        lock.symlink_to(other)
        self.expect('upgrade', 'rejected:unsafeStorage', sequence=20)
        self.assertEqual(other.read_bytes(), b'untouched')

    def test_acl_is_not_ignored_by_private_mode_check(self):
        self.seed()
        for path in (self.directory, self.directory / 'release.json', self.directory / 'release.lock'):
            with self.subTest(path=path.name):
                subprocess.run(['chmod', '+a', 'everyone allow read', str(path)],
                               check=True, capture_output=True, timeout=5)
                try:
                    self.expect('load', 'rejected:unsafeStorage')
                finally:
                    subprocess.run(['chmod', '-N', str(path)], check=True, capture_output=True, timeout=5)
        self.expect('load', 'sequence=10 owner=501')

    def test_crash_before_replacement_keeps_old_policy(self):
        self.seed()
        result = self.run_store('upgrade', sequence=20, checkpoint='release.json:before-rename')
        self.assertEqual(result.returncode, 86)
        self.expect('load', 'sequence=10 owner=501')
        self.expect('upgrade', 'sequence=20 owner=501', sequence=20)

    def test_crash_after_replacement_has_complete_new_policy(self):
        self.seed()
        result = self.run_store('upgrade', sequence=20, checkpoint='release.json:after-rename')
        self.assertEqual(result.returncode, 86)
        self.expect('load', 'sequence=20 owner=501')
        self.expect('upgrade', 'rejected:rollback', sequence=10, expected=20)

    def test_interrupted_bootstrap_requires_recovery_not_reset(self):
        result = self.run_store('bootstrap', checkpoint='initialized:after-rename')
        self.assertEqual(result.returncode, 86)
        self.expect('load', 'rejected:invalidState')
        self.expect('bootstrap', 'rejected:alreadyInitialized', sequence=1)
