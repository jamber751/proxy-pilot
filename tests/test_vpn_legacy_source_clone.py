"""Root-only private clone preparation. Run solely in disposable macOS VM."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import test_vpn_staged_application as staged


@unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() == 0
                     and os.environ.get('PROXYPILOT_VM_ROOT_TESTS') == '1',
                     'root fixture requires explicit disposable macOS VM opt-in')
class VPNLegacySourceCloneTests(unittest.TestCase):
    root_vm_fixture = True
    command = staged.VPNStagedApplicationTests.__dict__['command']
    make_app = staged.VPNStagedApplicationTests.make_app
    sign = staged.VPNStagedApplicationTests.sign
    pins = staged.VPNStagedApplicationTests.pins

    @classmethod
    def setUpClass(cls):
        staged.VPNStagedApplicationTests.setUpClass.__func__(cls)
        cls.clone_checker = cls.build / 'clone-checker'
        cls.command(['swiftc', '-D', 'VPN_LEGACY_SOURCE_CLONE_TESTING',
                     *[str(staged.HELPER / name) for name in (
                         'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
                         'VPNStagedApplication.swift', 'VPNLegacySourceClone.swift')],
                     str(staged.ROOT / 'tests/vpn_legacy_source_clone_checks.swift'),
                     '-o', str(cls.clone_checker)])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-legacy-clone-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.source = self.work / 'source'; self.source.mkdir(mode=0o700)
        self.destination = self.work / 'copy'; self.destination.mkdir(mode=0o700)
        self.app = self.source / 'ProxyPilot.app'; self.make_app()
        self.source_pins = self.pins()
        self.before = self.snapshot(self.source)

    @staticmethod
    def snapshot(root):
        result = {}
        for path in [root, *root.rglob('*')]:
            value = path.lstat()
            content = os.readlink(path) if path.is_symlink() else (
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
            result[str(path.relative_to(root))] = (
                value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, content)
        return result

    def invoke(self, operation='prepare'):
        result = subprocess.run([str(self.clone_checker), operation, str(self.source),
                                 str(self.destination), self.source_pins['arm64'],
                                 self.source_pins['x86_64']], env=staged.ENV,
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(self.snapshot(self.source), self.before, 'source tree changed')
        return result

    def test_signed_clone_has_exact_owner_and_unchanged_bytes(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        clone = self.destination / 'ProxyPilot.app'
        for path in [clone, *clone.rglob('*')]:
            self.assertEqual(path.lstat().st_uid, 501)
        self.assertEqual(self.destination.stat().st_uid, 0)
        original = self.snapshot(self.app); copied = self.snapshot(clone)
        self.assertEqual(original.keys(), copied.keys())
        for name in original:
            # Ownership/inodes change, exact file modes, groups and bytes do not.
            self.assertEqual(original[name][2], copied[name][2])
            self.assertEqual(original[name][4:], copied[name][4:])

    def test_nonempty_destination_is_preserved(self):
        marker = self.destination / 'unfamiliar'; marker.write_text('keep')
        result = self.invoke()
        self.assertIn('occupiedDestination', result.stdout)
        self.assertEqual(result.returncode, 77)
        self.assertEqual(marker.read_text(), 'keep')
        self.assertEqual(list(self.destination.iterdir()), [marker])

    def test_invalid_owner_rejected_without_copy(self):
        self.assertEqual(self.invoke('invalid-owner').returncode, 77)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_tampered_copy_rejected_without_source_changes(self):
        self.assertEqual(self.invoke('tamper-copy').returncode, 77)

    def test_interrupted_private_copies_are_not_implicitly_resumed(self):
        for operation in ('stop-after-clone', 'stop-mid-owner'):
            with self.subTest(operation=operation):
                self.assertEqual(self.invoke(operation).returncode, 77)
                interrupted = self.snapshot(self.destination)
                retry = self.invoke()
                self.assertEqual(retry.returncode, 77)
                self.assertIn('occupiedDestination', retry.stdout)
                self.assertEqual(self.snapshot(self.destination), interrupted)
                shutil.rmtree(self.destination)
                self.destination.mkdir(mode=0o700)

    def test_source_owner_mismatch_rejected_without_copy(self):
        os.chown(self.app / 'Contents/Resources/data.txt', 501, -1)
        self.before = self.snapshot(self.source)
        self.assertEqual(self.invoke().returncode, 77)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_destination_inside_source_is_rejected(self):
        nested = self.app / 'Contents/Resources/private-copy'
        nested.mkdir(mode=0o700)
        self.sign(self.app, 'kz.documentolog.proxypilot')
        self.source_pins = self.pins()
        self.before = self.snapshot(self.source)
        self.destination = nested
        self.assertEqual(self.invoke().returncode, 77)
        self.assertEqual(list(nested.iterdir()), [])

    def test_destination_must_be_private(self):
        self.destination.chmod(0o755)
        self.assertEqual(self.invoke().returncode, 77)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_signed_source_corruption_is_rejected_before_clone(self):
        (self.app / 'Contents/Resources/data.txt').write_text('changed')
        self.before = self.snapshot(self.source)
        self.assertEqual(self.invoke().returncode, 77)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_same_source_destination_is_rejected(self):
        self.destination = self.source
        self.assertEqual(self.invoke().returncode, 77)


@unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() != 0,
                     'ordinary-user refusal check')
class VPNLegacySourceCloneUnprivilegedTests(unittest.TestCase):
    command = staged.VPNStagedApplicationTests.__dict__['command']

    @classmethod
    def setUpClass(cls):
        VPNLegacySourceCloneTests.setUpClass.__func__(cls)

    def test_nonroot_is_refused_before_any_copy(self):
        source = self.build / 'empty-source'; source.mkdir(mode=0o700)
        target = self.build / 'empty-target'; target.mkdir(mode=0o700)
        result = subprocess.run([str(self.clone_checker), 'prepare', str(source), str(target),
                                 'a' * 40, 'b' * 40], env=staged.ENV,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 77)
        self.assertEqual(result.stdout.strip(), 'rejected:requiresRoot')
        self.assertEqual(list(source.iterdir()), [])
        self.assertEqual(list(target.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
