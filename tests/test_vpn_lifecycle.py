"""Cross-process ownership of the helper lifecycle, with actual separate processes.

Disposable directories only: no launchd, no root, no service and no VPN state.
Proving exclusion between unprivileged processes is not proof of root ownership.
"""
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Holder:
    """A separate process holding a lease and answering one command at a time."""

    def __init__(self, executable, directory):
        self.process = subprocess.Popen([str(executable), 'lease', str(directory)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)

    def line(self, timeout=15):
        ready, _, _ = select.select([self.process.stdout], [], [], timeout)
        if not ready:
            raise AssertionError('no answer from the lease holder')
        return self.process.stdout.readline().strip()

    def send(self, command):
        self.process.stdin.write(command + '\n')
        self.process.stdin.flush()
        return self.line()

    def stop(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=15)
        for stream in (self.process.stdin, self.process.stdout):
            if stream:
                stream.close()


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise unittest.SkipTest('Never run the ownership fixture as root')
        cls.build = tempfile.TemporaryDirectory(prefix='pp-life-build-', dir='/tmp')
        cls.addClassCleanup(cls.build.cleanup)
        cls.work = Path(cls.build.name)
        sources = [ROOT / 'app/vpn-helper/VPNLifecycleOwnership.swift', ROOT / 'tests/vpn_lifecycle_checks.swift']
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.work / f'lifecycle-{arch}'
            result = subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0', *map(str, sources),
                                     '-o', str(output)], capture_output=True, text=True, timeout=180)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
            slices.append(str(output))
        cls.executable = cls.work / 'lifecycle'
        subprocess.run(['lipo', '-create', *slices, '-output', str(cls.executable)], check=True, timeout=60)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pp-life-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'store'
        self.directory.mkdir(mode=0o700)
        self.lock = self.directory / 'lifecycle.lock'

    def hold(self):
        holder = Holder(self.executable, self.directory)
        self.addCleanup(holder.stop)
        self.assertEqual(holder.line(), 'held:acquired')
        return holder

    def take(self):
        return subprocess.run([str(self.executable), 'try', str(self.directory)],
                              capture_output=True, text=True, timeout=15).stdout.strip()

    def test_second_process_cannot_take_owned_lifecycle(self):
        self.hold()
        self.assertEqual(self.take(), 'try:busy')

    def test_release_hands_ownership_to_the_next_process(self):
        holder = self.hold()
        self.assertEqual(holder.send('release'), 'released')
        self.assertEqual(self.take(), 'try:acquired')

    def test_exited_owner_releases_ownership_without_cleanup(self):
        holder = self.hold()
        self.assertEqual(self.take(), 'try:busy')
        self.assertEqual(holder.send('crash'), '')
        self.assertEqual(holder.process.wait(timeout=15), 86)
        self.assertEqual(self.take(), 'try:acquired')

    def test_same_process_cannot_take_a_second_lease(self):
        holder = self.hold()
        self.assertEqual(holder.send('again'), 'again:busy')
        self.assertEqual(holder.send('check'), 'check:ok')

    def test_replaced_lock_is_detected_by_the_owner(self):
        holder = self.hold()
        self.assertEqual(holder.send('check'), 'check:ok')
        replacement = self.directory / 'other'
        replacement.touch(mode=0o600)
        replacement.replace(self.lock)
        # A racing writer can hand the new file to a second supervisor, so the
        # holder must fail closed instead of trusting the lock it still holds.
        self.assertEqual(holder.send('check'), 'check:lost')
        self.assertEqual(self.take(), 'try:acquired')

    def test_renamed_lock_is_detected_by_the_owner(self):
        holder = self.hold()
        # The held file survives under another name, so its link count still
        # looks correct: only comparing it with the directory entry catches this.
        self.lock.rename(self.directory / 'moved')
        self.lock.touch(mode=0o600)
        self.assertEqual(holder.send('check'), 'check:lost')
        self.assertEqual(self.take(), 'try:acquired')

    def test_unlinked_lock_is_detected_by_the_owner(self):
        holder = self.hold()
        self.lock.unlink()
        self.assertEqual(holder.send('check'), 'check:lost')

    def test_released_lease_cannot_be_rechecked(self):
        holder = self.hold()
        self.assertEqual(holder.send('release'), 'released')
        self.assertEqual(holder.send('check'), 'check:lost')

    def test_symlinked_lock_is_rejected(self):
        target = Path(self.temp.name) / 'elsewhere'
        target.touch(mode=0o600)
        self.lock.symlink_to(target)
        self.assertEqual(self.take(), 'try:unsafeStorage')

    def test_group_or_world_accessible_lock_is_rejected(self):
        self.lock.touch(mode=0o644)
        self.assertEqual(self.take(), 'try:unsafeStorage')

    def test_hard_linked_lock_is_rejected(self):
        self.lock.touch(mode=0o600)
        os.link(self.lock, self.directory / 'second-name')
        self.assertEqual(self.take(), 'try:unsafeStorage')

    def test_shared_directory_is_rejected(self):
        self.directory.chmod(0o755)
        self.assertEqual(self.take(), 'try:unsafeStorage')

    def test_directory_acl_is_rejected(self):
        subprocess.run(['chmod', '+a', f'{os.getlogin()} allow read', str(self.directory)],
                       check=True, timeout=15)
        self.assertEqual(self.take(), 'try:unsafeStorage')

    def test_lock_acl_is_rejected(self):
        self.lock.touch(mode=0o600)
        subprocess.run(['chmod', '+a', f'{os.getlogin()} allow read', str(self.lock)],
                       check=True, timeout=15)
        self.assertEqual(self.take(), 'try:unsafeStorage')
