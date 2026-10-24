"""Typed live rescue cleanup in disposable root VM fixtures only."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

import test_vpn_joint_update_cleanup as cleanup
import test_vpn_rescue_executor as identity


@unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() == 0
                     and os.environ.get('PROXYPILOT_VM_ROOT_TESTS') == '1',
                     'explicit disposable macOS root VM fixture')
class VPNRescueCleanupRootTests(unittest.TestCase):
    root_vm_fixture = True
    command = cleanup.VPNJointUpdateCleanupTests.__dict__['command']
    make_app = cleanup.VPNJointUpdateCleanupTests.make_app
    sign = cleanup.VPNJointUpdateCleanupTests.sign
    pins = cleanup.VPNJointUpdateCleanupTests.pins

    @classmethod
    def setUpClass(cls):
        cleanup.VPNJointUpdateCleanupTests.setUpClass.__func__(cls)
        sources = [cleanup.HELPER / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperArtifact.swift',
            'VPNReleaseStore.swift', 'VPNLifecycleOwnership.swift', 'VPNDirectoryProvisioner.swift',
            'VPNStagedApplication.swift', 'VPNJointUpdateCleanup.swift', 'VPNRescueAuthorization.swift',
            'VPNRescueExecutor.swift', 'VPNRescueCleanupContext.swift', 'VPNRescueCleanupBoundary.swift')]
        sources.append(cleanup.ROOT / 'tests/vpn_rescue_cleanup_checks.swift')
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.build / ('rescue-cleanup-' + arch)
            cls.command(['swiftc', '-D', 'VPN_RESCUE_EXECUTOR_TESTING',
                         '-D', 'VPN_JOINT_UPDATE_CLEANUP_TESTING',
                         '-D', 'VPN_JOINT_UPDATE_CLEANUP_ROOT_TESTING', '-D', 'VPN_EXPLICIT_RESCUE',
                         '-target', arch + '-apple-macosx11.0', *map(str, sources), '-o', str(output)])
            slices.append(str(output))
        cls.rescue_binary = cls.build / 'rescue-cleanup'
        cls.command(['lipo', '-create', *slices, '-output', str(cls.rescue_binary)])
        cls.rescue_binary.chmod(0o700)
        identity.RescueBuild.sign(cls.rescue_binary)
        cls.rescue_pins = identity.RescueBuild.pins(cls.rescue_binary)

    def setUp(self):
        cleanup.VPNJointUpdateCleanupTests.setUp(self)
        # A real staged transaction already acquired this namespace lease.
        # Seed its lock before snapshots so refusal checks measure payload
        # mutations rather than the first acquisition creating an empty lock.
        (self.update / 'lifecycle.lock').touch(mode=0o600, exist_ok=False)
        self.rescue = self.work / 'rescue'; self.rescue.mkdir(mode=0o700)
        self.runner = self.rescue / 'vpn-rescue'
        shutil.copyfile(self.rescue_binary, self.runner); self.runner.chmod(0o700)
        self.installed_inode = (self.applications / 'ProxyPilot.app').stat().st_ino

    def invoke(self, operation='cleanup', runner=None):
        return subprocess.run([str(runner or getattr(self, 'runner', self.rescue_binary)), operation,
                               str(self.service), str(self.update), str(self.retired), str(self.applications),
                               *map(str, self.manifests), str(self.helper), str(self.work / 'rescue'),
                               str(self.rescue_binary), self.rescue_pins['arm64'], self.rescue_pins['x86_64']],
                              env=cleanup.ENV, capture_output=True, text=True, timeout=180)

    def tree_snapshot(self):
        return {(str(path), path.lstat().st_ino, path.lstat().st_uid)
                for root in (self.applications, self.update, self.retired)
                for path in (root, *root.rglob('*'))}

    def assert_clean(self):
        self.assertFalse((self.service / 'cleanup.json').exists())
        self.assertEqual(list(self.retired.iterdir()), [])
        self.assertEqual([p.name for p in self.applications.iterdir()], ['ProxyPilot.app'])
        self.assertEqual([p.name for p in self.update.iterdir()], ['lifecycle.lock'])
        app = self.applications / 'ProxyPilot.app'
        self.assertEqual(app.stat().st_ino, self.installed_inode)
        self.assertTrue(all(p.lstat().st_uid == 0 for p in (app, *app.rglob('*'))))

    def test_live_cleanup_removes_only_authorized_copies(self):
        result = self.invoke(); self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'retired-authenticated-receipt'); self.assert_clean()
        retry = self.invoke(); self.assertEqual(retry.returncode, 77, retry.stdout + retry.stderr)
        self.assertIn('needsSeparateCompletionProof', retry.stdout)

    def test_invalid_context_or_live_proof_has_no_cleanup_side_effect(self):
        before = self.tree_snapshot()
        for operation in ('wrong-context-edge', 'wrong-live-edge', 'expired-lease', 'foreign-store', 'wrong-held-lease'):
            with self.subTest(operation=operation):
                result = self.invoke(operation)
                self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                self.assertEqual(self.tree_snapshot(), before)
        result = self.invoke('stale-uuid'); self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(self.tree_snapshot(), before)

    def test_static_copied_binary_cannot_replace_live_identity(self):
        before = self.tree_snapshot()
        result = self.invoke(runner=self.rescue_binary)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(self.tree_snapshot(), before)

    def test_changed_live_executor_refused_before_cleanup(self):
        before = self.tree_snapshot(); result = self.invoke('changed-live-executor')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(self.tree_snapshot(), before)

    def test_changed_installed_b_refused_before_cleanup(self):
        resource = self.applications / 'ProxyPilot.app/Contents/Resources/data.txt'
        resource.write_text('changed installed B')
        before = self.tree_snapshot(); result = self.invoke()
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(self.tree_snapshot(), before)

    def test_user_owned_retained_a_refused_before_deletion(self):
        app = self.applications / '.ProxyPilot.vpn-update/ProxyPilot.app'
        for path in (app, *app.rglob('*')): os.chown(path, 501, -1, follow_symlinks=False)
        before = {(str(p), p.lstat().st_ino) for p in (app, *app.rglob('*'))}
        result = self.invoke(); self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual({(str(p), p.lstat().st_ino) for p in (app, *app.rglob('*'))}, before)
        self.assertTrue(all((self.update / name / 'ProxyPilot.app').exists()
                            for name in ('current', 'candidate', 'executor')))
        self.assertTrue((self.service / 'cleanup.json').exists())

    def test_gc_resume_rejects_surviving_user_owned_entries(self):
        result = self.invoke('crash:gc:after-authorize')
        self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
        app = self.applications / ('.ProxyPilot.vpn-update.retired-' + self.transaction) / 'ProxyPilot.app'
        os.chown(app, 501, -1)
        before = self.tree_snapshot(); result = self.invoke()
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(self.tree_snapshot(), before)
        os.chown(app, 0, -1)
        result = self.invoke(); self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_clean()

    def test_gc_receipt_drift_stops_before_deletion(self):
        result = self.invoke('receipt-drift-before-gc')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        archive = self.retired / self.transaction
        for name in ('current', 'candidate', 'executor'):
            self.assertTrue((archive / name / 'ProxyPilot.app/Contents/MacOS/ProxyPilot').is_file())
        self.assertTrue((self.service / 'cleanup.json').exists())

    def test_lost_lease_during_gc_does_not_remove_next_root_or_receipt(self):
        result = self.invoke('lease-drift-during-gc')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue((self.retired / self.transaction / 'current/ProxyPilot.app').is_dir())
        self.assertTrue((self.service / 'cleanup.json').exists())

    def assert_crash_recovers(self, checkpoint):
        result = self.invoke('crash:' + checkpoint)
        self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
        result = self.invoke(); self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_clean()

    def test_retry_after_application_rename(self): self.assert_crash_recovers('application:after-rename')
    def test_retry_after_update_rename(self): self.assert_crash_recovers('update:after-current')
    def test_retry_after_gc_authorization(self): self.assert_crash_recovers('gc:after-authorize')
    def test_retry_after_partial_gc(self): self.assert_crash_recovers('gc:after-child')


if __name__ == '__main__': unittest.main()
