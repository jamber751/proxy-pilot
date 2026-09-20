"""Atomic, resumable preparation of a protected replacement executor copy."""
import fcntl
import os
import shutil
import subprocess
import sys
import unittest

from test_vpn_staged_application import VPNStagedApplicationTests, ROOT, HELPER, ENV


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNExecutorProvisioningTests(VPNStagedApplicationTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.provisioner = cls.build / 'executor-provisioning'
        sanitize = ['-sanitize=address'] if os.environ.get('PP_EXECUTOR_PROVISION_ASAN') == '1' else []
        cls.command(['swiftc', *sanitize, '-D', 'VPN_EXECUTOR_PROVISIONING_TESTING',
                     *[str(HELPER / name) for name in (
                         'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
                         'VPNLifecycleOwnership.swift', 'VPNStagedApplication.swift',
                         'VPNReplacementExecutor.swift', 'VPNProtectedApplicationSwap.swift',
                         'VPNReplacementExecutorProvisioner.swift')],
                     str(ROOT / 'tests/vpn_executor_provisioning_checks.swift'),
                     '-o', str(cls.provisioner)])

    def setUp(self):
        super().setUp()
        self.base = self.work / 'transaction'; self.base.mkdir(mode=0o700)
        self.current = self.base / 'current'; self.stage.rename(self.current)
        self.a = self.pins_for(self.current / 'ProxyPilot.app')

    def pins_for(self, app):
        saved = self.app
        try:
            self.app = app
            return self.pins()
        finally:
            self.app = saved

    def invoke(self, operation='prepare'):
        return subprocess.run([str(self.provisioner), operation, str(self.base),
                               self.a['arm64'], self.a['x86_64']], env=ENV,
                              capture_output=True, text=True, timeout=90)

    def assert_result(self, operation='prepare', output='prepared'):
        result = self.invoke(operation)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), output)
        return result

    def assert_rejected(self, operation, error):
        result = self.invoke(operation)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), f'rejected:{error}')

    def assert_exact_copy(self):
        source = self.current / 'ProxyPilot.app'
        copy = self.base / 'executor/ProxyPilot.app'
        self.assertTrue(copy.is_dir())
        self.assertNotEqual(source.stat().st_ino, copy.stat().st_ino)
        self.assertEqual(self.pins_for(source), self.pins_for(copy))
        self.assertEqual((source / 'Contents/Resources/data.txt').read_bytes(),
                         (copy / 'Contents/Resources/data.txt').read_bytes())

    def test_prepare_and_idempotent_recheck(self):
        self.assert_result()
        self.assert_exact_copy()
        self.assertFalse((self.base / '.executor.preparing').exists())
        self.assert_result(output='alreadyPrepared')
        self.assert_exact_copy()

    def test_interruption_after_atomic_clone_recovers_forward(self):
        self.assert_rejected('throw-after-clone', 'failure')
        self.assertTrue((self.base / '.executor.preparing/ProxyPilot.app').is_dir())
        self.assertFalse((self.base / 'executor').exists())
        self.assert_result(output='recoveredPrepared')
        self.assert_exact_copy()

    def test_interruption_before_publish_recovers_forward(self):
        self.assert_rejected('throw-before-publish', 'failure')
        self.assertTrue((self.base / '.executor.preparing/ProxyPilot.app').is_dir())
        self.assert_result(output='recoveredPrepared')
        self.assert_exact_copy()

    def test_post_publish_failure_is_uncertain_without_deleting_copy(self):
        self.assert_rejected('throw-after-publish', 'commitUncertain')
        self.assert_exact_copy()
        self.assert_result(output='alreadyPrepared')

    def test_tampered_source_or_clone_never_publishes(self):
        for operation, error in (('tamper-copy', 'invalidSignature'),
                                 ('tamper-source', 'invalidSignature'),
                                 ('extra-copy', 'invalidBundle'),
                                 ('extra-source', 'invalidBundle')):
            with self.subTest(operation=operation):
                self.setUp()
                self.assert_rejected(operation, error)
                self.assertFalse((self.base / 'executor').exists())

    def test_hostile_existing_names_fail_closed(self):
        for name in ('executor', '.executor.preparing'):
            with self.subTest(name=name):
                self.setUp()
                (self.base / name).symlink_to(self.current, target_is_directory=True)
                self.assert_rejected('prepare', 'unsafeStorage')
                self.assertTrue((self.base / name).is_symlink())
                self.assertTrue((self.current / 'ProxyPilot.app').is_dir())

    def test_lock_contention_and_production_root_guard(self):
        self.assert_rejected('busy', 'busy')
        self.assert_rejected('production', 'requiresRoot')
        self.assertFalse((self.base / 'executor').exists())
        lock = os.open(self.base / 'lifecycle.lock', os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assert_rejected('prepare', 'busy')
        finally:
            os.close(lock)


def load_tests(loader, tests, pattern):
    names = [name for name in loader.getTestCaseNames(VPNExecutorProvisioningTests)
             if name in VPNExecutorProvisioningTests.__dict__]
    return unittest.TestSuite(VPNExecutorProvisioningTests(name) for name in names)


if __name__ == '__main__': unittest.main()
