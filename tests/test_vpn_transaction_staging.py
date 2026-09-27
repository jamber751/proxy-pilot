"""Fixed, atomic, resumable A/B application transaction staging."""
import fcntl
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_vpn_staged_application import VPNStagedApplicationTests, ROOT, HELPER, ENV


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNTransactionStagingTests(VPNStagedApplicationTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.stager = cls.build / 'transaction-staging'
        cls.command(['swiftc', '-D', 'VPN_APPLICATION_TRANSACTION_STAGING_TESTING',
                     *[str(HELPER / name) for name in (
                         'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
                         'VPNLifecycleOwnership.swift', 'VPNStagedApplication.swift',
                         'VPNDirectoryProvisioner.swift',
                         'VPNApplicationTransactionStager.swift')],
                     str(ROOT / 'tests/vpn_transaction_staging_checks.swift'),
                     '-o', str(cls.stager)])

    def setUp(self):
        super().setUp()
        self.previous_source = self.stage
        self.previous_app = self.app
        self.previous_pins = self.pins_for(self.previous_app)
        self.candidate_source = self.work / 'candidate-source'
        self.candidate_source.mkdir(mode=0o700)
        saved_stage, saved_app = self.stage, self.app
        self.stage = self.candidate_source
        self.app = self.candidate_source / 'ProxyPilot.app'
        self.make_app(version='1.7.0')
        self.candidate_app = self.app
        self.candidate_pins = self.pins_for(self.candidate_app)
        self.stage, self.app = saved_stage, saved_app
        self.base = self.work / 'update'
        self.base.mkdir(mode=0o700)

    def pins_for(self, app):
        saved = self.app
        try:
            self.app = app
            return self.pins()
        finally:
            self.app = saved

    def invoke(self, operation='prepare', candidate_pins=None):
        candidate_pins = candidate_pins or self.candidate_pins
        return subprocess.run([
            str(self.stager), operation, str(self.base),
            str(self.previous_source), str(self.candidate_source),
            self.previous_pins['arm64'], self.previous_pins['x86_64'],
            candidate_pins['arm64'], candidate_pins['x86_64']],
            env=ENV, capture_output=True, text=True, timeout=120)

    def assert_result(self, operation='prepare', output='staged'):
        result = self.invoke(operation)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), output)

    def assert_rejected(self, operation, error, candidate_pins=None):
        result = self.invoke(operation, candidate_pins)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), f'rejected:{error}')

    def assert_exact_slots(self):
        for name, source in (('current', self.previous_app),
                             ('candidate', self.candidate_app)):
            copy = self.base / name / 'ProxyPilot.app'
            self.assertTrue(copy.is_dir())
            self.assertNotEqual(source.stat().st_ino, copy.stat().st_ino)
            self.assertEqual(self.pins_for(source), self.pins_for(copy))
            self.assertEqual((source / 'Contents/Resources/data.txt').read_bytes(),
                             (copy / 'Contents/Resources/data.txt').read_bytes())

    def test_stages_exact_slots_and_is_idempotent(self):
        self.assert_result()
        self.assert_exact_slots()
        self.assertFalse((self.base / '.current.preparing').exists())
        self.assertFalse((self.base / '.candidate.preparing').exists())
        self.assert_result(output='alreadyStaged')

    def test_interruption_after_current_publication_resumes(self):
        self.assert_rejected('throw-after-current', 'commitUncertain')
        self.assertTrue((self.base / 'current/ProxyPilot.app').is_dir())
        self.assertFalse((self.base / 'candidate').exists())
        self.assert_result(output='resumed')
        self.assert_exact_slots()

    def test_interruption_after_candidate_clone_resumes(self):
        self.assert_rejected('throw-after-candidate-clone', 'failure')
        self.assertTrue((self.base / '.candidate.preparing/ProxyPilot.app').is_dir())
        self.assert_result(output='resumed')
        self.assert_exact_slots()

    def test_empty_pending_slot_resumes(self):
        (self.base / '.current.preparing').mkdir(mode=0o700)
        self.assert_result(output='resumed')
        self.assert_exact_slots()

    def test_damaged_or_ambiguous_slots_fail_closed(self):
        for kind in ('extra', 'symlink', 'published-and-pending'):
            with self.subTest(kind=kind):
                self.setUp()
                pending = self.base / '.current.preparing'
                if kind == 'extra':
                    pending.mkdir(mode=0o700); (pending / 'foreign').write_text('x')
                elif kind == 'symlink':
                    pending.symlink_to(self.previous_source, target_is_directory=True)
                else:
                    shutil.copytree(self.previous_source, self.base / 'current', symlinks=True)
                    pending.mkdir(mode=0o700)
                self.assert_rejected('prepare',
                                     'invalidLayout' if kind != 'symlink' else 'unsafeStorage')
                self.assertTrue(self.previous_app.is_dir())
                self.assertTrue(self.candidate_app.is_dir())

    def test_bad_candidate_or_mutation_never_completes(self):
        bad = dict(self.candidate_pins); bad['arm64'] = '00' * 20
        self.assert_rejected('prepare', 'invalidSignature', bad)
        self.assertFalse((self.base / 'current').exists())
        self.assert_rejected('wrong-transition', 'invalidLayout')
        self.assertFalse((self.base / 'current').exists())
        self.assert_rejected('tamper-candidate-copy', 'invalidSignature')
        self.assertFalse((self.base / 'candidate').exists())
        self.setUp()
        self.assert_rejected('tamper-previous-source', 'invalidSignature')
        self.assertFalse((self.base / 'current').exists())

    def test_lock_contention_and_production_root_guard(self):
        self.assert_rejected('busy', 'busy')
        self.assert_rejected('production', 'requiresRoot')
        lock = os.open(self.base / 'lifecycle.lock', os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assert_rejected('prepare', 'busy')
        finally:
            os.close(lock)


def load_tests(loader, tests, pattern):
    names = [name for name in loader.getTestCaseNames(VPNTransactionStagingTests)
             if name in VPNTransactionStagingTests.__dict__]
    return unittest.TestSuite(VPNTransactionStagingTests(name) for name in names)


if __name__ == '__main__': unittest.main()
