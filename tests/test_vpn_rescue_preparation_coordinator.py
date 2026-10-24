"""Rescue preparation/journal integration in explicit disposable root VM fixtures."""
import base64
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import test_vpn_rescue_executor as identity
import test_vpn_staged_application as staged

@unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() == 0
                     and os.environ.get('PROXYPILOT_VM_ROOT_TESTS') == '1',
                     'explicit disposable macOS root VM fixture')
class VPNRescuePreparationCoordinatorRootTests(unittest.TestCase):
    root_vm_fixture = True
    command = staged.VPNStagedApplicationTests.__dict__['command']
    make_app = staged.VPNStagedApplicationTests.make_app
    sign = staged.VPNStagedApplicationTests.sign
    pins = staged.VPNStagedApplicationTests.pins

    @classmethod
    def setUpClass(cls):
        staged.VPNStagedApplicationTests.setUpClass.__func__(cls)
        sources = [staged.HELPER / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
            'VPNRescueAuthorization.swift', 'VPNRescuePreparationAuthorization.swift',
            'VPNHelperArtifact.swift', 'VPNRescueExecutor.swift', 'VPNRescuePreparationExecutor.swift',
            'VPNLifecycleOwnership.swift', 'VPNStagedApplication.swift', 'VPNDirectoryProvisioner.swift',
            'VPNApplicationTransactionStager.swift', 'VPNReleaseStore.swift',
            'VPNInstallationPayload.swift', 'VPNReplacementExecutor.swift', 'VPNProtectedApplicationSwap.swift',
            'VPNReplacementExecutorProvisioner.swift', 'VPNRescuePreparationContext.swift',
            'VPNRescuePreparationCoordinator.swift')]
        sources.append(staged.ROOT / 'tests/vpn_rescue_preparation_coordinator_checks.swift')
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.build / ('coordinator-' + arch)
            cls.command(['swiftc', '-D', 'VPN_RESCUE_EXECUTOR_TESTING', '-D', 'VPN_RESCUE_PREPARATION',
                         '-D', 'VPN_RESCUE_PREPARATION_COORDINATOR_TESTING',
                         '-D', 'VPN_APPLICATION_TRANSACTION_STAGING_TESTING', '-D', 'VPN_RELEASE_STORE_TESTING',
                         '-target', arch + '-apple-macosx11.0', *map(str, sources), '-o', str(output)])
            slices.append(str(output))
        cls.binary = cls.build / 'preparation-coordinator'
        cls.command(['lipo', '-create', *slices, '-output', str(cls.binary)])
        cls.binary.chmod(0o700); identity.RescueBuild.sign(cls.binary)
        cls.rescue_pins = identity.RescueBuild.pins(cls.binary)
        cls.helper = cls.build / 'helper'
        shutil.copyfile(cls.universal, cls.helper)
        cls.helper.chmod(0o700)
        cls.command(['codesign', '--force', '--sign', '-', '--identifier',
                     'kz.documentolog.proxypilot.vpn-helper', '--options', 'runtime,hard,kill', str(cls.helper)])
        cls.helper_pins = identity.RescueBuild.pins(cls.helper)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-rescue-prepare-', dir='/tmp')
        self.addCleanup(temporary.cleanup); self.work = Path(temporary.name)
        self.source = self.work / 'source'; self.source.mkdir(mode=0o700)
        self.candidate = self.work / 'candidate'; self.candidate.mkdir(mode=0o700)
        self.app = self.source / 'ProxyPilot.app'; self.make_app(version='1.6.0'); self.a = self.pins()
        self.app = self.candidate / 'ProxyPilot.app'; self.make_app(version='1.7.0')
        if self._testMethodName != 'test_candidate_without_capability_creates_no_authority':
            info = self.app / 'Contents/Info.plist'; metadata = plistlib.loads(info.read_bytes())
            metadata['ProxyPilotVPNRootOwnedUpdateExecutor'] = '1'
            info.write_bytes(plistlib.dumps(metadata)); self.sign(self.app, staged.APP_ID)
        self.b = self.pins()
        for folder, pins, version in ((self.source, self.a, '1.6.0'), (self.candidate, self.b, '1.7.0')):
            self.command([str(self.checker), 'inspect', str(folder), pins['arm64'], pins['x86_64'], version])
        self.service = self.work / 'service'; self.service.mkdir(mode=0o700)
        self.update = self.work / 'update'; self.update.mkdir(mode=0o700)
        self.rescue = self.work / 'rescue'; self.rescue.mkdir(mode=0o700)
        self.runner = self.rescue / 'vpn-rescue'; shutil.copyfile(self.binary, self.runner); self.runner.chmod(0o700)
        self.assert_ok('setup', 'setup')
        self.source_before = self.snapshot(self.source, self.candidate)

    def invoke(self, operation='prepare', runner=None):
        return subprocess.run([str(runner or self.runner), operation, str(self.service), str(self.update),
            str(self.source), str(self.candidate), str(self.rescue), str(self.binary), str(self.helper),
            self.rescue_pins['arm64'], self.rescue_pins['x86_64'], self.a['arm64'], self.a['x86_64'],
            self.b['arm64'], self.b['x86_64'], self.helper_pins['arm64'], self.helper_pins['x86_64']],
            env=staged.ENV, capture_output=True, text=True, timeout=90)

    def assert_ok(self, operation='prepare', expected=None):
        result = self.invoke(operation); self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        if expected: self.assertEqual(result.stdout.strip(), expected)
        return result

    def snapshot(self, *roots):
        result = {}
        for root in roots:
            for path in (root, *root.rglob('*')):
                info = path.lstat()
                result[str(path)] = (info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                                    path.read_bytes() if path.is_file() else b'')
        return result

    def assert_prepared(self):
        journal = json.loads((self.service / 'update.json').read_text())
        self.assertEqual((journal['phase'], journal['revision'], journal['owner']), ('prepared', 0, 501))
        self.assertFalse((self.service / 'preparation.json').exists())
        for name in ('current', 'candidate', 'executor'):
            self.assertTrue((self.update / name / 'ProxyPilot.app').is_dir())
        self.assertEqual(self.snapshot(self.source, self.candidate), self.source_before)
        selected = json.loads((self.service / 'release.json').read_text())
        self.assertEqual(selected['owner'], 501)
        self.assertIn('sequence=139\n', base64.b64decode(selected['payload']).decode())

    def test_clean_to_prepared_and_idempotent_retry(self):
        self.assert_ok(expected='prepared:0'); self.assert_prepared()
        before = self.snapshot(self.service, self.update)
        self.assert_ok(expected='alreadyPrepared:0'); self.assert_prepared()
        self.assertEqual(self.snapshot(self.service, self.update), before)

    def interrupted(self, point, exit_code=77):
        result = self.invoke('interrupt:' + point)
        self.assertEqual(result.returncode, exit_code, result.stdout + result.stderr)
        if exit_code == 77:
            self.assertIn('rejected:interrupted', result.stdout)
        if point in ('afterPreparation', 'afterApplicationStaging'):
            self.assertTrue((self.service / 'preparation.json').exists())
            self.assertFalse((self.service / 'update.json').exists())
        elif point == 'afterJournal':
            self.assertFalse((self.service / 'preparation.json').exists())
            self.assertTrue((self.service / 'update.json').exists())
            self.assertFalse((self.update / 'executor').exists())
        elif point == 'conversion':
            preparation = json.loads((self.service / 'preparation.json').read_text())
            journal = json.loads((self.service / 'update.json').read_text())
            self.assertEqual(preparation['transactionID'], journal['transactionID'])
            self.assertEqual((journal['phase'], journal['revision']), ('prepared', 0))
        self.assertEqual(self.snapshot(self.source, self.candidate), self.source_before)
        self.assert_ok(expected='resumed:0'); self.assert_prepared()

    def test_resume_after_preparation(self): self.interrupted('afterPreparation')
    def test_resume_after_staging(self): self.interrupted('afterApplicationStaging')
    def test_resume_after_journal(self): self.interrupted('afterJournal')
    def test_resume_after_executor(self):
        result = self.invoke('interrupt:afterExecutor'); self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn('rejected:interrupted', result.stdout)
        self.assert_prepared()
        self.assert_ok(expected='alreadyPrepared:0'); self.assert_prepared()
    def test_conversion_window_resumes(self): self.interrupted('conversion', exit_code=86)

    def refused_state(self, setup):
        self.assert_ok(setup, 'setup')
        before = self.snapshot(self.service, self.update, self.source, self.candidate)
        result = self.invoke(); self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(self.snapshot(self.service, self.update, self.source, self.candidate), before)
    def test_foreign_preparation_is_not_superseded(self): self.refused_state('setup-foreign')
    def test_pending_state_is_not_reprepared(self): self.refused_state('setup-pending')
    def test_cleanup_receipt_blocks_preparation(self): self.refused_state('setup-receipt')
    def test_candidate_without_capability_creates_no_authority(self):
        before = self.snapshot(self.service, self.update)
        result = self.invoke(); self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn('incompatibleExecutor', result.stdout)
        self.assertEqual(self.snapshot(self.service, self.update), before)
    def test_static_copy_is_not_the_live_executor(self):
        before = self.snapshot(self.service, self.update)
        result = self.invoke(runner=self.binary); self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(self.snapshot(self.service, self.update), before)

if __name__ == '__main__': unittest.main()
