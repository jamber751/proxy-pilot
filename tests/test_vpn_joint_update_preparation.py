"""Resumable preparation before any VPN/app selector changes."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_vpn_staged_application import VPNStagedApplicationTests, ROOT, HELPER, ENV


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNJointUpdatePreparationTests(VPNStagedApplicationTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.driver = cls.build / 'joint-update-preparation'
        sources = [HELPER / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
            'VPNHelperArtifact.swift', 'VPNReleaseStore.swift',
            'VPNLifecycleOwnership.swift', 'VPNDirectoryProvisioner.swift',
            'VPNStagedApplication.swift', 'VPNApplicationTransactionStager.swift',
            'VPNReplacementExecutor.swift', 'VPNProtectedApplicationSwap.swift',
            'VPNReplacementExecutorProvisioner.swift', 'VPNInstallationPayload.swift',
            'VPNJointUpdatePreparation.swift')]
        cls.command(['swiftc', '-D', 'VPN_APPLICATION_TRANSACTION_STAGING_TESTING',
                     '-D', 'VPN_EXECUTOR_PROVISIONING_TESTING',
                     '-D', 'VPN_EXECUTOR_HANDOFF_TESTING',
                     '-D', 'VPN_JOINT_UPDATE_PREPARATION_TESTING',
                     *map(str, sources),
                     str(ROOT / 'tests/vpn_joint_update_preparation_checks.swift'),
                     '-o', str(cls.driver)])
        cls.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                     '--identifier', 'kz.documentolog.proxypilot', str(cls.driver)])
        cls.helper = cls.build / 'joint-helper'
        shutil.copyfile(cls.universal, cls.helper)
        cls.helper.chmod(0o700)
        cls.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                     '--identifier', 'kz.documentolog.proxypilot.vpn-helper',
                     str(cls.helper)])
        cls.helper_pins = cls.code_pins(cls.helper)

    @classmethod
    def code_pins(cls, path):
        result = {}
        for arch in ('arm64', 'x86_64'):
            text = cls.command(['codesign', '-d', '--verbose=4', '--arch', arch,
                                str(path)]).stderr
            result[arch] = next(row[7:] for row in text.splitlines()
                                if row.startswith('CDHash='))
        return result

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
        self.service = self.work / 'service'; self.service.mkdir(mode=0o700)
        self.update = self.work / 'update'; self.update.mkdir(mode=0o700)

    def pins_for(self, app):
        saved = self.app
        try:
            self.app = app
            return self.pins()
        finally:
            self.app = saved

    def invoke(self, operation='prepare'):
        return subprocess.run([
            str(self.driver), operation, str(self.service), str(self.update),
            str(self.previous_source), str(self.candidate_source), str(self.helper),
            self.previous_pins['arm64'], self.previous_pins['x86_64'],
            self.candidate_pins['arm64'], self.candidate_pins['x86_64'],
            self.helper_pins['arm64'],
            self.helper_pins['x86_64']], env=ENV, capture_output=True,
            text=True, timeout=120)

    def assert_result(self, operation='prepare', output='prepared:0'):
        result = self.invoke(operation)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), output)

    def assert_rejected(self, operation, error):
        result = self.invoke(operation)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), f'rejected:{error}')

    def test_prepares_all_material_without_changing_selector(self):
        self.assert_result()
        self.assertTrue((self.update / 'current/ProxyPilot.app').is_dir())
        self.assertTrue((self.update / 'candidate/ProxyPilot.app').is_dir())
        self.assertTrue((self.update / 'executor/ProxyPilot.app').is_dir())
        self.assertTrue((self.service / 'update.json').is_file())
        self.assert_result(output='alreadyPrepared:0')

    def test_interruption_after_application_staging_resumes(self):
        self.assert_rejected('throw-after-staging', 'failure')
        self.assertFalse((self.service / 'update.json').exists())
        self.assertFalse((self.update / 'executor').exists())
        self.assert_result(output='resumed:0')

    def test_interruption_after_journal_resumes_executor(self):
        self.assert_rejected('throw-after-journal', 'failure')
        self.assertTrue((self.service / 'update.json').is_file())
        self.assertFalse((self.update / 'executor').exists())
        self.assert_result(output='resumed:0')

    def test_pending_retry_revalidates_all_prepared_material(self):
        self.assert_result('mark-pending', output='pending:1')
        self.assert_result(output='alreadyPrepared:1')
        self.assertTrue((self.update / 'executor/ProxyPilot.app').is_dir())

    def test_service_lock_and_production_root_guard(self):
        self.assert_rejected('busy', 'busy')
        self.assert_rejected('production', 'requiresRoot')
        self.assertFalse((self.service / 'update.json').exists())


def load_tests(loader, tests, pattern):
    names = [name for name in loader.getTestCaseNames(VPNJointUpdatePreparationTests)
             if name in VPNJointUpdatePreparationTests.__dict__]
    return unittest.TestSuite(VPNJointUpdatePreparationTests(name) for name in names)


if __name__ == '__main__': unittest.main()
