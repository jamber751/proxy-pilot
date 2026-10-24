"""Prepared-to-destination rescue replacement in disposable root VM fixtures."""
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
import test_vpn_rescue_preparation_coordinator as preparation
import test_vpn_rescue_executor as identity
import test_vpn_staged_application as staged

@unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() == 0
                     and os.environ.get('PROXYPILOT_VM_ROOT_TESTS') == '1',
                     'explicit disposable macOS root VM fixture')
class VPNRescueReplacementCoordinatorRootTests(unittest.TestCase):
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
            'VPNRescuePreparationCoordinator.swift', 'VPNRescueJournalContext.swift',
            'VPNRescuePendingCoordinator.swift', 'VPNApplicationDestinationStage.swift',
            'VPNApplicationDestinationExchange.swift', 'VPNRescueReplacementCoordinator.swift')]
        sources.append(staged.ROOT / 'tests/vpn_rescue_replacement_coordinator_checks.swift')
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.build / ('coordinator-' + arch)
            cls.command(['swiftc', '-D', 'VPN_RESCUE_EXECUTOR_TESTING', '-D', 'VPN_RESCUE_PREPARATION',
                         '-D', 'VPN_RESCUE_PREPARATION_COORDINATOR_TESTING',
                         '-D', 'VPN_RESCUE_REPLACEMENT_COORDINATOR_TESTING', '-D', 'VPN_EXPLICIT_RESCUE',
                         '-D', 'VPN_APPLICATION_SWAP_ROOT_TESTING',
                         '-D', 'VPN_APPLICATION_DESTINATION_TESTING', '-D', 'VPN_APPLICATION_DESTINATION_ROOT_TESTING',
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

    invoke = preparation.VPNRescuePreparationCoordinatorRootTests.invoke
    assert_ok = preparation.VPNRescuePreparationCoordinatorRootTests.assert_ok
    snapshot = preparation.VPNRescuePreparationCoordinatorRootTests.snapshot

    def setUp(self):
        preparation.VPNRescuePreparationCoordinatorRootTests.setUp(self)
        self.assert_ok('prepare', 'prepared:0')
        self.selection = (self.service / 'release.json').read_bytes()
        self.previous_inode = (self.source / 'ProxyPilot.app').stat().st_ino
        self.slot_inodes = self.inodes()
        self.candidate_before = self.snapshot(self.candidate)

    def inodes(self):
        folders = [self.source / 'ProxyPilot.app', self.source / '.ProxyPilot.vpn-update/ProxyPilot.app',
                   self.update / 'current/ProxyPilot.app', self.update / 'candidate/ProxyPilot.app',
                   self.update / 'executor/ProxyPilot.app']
        return tuple(path.stat().st_ino if path.exists() else None for path in folders)

    def assert_pending_b(self):
        journal = json.loads((self.service / 'update.json').read_text())
        self.assertEqual((journal['phase'], journal['revision'], journal['owner']), ('replacementPending', 1, 501))
        self.assertEqual((self.service / 'release.json').read_bytes(), self.selection)
        self.assertFalse((self.service / 'preparation.json').exists())
        self.assertFalse((self.service / 'cleanup.json').exists())
        self.assertEqual((self.source / '.ProxyPilot.vpn-update/ProxyPilot.app').stat().st_ino, self.previous_inode)
        self.assertEqual((self.update / 'current/ProxyPilot.app').stat().st_ino, self.slot_inodes[3])
        self.assertEqual((self.update / 'candidate/ProxyPilot.app').stat().st_ino, self.slot_inodes[2])
        for folder, pins, version in ((self.source, self.b, '1.7.0'),
                                      (self.source / '.ProxyPilot.vpn-update', self.a, '1.6.0'),
                                      (self.update / 'current', self.b, '1.7.0'),
                                      (self.update / 'candidate', self.a, '1.6.0'),
                                      (self.update / 'executor', self.a, '1.6.0')):
            self.command([str(self.checker), 'inspect', str(folder), pins['arm64'], pins['x86_64'], version])
        self.assertEqual(self.snapshot(self.candidate), self.candidate_before)

    def test_prepared_to_destination_keeps_source_selected_and_arms_once(self):
        result = self.assert_ok('run')
        self.assertEqual(result.stdout.strip(), 'exchanged:trace=arm,drain,pending,protected,stage,destination')
        self.assert_pending_b()
        before = self.inodes()
        result = self.assert_ok('run')
        self.assertEqual(result.stdout.strip(), 'alreadyExchanged:trace=arm,drain,stage')
        self.assertEqual(self.inodes(), before); self.assert_pending_b()

    def test_pending_before_protected_swap_resumes(self):
        self.assert_ok('make-pending', 'setup')
        result = self.assert_ok('run')
        self.assertEqual(result.stdout.strip(), 'exchanged:trace=arm,drain,protected,stage,destination')
        self.assert_pending_b()

    def interrupted(self, point):
        result = self.invoke('crash:' + point)
        self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
        self.assertIn('crash:' + point, result.stdout)
        self.assert_ok('run'); self.assert_pending_b()
        before = self.inodes()
        self.assert_ok('run'); self.assertEqual(self.inodes(), before)

    def test_resume_after_arm(self): self.interrupted('afterArm')
    def test_resume_after_drain(self): self.interrupted('afterDrain')
    def test_resume_after_pending_before_protected_swap(self): self.interrupted('afterPending')
    def test_resume_after_protected_swap(self): self.interrupted('protected:afterExchange')
    def test_resume_after_destination_clone(self): self.interrupted('destinationStage:afterClone')
    def test_resume_after_destination_stage(self): self.interrupted('afterDestinationStage')
    def test_resume_after_destination_exchange(self): self.interrupted('destination:afterExchange')
    def test_resume_after_destination_sync(self): self.interrupted('destination:afterSync')

    def refusal(self, operation='run', trace='', include_candidate=True):
        roots = (self.service, self.update, self.source) + ((self.candidate,) if include_candidate else ())
        before = self.snapshot(*roots)
        result = self.invoke(operation)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue(result.stdout.strip().endswith(':trace=' + trace), result.stdout)
        self.assertEqual(self.snapshot(*roots), before)

    def test_foreign_preparation_blocks_before_arm(self):
        self.assert_ok('make-preparation', 'setup'); self.refusal()
    def test_cleanup_receipt_blocks_before_arm(self):
        self.assert_ok('make-receipt', 'setup'); self.refusal()
    def test_foreign_signed_edge_blocks_before_arm(self):
        self.assert_ok('make-foreign-edge', 'setup'); self.refusal()
    def test_foreign_lease_blocks_before_arm(self): self.refusal('foreign-lease', include_candidate=False)
    def test_expired_lease_blocks_before_arm(self): self.refusal('expired-lease')
    def test_unknown_installed_app_blocks_before_arm(self):
        (self.source / 'ProxyPilot.app/Contents/Resources/data.txt').write_text('changed')
        self.refusal()
    def test_unknown_protected_app_blocks_before_arm(self):
        (self.update / 'candidate/ProxyPilot.app/Contents/Resources/data.txt').write_text('changed')
        self.refusal()
    def test_arm_failure_does_not_drain_mark_or_swap(self): self.refusal('arm-failure', 'arm')
    def test_drain_failure_does_not_mark_or_swap(self): self.refusal('drain-failure', 'arm,drain')
    def test_changed_uuid_after_arm_prevents_drain_and_swap(self):
        before = self.inodes(); selected = (self.service / 'release.json').read_bytes()
        result = self.invoke('stale-after-arm')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue(result.stdout.strip().endswith(':trace=arm'), result.stdout)
        self.assertEqual(self.inodes(), before)
        self.assertEqual((self.service / 'release.json').read_bytes(), selected)
        self.assertEqual(json.loads((self.service / 'update.json').read_text())['revision'], 0)
    def test_lease_lost_after_arm_prevents_drain_and_swap(self): self.refusal('lease-after-arm', 'arm')
    def test_nonlive_copy_cannot_run_replacement(self):
        before = self.snapshot(self.service, self.update, self.source)
        result = self.invoke('run', runner=self.binary)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue(result.stdout.strip().endswith(':trace='), result.stdout)
        self.assertEqual(self.snapshot(self.service, self.update, self.source), before)

if __name__ == '__main__': unittest.main()
