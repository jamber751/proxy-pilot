"""Unprivileged broker isolation and callback-order integration; no launchd."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import test_vpn_staged_application as staged
import test_vpn_rescue_executor as identity


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNRescueBrokerCoordinatorTests(unittest.TestCase):
    command = staged.VPNStagedApplicationTests.__dict__['command']
    make_app = staged.VPNStagedApplicationTests.make_app
    sign = staged.VPNStagedApplicationTests.sign
    pins = staged.VPNStagedApplicationTests.pins

    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0: raise unittest.SkipTest('Never root')
        staged.VPNStagedApplicationTests.setUpClass.__func__(cls)
        cls.driver = cls.build / 'broker-coordinator'
        names = ('VPNPeerAuthentication.swift VPNReleaseAuthorization.swift VPNRescueAuthorization.swift '
                 'VPNHelperArtifact.swift VPNInstallationPayload.swift VPNStagedApplication.swift VPNReleaseStore.swift '
                 'VPNLifecycleOwnership.swift VPNActivationBudget.swift VPNUpdateBrokerProtocol.swift '
                 'VPNUpdateBrokerTransactionStore.swift VPNUpdateBrokerStatusStore.swift VPNUpdateBrokerInbox.swift '
                 'VPNUpdateBrokerStateRemoval.swift VPNRescueBrokerCoordinator.swift VPNUpdateBrokerRotation.swift '
                 'VPNDirectoryProvisioner.swift VPNUpdateBrokerLaunchdJob.swift').split()
        cls.command(['swiftc', '-D', 'VPN_RESCUE_BROKER_TESTING',
                     *map(str, (staged.HELPER / name for name in names)),
                     str(staged.ROOT / 'tests/vpn_rescue_broker_coordinator_checks.swift'), '-o', str(cls.driver)])
        cls.helper = cls.build / 'helper'; shutil.copyfile(cls.universal, cls.helper)
        cls.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                     '--identifier', staged.APP_ID + '.vpn-helper', str(cls.helper)]); cls.helper.chmod(0o700)
        cls.helper_pins = identity.RescueBuild.pins(cls.helper)
        cls.engine = cls.build / 'engine'; shutil.copyfile(cls.universal, cls.engine)
        cls.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                     '--identifier', staged.APP_ID + '.openvpn', str(cls.engine)]); cls.engine.chmod(0o700)
        cls.engine_pins = identity.RescueBuild.pins(cls.engine)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-rescue-broker-', dir='/tmp')
        self.addCleanup(temporary.cleanup); self.work = Path(temporary.name)
        for name in ('service', 'broker', 'b', 'c'):
            (self.work / name).mkdir(mode=0o700)
        self.app = self.work / 'b/ProxyPilot.app'; self.make_app(version='1.6.0'); self.b = self.pins()
        self.app = self.work / 'c/ProxyPilot.app'; self.make_app(version='1.7.0'); self.c = self.pins()

    def check(self, operation, accepted=False, expected=None):
        result = subprocess.run([str(self.driver), operation, *[str(self.work / name) for name in ('service', 'broker', 'b', 'c')],
            str(self.helper), self.b['arm64'], self.b['x86_64'], self.c['arm64'], self.c['x86_64'],
            self.helper_pins['arm64'], self.helper_pins['x86_64'], str(self.engine),
            self.engine_pins['arm64'], self.engine_pins['x86_64']], env=staged.ENV,
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0 if accepted else 77, result.stdout + result.stderr)
        if expected: self.assertIn(expected, result.stdout)
        return result

    def test_broker_reconciliation_preserves_manual_off(self): self.check('final-off', True, 'reconciled:trace=probe,install,probe,probe:desired=false')
    def test_broker_reconciliation_preserves_on(self): self.check('final-on', True, 'desired=true')
    def test_already_ready_never_reinstalls(self): self.check('already-ready', True, 'alreadyReady:trace=probe,probe:desired=false')
    def test_complete_history_is_preserved(self): self.check('complete-inbox', True, 'reconciled:')
    def test_orphan_publication_refuses_before_job_actions(self): self.check('orphan-inbox', expected='trace=')
    def test_orphan_preparing_refuses_before_job_actions(self): self.check('orphan-preparing', expected='trace=')
    def test_accepted_without_journal_reference_refuses(self): self.check('active-accepted', expected='trace=')
    def test_exact_prepared_reference_is_bound(self): self.check('active-prepared', True, 'matching-active-bound')
    def test_prepared_broker_advances_only_after_pending(self): self.check('active-pending', True, 'matching-active-bound')
    def test_unarmed_prepared_index_advances_only_after_pending(self): self.check('active-unarmed-pending', True, 'matching-active-bound')
    def test_foreign_inbox_cannot_adopt_service_journal(self): self.check('active-foreign-inbox', expected='trace=')
    def test_foreign_uuid_cannot_adopt_service_journal(self): self.check('active-foreign-uuid', expected='trace=')
    def test_identity_loss_prevents_actions(self): self.check('lost-input', expected='trace=')
    def test_install_failure_preserves_service_budget(self): self.check('install-failure', expected='trace=probe,install')
    def test_phase6_detach_restore_orders_service_retirement(self): self.check('backup-retire', True, 'backup-retired-after-service')
    def test_backup_remains_resumable_if_stale_owner_retired_inbox(self): self.check('backup-missing-inbox', True, 'backup-retired-after-service')
    def test_backup_survives_fresh_coordinator(self): self.check('backup-fresh', True, 'backup-retired-after-service')
    def test_missing_inbox_backup_survives_fresh_coordinator(self): self.check('backup-missing-inbox-fresh', True, 'backup-retired-after-service')
    def test_backup_cannot_adopt_different_journal_uuid(self): self.check('backup-mismatched', expected='trace=')
    def test_current_rotation_retries_phase6_without_backwards_advance(self): self.check('rotation-retry', True, 'rotation-retried:trace=rotate')
    def test_current_rotation_advances_phase5(self): self.check('rotation-phase5', True, 'rotation-retried:trace=rotate')
    def test_current_rotation_rejects_foreign_completed_reference(self): self.check('rotation-invalid-ref', expected='trace=')
    def test_normal_index_plus_backup_refuses(self): self.check('backup-both', expected='trace=')


if __name__ == '__main__': unittest.main()
