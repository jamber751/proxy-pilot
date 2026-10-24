"""Pending coordinator ordering and failure checks in disposable root VM fixtures.

No real Applications, service or recovery daemon is touched. Journal mutations
are confined to fixture setup and explicitly injected stale-state cases.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import test_vpn_staged_application as staged
import test_vpn_rescue_executor as identity


@unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() == 0
                     and os.environ.get('PROXYPILOT_VM_ROOT_TESTS') == '1',
                     'explicit disposable macOS root VM fixture')
class VPNRescuePendingCoordinatorRootTests(unittest.TestCase):
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
            'VPNRescueAuthorization.swift', 'VPNHelperArtifact.swift', 'VPNRescueExecutor.swift',
            'VPNLifecycleOwnership.swift', 'VPNStagedApplication.swift',
            'VPNReplacementExecutor.swift', 'VPNProtectedApplicationSwap.swift',
            'VPNApplicationDestinationStage.swift', 'VPNApplicationDestinationExchange.swift',
            'VPNReleaseStore.swift', 'VPNRescueJournalContext.swift', 'VPNRescuePendingCoordinator.swift')]
        sources.append(staged.ROOT / 'tests/vpn_rescue_pending_coordinator_checks.swift')
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.build / ('rescue-' + arch)
            cls.command(['swiftc', '-D', 'VPN_RESCUE_EXECUTOR_TESTING',
                         '-D', 'VPN_APPLICATION_DESTINATION_TESTING',
                         '-D', 'VPN_APPLICATION_DESTINATION_ROOT_TESTING', '-D', 'VPN_EXPLICIT_RESCUE',
                         '-target', arch + '-apple-macosx11.0', *map(str, sources), '-o', str(output)])
            slices.append(str(output))
        cls.rescue_binary = cls.build / 'rescue-exchange'
        cls.command(['lipo', '-create', *slices, '-output', str(cls.rescue_binary)])
        cls.rescue_binary.chmod(0o700)
        identity.RescueBuild.sign(cls.rescue_binary)
        cls.rescue_pins = identity.RescueBuild.pins(cls.rescue_binary)

        cls.helper = cls.build / 'helper'
        shutil.copyfile(cls.universal, cls.helper)
        cls.command(['codesign', '--force', '--sign', '-', '--identifier',
                     'kz.documentolog.proxypilot.vpn-helper', '--options', 'runtime,hard,kill', str(cls.helper)])
        cls.helper_pins = identity.RescueBuild.pins(cls.helper)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-rescue-exchange-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        source_a = self.work / 'a'; source_a.mkdir(mode=0o700)
        self.app = source_a / 'ProxyPilot.app'; self.make_app(version='1.6.0')
        self.a = self.pins()
        source_b = self.work / 'b'; source_b.mkdir(mode=0o700)
        self.app = source_b / 'ProxyPilot.app'; self.make_app(version='1.7.0')
        self.b = self.pins()
        self.base = self.work / 'transaction'; self.base.mkdir(mode=0o700)
        for name, source in [('current', source_b), ('candidate', source_a), ('executor', source_a)]:
            target = self.base / name; target.mkdir(mode=0o700)
            shutil.copytree(source / 'ProxyPilot.app', target / 'ProxyPilot.app', symlinks=True)
        self.destination = self.work / 'Applications'; self.destination.mkdir(mode=0o700)
        shutil.copytree(source_a / 'ProxyPilot.app', self.destination / 'ProxyPilot.app', symlinks=True)
        self.stage = self.destination / '.ProxyPilot.vpn-update'; self.stage.mkdir(mode=0o700)
        shutil.copytree(source_b / 'ProxyPilot.app', self.stage / 'ProxyPilot.app', symlinks=True)
        self.rescue = self.work / 'rescue'; self.rescue.mkdir(mode=0o700)
        self.runner = self.rescue / 'vpn-rescue'
        shutil.copyfile(self.rescue_binary, self.runner); self.runner.chmod(0o700)
        self.service = self.work / 'service'; self.service.mkdir(mode=0o700)
        result = self.invoke('setup')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.before = self.identities()
        self.state_before = self.state()

    def identities(self):
        return tuple((folder / 'ProxyPilot.app').stat().st_ino for folder in (self.destination, self.stage))

    def state(self):
        return {p.name: (p.read_bytes(), p.stat().st_ino, p.stat().st_uid, p.stat().st_mode)
                for p in self.service.iterdir()}

    def invoke(self, operation='run'):
        return subprocess.run([str(self.runner), operation, str(self.base),
                               str(self.destination), str(self.rescue), str(self.rescue_binary),
                               self.rescue_pins['arm64'], self.rescue_pins['x86_64'],
                               self.a['arm64'], self.a['x86_64'], self.b['arm64'], self.b['x86_64'],
                               str(self.service), str(self.helper),
                               self.helper_pins['arm64'], self.helper_pins['x86_64']],
                              env=staged.ENV, capture_output=True, text=True, timeout=60)

    def test_order_and_retry_leave_pending_state_unchanged(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'exchanged:trace=arm,drain,exchange')
        self.assertEqual(self.identities(), self.before[::-1])
        self.assertEqual(self.state(), self.state_before)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'alreadyExchanged:trace=arm,drain')
        self.assertEqual(self.identities(), self.before[::-1])
        self.assertEqual(self.state(), self.state_before)

    def test_acknowledged_exchange_observations_are_readonly(self):
        budget = self.service / 'activation.json'
        budget.write_bytes(b'{"desired":false,"failures":0,"schema":1}'); budget.chmod(0o600)
        before = self.state()
        result = self.invoke('observe-repeat')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'observed:3:trace=arm,drain,exchange')
        self.assertEqual(self.identities(), self.before[::-1])
        self.assertEqual(self.state(), before)

    def test_observer_refuses_still_installed_source_without_callbacks(self):
        self.refused('observe-source', '')

    def test_observer_refuses_foreign_installed_app_without_replay(self):
        self.refused_observation('observe-foreign')

    def test_observer_refuses_installed_app_changed_after_inspection(self):
        self.refused_observation('observe-changed-installed')

    def test_observer_rechecks_context_after_inspection(self):
        self.refused_observation('observe-stale', changed=True)

    def test_observer_rechecks_live_lease_after_inspection(self):
        self.refused_observation('observe-lease')

    def test_observer_rechecks_live_executor_after_inspection(self):
        self.refused_observation('observe-executor')

    def refused_observation(self, operation, changed=False):
        result = self.invoke(operation)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue(result.stdout.strip().endswith(':trace=arm,drain,exchange'), result.stdout)
        self.assertEqual(self.identities(), self.before[::-1])
        if not changed: self.assertEqual(self.state(), self.state_before)

    def test_missing_destination_stage_is_prepared_then_exchanged(self):
        shutil.rmtree(self.stage)
        installed = (self.destination / 'ProxyPilot.app').stat().st_ino
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'exchanged:trace=arm,drain,exchange')
        self.assertEqual((self.stage / 'ProxyPilot.app').stat().st_ino, installed)
        self.assertEqual(self.state(), self.state_before)
        self.command([str(self.checker), 'inspect', str(self.destination),
                      self.b['arm64'], self.b['x86_64'], '1.7.0'])
        before = self.identities()
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'alreadyExchanged:trace=arm,drain')
        self.assertEqual(self.identities(), before)
        self.assertEqual(self.state(), self.state_before)

    def refused(self, operation, trace, changed=False):
        result = self.invoke(operation)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue(result.stdout.strip().endswith(':trace=' + trace), result.stdout)
        self.assertEqual(self.identities(), self.before)
        if not changed:
            self.assertEqual(self.state(), self.state_before)

    def test_stale_before_has_no_callbacks(self):
        self.refused('stale-before', '', changed=True)

    def test_arm_failure_has_no_drain_or_swap(self):
        self.refused('arm-failure', 'arm')

    def test_drain_failure_has_no_swap(self):
        self.refused('drain-failure', 'arm,drain')

    def test_stale_after_arm_has_no_drain_or_swap(self):
        self.refused('stale-after-arm', 'arm', changed=True)

    def test_stale_after_drain_has_no_swap(self):
        self.refused('stale-after-drain', 'arm,drain', changed=True)

    def test_invalid_layout_has_no_callbacks(self):
        (self.stage / 'ProxyPilot.app/Contents/Resources/data.txt').write_text('changed')
        self.refused('run', '')

    def refused_without_stage(self):
        shutil.rmtree(self.stage)
        before = (self.destination / 'ProxyPilot.app').stat().st_ino
        result = self.invoke()
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue(result.stdout.strip().endswith(':trace='), result.stdout)
        self.assertFalse(self.stage.exists())
        self.assertEqual((self.destination / 'ProxyPilot.app').stat().st_ino, before)
        self.assertEqual(self.state(), self.state_before)

    def test_unknown_installed_app_does_not_create_stage_or_drain(self):
        (self.destination / 'ProxyPilot.app/Contents/Resources/data.txt').write_text('changed')
        self.refused_without_stage()

    def test_unknown_protected_candidate_does_not_create_stage_or_drain(self):
        (self.base / 'current/ProxyPilot.app/Contents/Resources/data.txt').write_text('changed')
        self.refused_without_stage()

    def test_unknown_protected_previous_does_not_create_stage_or_drain(self):
        (self.base / 'candidate/ProxyPilot.app/Contents/Resources/data.txt').write_text('changed')
        self.refused_without_stage()

    def test_unknown_retained_executor_does_not_create_stage_or_drain(self):
        (self.base / 'executor/ProxyPilot.app/Contents/Resources/data.txt').write_text('changed')
        self.refused_without_stage()

    def test_finish_role_refuses_unexchanged_protected_layout(self):
        current = self.base / 'current'
        candidate = self.base / 'candidate'
        temporary = self.base / 'moving'
        current.rename(temporary); candidate.rename(current); temporary.rename(candidate)
        self.refused_without_stage()

    def test_interrupted_exchange_retries_forward_without_journal_mutation(self):
        result = self.invoke('after-exchange-failure')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn('commitUncertain:trace=arm,drain,exchange', result.stdout)
        self.assertEqual(self.identities(), self.before[::-1])
        self.assertEqual(self.state(), self.state_before)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.identities(), self.before[::-1])
        self.assertEqual(self.state(), self.state_before)

    def test_stale_after_exchange_is_detected_without_inverse(self):
        result = self.invoke('stale-after-exchange')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn('trace=arm,drain,exchange', result.stdout)
        self.assertEqual(self.identities(), self.before[::-1])


if __name__ == '__main__':
    unittest.main()
