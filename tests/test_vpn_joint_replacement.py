"""Journal-authorized protected copy exchange with no launchd or live helper."""
import re
import shutil
import subprocess
import sys
import unittest

try:
    from tests.test_vpn_staged_application import VPNStagedApplicationTests, ROOT, HELPER, ENV
except ModuleNotFoundError:
    from test_vpn_staged_application import VPNStagedApplicationTests, ROOT, HELPER, ENV


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNJointReplacementTests(VPNStagedApplicationTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        sources = [HELPER / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperArtifact.swift',
            'VPNReleaseStore.swift', 'VPNLifecycleOwnership.swift', 'VPNDirectoryProvisioner.swift',
            'VPNHelperProtocol.swift', 'VPNHelperReadiness.swift', 'VPNHelperSession.swift',
            'VPNActivationBudget.swift', 'VPNActivationCoordinator.swift', 'VPNProfileVault.swift',
            'VPNEndpointDirectory.swift', 'VPNLaunchdRuntime.swift', 'VPNRecoveryLaunchdJob.swift', 'VPNInstaller.swift',
            'VPNStagedApplication.swift', 'VPNInstalledApplication.swift',
            'VPNInstalledCandidateHandoff.swift', 'VPNSelectedCandidateFinalizer.swift',
            'VPNSelectedCandidateRecovery.swift',
            'VPNProtectedApplicationSwap.swift',
            'VPNReplacementExecutor.swift', 'VPNApplicationDestinationStage.swift',
            'VPNApplicationDestinationExchange.swift', 'VPNJointApplicationReplacement.swift')]
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.build / f'joint-{arch}'
            cls.command(['swiftc', '-D', 'VPN_INSTALLER_TESTING', '-D', 'VPN_APPLICATION_SWAP_TESTING',
                         '-D', 'VPN_RELEASE_STORE_TESTING',
                         '-D', 'VPN_APPLICATION_DESTINATION_TESTING',
                         '-D', 'VPN_INSTALLED_CANDIDATE_HANDOFF_TESTING',
                         '-D', 'VPN_EXECUTOR_HANDOFF_TESTING',
                         '-D', 'VPN_ENGINE_DELIVERY_TESTING', '-D', 'VPN_LAUNCHD_TESTING',
                         '-D', 'VPN_HELPER_READINESS_TESTING', '-target', f'{arch}-apple-macosx11.0',
                         *map(str, sources), str(ROOT / 'tests/vpn_joint_replacement_checks.swift'),
                         '-o', str(output)])
            slices.append(str(output))
        cls.joint = cls.build / 'joint'
        cls.command(['lipo', '-create', *slices, '-output', str(cls.joint)])
        cls.helper = cls.build / 'helper'
        shutil.copyfile(cls.universal, cls.helper)
        cls.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                     '--identifier', 'kz.documentolog.proxypilot.vpn-helper', str(cls.helper)])
        cls.helper_pins = cls.code_pins(cls.helper)

    @classmethod
    def code_pins(cls, path):
        result = {}
        for arch in ('arm64', 'x86_64'):
            text = cls.command(['codesign', '-d', '--verbose=4', '--arch', arch, str(path)]).stderr
            result[arch] = re.search(r'^CDHash=([a-f0-9]{40})$', text, re.M).group(1)
        return result

    def setUp(self):
        super().setUp()
        self.support = self.work / 'support'; self.support.mkdir(mode=0o755)
        self.apps = self.work / 'apps'; self.apps.mkdir(mode=0o700)
        self.current = self.apps / 'current'; self.candidate = self.apps / 'candidate'
        self.stage.rename(self.current)
        self.replace_main_and_sign(self.current / 'ProxyPilot.app')
        self.candidate.mkdir(mode=0o700)
        self.stage = self.candidate; self.app = self.candidate / 'ProxyPilot.app'
        self.make_app(version='1.7.0')
        self.replace_main_and_sign(self.app)
        self.a = self.code_pins(self.current / 'ProxyPilot.app')
        self.b = self.code_pins(self.app)
        self.executor = self.apps / 'executor'
        self.executor.mkdir(mode=0o700)
        executor_bundle = self.executor / 'ProxyPilot.app'
        shutil.copytree(self.current / 'ProxyPilot.app', executor_bundle, symlinks=True)
        self.runner_a = executor_bundle / 'Contents/MacOS/ProxyPilot'
        external_bundle = self.work / 'ExternalA.app'
        shutil.copytree(executor_bundle, external_bundle, symlinks=True)
        self.runner_external_a = external_bundle / 'Contents/MacOS/ProxyPilot'
        runner_b_bundle = self.work / 'RunnerB.app'
        shutil.copytree(self.app, runner_b_bundle, symlinks=True)
        self.runner_b = runner_b_bundle / 'Contents/MacOS/ProxyPilot'
        updater_bundle = self.work / 'Updater.app'
        shutil.copytree(self.current / 'ProxyPilot.app', updater_bundle, symlinks=True)
        updater_main = updater_bundle / 'Contents/MacOS/ProxyPilot'
        self.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                      '--identifier', 'kz.documentolog.proxypilot.updater', str(updater_main)])
        self.sign(updater_bundle, 'kz.documentolog.proxypilot.updater')
        self.runner_updater = updater_main
        self.initial = self.identities()
        self.executor_identity = (self.executor.stat().st_ino,
                                  executor_bundle.stat().st_ino,
                                  self.runner_a.read_bytes())
        self.destination = self.work / 'Applications'; self.destination.mkdir(mode=0o700)
        shutil.copytree(self.current / 'ProxyPilot.app', self.destination / 'ProxyPilot.app', symlinks=True)
        (self.destination / 'Other.app').mkdir()
        (self.destination / 'Other.app/sentinel').write_text('untouched')

    def replace_main_and_sign(self, app):
        executable = app / 'Contents/MacOS/ProxyPilot'
        shutil.copyfile(self.joint, executable)
        executable.chmod(0o755)
        self.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                      '--identifier', 'kz.documentolog.proxypilot', str(executable)])
        self.sign(app, 'kz.documentolog.proxypilot')

    def identities(self):
        return tuple((self.apps / slot / 'ProxyPilot.app').stat().st_ino
                     for slot in ('current', 'candidate'))

    def invoke(self, operation, executable=None):
        args = [str(executable or self.runner_a), operation, str(self.support), str(self.apps),
                str(self.helper), self.a['arm64'], self.a['x86_64'], self.b['arm64'],
                self.b['x86_64'], self.helper_pins['arm64'], self.helper_pins['x86_64'],
                str(self.destination)]
        return subprocess.run(args, env=ENV, capture_output=True, text=True, timeout=60)

    def setup_journal(self, operation='setup'):
        result = self.invoke(operation)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith('setup:'), result.stdout)
        return result.stdout.strip().split(':')[1]

    def setup_selector_crash(self):
        result = self.invoke('setup-selector-crash')
        self.assertEqual(result.returncode, 86, result.stdout + result.stderr)

    def assert_no_effect(self):
        self.assertEqual(self.identities(), self.initial)
        self.assertFalse((self.apps / 'factory-marker').exists())
        self.assertFalse((self.apps / 'drain-marker').exists())
        self.assertFalse((self.apps / 'start-marker').exists())

    def assert_rejected(self, result, error):
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith('rejected:'), result.stdout)
        self.assertIn(error, result.stdout)

    def test_valid_exchange_and_retry_preserve_protected_state(self):
        self.setup_journal()
        service = self.support / 'ProxyPilot/VPN'
        before = {name: (service / name).read_bytes() for name in
                  ('release.json', 'update.json', 'activation.json')}
        first = self.invoke('exchange')
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertIn('result:exchanged:phase=replacementPending:revision=1:selected=10', first.stdout)
        self.assertEqual(self.identities(), self.initial[::-1])
        self.assertTrue((self.apps / 'factory-marker').exists())
        self.assertTrue((self.apps / 'drain-marker').exists())
        self.assertFalse((self.apps / 'start-marker').exists())
        (self.apps / 'factory-marker').unlink(); (self.apps / 'drain-marker').unlink()
        retry = self.invoke('exchange')
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertIn('result:already:phase=replacementPending:revision=1:selected=10', retry.stdout)
        self.assertTrue((self.apps / 'factory-marker').exists())
        self.assertTrue((self.apps / 'drain-marker').exists())
        self.assertFalse((self.apps / 'start-marker').exists())
        self.assertEqual(self.executor_identity,
                         (self.executor.stat().st_ino,
                          (self.executor / 'ProxyPilot.app').stat().st_ino,
                          self.runner_a.read_bytes()))
        failed_retry = self.invoke('drain-fail')
        self.assert_rejected(failed_retry, 'commitUncertain')
        self.assertEqual(self.identities(), self.initial[::-1])
        self.assertEqual(before, {name: (service / name).read_bytes() for name in before})

    def test_full_disk_install_and_retry_remain_journal_pending(self):
        self.setup_journal()
        first = self.invoke('install')
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertIn('result:exchanged:phase=replacementPending:revision=1:selected=10', first.stdout)
        self.assertEqual(self.identities(), self.initial[::-1])
        self.assertEqual(self.code_pins(self.destination / 'ProxyPilot.app'), self.b)
        retained = self.destination / '.ProxyPilot.vpn-update/ProxyPilot.app'
        self.assertEqual(self.code_pins(retained), self.a)
        self.assertEqual((self.apps / 'drain-marker').read_text(), '1')
        self.assertEqual((self.destination / 'Other.app/sentinel').read_text(), 'untouched')
        (self.apps / 'drain-marker').unlink()
        retry = self.invoke('install')
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertIn('result:already:phase=replacementPending:revision=1:selected=10', retry.stdout)
        self.assertEqual((self.apps / 'drain-marker').read_text(), '1')
        self.assertEqual(self.code_pins(self.destination / 'ProxyPilot.app'), self.b)
        self.assertEqual(self.code_pins(retained), self.a)

    def test_prepared_executor_begins_replacement_under_one_lease(self):
        self.setup_journal('setup-prepared')
        result = self.invoke('install-begin')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('result:exchanged:phase=replacementPending:revision=1:selected=10',
                      result.stdout)
        self.assertEqual((self.apps / 'drain-marker').read_text(), '1')
        self.assertEqual(self.code_pins(self.destination / 'ProxyPilot.app'), self.b)
        self.assertEqual((self.destination / 'Other.app/sentinel').read_text(), 'untouched')

    def test_selected_desired_off_completes_without_starting_helper(self):
        self.setup_journal('setup-selected')
        result = self.invoke('finalize-off')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'finalized:off:phase=completed:revision=3')
        self.assertFalse((self.apps / 'start-marker').exists())

    def test_successful_finalization_retires_the_terminal_journal(self):
        self.setup_journal('setup-selected')
        result = self.invoke('finalize-and-retire-off')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'finalized:off:journal=retired')
        self.assertFalse((self.apps / 'start-marker').exists())

    def test_selected_desired_on_start_failure_cleans_up_and_stays_selected(self):
        self.setup_journal('setup-selected-on')
        result = self.invoke('finalize-on-start-fail')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn('launchFailed', result.stdout)
        service = self.support / 'ProxyPilot/VPN'
        record = __import__('json').loads((service / 'update.json').read_text())
        self.assertEqual((record['phase'], record['revision']), ('selected', 2))
        self.assertTrue((self.apps / 'start-marker').exists())
        self.assertTrue((self.apps / 'drain-marker').exists())
        self.assertEqual((self.apps / 'drain-marker').read_text(), '1')

    def test_selected_off_recovers_forward_and_retires_journal(self):
        self.setup_journal('setup-selected')
        result = self.invoke('recover-selected-off')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'recovered:off:journal=retired:selected=11')
        self.assertFalse((self.apps / 'start-marker').exists())

    def test_selector_commit_crash_recovers_forward_and_retires_journal(self):
        self.setup_selector_crash()
        result = self.invoke('recover-selector-crash-off')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'recovered:off:journal=retired:selected=11')
        self.assertFalse((self.apps / 'start-marker').exists())

    def test_completed_off_is_drained_before_terminal_retirement(self):
        self.setup_journal('setup-completed')
        result = self.invoke('recover-completed-off')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'recovered:off:journal=retired:selected=11')
        self.assertFalse((self.apps / 'start-marker').exists())
        self.assertEqual((self.apps / 'drain-marker').read_text(), '1')

    def test_recovery_refuses_nonterminal_journal_before_runtime_effects(self):
        self.setup_journal('setup-prepared')
        result = self.invoke('recover-prepared')
        self.assert_rejected(result, 'invalidJournal')
        self.assert_no_effect()

    def test_selected_on_recovery_failure_keeps_forward_retry_journal(self):
        self.setup_journal('setup-selected-on')
        result = self.invoke('recover-selected-on-start-fail')
        self.assert_rejected(result, 'launchFailed')
        service = self.support / 'ProxyPilot/VPN'
        record = __import__('json').loads((service / 'update.json').read_text())
        self.assertEqual((record['phase'], record['revision']), ('selected', 2))
        self.assertTrue((self.apps / 'start-marker').exists())
        self.assertEqual((self.apps / 'drain-marker').read_text(), '1')

    def test_completed_on_recovery_failure_does_not_retire_journal(self):
        self.setup_journal('setup-completed-on')
        result = self.invoke('recover-completed-on-start-fail')
        self.assert_rejected(result, 'launchFailed')
        service = self.support / 'ProxyPilot/VPN'
        record = __import__('json').loads((service / 'update.json').read_text())
        self.assertEqual((record['phase'], record['revision']), ('completed', 3))
        self.assertTrue((self.apps / 'start-marker').exists())
        self.assertEqual((self.apps / 'drain-marker').read_text(), '2')

    def test_context_refusals_precede_runtime_and_namespace_effects(self):
        for setup, operation in (('setup', 'wrong-uuid'), ('setup', 'wrong-revision'),
                                 ('setup-prepared', 'exchange'), ('setup-selected', 'exchange')):
            with self.subTest(setup=setup, operation=operation):
                self.setUp(); self.setup_journal(setup)
                result = self.invoke(operation)
                expected = 'staleRevision' if operation.startswith('wrong-') else 'invalidUpdateJournal'
                self.assert_rejected(result, expected)
                self.assert_no_effect()

    def test_wrong_process_and_invalid_candidate_never_drain(self):
        self.setup_journal()
        for executable in (self.runner_b, self.runner_updater):
            denied = self.invoke('exchange', executable=executable)
            self.assert_rejected(denied, 'denied')
            self.assert_no_effect()
        (self.candidate / 'ProxyPilot.app/Contents/Resources/data.txt').write_text('corrupt')
        invalid = self.invoke('exchange')
        self.assert_rejected(invalid, 'invalidLayout')
        self.assert_no_effect()

    def test_external_exact_a_and_unsafe_executor_slots_are_refused_before_factory(self):
        self.setup_journal()
        external = self.invoke('exchange', executable=self.runner_external_a)
        self.assert_rejected(external, 'unsafeExecutor')
        self.assert_no_effect()
        self.executor.chmod(0o755)
        unsafe = self.invoke('exchange')
        self.assert_rejected(unsafe, 'unsafeExecutor')
        self.assert_no_effect()

    def test_missing_symlink_and_corrupt_executor_are_refused_before_factory(self):
        for mutation, error in (('missing', 'unsafeExecutor'), ('symlink', 'unsafeExecutor'),
                                ('corrupt', 'invalidSignature')):
            with self.subTest(mutation=mutation):
                self.setUp(); self.setup_journal()
                executable = self.runner_external_a
                if mutation == 'missing':
                    shutil.rmtree(self.executor)
                elif mutation == 'symlink':
                    target = self.work / 'executor-target'
                    self.executor.rename(target); self.executor.symlink_to(target, target_is_directory=True)
                else:
                    (self.executor / 'ProxyPilot.app/Contents/Resources/data.txt').write_text('corrupt')
                    executable = self.runner_a
                result = self.invoke('exchange', executable=executable)
                self.assert_rejected(result, error)
                self.assert_no_effect()

    def test_lifecycle_namespace_and_production_guards_precede_effects(self):
        self.setup_journal()
        for operation, error in (('service-busy', 'busy'), ('namespace-busy', 'busy'),
                                 ('production', 'requiresRoot')):
            with self.subTest(operation=operation):
                result = self.invoke(operation)
                self.assert_rejected(result, error)
                self.assert_no_effect()

    def test_drain_failure_and_post_drain_rechecks_do_not_swap(self):
        for operation in ('drain-fail', 'lose-lease', 'corrupt-journal', 'mutate-tree',
                          'executor-corrupt', 'executor-replace'):
            with self.subTest(operation=operation):
                self.setUp(); self.setup_journal()
                result = self.invoke(operation)
                expected = {'drain-fail': 'cleanupNotConfirmed', 'lose-lease': 'lost',
                            'corrupt-journal': 'invalidUpdateJournal',
                            'mutate-tree': 'invalidSignature',
                            'executor-corrupt': 'invalidSignature',
                            'executor-replace': 'unsafeExecutor'}[operation]
                self.assert_rejected(result, expected)
                self.assertEqual(self.identities(), self.initial)
                self.assertTrue((self.apps / 'factory-marker').exists())
                self.assertTrue((self.apps / 'drain-marker').exists())
                self.assertFalse((self.apps / 'start-marker').exists())

    def test_post_exchange_executor_failure_is_uncertain_without_rollback(self):
        for operation in ('raw-after-executor-corrupt', 'raw-after-executor-replace'):
            with self.subTest(operation=operation):
                self.setUp(); self.setup_journal()
                result = self.invoke(operation)
                self.assert_rejected(result, 'commitUncertain')
                self.assertEqual(self.identities(), self.initial[::-1])
                self.assertFalse((self.apps / 'factory-marker').exists())
                self.assertFalse((self.apps / 'drain-marker').exists())
                self.assertFalse((self.apps / 'start-marker').exists())


def load_tests(loader, tests, pattern):
    names = [name for name in loader.getTestCaseNames(VPNJointReplacementTests)
             if name in VPNJointReplacementTests.__dict__]
    return unittest.TestSuite(VPNJointReplacementTests(name) for name in names)


if __name__ == '__main__': unittest.main()
