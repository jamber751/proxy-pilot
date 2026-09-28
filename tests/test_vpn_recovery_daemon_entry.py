"""Real ServiceMain/recover-update through disposable per-user launchd."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from tests import test_vpn_staged_application as staged

ROOT, HELPER, APP_ID, ENV = staged.ROOT, staged.HELPER, staged.APP_ID, staged.ENV


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNRecoveryDaemonEntryTests(unittest.TestCase):
    @classmethod
    def command(cls, args):
        result = subprocess.run(args, env=ENV, capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise AssertionError(' '.join(map(str, args)) + '\n' + result.stdout + result.stderr)
        return result

    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise unittest.SkipTest('Never run the recovery fixture as root')
        cls.temporary = tempfile.TemporaryDirectory(prefix='pp-recovery-entry-build-', dir='/tmp')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.build = Path(cls.temporary.name)
        source = cls.build / 'fixture.c'; source.write_text('int main(void) { return 86; }\n')
        cls.slices = {}
        for arch in ('arm64', 'x86_64'):
            cls.slices[arch] = cls.build / f'app-{arch}'
            cls.command(['clang', '-target', arch + '-apple-macosx11.0',
                         str(source), '-o', str(cls.slices[arch])])
        cls.universal = cls.build / 'app-universal'
        cls.command(['lipo', '-create', *map(str, cls.slices.values()),
                     '-output', str(cls.universal)])
        cls.domain = f'gui/{os.geteuid()}'
        if subprocess.run(['/bin/launchctl', 'print', cls.domain], capture_output=True,
                          timeout=60).returncode:
            raise unittest.SkipTest('no reachable per-user GUI launchd domain')
        components = [
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNReleaseTrust.swift',
            'VPNHelperArtifact.swift', 'VPNReleaseStore.swift', 'VPNDirectoryProvisioner.swift',
            'VPNEndpointDirectory.swift', 'VPNHelperProtocol.swift', 'VPNHelperReadiness.swift',
            'VPNHelperListener.swift', 'VPNProfileVault.swift', 'VPNLifecycleOwnership.swift',
            'VPNActivationBudget.swift', 'VPNActivationCoordinator.swift', 'VPNLaunchdRuntime.swift',
            'VPNRecoveryLaunchdJob.swift', 'VPNStagedApplication.swift', 'VPNInstalledApplication.swift',
            'VPNSelectedCandidateFinalizer.swift', 'VPNSelectedCandidateRecovery.swift',
            'VPNJointUpdateCleanup.swift', 'VPNHelperRuntime.swift', 'VPNHelperDaemon.swift',
            'VPNSelectedCandidateRecoveryDaemonEntry.swift', 'ServiceMain.swift',
        ]
        sources = [ROOT / 'app/VPNConfiguration.swift', ROOT / 'app/VPNProfileImporter.swift']
        sources += [HELPER / name for name in components]
        sources += [ROOT / 'tests/vpn_recovery_daemon_entry_checks.swift']
        flags = ['-D', 'VPN_RECOVERY_DAEMON_ENTRY', '-D', 'VPN_RECOVERY_DAEMON_TESTING',
                 '-D', 'VPN_DAEMON_TESTING', '-D', 'VPN_LAUNCHD_TESTING',
                 '-D', 'VPN_APPLICATION_DESTINATION_TESTING',
                 '-D', 'VPN_HELPER_READINESS_TESTING', '-D', 'VPN_HELPER_LISTENER_TESTING']
        helper_slices = []
        probe_slices = []
        probe_sources = [HELPER / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
            'VPNHelperProtocol.swift', 'VPNHelperReadiness.swift')]
        probe_sources.append(ROOT / 'tests/vpn_recovery_probe.swift')
        for arch in ('arm64', 'x86_64'):
            helper = cls.build / f'recovery-helper-{arch}'
            cls.command(['swiftc', '-O', '-parse-as-library', *flags,
                         '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(helper)])
            helper_slices.append(str(helper))
            probe = cls.build / f'recovery-probe-{arch}'
            cls.command(['swiftc', '-D', 'VPN_HELPER_READINESS_TESTING',
                         '-target', f'{arch}-apple-macosx11.0',
                         *map(str, probe_sources), '-o', str(probe)])
            probe_slices.append(str(probe))
        cls.recovery_helper = cls.build / 'recovery-helper'
        cls.recovery_probe = cls.build / 'recovery-probe'
        cls.command(['lipo', '-create', *helper_slices, '-output', str(cls.recovery_helper)])
        cls.command(['lipo', '-create', *probe_slices, '-output', str(cls.recovery_probe)])
        cls.recovery_helper.chmod(0o700)
        cls.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                     '--identifier', 'kz.documentolog.proxypilot.vpn-helper',
                     str(cls.recovery_helper)])
        cls.helper_pins = cls.code_pins(cls.recovery_helper)

    @classmethod
    def code_pins(cls, path):
        pins = {}
        for arch in ('arm64', 'x86_64'):
            result = cls.command(['codesign', '-d', '--verbose=4', '--arch', arch, str(path)])
            pins[arch] = re.search(r'^CDHash=([a-f0-9]{40})$', result.stderr, re.M).group(1)
        return pins

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-recovery-entry-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.stage = self.work / 'stage'; self.stage.mkdir(mode=0o700)
        self.app = self.stage / 'ProxyPilot.app'
        staged.VPNStagedApplicationTests.make_app(self)
        self.previous_pins = self.pins()
        previous_app = self.work / 'Previous.app'
        shutil.copytree(self.app, previous_app, symlinks=True)
        self.rebuild(version='1.7.0')
        executable = self.app / 'Contents/MacOS/ProxyPilot'
        shutil.copyfile(self.recovery_probe, executable)
        executable.chmod(0o755)
        self.sign(executable, APP_ID)
        self.sign(self.app, APP_ID)
        self.candidate_pins = self.pins()
        self.root = self.work / 'recovery-root'; self.root.mkdir(mode=0o700)
        self.storage = self.root / 'store'; self.storage.mkdir(mode=0o700)
        self.applications = self.root / 'Applications'; self.applications.mkdir(mode=0o700)
        self.plists = self.root / 'plists'; self.plists.mkdir(mode=0o755)
        early_state = {
            'test_prepared_a_is_reconciled_without_advancing_the_journal':
                ('fixture-prepare-prepared', True),
            'test_pending_a_is_reconciled_without_selecting_candidate':
                ('fixture-prepare-pending-a', True),
            'test_pending_b_recovers_forward_without_a_live_updater':
                ('fixture-prepare-pending-b', False),
            'test_prepared_recovery_waits_for_the_lifecycle_lease':
                ('fixture-prepare-prepared', True),
            'test_cancelled_early_recovery_job_disarms':
                ('fixture-prepare-cancelled', True),
        }.get(self._testMethodName)
        if early_state and early_state[1]:
            shutil.move(str(previous_app), self.applications / 'ProxyPilot.app')
        else:
            shutil.move(str(self.app), self.applications / 'ProxyPilot.app')
        storage_identity = self.storage.stat()
        identity = f'{storage_identity.st_dev}:{storage_identity.st_ino}'
        suffix = hashlib.sha256(identity.encode()).hexdigest()[:16]
        self.helper_label = f'kz.documentolog.proxypilot.vpn-helper.e2e-{suffix}'
        self.recovery_label = f'kz.documentolog.proxypilot.vpn-recovery.e2e-{suffix}'
        self.addCleanup(self.boot_out, self.helper_label)
        self.addCleanup(self.boot_out, self.recovery_label)
        prepare_action = (early_state[0] if early_state else
            ('fixture-prepare-off'
             if self._testMethodName == 'test_retired_cleanup_transient_failure_retries_and_disarms'
             else 'fixture-prepare'))
        prepared = self.run_helper(prepare_action, str(self.storage),
            self.previous_pins['arm64'], self.previous_pins['x86_64'],
            self.candidate_pins['arm64'], self.candidate_pins['x86_64'],
            self.helper_pins['arm64'], self.helper_pins['x86_64'])
        expected = {
            'fixture-prepare-prepared': 'prepared:prepared:0',
            'fixture-prepare-pending-a': 'prepared:replacementPending:1',
            'fixture-prepare-pending-b': 'prepared:replacementPending:1',
            'fixture-prepare-cancelled': 'prepared:cancelled:1',
        }.get(prepare_action, 'prepared:selected:2')
        self.assertEqual(prepared.stdout.strip(), expected, prepared.stdout + prepared.stderr)

    def make_app(self, **options):
        return staged.VPNStagedApplicationTests.make_app(self, **options)

    def rebuild(self, **options):
        return staged.VPNStagedApplicationTests.rebuild(self, **options)

    def sign(self, path, identifier, entitlements=None):
        return staged.VPNStagedApplicationTests.sign(self, path, identifier, entitlements)

    def pins(self):
        return staged.VPNStagedApplicationTests.pins(self)

    def run_helper(self, *arguments, timeout=60):
        return subprocess.run([str(self.recovery_helper), *arguments], env=ENV,
                              capture_output=True, text=True, timeout=timeout)

    def boot_out(self, label):
        subprocess.run(['/bin/launchctl', 'bootout', f'{self.domain}/{label}'],
                       capture_output=True, timeout=60)

    def loaded(self, label):
        return subprocess.run(['/bin/launchctl', 'print', f'{self.domain}/{label}'],
                              capture_output=True, text=True, timeout=60).returncode == 0

    def wait_recovered(self, timeout=25):
        deadline = time.monotonic() + timeout
        journal = self.storage / 'update.json'
        while time.monotonic() < deadline:
            if not journal.exists() and self.loaded(self.helper_label):
                return
            time.sleep(0.05)
        recovery = subprocess.run(['/bin/launchctl', 'print', f'{self.domain}/{self.recovery_label}'],
                                  capture_output=True, text=True, timeout=60)
        error = self.storage / 'fixture-error.txt'
        self.fail(f'journal={journal.exists()} helper={self.loaded(self.helper_label)} '
                  f'error={error.read_text() if error.exists() else "none"}\n{recovery.stdout}')

    def assert_terminal_state(self):
        envelope = json.loads((self.storage / 'release.json').read_text())
        payload = base64.b64decode(envelope['payload']).decode()
        self.assertIn('sequence=11\n', payload)
        self.assertFalse((self.storage / 'update.json').exists())
        budget = json.loads((self.storage / 'activation.json').read_text())
        self.assertEqual((budget['desired'], budget['failures']), (True, 0))
        self.assertTrue(self.loaded(self.helper_label))

    def wait_recovery_cleanup(self):
        description = self.plists / f'{self.recovery_label}.plist'
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if not self.loaded(self.recovery_label) and not description.exists():
                break
            time.sleep(0.05)
        self.assertFalse(self.loaded(self.recovery_label))
        self.assertFalse(description.exists())
        self.assertTrue(self.loaded(self.helper_label))

    def wait_source_reconciled(self, phase, revision, timeout=25):
        deadline = time.monotonic() + timeout
        description = self.plists / f'{self.recovery_label}.plist'
        journal_path = self.storage / 'update.json'
        while time.monotonic() < deadline:
            journal = json.loads(journal_path.read_text())
            if (journal['phase'] == phase and journal['revision'] == revision
                    and self.loaded(self.helper_label)
                    and not self.loaded(self.recovery_label)
                    and not description.exists()):
                break
            time.sleep(0.05)
        journal = json.loads(journal_path.read_text())
        self.assertEqual((journal['phase'], journal['revision']), (phase, revision))
        envelope = json.loads((self.storage / 'release.json').read_text())
        self.assertIn('sequence=10\n', base64.b64decode(envelope['payload']).decode())
        self.assertTrue(self.loaded(self.helper_label))
        self.assertFalse(self.loaded(self.recovery_label))
        self.assertFalse(description.exists())
        budget = json.loads((self.storage / 'activation.json').read_text())
        self.assertEqual((budget['desired'], budget['failures']), (True, 0))

    def test_desired_on_recovery_runs_real_service_entry_through_launchd(self):
        armed = self.run_helper('fixture-arm', str(self.storage))
        self.assertEqual(armed.stdout.strip(), 'armed', armed.stdout + armed.stderr)
        self.wait_recovered()
        self.assert_terminal_state()
        self.wait_recovery_cleanup()

    def test_prepared_a_is_reconciled_without_advancing_the_journal(self):
        armed = self.run_helper('fixture-arm', str(self.storage))
        self.assertEqual(armed.stdout.strip(), 'armed', armed.stdout + armed.stderr)
        self.wait_source_reconciled('prepared', 0)

    def test_pending_a_is_reconciled_without_selecting_candidate(self):
        armed = self.run_helper('fixture-arm', str(self.storage))
        self.assertEqual(armed.stdout.strip(), 'armed', armed.stdout + armed.stderr)
        self.wait_source_reconciled('replacementPending', 1)

    def test_pending_b_recovers_forward_without_a_live_updater(self):
        armed = self.run_helper('fixture-arm', str(self.storage))
        self.assertEqual(armed.stdout.strip(), 'armed', armed.stdout + armed.stderr)
        self.wait_recovered()
        self.assert_terminal_state()
        self.wait_recovery_cleanup()

    def test_prepared_recovery_waits_for_the_lifecycle_lease(self):
        holder = subprocess.Popen(
            [str(self.recovery_helper), 'fixture-arm-held', str(self.storage)],
            env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup_holder():
            if holder.poll() is None:
                holder.kill()
            if not holder.stdout.closed and not holder.stderr.closed:
                holder.communicate()
        self.addCleanup(cleanup_holder)
        self.assertEqual(holder.stdout.readline().strip(), 'armed:held')
        deadline = time.monotonic() + 5
        state = ''
        while time.monotonic() < deadline:
            state = subprocess.run(
                ['/bin/launchctl', 'print', f'{self.domain}/{self.recovery_label}'],
                capture_output=True, text=True, timeout=60).stdout
            if 'last exit code = 75' in state:
                break
            time.sleep(0.05)
        self.assertIn('last exit code = 75', state)
        self.assertEqual(holder.wait(timeout=10), 0, holder.stderr.read())
        holder.stdout.close(); holder.stderr.close()
        self.wait_source_reconciled('prepared', 0, timeout=30)

    def test_cancelled_early_recovery_job_disarms(self):
        armed = self.run_helper('fixture-arm', str(self.storage))
        self.assertEqual(armed.stdout.strip(), 'armed', armed.stdout + armed.stderr)
        description = self.plists / f'{self.recovery_label}.plist'
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if not self.loaded(self.recovery_label) and not description.exists():
                break
            time.sleep(0.05)
        self.assertFalse(self.loaded(self.recovery_label))
        self.assertFalse(description.exists())
        journal = json.loads((self.storage / 'update.json').read_text())
        self.assertEqual((journal['phase'], journal['revision']), ('cancelled', 1))

    def test_exit_75_is_retried_after_the_lifecycle_lease_is_released(self):
        holder = subprocess.Popen([str(self.recovery_helper), 'fixture-arm-held', str(self.storage)],
                                  env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def cleanup_holder():
            if holder.poll() is None:
                holder.kill()
            if not holder.stdout.closed and not holder.stderr.closed:
                holder.communicate()
        self.addCleanup(cleanup_holder)
        self.assertEqual(holder.stdout.readline().strip(), 'armed:held')
        deadline = time.monotonic() + 5
        saw_temporary_failure = False
        while time.monotonic() < deadline:
            state = subprocess.run(['/bin/launchctl', 'print', f'{self.domain}/{self.recovery_label}'],
                                   capture_output=True, text=True, timeout=60).stdout
            if 'last exit code = 75' in state:
                saw_temporary_failure = True
                break
            time.sleep(0.05)
        self.assertTrue(saw_temporary_failure, state)
        self.assertEqual(holder.wait(timeout=10), 0, holder.stderr.read())
        holder.stdout.close(); holder.stderr.close()
        self.wait_recovered(timeout=30)
        self.assert_terminal_state()
        self.wait_recovery_cleanup()

    def test_retired_cleanup_transient_failure_retries_and_disarms(self):
        injection = self.storage / 'inject-cleanup-once'
        injection.write_text('fail once')
        armed = self.run_helper('fixture-arm', str(self.storage))
        self.assertEqual(armed.stdout.strip(), 'armed', armed.stdout + armed.stderr)
        deadline = time.monotonic() + 8
        saw_temporary_failure = False
        state = ''
        while time.monotonic() < deadline:
            state = subprocess.run(['/bin/launchctl', 'print', f'{self.domain}/{self.recovery_label}'],
                                   capture_output=True, text=True, timeout=60).stdout
            if 'last exit code = 75' in state:
                saw_temporary_failure = True
                break
            time.sleep(0.05)
        self.assertTrue(saw_temporary_failure, state)
        self.assertFalse((self.storage / 'update.json').exists())
        self.assertFalse(injection.exists())
        self.assertFalse((self.storage / 'cleanup-complete').exists())
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if ((self.storage / 'cleanup-complete').exists()
                    and not self.loaded(self.recovery_label)):
                break
            time.sleep(0.05)
        self.assertTrue((self.storage / 'cleanup-complete').exists())
        self.assertFalse(self.loaded(self.recovery_label))
        self.assertFalse((self.plists / f'{self.recovery_label}.plist').exists())
        envelope = json.loads((self.storage / 'release.json').read_text())
        self.assertIn('sequence=11\n', base64.b64decode(envelope['payload']).decode())
        budget = json.loads((self.storage / 'activation.json').read_text())
        self.assertEqual((budget['desired'], budget['failures']), (False, 0))
        self.assertFalse(self.loaded(self.helper_label))


if __name__ == '__main__':
    unittest.main()
