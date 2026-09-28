"""The installation sequence end to end, without root.

A disposable base directory stands in for /Library/Application Support and the
user's own launchd domain for the system domain. Every test boots its label out.
Proving the order and the refusals is not proof of a privileged system install.
"""
import fcntl
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
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'app/vpn-helper'
COMPONENTS = ['VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperProtocol.swift',
              'VPNHelperReadiness.swift', 'VPNHelperSession.swift',
              'VPNHelperArtifact.swift', 'VPNReleaseStore.swift', 'VPNLifecycleOwnership.swift',
              'VPNDirectoryProvisioner.swift', 'VPNLaunchdRuntime.swift', 'VPNRecoveryLaunchdJob.swift',
              'VPNActivationBudget.swift', 'VPNActivationCoordinator.swift', 'VPNProfileVault.swift',
              'VPNStagedApplication.swift', 'VPNApplicationDestinationStage.swift',
              'VPNJointUpdateCleanup.swift',
              'VPNInstaller.swift', 'VPNEndpointDirectory.swift']
SERVICE = ['VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperArtifact.swift',
           'VPNReleaseStore.swift', 'VPNHelperProtocol.swift', 'VPNProfileVault.swift',
           'VPNHelperListener.swift', 'VPNEndpointDirectory.swift']
# The helper re-validates profiles with the application's own importer.
IMPORTER = [ROOT / 'app/VPNConfiguration.swift', ROOT / 'app/VPNProfileImporter.swift']
SEAMS = ['-D', 'VPN_HELPER_READINESS_TESTING', '-D', 'VPN_LAUNCHD_TESTING', '-D', 'VPN_INSTALLER_TESTING']


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNInstallerTests(unittest.TestCase):
    service_components = SERVICE
    service_main = ROOT / 'tests/vpn_helper_service.swift'
    service_flags = []

    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise unittest.SkipTest('Never run the installation fixture as root')
        cls.domain = f'gui/{os.geteuid()}'
        if subprocess.run(['/bin/launchctl', 'print', cls.domain], capture_output=True, timeout=60).returncode:
            raise unittest.SkipTest('no reachable per-user GUI launchd domain')
        cls.build = tempfile.TemporaryDirectory(prefix='pp-ins-build-', dir='/tmp')
        cls.addClassCleanup(cls.build.cleanup)
        cls.work = Path(cls.build.name)
        for name, sources, flags in [
            ('installer', [HELPER / source for source in COMPONENTS] + [ROOT / 'tests/vpn_installer_checks.swift'], SEAMS),
            ('server', [HELPER / source for source in cls.service_components] + IMPORTER
             + [cls.service_main], cls.service_flags),
        ]:
            slices = []
            for arch in ('arm64', 'x86_64'):
                output = cls.work / f'{name}-{arch}'
                cls.command(['swiftc', *flags, '-D', 'VPN_ENGINE_DELIVERY_TESTING', '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(output)])
                slices.append(str(output))
            cls.command(['lipo', '-create', *slices, '-output', str(cls.work / name)])
        # The installer must also compile without any of its test seams.
        for arch in ('arm64', 'x86_64'):
            cls.command(['swiftc', '-emit-library', '-target', f'{arch}-apple-macosx11.0',
                         *[str(HELPER / source) for source in COMPONENTS], '-o', str(cls.work / f'production-{arch}.dylib')])
        asan_slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.work / f'installer-asan-{arch}'
            cls.command(['swiftc', *SEAMS, '-D', 'VPN_ENGINE_DELIVERY_TESTING', '-sanitize=address',
                         '-target', f'{arch}-apple-macosx11.0',
                         *[str(HELPER / source) for source in COMPONENTS],
                         str(ROOT / 'tests/vpn_installer_checks.swift'), '-o', str(output)])
            asan_slices.append(str(output))
        cls.command(['lipo', '-create', *asan_slices, '-output', str(cls.work / 'installer-asan')])
        for revision in (1, 2):
            slices = []
            for arch in ('arm64', 'x86_64'):
                output = cls.work / f'engine-{revision}-{arch}'
                cls.command(['clang', '-target', f'{arch}-apple-macosx11.0', f'-DFIXTURE_REVISION={revision}',
                             str(ROOT / 'tests/vpn-deployment/HelperFixture.c'), '-o', str(output)])
                slices.append(str(output))
            cls.command(['lipo', '-create', *slices, '-output', str(cls.work / f'engine-v{revision}')])
        shutil.copyfile(cls.work / 'engine-v1', cls.work / 'engine-weak')
        cls.pins = {}
        for name, identifier, options in [
            ('server', 'kz.documentolog.proxypilot.vpn-helper', 'runtime,hard,kill'),
            ('installer', 'kz.documentolog.proxypilot', 'runtime,hard,kill'),
            ('installer-asan', 'kz.documentolog.proxypilot', 'runtime,hard,kill'),
            ('installer-next', 'kz.documentolog.proxypilot', 'runtime,hard,kill,restrict'),
            # Stronger than the real worker: even a hardened worker with signed
            # matching pins must not acquire the app's installer identity.
            ('updater', 'kz.documentolog.proxypilot.updater', 'runtime,hard,kill'),
            ('engine-v1', 'kz.documentolog.proxypilot.openvpn', 'runtime,hard,kill'),
            ('engine-v2', 'kz.documentolog.proxypilot.openvpn', 'runtime,hard,kill'),
            ('engine-weak', 'kz.documentolog.proxypilot.openvpn', 'runtime'),
        ]:
            if name in ('installer-next', 'updater'):
                shutil.copyfile(cls.work / 'installer', cls.work / name)
                cls.command(['codesign', '--remove-signature', str(cls.work / name)])
            (cls.work / name).chmod(0o700)
            cls.command(['codesign', '--force', '--sign', '-', '--identifier', identifier,
                         '--options', options, str(cls.work / name)])
            cls.pins[name] = {}
            for arch in ('arm64', 'x86_64'):
                result = cls.command(['codesign', '-d', '--verbose=4', '--arch', arch, str(cls.work / name)])
                cls.pins[name][arch] = re.search(r'^CDHash=([a-f0-9]{40})$', result.stderr, re.M).group(1)

    @staticmethod
    def command(args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise AssertionError(' '.join(map(str, args)) + '\n' + result.stdout + result.stderr)
        return result

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pp-ins-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.support = self.base / 'support'
        self.support.mkdir(mode=0o755)
        self.storage = self.support / 'ProxyPilot' / 'VPN'
        self.plists = self.base / 'plists'
        self.plists.mkdir(mode=0o755)
        self.label = f'kz.documentolog.proxypilot.vpn-helper.test-{uuid.uuid4().hex}'
        self.addCleanup(self.boot_out)

    def boot_out(self):
        subprocess.run(['/bin/launchctl', 'bootout', f'{self.domain}/{self.label}'], capture_output=True, timeout=60)

    def loaded(self):
        return subprocess.run(['/bin/launchctl', 'print', f'{self.domain}/{self.label}'],
                              capture_output=True, timeout=60).returncode == 0

    def run_installer(self, action='install', sequence=10, expected=0, *, executable='installer', app_build=None,
                      engine=None, omit_engine=False, tamper_engine=False):
        artifact = (self.work / 'server').read_bytes()
        app_pins = self.pins[app_build or executable]
        fields = {'format': 1, 'product': 'kz.documentolog.proxypilot', 'sequence': sequence,
                  'version': '1.6.0', 'protocol': 1,
                  'app-arm64': app_pins['arm64'], 'app-x86_64': app_pins['x86_64'],
                  'helper-arm64': self.pins['server']['arm64'], 'helper-x86_64': self.pins['server']['x86_64'],
                  'helper-sha256': hashlib.sha256(artifact).hexdigest(), 'helper-bytes': len(artifact)}
        if engine:
            data = (self.work / engine).read_bytes()
            fields['format'] = 2
            fields.update({'engine-version': '2.7.7', 'engine-crypto-version': '3.5.8',
                           'engine-arm64': self.pins[engine]['arm64'], 'engine-x86_64': self.pins[engine]['x86_64'],
                           'engine-sha256': hashlib.sha256(data).hexdigest(), 'engine-bytes': len(data)})
        manifest, candidate = self.base / 'manifest', self.base / 'candidate'
        manifest.write_text(''.join(f'{key}={value}\n' for key, value in fields.items()))
        candidate.write_bytes(artifact)
        arguments = [str(self.work / executable), action, str(self.support), str(manifest),
                     str(candidate), str(expected), self.label, str(self.plists)]
        if engine and not omit_engine:
            engine_path = self.base / 'engine-candidate'
            engine_path.write_bytes(data + b'tampered' if tamper_engine else data)
            arguments.append(str(engine_path))
        if action.startswith('prepare'):
            previous_envelope = json.loads((self.storage / 'release.json').read_text())
            previous = base64.b64decode(previous_envelope['payload'])
            edge_fields = {
                'format': 1, 'product': 'kz.documentolog.proxypilot',
                'from-sequence': expected, 'from-sha256': hashlib.sha256(previous).hexdigest(),
                'to-sequence': sequence, 'to-sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
            }
            transition = self.base / 'transition'
            transition.write_text(''.join(f'{key}={value}\n' for key, value in edge_fields.items()))
            arguments.insert(8, str(transition))
        return subprocess.run(arguments, capture_output=True, text=True, timeout=120)

    def engine_name(self, engine='engine-v1'):
        return 'engine-' + hashlib.sha256((self.work / engine).read_bytes()).hexdigest()

    def test_engine_installation_selects_complete_set_without_running_engine(self):
        result = self.run_installer(engine='engine-v1')
        self.assertEqual(result.stdout.strip(), 'ready:10', result.stdout + result.stderr)
        selected = self.storage / self.engine_name()
        self.assertEqual(selected.read_bytes(), (self.work / 'engine-v1').read_bytes())
        self.assertEqual(selected.stat().st_mode & 0o7777, 0o700)
        self.assertTrue(self.loaded())

    def test_engine_missing_or_tampered_initial_input_creates_nothing(self):
        for options in [dict(omit_engine=True), dict(tamper_engine=True)]:
            result = self.run_installer(engine='engine-v1', **options)
            self.assertEqual(result.stdout.strip(), 'rejected:invalidEngineArtifact', result.stdout + result.stderr)
            self.assertFalse((self.support / 'ProxyPilot').exists())
            self.assertFalse(self.loaded())

    def test_engine_update_refusal_preserves_running_pid_policy_and_budget(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        before = self.running_snapshot()
        for options in [dict(engine='engine-v1', omit_engine=True), dict(engine='engine-v1', tamper_engine=True),
                        dict(engine='engine-weak')]:
            result = self.run_installer('update', sequence=11, expected=10, **options)
            self.assertEqual(result.stdout.strip(), 'rejected:invalidEngineArtifact', result.stdout + result.stderr)
            self.assertEqual(self.running_snapshot(), before)

    def test_engine_upgrade_retry_and_removal_include_retained_versions(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        for sequence, expected, engine in [(11, 10, 'engine-v1'), (11, 11, 'engine-v1'), (12, 11, 'engine-v2')]:
            result = self.run_installer('update', sequence=sequence, expected=expected, engine=engine)
            self.assertEqual(result.stdout.strip(), f'ready:{sequence}', result.stdout + result.stderr)
        self.assertTrue((self.storage / self.engine_name()).exists())
        self.assertTrue((self.storage / self.engine_name('engine-v2')).exists())
        result = self.run_installer('uninstall')
        self.assertEqual(result.stdout.strip(), 'uninstalled', result.stdout + result.stderr)
        self.assertFalse(self.loaded())
        self.assertFalse((self.support / 'ProxyPilot').exists())

    def test_engine_uninstall_keeps_unknown_lookalike_and_service_running(self):
        self.assertEqual(self.run_installer(engine='engine-v1').stdout.strip(), 'ready:10')
        (self.storage / 'engine-not-ours').write_text('keep')
        before = self.running_snapshot()
        result = self.run_installer('uninstall')
        self.assertEqual(result.stdout.strip(), 'rejected:unexpectedContent', result.stdout + result.stderr)
        self.assertEqual(self.running_snapshot(), before)

    def test_installation_provisions_storage_and_starts_the_service(self):
        result = self.run_installer()
        self.assertEqual(result.stdout.strip(), 'ready:10', result.stdout + result.stderr)
        for directory in (self.support / 'ProxyPilot', self.storage):
            self.assertEqual(directory.stat().st_mode & 0o7777, 0o700)
        self.assertTrue((self.storage / 'release.json').exists())
        self.assertTrue((self.storage / 'helper.sock').is_socket())
        self.assertTrue(self.loaded())

    def test_a_second_installation_is_refused_and_leaves_the_service_alone(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        result = self.run_installer()
        self.assertEqual(result.stdout.strip(), 'rejected:alreadyInstalled', result.stdout + result.stderr)
        self.assertTrue(self.loaded())

    def test_an_unsigned_release_installs_nothing(self):
        result = self.run_installer('install-bad-signature')
        self.assertIn('rejected:', result.stdout)
        self.assertFalse((self.storage / 'release.json').exists())
        self.assertFalse(self.loaded())
        self.assertFalse((self.support / 'ProxyPilot').exists())

    def running_snapshot(self):
        result = self.command(['/bin/launchctl', 'print', f'{self.domain}/{self.label}'])
        pid = re.search(r'^\s*pid = (\d+)\s*$', result.stdout, re.M)
        self.assertIsNotNone(pid, result.stdout)
        files = {path.name: path.read_bytes() for path in self.storage.iterdir() if path.is_file()}
        return pid.group(1), files

    def test_unlisted_installer_is_refused_before_provisioning(self):
        result = self.run_installer(app_build='installer-next')
        self.assertEqual(result.stdout.strip(), 'rejected:denied', result.stdout + result.stderr)
        self.assertFalse((self.support / 'ProxyPilot').exists())
        self.assertFalse(self.loaded())

    def test_old_app_cannot_replace_policy_or_stop_service_for_new_app(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        before = self.running_snapshot()
        result = self.run_installer('update', sequence=11, expected=10, app_build='installer-next')
        self.assertEqual(result.stdout.strip(), 'rejected:denied', result.stdout + result.stderr)
        self.assertEqual(self.running_snapshot(), before)

    def test_updater_identity_is_refused_even_if_its_hashes_were_signed(self):
        result = self.run_installer(executable='updater')
        self.assertEqual(result.stdout.strip(), 'rejected:denied', result.stdout + result.stderr)
        self.assertFalse((self.support / 'ProxyPilot').exists())
        self.assertFalse(self.loaded())

    def test_separately_pinned_new_app_can_advance_but_old_app_cannot_follow(self):
        self.assertNotEqual(self.pins['installer'], self.pins['installer-next'])
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        before = self.running_snapshot()
        result = self.run_installer('update', sequence=11, expected=10, executable='installer-next')
        self.assertEqual(result.stdout.strip(), 'ready:11', result.stdout + result.stderr)
        after = self.running_snapshot()
        self.assertNotEqual(before[0], after[0])
        self.assertNotEqual(before[1]['release.json'], after[1]['release.json'])
        result = self.run_installer('update', sequence=12, expected=11, app_build='installer-next')
        self.assertEqual(result.stdout.strip(), 'rejected:denied', result.stdout + result.stderr)
        self.assertEqual(self.running_snapshot(), after)

    def test_matching_new_app_identity_does_not_bypass_expected_revision(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        before = self.running_snapshot()
        result = self.run_installer('update', sequence=11, expected=9, executable='installer-next')
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.running_snapshot(), before)

    def test_update_replaces_the_installed_release(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        result = self.run_installer('update', sequence=11, expected=10)
        self.assertEqual(result.stdout.strip(), 'ready:11', result.stdout + result.stderr)
        self.assertTrue(self.loaded())

    def test_old_app_prepares_candidate_only_pins_without_touching_running_a(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        before = self.running_snapshot()
        result = self.run_installer('prepare', sequence=11, expected=10, app_build='installer-next')
        self.assertEqual(result.stdout.strip(), 'prepared:10->11 phase:prepared', result.stdout + result.stderr)
        after = self.running_snapshot()
        self.assertEqual(after[0], before[0])
        self.assertEqual(after[1]['release.json'], before[1]['release.json'])
        self.assertEqual(after[1]['activation.json'], before[1]['activation.json'])
        self.assertIn('update.json', after[1])
        self.assertEqual(self.run_installer('probe').stdout.strip(), 'ready:10')
        ordinary = self.run_installer('update', sequence=11, expected=10, app_build='installer-next')
        self.assertEqual(ordinary.stdout.strip(), 'rejected:denied', ordinary.stdout + ordinary.stderr)

    def test_candidate_and_updater_identities_cannot_prepare_when_not_selected_a(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        before = self.running_snapshot()
        for executable in ('installer-next', 'updater'):
            with self.subTest(executable=executable):
                result = self.run_installer('prepare', sequence=11, expected=10,
                                            executable=executable, app_build=executable)
                self.assertEqual(result.stdout.strip(), 'rejected:denied', result.stdout + result.stderr)
                self.assertEqual(self.running_snapshot(), before)
                self.assertFalse((self.storage / 'update.json').exists())

    def test_invalid_edge_and_stale_sequence_leave_installation_untouched(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        before = self.running_snapshot()
        for action, expected in [('prepare-bad-edge', 10), ('prepare', 9)]:
            with self.subTest(action=action):
                result = self.run_installer(action, sequence=11, expected=expected,
                                            app_build='installer-next')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.running_snapshot(), before)
                self.assertFalse((self.storage / 'update.json').exists())

    def test_held_lifecycle_lease_blocks_preparation_without_changes(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        before = self.running_snapshot()
        with open(self.storage / 'lifecycle.lock', 'r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_installer('prepare', sequence=11, expected=10,
                                        app_build='installer-next')
        self.assertEqual(result.stdout.strip(), 'rejected:busy', result.stdout + result.stderr)
        self.assertEqual(self.running_snapshot(), before)
        self.assertFalse((self.storage / 'update.json').exists())

    def prepare_joint_update(self):
        result = self.run_installer('prepare', sequence=11, expected=10, app_build='installer-next')
        self.assertEqual(result.stdout.strip(), 'prepared:10->11 phase:prepared', result.stdout + result.stderr)

    def journal_action(self, action, executable='installer'):
        return self.run_installer(action, sequence=11, expected=10, executable=executable)

    def journal_record(self):
        return json.loads((self.storage / 'update.json').read_text())

    def test_authenticated_a_begin_drains_without_selecting_or_charging_budget(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        self.prepare_joint_update()
        release = (self.storage / 'release.json').read_bytes()
        budget = (self.storage / 'activation.json').read_bytes()
        result = self.journal_action('journal-begin')
        self.assertEqual(result.stdout.strip(), 'journal:replacementPending:1', result.stdout + result.stderr)
        self.assertFalse(self.loaded())
        self.assertEqual((self.storage / 'release.json').read_bytes(), release)
        self.assertEqual((self.storage / 'activation.json').read_bytes(), budget)
        self.assertEqual(self.journal_record()['phase'], 'replacementPending')

    def test_cancel_and_retire_prepared_do_not_stop_or_restart_a(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        self.prepare_joint_update()
        before = self.running_snapshot()
        result = self.journal_action('journal-cancel')
        self.assertEqual(result.stdout.strip(), 'journal:cancelled:1', result.stdout + result.stderr)
        self.assertFalse((self.support / 'runtime-built').exists())
        after_cancel = self.running_snapshot()
        self.assertEqual(after_cancel[0], before[0])
        self.assertEqual(after_cancel[1]['release.json'], before[1]['release.json'])
        self.assertEqual(after_cancel[1]['activation.json'], before[1]['activation.json'])
        result = self.journal_action('journal-retire')
        self.assertEqual(result.stdout.strip(), 'journal:retired', result.stdout + result.stderr)
        self.assertFalse((self.support / 'runtime-built').exists())
        self.assertFalse((self.storage / 'update.json').exists())
        after_retire = self.running_snapshot()
        self.assertEqual(after_retire[0], before[0])
        self.assertEqual(after_retire[1]['activation.json'], before[1]['activation.json'])

    def test_pending_refuses_cancel_repeat_begin_and_cancelled_retirement(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        self.prepare_joint_update()
        self.assertEqual(self.journal_action('journal-begin').stdout.strip(), 'journal:replacementPending:1')
        marker = self.support / 'runtime-built'
        marker.unlink()
        preserved = (self.storage / 'update.json').read_bytes()
        for action in ('journal-cancel', 'journal-begin', 'journal-retire'):
            with self.subTest(action=action):
                result = self.journal_action(action)
                self.assertEqual(result.stdout.strip(), 'rejected:invalidUpdateJournal', result.stdout + result.stderr)
                self.assertEqual((self.storage / 'update.json').read_bytes(), preserved)
        self.assertFalse(marker.exists(), 'repeat begin must be refused before runtime construction')

    def test_management_refuses_wrong_identity_revision_uuid_and_held_lease_before_runtime(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        self.prepare_joint_update()
        before = self.running_snapshot()
        marker = self.support / 'runtime-built'
        cases = [('journal-begin', 'installer-next', 'denied'),
                 ('journal-begin', 'updater', 'denied'),
                 ('journal-begin-wrong-uuid', 'installer', 'staleRevision'),
                 ('journal-begin-wrong-revision', 'installer', 'staleRevision')]
        for action, executable, error in cases:
            with self.subTest(action=action, executable=executable):
                result = self.journal_action(action, executable=executable)
                self.assertEqual(result.stdout.strip(), f'rejected:{error}', result.stdout + result.stderr)
                self.assertFalse(marker.exists())
                self.assertEqual(self.running_snapshot(), before)
        with open(self.storage / 'lifecycle.lock', 'r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.journal_action('journal-begin')
        self.assertEqual(result.stdout.strip(), 'rejected:busy', result.stdout + result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(self.running_snapshot(), before)

    def test_failed_or_unconfirmed_drain_does_not_advance_prepared(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        self.prepare_joint_update()
        result = self.journal_action('journal-begin-fail-stop')
        self.assertEqual(result.stdout.strip(), 'rejected:cleanupNotConfirmed', result.stdout + result.stderr)
        self.assertEqual(self.journal_record()['phase'], 'prepared')
        self.assertTrue(self.loaded())
        (self.support / 'runtime-built').unlink()
        result = self.journal_action('journal-begin-lose-lease')
        self.assertEqual(result.stdout.strip(), 'rejected:lost', result.stdout + result.stderr)
        self.assertEqual(self.journal_record()['phase'], 'prepared')

    def test_stopped_before_journal_advance_remains_prepared_and_cancellation_does_not_restart(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        self.prepare_joint_update()
        budget = (self.storage / 'activation.json').read_bytes()
        result = self.journal_action('journal-begin-stop-then-fail')
        self.assertEqual(result.stdout.strip(), 'rejected:cleanupNotConfirmed', result.stdout + result.stderr)
        self.assertFalse(self.loaded())
        self.assertEqual(self.journal_record()['phase'], 'prepared')
        self.assertEqual((self.storage / 'activation.json').read_bytes(), budget)
        (self.support / 'runtime-built').unlink()
        self.assertEqual(self.journal_action('journal-cancel').stdout.strip(), 'journal:cancelled:1')
        self.assertFalse(self.loaded())
        self.assertFalse((self.support / 'runtime-built').exists())
        self.assertEqual((self.storage / 'activation.json').read_bytes(), budget)
        self.assertEqual(self.journal_action('journal-retire').stdout.strip(), 'journal:retired')
        self.assertFalse(self.loaded())
        self.assertFalse((self.support / 'runtime-built').exists())
        self.assertEqual((self.storage / 'activation.json').read_bytes(), budget)

    def test_missing_or_corrupt_journal_is_refused_before_runtime(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        before = self.running_snapshot()
        marker = self.support / 'runtime-built'
        result = self.journal_action('journal-begin')
        self.assertEqual(result.stdout.strip(), 'rejected:invalidUpdateJournal', result.stdout + result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(self.running_snapshot(), before)
        (self.storage / 'update.json').write_text('{broken')
        (self.storage / 'update.json').chmod(0o600)
        result = self.journal_action('journal-begin')
        self.assertEqual(result.stdout.strip(), 'rejected:invalidUpdateJournal', result.stdout + result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(self.running_snapshot()[:1], before[:1])

    def test_update_without_an_installation_is_refused(self):
        result = self.run_installer('update', sequence=11, expected=10)
        self.assertEqual(result.stdout.strip(), 'rejected:notInstalled', result.stdout + result.stderr)
        self.assertFalse(self.loaded())

    def test_a_running_supervisor_blocks_a_concurrent_installation(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        with open(self.storage / 'lifecycle.lock', 'r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_installer('update', sequence=11, expected=10)
        self.assertEqual(result.stdout.strip(), 'rejected:busy', result.stdout + result.stderr)

    def test_a_shared_application_directory_is_refused(self):
        (self.support / 'ProxyPilot').mkdir(mode=0o755, parents=True)
        result = self.run_installer()
        self.assertEqual(result.stdout.strip(), 'rejected:unsafeDirectory', result.stdout + result.stderr)
        self.assertFalse(self.loaded())

    def test_production_entry_requires_root(self):
        self.assertEqual(self.run_installer('root-entry').stdout.strip(), 'root-entry:requiresRoot')

    def test_uninstall_stops_the_service_and_removes_every_file(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        result = self.run_installer('uninstall')
        self.assertEqual(result.stdout.strip(), 'uninstalled', result.stdout + result.stderr)
        self.assertFalse(self.loaded())
        self.assertFalse((self.plists / f'{self.label}.plist').exists())
        self.assertFalse((self.support / 'ProxyPilot').exists())
        self.assertEqual(sorted(os.listdir(self.support)), [])

    def test_uninstall_preserves_separate_joint_update_transaction(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        update = self.support / 'ProxyPilot' / 'Update'
        update.mkdir(mode=0o700)
        retained = update / 'retained-transaction'
        retained.write_bytes(b'cleaned by a separate authenticated transaction')
        result = self.run_installer('uninstall')
        self.assertEqual(result.stdout.strip(), 'uninstalled', result.stdout + result.stderr)
        self.assertFalse(self.loaded())
        self.assertFalse(self.storage.exists())
        self.assertEqual(retained.read_bytes(),
                         b'cleaned by a separate authenticated transaction')

    def test_asan_directory_enumeration_handles_many_variable_dirent_records(self):
        (self.support / 'ProxyPilot').mkdir(mode=0o700)
        self.storage.mkdir(mode=0o700)
        for index in range(600):
            (self.storage / f'.release-{index:04d}.tmp').write_bytes(b'x')
        result = self.run_installer('enumerate-removable', executable='installer-asan')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'enumerated:600:600', result.stdout + result.stderr)
        self.assertNotIn('AddressSanitizer', result.stderr)
        self.assertFalse(self.loaded())
        self.assertFalse((self.plists / f'{self.label}.plist').exists())
        self.assertEqual(len(list(self.storage.iterdir())), 600)

    def test_uninstall_without_an_installation_is_refused(self):
        result = self.run_installer('uninstall')
        self.assertEqual(result.stdout.strip(), 'rejected:notInstalled', result.stdout + result.stderr)

    def test_uninstall_keeps_foreign_files_and_removes_nothing(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        (self.storage / 'someone-elses.txt').write_text('keep me')
        result = self.run_installer('uninstall')
        self.assertEqual(result.stdout.strip(), 'rejected:unexpectedContent', result.stdout + result.stderr)
        self.assertTrue((self.storage / 'release.json').exists())
        self.assertTrue((self.storage / 'someone-elses.txt').exists())
        # Refusing must not leave a stopped service and a half-removed install.
        self.assertTrue(self.loaded())
        self.assertTrue((self.plists / f'{self.label}.plist').exists())

    def test_a_held_lease_blocks_uninstall(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        with open(self.storage / 'lifecycle.lock', 'r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_installer('uninstall')
        self.assertEqual(result.stdout.strip(), 'rejected:busy', result.stdout + result.stderr)
        self.assertTrue((self.storage / 'release.json').exists())

    def test_the_service_description_survives_a_stop_so_a_boot_restarts_it(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        plist = self.plists / f'{self.label}.plist'
        self.boot_out()
        self.assertFalse(self.loaded())
        self.assertTrue(plist.exists())
        # launchd loading the description is what a restart does for us.
        self.command(['/bin/launchctl', 'bootstrap', self.domain, str(plist)])
        self.assertTrue(self.loaded())

    def test_after_uninstall_no_description_can_restart_the_service(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        plist = self.plists / f'{self.label}.plist'
        self.assertEqual(self.run_installer('uninstall').stdout.strip(), 'uninstalled')
        self.assertFalse(plist.exists())
        self.assertFalse(self.loaded())
