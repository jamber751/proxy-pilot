"""Build/inspect scripts-only packages. Never open Installer or elevate.

The complete App uses a disposable embedded public key and an inert/trapping CLI;
entering normal GUI bootstrap is a test failure. All keys are fixture-only.
"""
import os
import hashlib
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

from test_vpn_installer import COMPONENTS

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'app/vpn-helper'
PACKAGER = ROOT / 'app/vpn-package/package.py'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
ENGINE_ARTIFACT = os.environ.get('PROXYPILOT_VPN_ENGINE_ARTIFACT')


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0: raise unittest.SkipTest('Never run package tests as root')
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-pkg-build-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.build = Path(cls.temp.name)
        source = (ROOT / 'app/main.swift').read_text()
        prefix, remainder = source.split('\nenum CLI {', 1)
        _, model = remainder.split('\nfinal class ProxyModel:', 1)
        source = prefix + '''
enum CLI {
    static func state() -> ProxyState? { fatalError("Real CLI is forbidden in package tests") }
    static func run(_ args: [String]) -> CommandResult { fatalError("Real CLI is forbidden in package tests") }
}
final class ProxyModel:''' + model
        source = source.replace('let app = NSApplication.shared',
                                'fatalError("Installer entered normal GUI bootstrap")\nlet app = NSApplication.shared')
        main = cls.build / 'main.swift'; main.write_text(source)
        trust = cls.build / 'VPNReleaseTrust.swift'
        text = (HELPER / 'VPNReleaseTrust.swift').read_text()
        production_public = (ROOT / 'app/vpn-release-public-key.txt').read_text().strip()
        if text.count(production_public) != 1: raise AssertionError('Trust source changed')
        trust.write_text(text.replace(production_public, 'IVL40Zt5HSRFMkLhXy6rbLfP+ntqXtMAl5YOBpiB2xI='))
        app_sources = [main, trust] + [HELPER / name for name in COMPONENTS]
        app_sources += [HELPER / f'{name}.swift' for name in
                        ('VPNApplicationTransactionStager',
                         'VPNJointUpdatePreparation',
                         'VPNInstalledApplication',
                         'VPNInstalledCandidateHandoff', 'VPNReplacementExecutor',
                         'VPNSelectedCandidateFinalizer', 'VPNSelectedCandidateRecovery',
                         'VPNSelectedCandidateRecoveryEntry',
                         'VPNReplacementExecutorProvisioner', 'VPNProtectedApplicationSwap',
                         'VPNReplacementExecutorHandoff', 'VPNJointApplicationReplacement',
                         'VPNInstalledCandidateEntry', 'VPNReplacementExecutorEntry',
                         'VPNApplicationDestinationExchange')]
        app_sources += [HELPER / f'{name}.swift' for name in
                        ('VPNUpdateBrokerLaunchdJob', 'VPNUpdateBrokerProtocol',
                         'VPNUpdateBrokerClient', 'VPNJointArtifactMount',
                         'VPNUpdateBrokerStatusStore', 'VPNUpdateBrokerTransactionStore',
                         'VPNUpdateBrokerInbox', 'VPNUpdateBrokerRotation',
                         'VPNUpdateBrokerInstallerCoordinator',
                         'VPNUpdateBrokerStateRemoval',
                         'VPNJointUpdateStartupStatus')]
        app_sources += [HELPER / f'{name}.swift' for name in ('VPNInstallationPayload', 'VPNInstallationEntry')]
        app_sources += [ROOT / 'app' / f'{name}.swift' for name in
                        ('Controls', 'Updates', 'VPNConfiguration', 'VPNProfileImporter', 'VPNStore')]
        app_sources += [ROOT / 'app/update-worker' / f'{name}.swift' for name in
                        ('IsolatedUpdates', 'UpdateWire', 'UpdateChannel')]
        signer_sources = [HELPER / f'{name}.swift' for name in
                          ('VPNPeerAuthentication', 'VPNReleaseAuthorization', 'VPNHelperArtifact', 'VPNInstallationPayload')]
        signer_sources += [ROOT / 'tests/vpn_payload_checks.swift']
        for name, compiler, sources, flags in [
            ('app', 'swiftc', app_sources, ['-D', 'VPN_INSTALLER_ENTRY', '-D', 'ISOLATED_UPDATER']),
            ('signer', 'swiftc', signer_sources, []),
            ('helper', 'clang', [ROOT / 'tests/vpn-deployment/HelperFixture.c'], []),
        ]:
            slices = []
            for arch in ('arm64', 'x86_64'):
                binary = cls.build / f'{name}-{arch}'
                cls.command([compiler, *flags, '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(binary)])
                slices.append(str(binary))
            cls.command(['lipo', '-create', *slices, '-output', str(cls.build / name)])
        cls.app = cls.build / 'ProxyPilot.app'
        (cls.app / 'Contents/MacOS').mkdir(parents=True)
        shutil.copyfile(cls.build / 'app', cls.app / 'Contents/MacOS/ProxyPilot')
        (cls.app / 'Contents/MacOS/ProxyPilot').chmod(0o700)
        info = dict(CFBundleIdentifier='kz.documentolog.proxypilot', CFBundleName='ProxyPilot',
                    CFBundleVersion='1.6.0', CFBundleShortVersionString='1.6.0', CFBundleExecutable='ProxyPilot',
                    CFBundlePackageType='APPL', LSMinimumSystemVersion='11.0', LSUIElement=True,
                    ProxyPilotVPNInstaller=True, ProxyPilotVPNReleaseSequence=2)
        (cls.app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
        for path, identifier in [(cls.app, 'kz.documentolog.proxypilot'),
                                 (cls.build / 'helper', 'kz.documentolog.proxypilot.vpn-helper')]:
            cls.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                         '--identifier', identifier, str(path)])

    @staticmethod
    def command(args):
        result = subprocess.run(args, env=ENV, capture_output=True, text=True, timeout=180)
        if result.returncode: raise AssertionError(result.stdout + result.stderr)
        return result

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pp-pkg-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.stage = self.work / 'stage'
        self.command([sys.executable, str(PACKAGER), 'prepare', '--app', str(self.app),
                      '--helper', str(self.build / 'helper'), '--sequence', '2', '--output', str(self.stage)])
        self.payload = self.stage / 'Payload'
        self.command([str(self.build / 'signer'), 'sign', str(self.payload)])

    def app_run(self, *args):
        return subprocess.run([str(self.payload / 'ProxyPilot.app/Contents/MacOS/ProxyPilot'), *args],
                              env=ENV, capture_output=True, text=True, timeout=10)

    def package(self, action='install', *, success=True, prepare=True):
        if action == 'update' and prepare and not (self.payload / 'vpn-update-transition').exists():
            self.prepare_joint_payload()
        output = self.work / f'{action}.pkg'
        result = subprocess.run([sys.executable, str(PACKAGER), 'build', '--stage', str(self.stage),
                                 '--action', action, '--output', str(output)], env=ENV,
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        if not success: self.assertFalse(output.exists())
        return output

    def test_full_app_verification_exits_before_gui_proxy_and_updater(self):
        result = self.app_run('--vpn-support-verify')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'VPN support package verified.')

    def test_prepare_requires_package_sequence_to_match_sealed_app(self):
        output = self.work / 'mismatched-stage'
        result = subprocess.run(
            [sys.executable, str(PACKAGER), 'prepare', '--app', str(self.app),
             '--helper', str(self.build / 'helper'), '--sequence', '3',
             '--output', str(output)], env=ENV, capture_output=True, text=True,
            timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())
        self.assertIn('does not match package sequence', result.stderr)

    def prepare_joint_payload(self):
        candidate = (self.payload / 'vpn-release.manifest').read_text()
        previous = self.work / 'previous.manifest'
        previous.write_text(candidate.replace('sequence=2\n', 'sequence=1\n'))
        previous_signature = self.work / 'previous.sig'
        self.command([str(self.build / 'signer'), 'sign-release', str(previous),
                      str(previous_signature)])
        self.command([sys.executable, str(PACKAGER), 'prepare-update',
                      '--stage', str(self.stage), '--previous-manifest', str(previous),
                      '--previous-signature', str(previous_signature)])
        self.command([str(self.build / 'signer'), 'sign-joint', str(self.payload)])

    def test_joint_payload_binds_previous_candidate_and_exact_edge(self):
        self.prepare_joint_payload()
        verified_app = self.app_run('--vpn-support-verify-update')
        self.assertEqual(verified_app.returncode, 0,
                         verified_app.stdout + verified_app.stderr)
        self.assertEqual(verified_app.stdout.strip(),
                         'VPN joint update package verified.')
        result = self.command([str(self.build / 'signer'), 'verify-joint',
                               str(self.payload), '1.6.0'])
        self.assertEqual(result.stdout.strip(), 'verified:1->2')
        for name in ('vpn-previous-release.manifest', 'vpn-update-transition',
                     'vpn-update-transition.sig'):
            with self.subTest(name=name):
                path = self.payload / name
                original = path.read_bytes(); path.write_bytes(original + b'x')
                refused = subprocess.run([str(self.build / 'signer'), 'verify-joint',
                                          str(self.payload), '1.6.0'], env=ENV,
                                         capture_output=True, text=True, timeout=10)
                self.assertEqual(refused.returncode, 77, refused.stdout + refused.stderr)
                path.write_bytes(original)

    def test_admin_operations_reject_nonroot_before_any_sidecar_read(self):
        (self.payload / 'vpn-release.manifest').unlink()
        for mode in ('install', 'update', 'remove'):
            result = self.app_run('--vpn-support-' + mode)
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertEqual(result.stderr, '')
        result = self.app_run('--vpn-protected-replacement-executor')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(result.stderr, '')
        for hidden in ('--vpn-installed-candidate-ready', '--vpn-selected-candidate-recovery'):
            result = self.app_run(hidden)
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertEqual(result.stderr, '')

    def test_unknown_or_extra_arguments_do_not_fall_through_to_gui(self):
        for args in [('--vpn-support-bogus',), ('--vpn-support-install', '/tmp/other'),
                     ('--vpn-support-verify', '--owner', '0'),
                     ('--vpn-support-verify-update', '/tmp/other'),
                     ('--vpn-protected-replacement-executor', '/tmp/other'),
                     ('--vpn-installed-candidate-ready', '/tmp/other'),
                     ('--vpn-selected-candidate-recovery', '/tmp/other')]:
            self.assertEqual(self.app_run(*args).returncode, 64)

    def test_changed_sidecar_fails_in_the_actual_entry(self):
        with (self.payload / 'vpn-helper').open('ab') as stream: stream.write(b'changed')
        result = self.app_run('--vpn-support-verify')
        self.assertEqual(result.returncode, 77)
        self.assertEqual(result.stderr,
                         'VPN support operation failed at payload. '
                         'No authorization was bypassed.\n')
        self.package(success=False)

    def test_packages_only_run_the_fixed_same_app_mode(self):
        for action in ('install', 'update', 'remove'):
            with self.subTest(action=action):
                package = self.package(action)
                expanded = self.work / f'expanded-{action}'
                self.command(['/usr/sbin/pkgutil', '--expand-full', str(package), str(expanded)])
                info = ET.parse(expanded / 'PackageInfo').getroot()
                self.assertEqual(info.attrib['minimumSystemVersion'], '11.0')
                self.assertEqual(info.attrib['identifier'], 'kz.documentolog.proxypilot.vpn-support.' + action)
                self.assertFalse((expanded / 'Payload').exists(), 'Must be scripts-only, no automatic system writes')
                scripts = expanded / 'Scripts'
                post = (scripts / 'postinstall').read_text()
                self.assertIn('--vpn-support-' + action, post)
                self.assertIn('/usr/bin/env -i', post)
                self.assertNotIn('@ACTION@', post)
                self.assertNotIn('launchctl', post)
                self.assertNotIn('chown', post)
                pre = (scripts / 'preinstall').read_text()
                expected_verify = ('--vpn-support-verify-update' if action == 'update'
                                   else '--vpn-support-verify')
                self.assertIn(expected_verify, pre)
                for name in ('preinstall', 'postinstall'):
                    result = subprocess.run(['/bin/zsh', str(scripts / name), 'test.pkg', '/', '/'],
                                            env=ENV, capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 77)
                self.command(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(scripts / 'Payload/ProxyPilot.app')])
                result = self.command([str(scripts / 'Payload/ProxyPilot.app/Contents/MacOS/ProxyPilot'), '--vpn-support-verify'])
                self.assertIn('package verified', result.stdout)

    def test_update_package_requires_complete_joint_sidecars(self):
        self.package('update')
        for name in ('vpn-previous-release.manifest', 'vpn-previous-release.sig',
                     'vpn-update-transition', 'vpn-update-transition.sig'):
            with self.subTest(name=name):
                output = self.work / 'update.pkg'
                if output.exists(): output.unlink()
                path = self.payload / name
                original = path.read_bytes(); path.unlink()
                try: self.package('update', success=False, prepare=False)
                finally: path.write_bytes(original)

    def test_update_entry_uses_only_joint_preparation_and_executor_handoff(self):
        source = (HELPER / 'VPNInstallationEntry.swift').read_text()
        self.assertIn('VPNJointUpdatePreparation.prepare(', source)
        self.assertIn('VPNReplacementExecutorHandoff.launchPrepared(', source)
        self.assertNotIn('VPNInstaller.update(', source)
        self.assertNotIn('Process()', source)

    def test_prepare_update_never_overwrites_or_accepts_bad_signature(self):
        previous = self.work / 'previous.manifest'
        previous.write_text((self.payload / 'vpn-release.manifest').read_text()
                            .replace('sequence=2\n', 'sequence=1\n'))
        signature = self.work / 'previous.sig'; signature.write_text('invalid\n')
        command = [sys.executable, str(PACKAGER), 'prepare-update', '--stage', str(self.stage),
                   '--previous-manifest', str(previous), '--previous-signature', str(signature)]
        refused = subprocess.run(command, env=ENV, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(refused.returncode, 0)
        self.assertFalse((self.payload / 'vpn-previous-release.manifest').exists())
        self.command([str(self.build / 'signer'), 'sign-release', str(previous), str(signature)])
        self.command(command)
        before = {name: (self.payload / name).read_bytes() for name in
                  ('vpn-previous-release.manifest', 'vpn-previous-release.sig',
                   'vpn-update-transition', 'vpn-update-transition.sig')}
        refused = subprocess.run(command, env=ENV, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(before, {name: (self.payload / name).read_bytes() for name in before})

    def test_unsigned_package_cannot_be_built(self):
        (self.payload / 'vpn-release.sig').write_text('')
        self.package(success=False)

    def test_unexpected_payload_file_cannot_leak_into_package(self):
        (self.payload / 'private.ovpn').write_text('synthetic, not a real profile')
        self.package(success=False)

    def test_existing_release_is_not_overwritten(self):
        output = self.package()
        original = output.read_bytes()
        result = subprocess.run([sys.executable, str(PACKAGER), 'build', '--stage', str(self.stage),
                                 '--action', 'install', '--output', str(output)], env=ENV,
                                capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), original)

    def test_old_app_without_installer_marker_is_not_executed(self):
        path = self.payload / 'ProxyPilot.app/Contents/Info.plist'
        info = plistlib.loads(path.read_bytes()); del info['ProxyPilotVPNInstaller']
        path.write_bytes(plistlib.dumps(info))
        self.package(success=False)

    def prepare_engine(self):
        self.stage = self.work / 'engine-stage'
        self.command([sys.executable, str(PACKAGER), 'prepare', '--app', str(self.app),
                      '--helper', str(self.build / 'helper'), '--sequence', '2', '--output', str(self.stage),
                      '--engine-artifact', ENGINE_ARTIFACT])
        self.payload = self.stage / 'Payload'
        self.command([str(self.build / 'signer'), 'sign', str(self.payload)])

    def test_engine_sources_are_required_before_creating_stage(self):
        artifact = self.work / 'unreviewed'; (artifact / 'sources').mkdir(parents=True)
        (artifact / 'sources/sources.json').write_text('{}')
        for invalid in ['relative-artifact', str(self.work / 'missing'), str(artifact)]:
            output = self.work / 'refused'
            result = subprocess.run([sys.executable, str(PACKAGER), 'prepare', '--app', str(self.app),
                                     '--helper', str(self.build / 'helper'), '--sequence', '2', '--output', str(output),
                                     '--engine-artifact', invalid], env=ENV, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(output.exists())

    @unittest.skipUnless(ENGINE_ARTIFACT, 'Optional complete pinned engine build artifact')
    def test_actual_engine_is_preserved_in_all_packages_with_separate_sources(self):
        self.prepare_engine()
        original = (Path(ENGINE_ARTIFACT) / 'openvpn').read_bytes()
        self.assertEqual((self.payload / 'vpn-engine').read_bytes(), original)
        manifest = (self.payload / 'vpn-release.manifest').read_text()
        self.assertTrue(manifest.startswith('format=2\n'))
        self.assertIn('engine-sha256=' + hashlib.sha256(original).hexdigest(), manifest)
        self.assertEqual(self.app_run('--vpn-support-verify').returncode, 0)
        for action in ('install', 'update', 'remove'):
            package = self.package(action)
            expanded = self.work / ('engine-expanded-' + action)
            self.command(['/usr/sbin/pkgutil', '--expand-full', str(package), str(expanded)])
            copied = expanded / 'Scripts/Payload'
            self.assertEqual((copied / 'vpn-engine').read_bytes(), original)
            self.assertEqual(set(os.listdir(copied)), {'ProxyPilot.app', 'vpn-helper', 'vpn-engine', 'vpn-release.manifest', 'vpn-release.sig'})
            self.command([str(copied / 'ProxyPilot.app/Contents/MacOS/ProxyPilot'), '--vpn-support-verify'])
        sources = self.stage / 'EngineSources'
        self.assertEqual((sources / 'sources/sources.json').read_bytes(), (ROOT / 'app/vpn-engine/sources.json').read_bytes())
        self.assertEqual((sources / 'OpenVPN-COPYING.txt').read_bytes(), (Path(ENGINE_ARTIFACT) / 'OpenVPN-COPYING.txt').read_bytes())

    @unittest.skipUnless(ENGINE_ARTIFACT, 'Optional complete pinned engine build artifact')
    def test_engine_tampering_fails_actual_app_and_package_before_installation(self):
        self.prepare_engine()
        with (self.payload / 'vpn-engine').open('ab') as stream: stream.write(b'tampered')
        self.assertEqual(self.app_run('--vpn-support-verify').returncode, 77)
        self.package(success=False)

    @unittest.skipUnless(ENGINE_ARTIFACT, 'Optional complete pinned engine build artifact')
    def test_corresponding_source_and_license_tampering_prevents_distribution(self):
        self.prepare_engine()
        root = self.stage / 'EngineSources'
        paths = [root / 'OpenVPN-COPYING.txt', root / 'OpenSSL-LICENSE.txt', root / 'sources/build.py',
                 next((root / 'sources').glob('openssl-*.tar.gz'))]
        for path in paths:
            with self.subTest(path=path.name):
                original = path.read_bytes(); path.write_bytes(b'changed')
                try: self.package(success=False)
                finally: path.write_bytes(original)
        self.assertEqual(self.app_run('--vpn-support-verify').returncode, 0)
