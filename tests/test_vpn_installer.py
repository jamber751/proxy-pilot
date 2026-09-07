"""The installation sequence end to end, without root.

A disposable base directory stands in for /Library/Application Support and the
user's own launchd domain for the system domain. Every test boots its label out.
Proving the order and the refusals is not proof of a privileged system install.
"""
import fcntl
import hashlib
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
COMPONENTS = ['VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperReadiness.swift',
              'VPNHelperArtifact.swift', 'VPNReleaseStore.swift', 'VPNLifecycleOwnership.swift',
              'VPNHelperListener.swift', 'VPNDirectoryProvisioner.swift', 'VPNLaunchdRuntime.swift',
              'VPNActivationBudget.swift', 'VPNActivationCoordinator.swift', 'VPNInstaller.swift']
SERVICE = ['VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperArtifact.swift',
           'VPNReleaseStore.swift', 'VPNHelperListener.swift']
SEAMS = ['-D', 'VPN_HELPER_READINESS_TESTING', '-D', 'VPN_LAUNCHD_TESTING', '-D', 'VPN_INSTALLER_TESTING']


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNInstallerTests(unittest.TestCase):
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
            ('server', [HELPER / source for source in SERVICE] + [ROOT / 'tests/vpn_helper_service.swift'], []),
        ]:
            slices = []
            for arch in ('arm64', 'x86_64'):
                output = cls.work / f'{name}-{arch}'
                cls.command(['swiftc', *flags, '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(output)])
                slices.append(str(output))
            cls.command(['lipo', '-create', *slices, '-output', str(cls.work / name)])
        # The installer must also compile without any of its test seams.
        for arch in ('arm64', 'x86_64'):
            cls.command(['swiftc', '-emit-library', '-target', f'{arch}-apple-macosx11.0',
                         *[str(HELPER / source) for source in COMPONENTS], '-o', str(cls.work / f'production-{arch}.dylib')])
        cls.pins = {}
        for name, identifier in [('server', 'kz.documentolog.proxypilot.vpn-helper'),
                                 ('installer', 'kz.documentolog.proxypilot')]:
            (cls.work / name).chmod(0o700)
            cls.command(['codesign', '--force', '--sign', '-', '--identifier', identifier,
                         '--options', 'runtime,hard,kill', str(cls.work / name)])
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

    def run_installer(self, action='install', sequence=10, expected=0):
        artifact = (self.work / 'server').read_bytes()
        fields = {'format': 1, 'product': 'kz.documentolog.proxypilot', 'sequence': sequence,
                  'version': '1.6.0', 'protocol': 1,
                  'app-arm64': self.pins['installer']['arm64'], 'app-x86_64': self.pins['installer']['x86_64'],
                  'helper-arm64': self.pins['server']['arm64'], 'helper-x86_64': self.pins['server']['x86_64'],
                  'helper-sha256': hashlib.sha256(artifact).hexdigest(), 'helper-bytes': len(artifact)}
        manifest, candidate = self.base / 'manifest', self.base / 'candidate'
        manifest.write_text(''.join(f'{key}={value}\n' for key, value in fields.items()))
        candidate.write_bytes(artifact)
        return subprocess.run([str(self.work / 'installer'), action, str(self.support), str(manifest),
                               str(candidate), str(expected), self.label, str(self.plists)],
                              capture_output=True, text=True, timeout=120)

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

    def test_update_replaces_the_installed_release(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')
        result = self.run_installer('update', sequence=11, expected=10)
        self.assertEqual(result.stdout.strip(), 'ready:11', result.stdout + result.stderr)
        self.assertTrue(self.loaded())

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
