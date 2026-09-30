"""Drive the real launchd adapter through the real coordinator.

Services are registered in the current user's own launchd domain under a
disposable label, never in the system domain and never in /Library/LaunchDaemons.
Every test boots the label out afterwards. Inert fixtures only: no root, no VPN
profile, no routes, no DNS. Passing this is not proof of a root daemon install.
"""
import hashlib
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'app/vpn-helper'
COMPONENTS = ['VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperProtocol.swift',
              'VPNHelperReadiness.swift', 'VPNHelperSession.swift',
              'VPNHelperArtifact.swift', 'VPNReleaseStore.swift', 'VPNLifecycleOwnership.swift',
              'VPNLaunchdRuntime.swift', 'VPNRecoveryLaunchdJob.swift',
              'VPNActivationBudget.swift', 'VPNActivationCoordinator.swift', 'VPNEndpointDirectory.swift']
SERVICE = ['VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperArtifact.swift',
           'VPNReleaseStore.swift', 'VPNHelperProtocol.swift', 'VPNApplicationSpec.swift',
           'VPNTunnelStateStore.swift', 'VPNProfileVault.swift',
           'OpenVPNManagementEvent.swift', 'OpenVPNStateEvidence.swift', 'OpenVPNManagementParser.swift',
           'OpenVPNManagementClient.swift', 'VPNManagementSocketReservation.swift',
           'VPNEngineProcess.swift', 'VPNEngineSupervisor.swift',
           'VPNKernelInterfaceSnapshot.swift', 'VPNTunnelInterfaceResolver.swift',
           'VPNRouteJournal.swift', 'VPNRoutePlan.swift', 'VPNRouteTransaction.swift',
           'VPNDarwinRouteSocket.swift', 'VPNPeerRouteEvidenceResolver.swift',
           'VPNTunnelRouteController.swift', 'VPNTunnelCoordinator.swift',
           'VPNLifecycleOwnership.swift', 'VPNHelperRuntime.swift',
           'VPNHelperListener.swift', 'VPNEndpointDirectory.swift']
# The helper re-validates profiles with the application's own importer.
IMPORTER = [ROOT / 'app/VPNConfiguration.swift', ROOT / 'app/VPNProfileImporter.swift']


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNLaunchdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise unittest.SkipTest('Never register the test service as root')
        cls.domain = f'gui/{os.geteuid()}'
        if subprocess.run(['/bin/launchctl', 'print', cls.domain], capture_output=True,
                          timeout=60).returncode:
            raise unittest.SkipTest('no reachable per-user GUI launchd domain')
        cls.build = tempfile.TemporaryDirectory(prefix='pp-lnd-build-', dir='/tmp')
        cls.addClassCleanup(cls.build.cleanup)
        cls.work = Path(cls.build.name)
        (cls.work / 'idle.swift').write_text('import Darwin\nexit(0)\n')
        for name, sources, flags in [
            ('driver', [HELPER / source for source in COMPONENTS] + [ROOT / 'tests/vpn_launchd_checks.swift'],
             ['-D', 'VPN_HELPER_READINESS_TESTING', '-D', 'VPN_LAUNCHD_TESTING']),
            ('server', [HELPER / source for source in SERVICE] + IMPORTER
             + [ROOT / 'tests/vpn_helper_service.swift'],
             ['-D', 'VPN_ENGINE_SUPERVISOR_FIXTURE']),
            ('idle', [cls.work / 'idle.swift'], []),
        ]:
            slices = []
            for arch in ('arm64', 'x86_64'):
                output = cls.work / f'{name}-{arch}'
                cls.command(['swiftc', *flags, '-target', f'{arch}-apple-macosx11.0',
                             *map(str, sources), '-o', str(output)])
                slices.append(str(output))
            cls.command(['lipo', '-create', *slices, '-output', str(cls.work / name)])
        # The adapter must also compile without its test seam.
        for arch in ('arm64', 'x86_64'):
            cls.command(['swiftc', '-emit-library', '-target', f'{arch}-apple-macosx11.0',
                         *[str(HELPER / source) for source in COMPONENTS],
                         '-o', str(cls.work / f'production-{arch}.dylib')])
        cls.pins = {}
        for name, identifier in [('server', 'kz.documentolog.proxypilot.vpn-helper'),
                                 ('idle', 'kz.documentolog.proxypilot.vpn-helper'),
                                 # The driver stands in for the owner's application, which the
                                 # listener authenticates against the release's pinned hashes.
                                 ('driver', 'kz.documentolog.proxypilot')]:
            path = cls.work / name
            path.chmod(0o700)
            cls.command(['codesign', '--force', '--sign', '-', '--identifier', identifier,
                         '--options', 'runtime,hard,kill', str(path)])
            cls.pins[name] = {}
            for arch in ('arm64', 'x86_64'):
                result = cls.command(['codesign', '-d', '--verbose=4', '--arch', arch, str(path)])
                cls.pins[name][arch] = re.search(r'^CDHash=([a-f0-9]{40})$', result.stderr, re.M).group(1)

    @staticmethod
    def command(args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise AssertionError(' '.join(map(str, args)) + '\n' + result.stdout + result.stderr)
        return result

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pp-lnd-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.storage = self.base / 'store'
        self.storage.mkdir(mode=0o700)
        self.plists = self.base / 'plists'
        self.plists.mkdir(mode=0o755)
        self.label = f'kz.documentolog.proxypilot.vpn-helper.test-{uuid.uuid4().hex}'
        self.addCleanup(self.boot_out)
        self.assertEqual(self.run_driver('seed', helper='server', sequence=10).stdout.strip(), 'selected:10')

    def boot_out(self):
        subprocess.run(['/bin/launchctl', 'bootout', f'{self.domain}/{self.label}'],
                       capture_output=True, timeout=60)
        subprocess.run(['/bin/launchctl', 'bootout', f'{self.domain}/{self.label}.recovery'],
                       capture_output=True, timeout=60)

    def service_pid(self):
        result = subprocess.run(['/bin/launchctl', 'print', f'{self.domain}/{self.label}'],
                                capture_output=True, text=True, timeout=60)
        found = re.search(r'^\s*pid = (\d+)$', result.stdout, re.M)
        return int(found.group(1)) if found else None

    def loaded(self):
        return subprocess.run(['/bin/launchctl', 'print', f'{self.domain}/{self.label}'],
                              capture_output=True, timeout=60).returncode == 0

    def recovery_loaded(self):
        return subprocess.run(['/bin/launchctl', 'print', f'{self.domain}/{self.label}.recovery'],
                              capture_output=True, timeout=60).returncode == 0

    def run_driver(self, action='update', helper='server', sequence=11, expected=10, timeout=90):
        artifact = (self.work / helper).read_bytes()
        fields = {'format': 1, 'product': 'kz.documentolog.proxypilot', 'sequence': sequence,
                  'version': '1.6.0', 'protocol': 1,
                  'app-arm64': self.pins['driver']['arm64'], 'app-x86_64': self.pins['driver']['x86_64'],
                  'helper-arm64': self.pins[helper]['arm64'], 'helper-x86_64': self.pins[helper]['x86_64'],
                  'helper-sha256': hashlib.sha256(artifact).hexdigest(), 'helper-bytes': len(artifact)}
        manifest, candidate = self.base / 'manifest', self.base / 'candidate'
        manifest.write_text(''.join(f'{key}={value}\n' for key, value in fields.items()))
        candidate.write_bytes(artifact)
        return subprocess.run([str(self.work / 'driver'), action, str(self.storage), str(manifest),
                               str(candidate), str(expected), self.label, str(self.plists)],
                              capture_output=True, text=True, timeout=timeout)

    def test_update_starts_a_real_service_and_authenticates_readiness(self):
        result = self.run_driver()
        self.assertEqual(result.stdout.strip(), 'ready:11', result.stdout + result.stderr)
        self.assertTrue(self.loaded())
        self.assertTrue((self.storage / 'helper.sock').is_socket())
        self.assertEqual(self.run_driver('load').stdout.strip(), 'selected:11')

    def test_stop_confirms_the_service_is_gone_and_removes_its_socket(self):
        self.assertEqual(self.run_driver().stdout.strip(), 'ready:11')
        self.assertEqual(self.run_driver('stop').stdout.strip(), 'stopped')
        self.assertFalse(self.loaded())
        self.assertFalse((self.storage / 'helper.sock').exists())

    def test_stop_confirms_the_helper_process_is_gone(self):
        self.assertEqual(self.run_driver().stdout.strip(), 'ready:11')
        pid = self.service_pid()
        self.assertIsNotNone(pid)
        self.assertEqual(self.run_driver('stop').stdout.strip(), 'stopped')
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_a_second_update_replaces_the_running_service(self):
        self.assertEqual(self.run_driver().stdout.strip(), 'ready:11')
        first = self.service_pid()
        result = self.run_driver(sequence=12, expected=11)
        self.assertEqual(result.stdout.strip(), 'ready:12', result.stdout + result.stderr)
        self.assertNotEqual(self.service_pid(), first)
        with self.assertRaises(ProcessLookupError):
            os.kill(first, 0)

    def test_stop_is_idempotent_without_a_loaded_service(self):
        self.assertEqual(self.run_driver('stop').stdout.strip(), 'stopped')
        self.assertFalse(self.loaded())

    def test_service_description_is_written_privately_and_atomically(self):
        self.assertEqual(self.run_driver().stdout.strip(), 'ready:11')
        plist = self.plists / f'{self.label}.plist'
        self.assertEqual(plist.stat().st_mode & 0o7777, 0o644)
        self.assertEqual(plist.stat().st_uid, os.geteuid())
        self.assertEqual([name for name in os.listdir(self.plists) if name.startswith('.')], [])
        content = subprocess.run(['/usr/bin/plutil', '-p', str(plist)], capture_output=True,
                                 text=True, timeout=60).stdout
        self.assertIn(f'"Label" => "{self.label}"', content)
        self.assertIn('"serve"', content)

    def test_recovery_job_uses_only_the_protected_helper_and_fixed_arguments(self):
        result = self.run_driver('recovery-arm')
        self.assertEqual(result.stdout.strip(), 'recovery:armed', result.stdout + result.stderr)
        plist = self.plists / f'{self.label}.recovery.plist'
        description = plistlib.loads(plist.read_bytes())
        protected = self.storage / ('helper-' + hashlib.sha256((self.work / 'server').read_bytes()).hexdigest())
        self.assertEqual(description['ProgramArguments'], [
            str(protected.resolve()), 'recover-update', '/Library/Application Support/ProxyPilot/VPN'])
        self.assertEqual(description['KeepAlive'], {'SuccessfulExit': False})
        self.assertTrue(description['RunAtLoad'])
        self.assertEqual(description['ThrottleInterval'], 10)
        self.assertEqual(self.run_driver('recovery-remove').stdout.strip(), 'recovery:removed')
        self.assertFalse(plist.exists())

    def test_recovery_job_can_durably_disarm_itself(self):
        self.assertEqual(self.run_driver('recovery-arm').stdout.strip(), 'recovery:armed')
        plist = self.plists / f'{self.label}.recovery.plist'
        self.assertTrue(plist.exists())
        self.assertTrue(self.recovery_loaded())
        result = self.run_driver('recovery-self-remove')
        self.assertEqual(result.stdout.strip(), 'recovery:self-removed', result.stdout + result.stderr)
        self.assertFalse(plist.exists())
        deadline = time.monotonic() + 5
        while self.recovery_loaded() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(self.recovery_loaded())

    def test_recover_restarts_the_selected_release(self):
        self.assertEqual(self.run_driver().stdout.strip(), 'ready:11')
        self.assertEqual(self.run_driver('stop').stdout.strip(), 'stopped')
        result = self.run_driver('recover')
        self.assertEqual(result.stdout.strip(), 'ready:11', result.stdout + result.stderr)
        self.assertTrue(self.loaded())

    def test_a_service_that_never_listens_fails_and_is_unloaded(self):
        started = time.monotonic()
        result = self.run_driver(helper='idle')
        self.assertEqual(result.stdout.strip(), 'failure:start cleanup:true', result.stdout + result.stderr)
        self.assertLess(time.monotonic() - started, 60)
        self.assertFalse(self.loaded())
        self.assertFalse((self.storage / 'helper.sock').exists())

    def test_a_foreign_file_on_the_socket_name_stops_activation(self):
        (self.storage / 'helper.sock').write_bytes(b'')
        result = self.run_driver()
        self.assertEqual(result.stdout.strip(), 'failure:stop cleanup:false', result.stdout + result.stderr)
        self.assertFalse(self.loaded())
        self.assertEqual(self.run_driver('load').stdout.strip(), 'selected:10')

    def test_production_entry_requires_root(self):
        self.assertEqual(self.run_driver('system').stdout.strip(), 'system:requiresRoot')

    def test_shared_storage_directory_is_rejected(self):
        self.storage.chmod(0o755)
        result = self.run_driver('stop')
        self.assertEqual(result.stdout.strip(), 'rejected:unsafeStorage', result.stdout + result.stderr)
