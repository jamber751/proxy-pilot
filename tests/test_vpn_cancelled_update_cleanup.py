"""Authority-preserving cleanup of a cancelled prepared joint update."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import test_vpn_staged_application as staged

ROOT, HELPER, ENV = staged.ROOT, staged.HELPER, staged.ENV


@unittest.skipUnless(os.uname().sysname == 'Darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNCancelledUpdateCleanupTests(unittest.TestCase):
    command = staged.VPNStagedApplicationTests.__dict__['command']
    make_app = staged.VPNStagedApplicationTests.make_app
    sign = staged.VPNStagedApplicationTests.sign
    pins = staged.VPNStagedApplicationTests.pins

    @classmethod
    def setUpClass(cls):
        staged.VPNStagedApplicationTests.setUpClass.__func__(cls)
        cls.helper = cls.build / 'cancel-helper'
        shutil.copyfile(cls.universal, cls.helper)
        cls.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                     '--identifier', 'kz.documentolog.proxypilot.vpn-helper', str(cls.helper)])
        cls.helper_pins = {}
        for arch in ('arm64', 'x86_64'):
            text = cls.command(['codesign', '-d', '--verbose=4', '--arch', arch,
                                str(cls.helper)]).stderr
            cls.helper_pins[arch] = re.search(r'^CDHash=([a-f0-9]{40})$', text, re.M).group(1)
        sources = [HELPER / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
            'VPNHelperArtifact.swift', 'VPNReleaseStore.swift',
            'VPNLifecycleOwnership.swift', 'VPNDirectoryProvisioner.swift',
            'VPNStagedApplication.swift', 'VPNJointUpdateCleanup.swift')]
        cls.cleanup = cls.build / 'cancel-cleanup-checks'
        cls.command(['swiftc', '-D', 'VPN_JOINT_UPDATE_CLEANUP_TESTING',
                     '-D', 'VPN_RELEASE_STORE_TESTING', *map(str, sources),
                     str(ROOT / 'tests/vpn_joint_update_cleanup_checks.swift'),
                     '-o', str(cls.cleanup)])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-cancel-cleanup-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        a_source = self.work / 'a'; a_source.mkdir(mode=0o700)
        self.stage = a_source; self.app = a_source / 'ProxyPilot.app'
        self.make_app(version='1.6.0'); self.a_pins = self.pins()
        b_source = self.work / 'b'; b_source.mkdir(mode=0o700)
        self.stage = b_source; self.app = b_source / 'ProxyPilot.app'
        self.make_app(version='1.7.0'); self.b_pins = self.pins()
        self.service = self.work / 'VPN'; self.service.mkdir(mode=0o700)
        self.update = self.work / 'Update'; self.update.mkdir(mode=0o700)
        self.retired = self.work / 'Retired'; self.retired.mkdir(mode=0o700)
        self.applications = self.work / 'Applications'; self.applications.mkdir(mode=0o700)
        for name, source in (('current', a_source), ('candidate', b_source), ('executor', a_source)):
            (self.update / name).mkdir(mode=0o700)
            shutil.copytree(source / 'ProxyPilot.app', self.update / name / 'ProxyPilot.app', symlinks=True)
        (self.applications / '.ProxyPilot.vpn-update').mkdir(mode=0o700)
        shutil.copytree(b_source / 'ProxyPilot.app',
                        self.applications / '.ProxyPilot.vpn-update/ProxyPilot.app', symlinks=True)
        helper = self.helper.read_bytes()
        self.manifests = []
        for sequence, version, pins in ((10, '1.6.0', self.a_pins), (11, '1.7.0', self.b_pins)):
            self.manifests.append(self.write_manifest(sequence, version, pins, helper))
        result = self.invoke('setup-cancelled')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.transaction = result.stdout.strip()

    def write_manifest(self, sequence, version, pins, helper):
        path = self.work / f'{sequence}.manifest'
        fields = {
            'format': '1', 'product': 'kz.documentolog.proxypilot',
            'sequence': str(sequence), 'version': version, 'protocol': '1',
            'app-arm64': pins['arm64'], 'app-x86_64': pins['x86_64'],
            'helper-arm64': self.helper_pins['arm64'],
            'helper-x86_64': self.helper_pins['x86_64'],
            'helper-sha256': hashlib.sha256(helper).hexdigest(),
            'helper-bytes': str(len(helper)),
        }
        path.write_bytes(''.join(f'{k}={v}\n' for k, v in fields.items()).encode())
        return path

    def invoke(self, operation):
        return subprocess.run([str(self.cleanup), operation, str(self.service),
                               str(self.update), str(self.retired), str(self.applications),
                               *map(str, self.manifests), str(self.helper), 'unused'],
                              env=ENV, capture_output=True, text=True, timeout=180)

    def assert_crash_recovers(self, point):
        result = self.invoke('cancel-crash:' + point)
        self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
        result = self.invoke('cleanup-cancelled')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.service / 'update.json').exists())

    def test_cleanup_retires_journal_and_all_exact_staging(self):
        result = self.invoke('cleanup-cancelled')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.service / 'update.json').exists())
        self.assertEqual([p.name for p in self.update.iterdir()], ['lifecycle.lock'])
        self.assertEqual(list(self.retired.iterdir()), [])
        self.assertEqual(list(self.applications.iterdir()), [])

    def test_different_candidate_can_prepare_after_cleanup(self):
        self.assertEqual(self.invoke('cleanup-cancelled').returncode, 0)
        helper = self.helper.read_bytes()
        self.manifests[1] = self.write_manifest(12, '1.8.0', self.b_pins, helper)
        result = self.invoke('prepare-next')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'next:12')

    def test_executor_and_application_stage_are_optional(self):
        shutil.rmtree(self.update / 'executor')
        shutil.rmtree(self.applications / '.ProxyPilot.vpn-update')
        result = self.invoke('cleanup-cancelled')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_after_clone_pending_executor_is_quarantined_and_collected(self):
        (self.update / 'executor').rename(self.update / '.executor.preparing')
        result = self.invoke('cleanup-cancelled')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.service / 'update.json').exists())
        self.assertEqual([p.name for p in self.update.iterdir()], ['lifecycle.lock'])
        self.assertEqual(list(self.retired.iterdir()), [])

    def test_uninstall_gate_cleans_after_clone_before_service_removal(self):
        (self.update / 'executor').rename(self.update / '.executor.preparing')
        result = self.invoke('uninstall-cleanup-cancelled')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.service / 'update.json').exists())
        self.assertEqual([p.name for p in self.update.iterdir()], ['lifecycle.lock'])
        self.assertEqual(list(self.retired.iterdir()), [])

    def test_published_and_pending_executor_are_mutually_exclusive(self):
        shutil.copytree(self.update / 'executor', self.update / '.executor.preparing',
                        symlinks=True)
        result = self.invoke('cleanup-cancelled')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue((self.service / 'update.json').exists())
        self.assertTrue((self.update / 'executor/ProxyPilot.app').is_dir())
        self.assertTrue((self.update / '.executor.preparing/ProxyPilot.app').is_dir())

    def test_hostile_pending_executor_outer_layout_fails_closed(self):
        (self.update / 'executor').rename(self.update / '.executor.preparing')
        (self.update / '.executor.preparing/foreign').write_text('keep')
        result = self.invoke('cleanup-cancelled')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue((self.service / 'update.json').exists())
        self.assertTrue((self.update / '.executor.preparing/foreign').exists())

    def test_pending_executor_gc_receipt_rejects_inode_rebind(self):
        (self.update / 'executor').rename(self.update / '.executor.preparing')
        crash = self.invoke('cancel-crash:cancel:gc-authorized')
        self.assertEqual(crash.returncode, 86, crash.stdout + crash.stderr)
        archived = self.retired / f'{self.transaction}-cancelled' / 'pending-executor'
        displaced = archived.with_name('pending-executor-displaced')
        archived.rename(displaced)
        archived.mkdir(mode=0o700)
        result = self.invoke('cleanup-cancelled')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue((self.service / 'update.json').exists())
        self.assertTrue((displaced / 'ProxyPilot.app').is_dir())

    def test_foreign_update_entry_fails_closed_with_journal(self):
        (self.update / 'foreign').write_text('keep')
        result = self.invoke('cleanup-cancelled')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue((self.service / 'update.json').exists())
        self.assertTrue((self.update / 'foreign').exists())

    def test_crash_after_application_quarantine(self):
        self.assert_crash_recovers('cancel:application-retired')

    def test_crash_mid_update_quarantine(self):
        self.assert_crash_recovers('cancel:update-after-candidate')

    def test_crash_after_gc_authorization(self):
        self.assert_crash_recovers('cancel:gc-authorized')

    def test_crash_during_gc(self):
        self.assert_crash_recovers('gc:after-child')


if __name__ == '__main__':
    unittest.main()
