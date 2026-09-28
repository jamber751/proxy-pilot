"""Crash-safe cleanup of authenticated joint-update working copies."""
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
class VPNJointUpdateCleanupTests(unittest.TestCase):
    command = staged.VPNStagedApplicationTests.__dict__['command']
    make_app = staged.VPNStagedApplicationTests.make_app
    sign = staged.VPNStagedApplicationTests.sign
    pins = staged.VPNStagedApplicationTests.pins

    @classmethod
    def setUpClass(cls):
        staged.VPNStagedApplicationTests.setUpClass.__func__(cls)
        cls.helper = cls.build / 'cleanup-helper'
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
        cls.cleanup = cls.build / 'cleanup-checks'
        cls.command(['swiftc', '-D', 'VPN_JOINT_UPDATE_CLEANUP_TESTING',
                     '-D', 'VPN_RELEASE_STORE_TESTING', *map(str, sources),
                     str(ROOT / 'tests/vpn_joint_update_cleanup_checks.swift'),
                     '-o', str(cls.cleanup)])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-cleanup-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.stage = self.work / 'a-source'; self.stage.mkdir(mode=0o700)
        self.app = self.stage / 'ProxyPilot.app'; self.make_app(version='1.6.0')
        a_source = self.stage
        self.a_pins = self.pins()
        self.stage = self.work / 'b-source'; self.stage.mkdir(mode=0o700)
        self.app = self.stage / 'ProxyPilot.app'; self.make_app(version='1.7.0')
        self.b_pins = self.pins()
        b_source = self.stage
        self.service = self.work / 'VPN'; self.service.mkdir(mode=0o700)
        self.update = self.work / 'Update'; self.update.mkdir(mode=0o700)
        self.retired = self.work / 'Retired'; self.retired.mkdir(mode=0o700)
        self.applications = self.work / 'Applications'; self.applications.mkdir(mode=0o700)
        (self.update / 'current').mkdir(mode=0o700)
        shutil.copytree(b_source / 'ProxyPilot.app', self.update / 'current/ProxyPilot.app', symlinks=True)
        for name in ('candidate', 'executor'):
            (self.update / name).mkdir(mode=0o700)
            shutil.copytree(a_source / 'ProxyPilot.app', self.update / name / 'ProxyPilot.app', symlinks=True)
        (self.applications / '.ProxyPilot.vpn-update').mkdir(mode=0o700)
        shutil.copytree(a_source / 'ProxyPilot.app',
                        self.applications / '.ProxyPilot.vpn-update/ProxyPilot.app', symlinks=True)
        helper = self.helper.read_bytes()
        self.manifests = []
        for sequence, version, pins in ((10, '1.6.0', self.a_pins), (11, '1.7.0', self.b_pins)):
            manifest = self.work / f'{sequence}.manifest'
            fields = {
                'format': '1', 'product': 'kz.documentolog.proxypilot',
                'sequence': str(sequence), 'version': version, 'protocol': '1',
                'app-arm64': pins['arm64'], 'app-x86_64': pins['x86_64'],
                'helper-arm64': self.helper_pins['arm64'],
                'helper-x86_64': self.helper_pins['x86_64'],
                'helper-sha256': hashlib.sha256(helper).hexdigest(),
                'helper-bytes': str(len(helper)),
            }
            manifest.write_bytes(''.join(f'{k}={v}\n' for k, v in fields.items()).encode())
            self.manifests.append(manifest)
        setup = self.invoke('setup')
        self.assertEqual(setup.returncode, 0, setup.stdout + setup.stderr)
        self.transaction = setup.stdout.strip()

    def invoke(self, operation='cleanup'):
        return subprocess.run([str(self.cleanup), operation, str(self.service),
                               str(self.update), str(self.retired), str(self.applications),
                               *map(str, self.manifests), str(self.helper), 'unused'],
                              env=ENV, capture_output=True, text=True, timeout=180)

    def test_cleanup_removes_only_verified_quarantine_and_receipt(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.service / 'cleanup.json').exists())
        self.assertEqual(list(self.retired.iterdir()), [])
        self.assertEqual(list(self.applications.iterdir()), [])
        self.assertEqual([p.name for p in self.update.iterdir()], ['lifecycle.lock'])

    def assert_crash_recovers(self, point):
        result = self.invoke('crash:' + point)
        self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.service / 'cleanup.json').exists())

    def test_crash_after_application_rename(self): self.assert_crash_recovers('application:after-rename')
    def test_crash_after_current_rename(self): self.assert_crash_recovers('update:after-current')
    def test_crash_after_candidate_rename(self): self.assert_crash_recovers('update:after-candidate')
    def test_crash_after_executor_rename(self): self.assert_crash_recovers('update:after-executor')
    def test_crash_after_gc_authorization(self): self.assert_crash_recovers('gc:after-authorize')
    def test_crash_during_gc(self): self.assert_crash_recovers('gc:after-child')

    def test_extra_update_entry_and_replaced_archive_fail_closed(self):
        (self.update / 'foreign').write_text('keep')
        result = self.invoke()
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue((self.service / 'cleanup.json').exists())
        self.assertTrue((self.update / 'foreign').exists())

    def test_symlinked_working_slot_is_never_followed(self):
        stage = self.applications / '.ProxyPilot.vpn-update'
        saved = self.work / 'saved-stage'
        stage.rename(saved)
        stage.symlink_to(saved)
        result = self.invoke()
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue(stage.is_symlink())
        self.assertTrue((saved / 'ProxyPilot.app').is_dir())
        self.assertTrue((self.service / 'cleanup.json').exists())

    def test_gc_root_inode_replacement_is_rejected_on_retry(self):
        result = self.invoke('crash:gc:after-authorize')
        self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
        root = self.retired / self.transaction
        current = root / 'current'
        displaced = root / 'current-displaced'
        current.rename(displaced)
        current.mkdir(mode=0o700)
        result = self.invoke()
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue((displaced / 'ProxyPilot.app').is_dir())
        self.assertTrue((self.service / 'cleanup.json').exists())


if __name__ == '__main__':
    unittest.main()
