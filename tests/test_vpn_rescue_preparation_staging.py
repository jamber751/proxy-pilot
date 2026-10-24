"""Typed root-owned legacy source staging in disposable VM directories only."""
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
import test_vpn_rescue_executor as identity
import test_vpn_staged_application as staged
ROOT, HELPER = identity.ROOT, identity.HELPER

@unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() == 0
                     and os.environ.get('PROXYPILOT_VM_ROOT_TESTS') == '1',
                     'explicit disposable macOS root VM fixture')
class VPNRescuePreparationStagingRootTests(identity.RescueBuild, unittest.TestCase):
    root_vm_fixture = True
    make_app = staged.VPNStagedApplicationTests.make_app
    @classmethod
    def setUpClass(cls):
        staged.VPNStagedApplicationTests.setUpClass.__func__(cls)
        cls.temporary = tempfile.TemporaryDirectory(prefix='pp-rescue-identity-build-', dir='/tmp')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.build = Path(cls.temporary.name)
        sources = [HELPER / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
            'VPNRescueAuthorization.swift', 'VPNRescuePreparationAuthorization.swift',
            'VPNHelperArtifact.swift', 'VPNRescueExecutor.swift', 'VPNRescuePreparationExecutor.swift',
            'VPNLifecycleOwnership.swift', 'VPNStagedApplication.swift', 'VPNDirectoryProvisioner.swift',
            'VPNApplicationTransactionStager.swift')]
        sources.append(ROOT / 'tests/vpn_rescue_preparation_staging_checks.swift')
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.build / arch
            cls.command(['swiftc', '-D', 'VPN_RESCUE_EXECUTOR_TESTING', '-D', 'VPN_RESCUE_PREPARATION', '-D', 'VPN_APPLICATION_TRANSACTION_STAGING_TESTING', '-target',
                         arch + '-apple-macosx11.0', *map(str, sources), '-o', str(output)])
            slices.append(str(output))
        cls.binary = cls.build / 'checks'
        cls.command(['lipo', '-create', *slices, '-output', str(cls.binary)])
        cls.binary.chmod(0o700)
        identity.RescueBuild.sign(cls.binary)
        cls.code_hashes = identity.RescueBuild.pins(cls.binary)

    def setUp(self):
        identity.RescueBuild.setUp(self)
        self.source = self.work / 'source'; self.source.mkdir(mode=0o700)
        self.candidate = self.work / 'candidate'; self.candidate.mkdir(mode=0o700)
        self.base = self.work / 'transaction'; self.base.mkdir(mode=0o700)
        self.app = self.source / 'ProxyPilot.app'
        self.make_app(version='1.6.0')
        self.a = staged.VPNStagedApplicationTests.pins(self)
        self.app = self.candidate / 'ProxyPilot.app'
        self.make_app(version='1.7.0')
        if self._testMethodName != 'test_candidate_without_sealed_capability_is_refused':
            info = self.app / 'Contents/Info.plist'
            metadata = plistlib.loads(info.read_bytes())
            metadata['ProxyPilotVPNRootOwnedUpdateExecutor'] = '1'
            info.write_bytes(plistlib.dumps(metadata))
            staged.VPNStagedApplicationTests.sign(self, self.app, staged.APP_ID)
        self.b = staged.VPNStagedApplicationTests.pins(self)
        self.source_before = self.source_snapshot()

    def source_snapshot(self):
        result = {}
        for folder in (self.source, self.candidate):
            for item in folder.rglob('*'):
                info = item.lstat()
                result[str(item)] = (info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                                     item.read_bytes() if item.is_file() else b'')
        return result

    def invoke(self, operation='live', runner=None):
        return subprocess.run([str(runner or self.artifact), operation, str(self.directory), str(self.binary),
            self.code_hashes['arm64'], self.code_hashes['x86_64'], self.a['arm64'], self.a['x86_64'],
            self.b['arm64'], self.b['x86_64'], str(self.base), str(self.source), str(self.candidate)],
            env=identity.ENV, capture_output=True, text=True, timeout=60)

    def refused_without_copies(self, operation='live', runner=None):
        result = self.invoke(operation, runner)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(list(self.base.iterdir()), [])

    def test_root_source_without_capability_stages_and_retries(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('staged:staged', result.stdout)
        self.assertEqual(self.invoke().stdout.strip(), 'staged:alreadyStaged')
        self.assertEqual(self.source_snapshot(), self.source_before)
        for slot in ('current', 'candidate'):
            self.assertEqual((self.base / slot / 'ProxyPilot.app').stat().st_uid, 0)

    def test_candidate_without_sealed_capability_is_refused(self): self.refused_without_copies()
    def test_wrong_edge_is_refused_before_copies(self): self.refused_without_copies('wrong-edge')
    def test_nonlive_process_is_refused_before_copies(self): self.refused_without_copies(runner=self.binary)
    def test_invalid_live_proof_is_refused_before_copies(self): self.refused_without_copies('chmod-after')
    def test_user_owned_source_is_refused(self):
        app = self.source / 'ProxyPilot.app'
        for item in [app, *app.rglob('*')]: os.chown(item, 501, -1, follow_symlinks=False)
        self.refused_without_copies()

    def test_live_proof_rechecked_before_publication(self):
        result = self.invoke('invalidate-before-publish')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertFalse((self.base / 'current').exists())
        self.assertFalse((self.base / 'candidate').exists())

    def test_interrupted_current_publication_resumes(self):
        result = self.invoke('interrupt-after-current')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue((self.base / 'current').exists())
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'staged:resumed')

if __name__ == '__main__':
    unittest.main()
