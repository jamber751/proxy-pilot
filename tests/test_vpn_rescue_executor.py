"""Static/live rescue identity. Root tests run only in disposable macOS VMs."""
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'app/vpn-helper'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
IDENTIFIER = 'kz.documentolog.proxypilot.vpn-rescue'


class RescueBuild:
    @classmethod
    def command(cls, arguments):
        result = subprocess.run(arguments, env=ENV, capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return result

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='pp-rescue-identity-build-', dir='/tmp')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.build = Path(cls.temporary.name)
        sources = [HELPER / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
            'VPNRescueAuthorization.swift', 'VPNHelperArtifact.swift', 'VPNRescueExecutor.swift')]
        sources.append(ROOT / 'tests/vpn_rescue_executor_checks.swift')
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.build / arch
            cls.command(['swiftc', '-D', 'VPN_RESCUE_EXECUTOR_TESTING', '-target',
                         arch + '-apple-macosx11.0', *map(str, sources), '-o', str(output)])
            slices.append(str(output))
        cls.binary = cls.build / 'checks'
        cls.command(['lipo', '-create', *slices, '-output', str(cls.binary)])
        cls.binary.chmod(0o700)
        cls.sign(cls.binary)
        cls.code_hashes = cls.pins(cls.binary)

    @classmethod
    def sign(cls, path, identifier=IDENTIFIER, hardened=True, entitlements=None):
        args = ['codesign', '--force', '--sign', '-', '--identifier', identifier]
        if hardened:
            args += ['--options', 'runtime,hard,kill']
        else:
            args += ['--options', 'runtime'] # explicitly omit hard/kill
        if entitlements:
            args += ['--entitlements', str(entitlements)]
        cls.command([*args, str(path)])

    @classmethod
    def pins(cls, path):
        result = {}
        for arch in ('arm64', 'x86_64'):
            output = cls.command(['codesign', '-d', '--verbose=4', '--arch', arch, str(path)]).stderr
            result[arch] = re.search(r'^CDHash=([a-f0-9]{40})$', output, re.M).group(1)
        return result

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-rescue-identity-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.directory = self.work / 'protected'; self.directory.mkdir(mode=0o700)
        self.artifact = self.directory / 'vpn-rescue'
        shutil.copyfile(self.binary, self.artifact); self.artifact.chmod(0o700)

    def invoke(self, operation='static', runner=None, reference=None, pins=None):
        pins = pins or self.code_hashes
        return subprocess.run([str(runner or self.binary), operation, str(self.directory),
                               str(reference or self.binary), pins['arm64'], pins['x86_64']],
                              env=ENV, capture_output=True, text=True, timeout=30)


@unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() == 0
                     and os.environ.get('PROXYPILOT_VM_ROOT_TESTS') == '1',
                     'explicit root test requires disposable macOS VM')
class VPNRescueExecutorRootTests(RescueBuild, unittest.TestCase):
    def test_static_and_live_proofs_are_distinct(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'static')
        wrong_process = self.invoke('live')
        self.assertEqual(wrong_process.returncode, 77, wrong_process.stdout + wrong_process.stderr)
        self.assertIn('wrongProcess', wrong_process.stdout)
        live = self.invoke('live', runner=self.artifact)
        self.assertEqual(live.returncode, 0, live.stdout + live.stderr)
        self.assertEqual(live.stdout.strip(), 'live')

    def test_rebound_or_changed_file_invalidates_observation(self):
        for operation in ('chmod-after', 'rebind-after'):
            with self.subTest(operation=operation):
                self.assertEqual(self.invoke(operation).returncode, 77)
                shutil.rmtree(self.directory); self.directory.mkdir(mode=0o700)
                shutil.copyfile(self.binary, self.artifact); self.artifact.chmod(0o700)

    def test_writable_or_nonprivate_storage_is_refused(self):
        self.directory.chmod(0o755)
        self.assertEqual(self.invoke().returncode, 77)
        self.directory.chmod(0o700); self.artifact.chmod(0o755)
        self.assertEqual(self.invoke().returncode, 77)

    def test_symlink_and_hardlink_are_refused(self):
        self.artifact.unlink(); self.artifact.symlink_to(self.binary)
        self.assertEqual(self.invoke().returncode, 77)
        self.artifact.unlink(); os.link(self.binary, self.artifact)
        self.assertEqual(self.invoke().returncode, 77)

    def test_wrong_owner_is_refused(self):
        os.chown(self.artifact, 501, -1)
        self.assertEqual(self.invoke().returncode, 77)

    def test_unknown_sibling_is_preserved_and_refused(self):
        sentinel = self.directory / 'unknown'; sentinel.write_text('keep')
        self.assertEqual(self.invoke().returncode, 77)
        self.assertEqual(sentinel.read_text(), 'keep')

    def test_changed_artifact_bytes_are_refused(self):
        with self.artifact.open('ab') as stream:
            stream.write(b'changed')
        self.assertEqual(self.invoke().returncode, 77)

    def test_wrong_pins_are_refused_even_when_bytes_match(self):
        result = self.invoke(pins={'arm64': '0' * 40, 'x86_64': '1' * 40})
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)

    def test_acl_is_refused(self):
        self.command(['chmod', '+a', 'everyone allow read', str(self.artifact)])
        self.assertEqual(self.invoke().returncode, 77)

    def test_thin_signed_artifact_is_refused(self):
        shutil.copyfile(self.build / 'arm64', self.artifact)
        self.artifact.chmod(0o700); self.sign(self.artifact)
        output = self.command(['codesign', '-d', '--verbose=4', str(self.artifact)]).stderr
        arm = re.search(r'^CDHash=([a-f0-9]{40})$', output, re.M).group(1)
        result = self.invoke(reference=self.artifact, pins={'arm64': arm, 'x86_64': '1' * 40})
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)

    def test_wrong_identifier_hardening_and_entitlements_are_refused(self):
        entitlement = self.work / 'entitlements.plist'
        entitlement.write_bytes(plistlib.dumps({'com.apple.security.cs.allow-jit': True}))
        for options in ({'identifier': 'kz.documentolog.proxypilot'},
                        {'hardened': False}, {'entitlements': entitlement}):
            with self.subTest(options=options):
                shutil.copyfile(self.binary, self.artifact); self.artifact.chmod(0o700)
                self.sign(self.artifact, **options)
                result = self.invoke(reference=self.artifact, pins=self.pins(self.artifact))
                self.assertEqual(result.returncode, 77, result.stdout + result.stderr)


@unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() != 0,
                     'ordinary-user refusal test')
class VPNRescueExecutorUnprivilegedTests(RescueBuild, unittest.TestCase):
    def test_ordinary_user_cannot_obtain_static_or_live_root_proof(self):
        for operation in ('static', 'live'):
            result = self.invoke(operation)
            self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), 'rejected:requiresRoot')


if __name__ == '__main__':
    unittest.main()
