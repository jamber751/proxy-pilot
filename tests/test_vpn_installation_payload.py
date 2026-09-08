"""Fixed package sidecars, real signatures and Universal helper validation; no root."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'app/vpn-helper'


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNInstallationPayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0: raise unittest.SkipTest('Never root')
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-payload-build-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.build = Path(cls.temp.name)
        for name, sources, compiler in [
            ('checks', [HELPER / f'{name}.swift' for name in ('VPNPeerAuthentication', 'VPNReleaseAuthorization',
             'VPNHelperArtifact', 'VPNInstallationPayload')] + [ROOT / 'tests/vpn_payload_checks.swift'], 'swiftc'),
            ('helper', [ROOT / 'tests/vpn-deployment/HelperFixture.c'], 'clang'),
        ]:
            slices = []
            for arch in ('arm64', 'x86_64'):
                output = cls.build / f'{name}-{arch}'
                cls.command([compiler, '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(output)])
                slices.append(str(output))
            cls.command(['lipo', '-create', *slices, '-output', str(cls.build / name)])
        cls.sign_helper(cls.build / 'helper')

    @staticmethod
    def command(args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
        if result.returncode: raise AssertionError(result.stdout + result.stderr)
        return result

    @classmethod
    def sign_helper(cls, path, *, identifier='kz.documentolog.proxypilot.vpn-helper', hardened=True):
        subprocess.run(['codesign', '--remove-signature', str(path)], capture_output=True)
        args = ['codesign', '--force', '--sign', '-', '--identifier', identifier]
        if hardened: args += ['--options', 'runtime,hard,kill']
        cls.command([*args, str(path)])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pp-payload-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        shutil.copyfile(self.build / 'helper', self.work / 'vpn-helper')
        (self.work / 'vpn-helper').chmod(0o700)
        self.manifest()

    def manifest(self):
        path = self.work / 'vpn-helper'
        data = path.read_bytes()
        pins = {}
        for arch in ('arm64', 'x86_64'):
            output = subprocess.run(['codesign', '-d', '--verbose=4', '--arch', arch, str(path)], capture_output=True, text=True)
            match = re.search(r'^CDHash=([a-f0-9]{40})$', output.stderr, re.M)
            pins[arch] = match.group(1) if match else '44' * 20
        fields = dict(format=1, product='kz.documentolog.proxypilot', sequence=1, version='1.6.0', protocol=1)
        fields.update({'app-arm64': '11' * 20, 'app-x86_64': '22' * 20,
                       'helper-arm64': pins['arm64'], 'helper-x86_64': pins['x86_64'],
                       'helper-sha256': hashlib.sha256(data).hexdigest(), 'helper-bytes': len(data)})
        (self.work / 'vpn-release.manifest').write_text(''.join(f'{key}={value}\n' for key, value in fields.items()))
        self.command([str(self.build / 'checks'), 'sign', str(self.work)])

    def verify(self, *, version='1.6.0', expected=77):
        result = subprocess.run([str(self.build / 'checks'), 'verify', str(self.work), version],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def test_signed_universal_package_is_accepted(self): self.verify(expected=0)
    def test_app_version_must_match(self): self.verify(version='1.6.1')

    def test_production_loader_requires_engine_declared_by_manifest(self):
        path = self.work / 'vpn-release.manifest'
        text = path.read_text().replace('format=1\n', 'format=2\n')
        fields = {'engine-version': '2.7.7', 'engine-crypto-version': '3.5.8',
                  'engine-arm64': '55' * 20, 'engine-x86_64': '66' * 20,
                  'engine-sha256': hashlib.sha256(b'engine').hexdigest(), 'engine-bytes': 6}
        path.write_text(text + ''.join(f'{key}={value}\n' for key, value in fields.items()))
        self.command([str(self.build / 'checks'), 'sign', str(self.work)])
        result = self.verify()
        self.assertIn('unsafePackage', result.stdout)

    def add_engine(self):
        path = self.work / 'vpn-engine'
        shutil.copyfile(self.build / 'helper', path); path.chmod(0o700)
        self.sign_helper(path, identifier='kz.documentolog.proxypilot.openvpn')
        data = path.read_bytes()
        pins = {}
        for arch in ('arm64', 'x86_64'):
            result = self.command(['codesign', '-d', '--verbose=4', '--arch', arch, str(path)])
            pins[arch] = re.search(r'^CDHash=([a-f0-9]{40})$', result.stderr, re.M).group(1)
        manifest = self.work / 'vpn-release.manifest'
        extra = {'engine-version': '2.7.7', 'engine-crypto-version': '3.5.8',
                 'engine-arm64': pins['arm64'], 'engine-x86_64': pins['x86_64'],
                 'engine-sha256': hashlib.sha256(data).hexdigest(), 'engine-bytes': len(data)}
        manifest.write_text(manifest.read_text().replace('format=1\n', 'format=2\n')
                            + ''.join(f'{key}={value}\n' for key, value in extra.items()))
        self.command([str(self.build / 'checks'), 'sign', str(self.work)])
        return path

    def test_complete_engine_package_is_accepted(self):
        self.add_engine(); self.verify(expected=0)

    def test_changed_engine_is_rejected(self):
        path = self.add_engine()
        with path.open('ab') as stream: stream.write(b'changed')
        self.verify()

    def test_extra_engine_without_signed_identity_is_rejected(self):
        shutil.copyfile(self.build / 'helper', self.work / 'vpn-engine'); self.verify()

    def test_engine_symlink_is_rejected(self):
        path = self.add_engine(); path.rename(self.work / 'original-engine')
        path.symlink_to('original-engine'); self.verify()

    def test_engine_hardlink_is_rejected(self):
        path = self.add_engine(); os.link(path, self.work / 'linked-engine'); self.verify()

    def test_engine_fifo_is_rejected_without_blocking(self):
        path = self.add_engine(); path.unlink(); os.mkfifo(path); self.verify()

    def test_engine_oversize_is_rejected_before_reading(self):
        path = self.add_engine()
        with path.open('r+b') as stream: stream.truncate(64 * 1024 * 1024 + 1)
        self.verify()

    def test_engine_shared_permissions_are_rejected(self):
        path = self.add_engine(); path.chmod(0o666); self.verify()

    def test_changed_manifest_is_rejected(self):
        with (self.work / 'vpn-release.manifest').open('a') as stream: stream.write('extra=1\n')
        self.verify()

    def test_signature_encoding_is_canonical(self):
        path = self.work / 'vpn-release.sig'; path.write_text(path.read_text() + '\n')
        self.verify()

    def test_signature_from_wrong_key_is_rejected(self):
        (self.work / 'vpn-release.sig').write_text('A' * 86 + '==\n')
        self.verify()

    def test_changed_helper_is_rejected(self):
        with (self.work / 'vpn-helper').open('ab') as stream: stream.write(b'changed')
        self.verify()

    def test_symlink_is_rejected(self):
        path = self.work / 'vpn-release.manifest'; path.rename(self.work / 'original')
        path.symlink_to('original'); self.verify()

    def test_hard_link_is_rejected(self):
        os.link(self.work / 'vpn-helper', self.work / 'other'); self.verify()

    def test_fifo_does_not_block(self):
        path = self.work / 'vpn-release.manifest'; path.unlink(); os.mkfifo(path)
        self.verify()

    def test_shared_package_is_rejected(self):
        self.work.chmod(0o777); self.verify()

    def test_group_writable_sidecar_is_rejected(self):
        (self.work / 'vpn-release.manifest').chmod(0o664); self.verify()

    def test_oversized_helper_is_rejected_before_reading(self):
        with (self.work / 'vpn-helper').open('r+b') as stream: stream.truncate(32 * 1024 * 1024 + 1)
        self.verify()

    def test_signed_unhardened_helper_is_rejected(self):
        self.sign_helper(self.work / 'vpn-helper', hardened=False); self.manifest(); self.verify()

    def test_signed_wrong_helper_identifier_is_rejected(self):
        self.sign_helper(self.work / 'vpn-helper', identifier='kz.documentolog.proxypilot.updater')
        self.manifest(); self.verify()

    def test_signed_thin_helper_is_rejected(self):
        shutil.copyfile(self.build / 'helper-arm64', self.work / 'vpn-helper')
        self.sign_helper(self.work / 'vpn-helper'); self.manifest(); self.verify()
