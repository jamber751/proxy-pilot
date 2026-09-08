"""Real static engine identity checks; inert fixtures, no VPN or production key."""
import hashlib
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
IDENTIFIER = 'kz.documentolog.proxypilot.openvpn'


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNEngineArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0: raise unittest.SkipTest('Never root')
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-engine-static-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.build = Path(cls.temp.name)
        sources = [ROOT / 'app/vpn-helper' / f'{name}.swift' for name in
                   ('VPNPeerAuthentication', 'VPNReleaseAuthorization', 'VPNHelperArtifact')]
        sources += [ROOT / 'tests/vpn_engine_artifact_checks.swift']
        for name, compiler, inputs in [('checks', 'swiftc', sources),
                                      ('engine', 'clang', [ROOT / 'tests/vpn-deployment/HelperFixture.c'])]:
            slices = []
            for arch in ('arm64', 'x86_64'):
                output = cls.build / f'{name}-{arch}'
                flags = ['-D', 'VPN_ENGINE_DELIVERY_TESTING'] if compiler == 'swiftc' else []
                cls.command([compiler, *flags, '-target', f'{arch}-apple-macosx11.0', *map(str, inputs), '-o', str(output)])
                slices.append(str(output))
            cls.command(['lipo', '-create', *slices, '-output', str(cls.build / name)])
        cls.sign(cls.build / 'engine')

    @staticmethod
    def command(args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
        if result.returncode: raise AssertionError(result.stdout + result.stderr)
        return result

    @classmethod
    def sign(cls, path, identifier=IDENTIFIER, options='runtime,hard,kill', entitlements=None):
        subprocess.run(['codesign', '--remove-signature', str(path)], capture_output=True, timeout=10)
        args = ['codesign', '--force', '--sign', '-', '--identifier', identifier]
        if options: args += ['--options', options]
        if entitlements:
            plist = path.with_suffix('.plist'); plist.write_bytes(plistlib.dumps(entitlements))
            args += ['--entitlements', str(plist)]
        cls.command([*args, str(path)])

    def setUp(self):
        self.work_temp = tempfile.TemporaryDirectory(prefix='pp-engine-candidate-', dir='/tmp')
        self.addCleanup(self.work_temp.cleanup)
        self.work = Path(self.work_temp.name)
        self.engine = self.work / 'engine'
        shutil.copyfile(self.build / 'engine', self.engine)
        self.engine.chmod(0o700)

    def manifest(self, changes=None):
        data = self.engine.read_bytes()
        pins = {}
        for arch in ('arm64', 'x86_64'):
            result = subprocess.run(['codesign', '-d', '--verbose=4', '--arch', arch, str(self.engine)],
                                    capture_output=True, text=True, timeout=10)
            match = re.search(r'^CDHash=([a-f0-9]{40})$', result.stderr, re.M)
            pins[arch] = match.group(1) if match else 'ff' * 20
        fields = dict(format=2, product='kz.documentolog.proxypilot', sequence=1, version='1.6.0', protocol=1)
        fields.update({'app-arm64': '11' * 20, 'app-x86_64': '22' * 20,
                       'helper-arm64': '33' * 20, 'helper-x86_64': '44' * 20,
                       'helper-sha256': '55' * 32, 'helper-bytes': 1,
                       'engine-version': '2.7.7', 'engine-crypto-version': '3.5.8',
                       'engine-arm64': pins['arm64'], 'engine-x86_64': pins['x86_64'],
                       'engine-sha256': hashlib.sha256(data).hexdigest(), 'engine-bytes': len(data)})
        fields.update(changes or {})
        path = self.work / 'manifest'
        path.write_text(''.join(f'{key}={value}\n' for key, value in fields.items()))
        return path

    def verify(self, expected=77, changes=None, manifest=None):
        result = subprocess.run([str(self.build / 'checks'), str(manifest or self.manifest(changes)), str(self.engine)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertIn('engine verified' if expected == 0 else 'rejected:invalidEngineArtifact', result.stdout)

    def test_exact_universal_engine_is_accepted_without_execution(self): self.verify(expected=0)

    def test_changed_bytes_are_rejected(self):
        manifest = self.manifest()
        with self.engine.open('ab') as stream: stream.write(b'tampered')
        self.verify(manifest=manifest)

    def test_each_architecture_pin_is_required(self):
        for arch in ('arm64', 'x86_64'):
            with self.subTest(arch=arch): self.verify(changes={f'engine-{arch}': 'aa' * 20})

    def test_helper_identity_cannot_substitute_for_engine(self):
        self.sign(self.engine, identifier='kz.documentolog.proxypilot.vpn-helper'); self.verify()

    def test_hardening_is_required(self):
        self.sign(self.engine, options=None); self.verify()

    def test_runtime_exceptions_are_rejected(self):
        self.sign(self.engine, entitlements={'com.apple.security.cs.disable-library-validation': True})
        self.verify()

    def test_non_native_slice_is_validated(self):
        weak = self.work / 'weak'; shutil.copyfile(self.engine, weak); self.sign(weak, options=None)
        for name, source, arch in [('arm', self.engine, 'arm64'), ('intel', weak, 'x86_64')]:
            self.command(['lipo', str(source), '-thin', arch, '-output', str(self.work / name)])
        self.command(['lipo', '-create', str(self.work / 'arm'), str(self.work / 'intel'), '-output', str(self.engine)])
        self.verify()

    def test_thin_engine_is_rejected(self):
        shutil.copyfile(self.build / 'engine-arm64', self.engine); self.sign(self.engine); self.verify()

    def test_signed_manifest_cannot_authorize_non_executable_bytes(self):
        self.engine.write_bytes(b'not a Mach-O executable'); self.verify()

    @unittest.skipUnless(os.environ.get('PROXYPILOT_VPN_ENGINE_CANDIDATE'), 'Optional locally built engine candidate')
    def test_local_openvpn_candidate_static_identity(self):
        source = Path(os.environ['PROXYPILOT_VPN_ENGINE_CANDIDATE'])
        self.assertTrue(source.is_absolute())
        shutil.copyfile(source, self.engine)
        self.verify(expected=0)
