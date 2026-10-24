"""Fixed static rescue package with synthetic signatures; no root or launches."""
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

import test_vpn_staged_application as staged
import test_vpn_rescue_executor as identity


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNRescueInstallationPayloadTests(unittest.TestCase):
    command = staged.VPNStagedApplicationTests.__dict__['command']
    make_app = staged.VPNStagedApplicationTests.make_app
    sign = staged.VPNStagedApplicationTests.sign
    pins = staged.VPNStagedApplicationTests.pins

    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0: raise unittest.SkipTest('Never root')
        staged.VPNStagedApplicationTests.setUpClass.__func__(cls)
        sources = [staged.HELPER / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNRescueAuthorization.swift',
            'VPNRescuePreparationAuthorization.swift', 'VPNHelperArtifact.swift',
            'VPNInstallationPayload.swift', 'VPNStagedApplication.swift', 'VPNRescueInstallationPayload.swift')]
        sources.append(staged.ROOT / 'tests/vpn_rescue_installation_payload_checks.swift')
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.build / ('payload-' + arch)
            cls.command(['swiftc', '-target', arch + '-apple-macosx11.0', *map(str, sources), '-o', str(output)])
            slices.append(str(output))
        cls.driver = cls.build / 'rescue-payload'
        cls.command(['lipo', '-create', *slices, '-output', str(cls.driver)])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-rescue-payload-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.root = self.work / 'package'; self.root.mkdir(mode=0o700)
        self.metadata = self.root / 'Metadata'; self.metadata.mkdir(mode=0o700)
        self.candidate = self.root / 'Candidate'; self.candidate.mkdir(mode=0o700)
        self.executable = self.root / 'Executable'; self.executable.mkdir(mode=0o700)
        self.app = self.candidate / 'ProxyPilot.app'; self.make_app(version='1.8.0')
        info = self.app / 'Contents/Info.plist'
        fields = plistlib.loads(info.read_bytes()); fields['ProxyPilotVPNRootOwnedUpdateExecutor'] = '1'
        info.write_bytes(plistlib.dumps(fields)); self.sign(self.app, staged.APP_ID)
        self.helper = self.candidate / 'vpn-helper'
        shutil.copyfile(self.universal, self.helper); self.helper.chmod(0o700)
        self.sign(self.helper, 'kz.documentolog.proxypilot.vpn-helper')
        self.artifact = self.executable / 'vpn-rescue'
        shutil.copyfile(self.universal, self.artifact); self.artifact.chmod(0o700)
        self.sign(self.artifact, 'kz.documentolog.proxypilot.vpn-rescue')
        self.fixture()

    def fixture(self, variant='fixture', engine=False):
        for folder in (self.metadata, self.candidate):
            for item in folder.iterdir():
                if item.name != 'ProxyPilot.app' and item.name not in ('vpn-helper', 'vpn-engine'):
                    item.unlink()
        app = self.pins(); helper = identity.RescueBuild.pins(self.helper)
        rescue = identity.RescueBuild.pins(self.artifact)
        args = [str(self.driver), variant, str(self.root), app['arm64'], app['x86_64'],
                helper['arm64'], helper['x86_64'], rescue['arm64'], rescue['x86_64']]
        if engine:
            pins = identity.RescueBuild.pins(self.candidate / 'vpn-engine')
            args += [pins['arm64'], pins['x86_64']]
        result = subprocess.run(args, env=staged.ENV, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def verify(self, operation='verify', accepted=False):
        result = subprocess.run([str(self.driver), operation, str(self.root)],
                                env=staged.ENV, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0 if accepted else 77, result.stdout + result.stderr)
        if accepted: self.assertIn('verified:137->139->141', result.stdout)
        return result

    def test_valid_package_and_retained_descriptors(self): self.verify(accepted=True)

    def test_optional_signed_engine(self):
        engine = self.candidate / 'vpn-engine'
        shutil.copyfile(self.universal, engine); engine.chmod(0o700)
        self.sign(engine, 'kz.documentolog.proxypilot.openvpn')
        self.fixture(engine=True); self.verify(accepted=True)

    def test_signed_cross_edge_rejected(self): self.fixture('fixture-cross-first'); self.verify()
    def test_signed_other_artifact_rejected(self): self.fixture('fixture-wrong-second-artifact'); self.verify()
    def test_signed_other_start_arch_pin_rejected(self): self.fixture('fixture-wrong-start-pin'); self.verify()
    def test_signed_finish_operation_cannot_authorize_preparation(self):
        self.fixture('fixture-finish-as-start'); self.verify()

    def test_missing_sealed_candidate_capability(self):
        info = self.app / 'Contents/Info.plist'
        fields = plistlib.loads(info.read_bytes()); fields.pop('ProxyPilotVPNRootOwnedUpdateExecutor')
        info.write_bytes(plistlib.dumps(fields)); self.sign(self.app, staged.APP_ID)
        self.fixture(); self.assertIn('missingCapability', self.verify().stdout)

    def test_changed_sealed_candidate_resource(self):
        (self.app / 'Contents/Resources/data.txt').write_text('changed'); self.verify()

    def test_unknown_names_rejected_in_every_directory(self):
        for directory in (self.root, self.executable, self.metadata, self.candidate):
            with self.subTest(directory=directory.name):
                path = directory / 'unexpected'; path.write_text('extra')
                self.verify(); path.unlink()

    def test_missing_inputs_rejected(self):
        for path in [self.metadata / name for name in ('source-release.manifest', 'first-transition',
                     'finish-first', 'prepare-second.sig', 'finish-second')]:
            with self.subTest(name=path.name):
                contents = path.read_bytes(); path.unlink(); self.verify(); path.write_bytes(contents)

    def test_changed_signed_inputs_rejected(self):
        for path in [self.metadata / name for name in ('source-release.manifest', 'first-transition',
                     'finish-first', 'prepare-second', 'finish-second')]:
            with self.subTest(name=path.name):
                original = path.read_bytes(); path.write_bytes(original + b'changed'); self.verify(); path.write_bytes(original)

    def test_signature_encoding_rejected(self):
        path = self.metadata / 'finish-first.sig'; path.write_bytes(path.read_bytes() + b'\n'); self.verify()

    def test_directory_symlinks_rejected(self):
        for name in ('Executable', 'Metadata', 'Candidate'):
            with self.subTest(name=name):
                path = self.root / name; old = self.work / ('old-' + name)
                path.rename(old); path.symlink_to(old, target_is_directory=True)
                self.verify(); path.unlink(); old.rename(path)

    def test_sidecar_symlink_and_hardlink_rejected(self):
        path = self.metadata / 'finish-first'; original = self.work / 'outside'
        path.rename(original); path.symlink_to(original); self.verify(); path.unlink()
        os.link(original, path); self.verify()

    def test_fifo_does_not_block(self):
        path = self.metadata / 'finish-first'; path.unlink(); os.mkfifo(path); self.verify()

    def test_oversized_input_rejected(self):
        path = self.metadata / 'finish-first'
        with path.open('wb') as stream: stream.truncate(2049)
        self.verify()

    def test_shared_directory_permissions_rejected(self):
        for directory in (self.root, self.executable, self.metadata, self.candidate):
            with self.subTest(directory=directory.name):
                directory.chmod(0o755); self.verify(); directory.chmod(0o700)

    def test_changed_artifact_rejected(self):
        with self.artifact.open('ab') as stream: stream.write(b'changed')
        self.verify()

    def test_rescue_executable_requires_private_executable_mode(self):
        self.artifact.chmod(0o600); self.verify()

    def test_rescue_identifier_must_match_static_signature(self):
        self.sign(self.artifact, 'kz.documentolog.proxypilot.vpn-helper')
        self.fixture(); self.verify()

    def test_manifest_version_must_match_sealed_candidate(self):
        info = self.app / 'Contents/Info.plist'
        fields = plistlib.loads(info.read_bytes()); fields['CFBundleVersion'] = '1.9.0'
        fields['CFBundleShortVersionString'] = '1.9.0'
        info.write_bytes(plistlib.dumps(fields)); self.sign(self.app, staged.APP_ID)
        self.fixture(); self.verify()

    def test_unexpected_unsigned_engine_rejected(self):
        shutil.copyfile(self.universal, self.candidate / 'vpn-engine'); self.verify()

    def test_named_directory_rebinding_invalidates_held_package(self):
        # Each operation replaces one subtree with an otherwise identical copy.
        for operation in ('replace-metadata', 'replace-executable', 'replace-candidate'):
            with self.subTest(operation=operation):
                result = self.verify(operation)
                self.assertIn('changed', result.stdout)
                name = operation.removeprefix('replace-').capitalize()
                shutil.rmtree(self.root / name)
                (self.work / ('old-' + name)).rename(self.root / name)

    def test_sidecar_change_invalidates_held_package(self): self.verify('change-sidecar')
    def test_candidate_change_invalidates_held_package(self): self.verify('change-app')
    def test_artifact_change_invalidates_held_package(self): self.verify('change-artifact')


if __name__ == '__main__': unittest.main()
