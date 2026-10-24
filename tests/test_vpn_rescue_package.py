"""Local package assembly with synthetic keys/native checkers; never install."""
import base64
import importlib.util
import os
from pathlib import Path, PurePosixPath
import plistlib
import shutil
import stat
import subprocess
import sys
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

import test_vpn_rescue_installation_payload as payload_tests
import test_vpn_staged_application as staged

SPEC = importlib.util.spec_from_file_location('vpn_rescue_package', staged.ROOT / 'app/vpn-rescue/package.py')
package = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(package)


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNRescuePackageTests(unittest.TestCase):
    command = staged.VPNStagedApplicationTests.__dict__['command']
    make_app = staged.VPNStagedApplicationTests.make_app
    sign = staged.VPNStagedApplicationTests.sign
    pins = staged.VPNStagedApplicationTests.pins
    fixture = payload_tests.VPNRescueInstallationPayloadTests.fixture

    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0: raise unittest.SkipTest('Never root')
        payload_tests.VPNRescueInstallationPayloadTests.setUpClass.__func__(cls)
        cls.key_tool = cls.build / 'synthetic-key-tool'
        sources = [staged.HELPER / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNReleaseTrust.swift',
            'VPNCompanionMetadata.swift', 'VPNRescueAuthorization.swift',
            'VPNRescuePreparationAuthorization.swift')]
        cls.command(['swiftc', '-D', 'VPN_RELEASE_KEY_TESTING', *map(str, sources),
                     str(staged.ROOT / 'app/vpn-release-key.swift'),
                     str(staged.ROOT / 'tests/vpn_rescue_package_signer.swift'), '-o', str(cls.key_tool)])

    def setUp(self):
        payload_tests.VPNRescueInstallationPayloadTests.setUp(self)
        info = self.app / 'Contents/Info.plist'
        fields = plistlib.loads(info.read_bytes())
        fields.update(LSMinimumSystemVersion='11.0', ProxyPilotVPNInstaller=True,
                      ProxyPilotVPNReleaseSequence=141)
        info.write_bytes(plistlib.dumps(fields)); self.sign(self.app, staged.APP_ID); self.fixture()
        self.standard = self.work / 'standard'; self.standard.mkdir(mode=0o700)
        shutil.copytree(self.candidate, self.standard / 'Payload', symlinks=True)
        self.public = self.work / 'public'
        self.public.write_text(self.command([str(self.key_tool), 'public']).stdout)
        self.stage = self.work / 'stage'
        self.calls = []
        actual_run = package.run
        self.component_fields = None

        def run(*args):
            self.calls.append(tuple(map(str, args)))
            if len(args) >= 3 and Path(args[0]).name == 'vpn-rescue' and args[1] == 'verify-package':
                # Execute the real static loader with a synthetic trust key;
                # the artifact itself is an inert, signed Universal C fixture.
                return actual_run(self.driver, 'verify', args[2])
            if Path(args[0]).name == 'pkgbuild':
                component_path = args[args.index('--component-plist') + 1]
                self.component_fields = plistlib.loads(Path(component_path).read_bytes())
            return actual_run(*args)

        patcher = mock.patch.object(package, 'run', side_effect=run); patcher.start(); self.addCleanup(patcher.stop)

    def prepare(self, **changes):
        args = dict(rescue=self.artifact, source_manifest=self.metadata / 'source-release.manifest',
                    source_signature=self.metadata / 'source-release.sig',
                    first_transition=self.metadata / 'first-transition',
                    first_signature=self.metadata / 'first-transition.sig', candidate_stage=self.standard,
                    key_tool=self.key_tool, public=self.public, output=self.stage)
        args.update(changes); package.prepare(**args)

    def signatures(self):
        return [self.stage / 'Rescue/Metadata' / (name + '.sig') for name in package.OPERATIONS]

    def snapshot(self, root):
        return {str(p): (p.lstat().st_mode, p.lstat().st_ino,
                         p.read_bytes() if p.is_file() else b'')
                for p in (root, *root.rglob('*'))}

    def test_prepare_is_unsigned_and_preserves_inputs(self):
        before = self.snapshot(self.root), self.snapshot(self.standard)
        self.prepare()
        self.assertEqual((self.snapshot(self.root), self.snapshot(self.standard)), before)
        self.assertTrue(all(p.stat().st_size == 0 for p in self.signatures()))
        commands = [call[1] for call in self.calls if call[0] == str(self.key_tool)]
        self.assertFalse(set(commands) & {'public', 'sign-rescue', 'sign-rescue-preparation'})
        root = self.stage / 'Rescue'
        self.assertEqual(set(p.name for p in root.iterdir()), {'Executable', 'Metadata', 'Candidate'})
        for directory in (root, root / 'Executable', root / 'Metadata', root / 'Candidate'):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((root / 'Executable/vpn-rescue').stat().st_mode), 0o700)

    def test_sign_all_statements_and_retry_without_overwrite(self):
        self.prepare(); package.sign(self.stage, self.key_tool, self.public)
        before = [(p.read_bytes(), p.stat().st_ino) for p in self.signatures()]
        self.assertTrue(all(len(data) == 89 for data, _ in before))
        self.assertEqual(package.verify(self.stage, self.key_tool, self.public), '1.8.0')
        package.sign(self.stage, self.key_tool, self.public)
        self.assertEqual([(p.read_bytes(), p.stat().st_ino) for p in self.signatures()], before)

    def test_tampered_unsigned_statement_never_reaches_signer(self):
        self.prepare()
        path = self.stage / 'Rescue/Metadata/prepare-second'
        path.write_bytes(path.read_bytes().replace(b'prepare-root-owned-update-and-authorize-replacement',
                                                 b'finish-root-owned-destination-and-cleanup'))
        self.calls.clear()
        with self.assertRaises(ValueError): package.sign(self.stage, self.key_tool, self.public)
        self.assertTrue(all(p.stat().st_size == 0 for p in self.signatures()))
        self.assertFalse(any(call[1] == 'public' for call in self.calls))

    def test_signature_symlink_rejected_before_any_signing(self):
        self.prepare()
        protected = self.work / 'keep'; protected.write_bytes(b'keep')
        last = self.signatures()[-1]; last.unlink(); last.symlink_to(protected)
        self.calls.clear()
        with self.assertRaises(ValueError): package.sign(self.stage, self.key_tool, self.public)
        self.assertEqual(protected.read_bytes(), b'keep')
        self.assertEqual(self.signatures()[0].stat().st_size, 0)
        self.assertFalse(any(call[1] == 'public' for call in self.calls))

    def test_input_symlink_and_existing_output_refused(self):
        link = self.work / 'rescue-link'; link.symlink_to(self.artifact)
        with self.assertRaises(ValueError): self.prepare(rescue=link)
        self.assertFalse(self.stage.exists())
        self.stage.mkdir(); (self.stage / 'keep').write_bytes(b'keep')
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual((self.stage / 'keep').read_bytes(), b'keep')

    def test_foreign_public_key_refuses_signing(self):
        self.prepare(); self.public.write_bytes(base64.b64encode(b'x' * 32) + b'\n')
        with self.assertRaises(ValueError): package.sign(self.stage, self.key_tool, self.public)
        self.assertTrue(all(p.stat().st_size == 0 for p in self.signatures()))

    def test_unsigned_build_does_not_call_pkgbuild(self):
        self.prepare(); self.calls.clear()
        output = self.work / 'unsigned.pkg'
        with self.assertRaises(ValueError): package.build(self.stage, self.key_tool, self.public, output)
        self.assertFalse(output.exists())
        self.assertFalse(any(Path(call[0]).name == 'pkgbuild' for call in self.calls))

    def test_real_package_contains_only_fixed_rescue_and_no_relocation(self):
        self.prepare(); package.sign(self.stage, self.key_tool, self.public)
        output = self.work / 'repair.pkg'
        package.build(self.stage, self.key_tool, self.public, output)
        expanded = self.work / 'expanded'
        self.command(['/usr/sbin/pkgutil', '--expand-full', str(output), str(expanded)])
        info = ET.parse(expanded / 'PackageInfo').getroot()
        self.assertEqual(info.attrib['identifier'], package.RESCUE_ID)
        self.assertEqual(info.attrib['install-location'], '/')
        install = expanded / 'Payload' / package.INSTALL_PATH.relative_to('/')
        self.assertTrue((install / 'Executable/vpn-rescue').is_file())
        self.assertFalse((expanded / 'Payload/Applications').exists())
        self.assertTrue((expanded / 'Scripts/Rescue/Metadata/finish-first.sig').is_file())
        self.assertIn('preflight-install', (expanded / 'Scripts/preinstall').read_text())
        postinstall = (expanded / 'Scripts/postinstall').read_text()
        self.assertIn('set -euo pipefail', postinstall)
        self.assertLess(postinstall.index('"$RESCUE_ROOT/Executable/vpn-rescue" repair'),
                        postinstall.index('/bin/rm -rf -- "$RESCUE_ROOT"'))
        bundles = [bundle for bundle in info.findall('.//bundle') if 'path' in bundle.attrib]
        self.assertTrue(bundles)
        for bundle in bundles:
            path = PurePosixPath(bundle.attrib['path'])
            prefix = package.INSTALL_PATH.relative_to('/').parts
            self.assertEqual(path.parts[:len(prefix)], prefix)
            self.assertNotIn('..', path.parts)
        self.assertEqual(self.component_fields, [{
            'RootRelativeBundlePath': str(package.INSTALL_PATH.relative_to('/') / 'Candidate/ProxyPilot.app'),
            'BundleIsRelocatable': False, 'BundleIsVersionChecked': False,
            'BundleHasStrictIdentifier': True, 'BundleOverwriteAction': 'upgrade',
        }])
        for relocation in info.findall('.//relocate'):
            # pkgbuild emits an empty <relocate/> even with relocation disabled.
            self.assertEqual(list(relocation), [])
            self.assertFalse(relocation.attrib)
            self.assertFalse((relocation.text or '').strip())
        before = output.read_bytes()
        with self.assertRaises(ValueError): package.build(self.stage, self.key_tool, self.public, output)
        self.assertEqual(output.read_bytes(), before)


if __name__ == '__main__': unittest.main()
