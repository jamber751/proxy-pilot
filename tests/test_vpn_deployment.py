"""Verify real universal signatures and atomic binary/policy selection, without execution."""
import hashlib
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
IDENTIFIER = 'kz.documentolog.proxypilot.vpn-helper'


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNDeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='proxypilot-deployment-build-')
        cls.addClassCleanup(cls.build.cleanup)
        cls.work = Path(cls.build.name)
        sources = [ROOT / 'app/vpn-helper' / name for name in
                   ('VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperArtifact.swift', 'VPNReleaseStore.swift')]
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.work / ('checker-' + arch)
            cls.command(['swiftc', '-D', 'VPN_RELEASE_STORE_TESTING', '-D', 'VPN_ENGINE_DELIVERY_TESTING', '-target', f'{arch}-apple-macosx11.0',
                         *map(str, sources), str(ROOT / 'tests/vpn_deployment_checks.swift'), '-o', str(output)])
            slices.append(str(output))
        cls.binary = cls.work / 'deployment-checks'
        cls.command(['lipo', '-create', *slices, '-output', str(cls.binary)])
        cls.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill', str(cls.binary)])
        cls.helpers = {}
        cls.pins = {}
        for revision in (1, 2):
            slices = []
            for arch in ('arm64', 'x86_64'):
                output = cls.work / f'helper-{revision}-{arch}'
                cls.command(['xcrun', 'clang', '-target', f'{arch}-apple-macosx11.0',
                             f'-DFIXTURE_REVISION={revision}', str(ROOT / 'tests/vpn-deployment/HelperFixture.c'),
                             '-o', str(output)])
                slices.append(str(output))
            output = cls.work / f'v{revision}'
            cls.command(['lipo', '-create', *slices, '-output', str(output)])
            cls.sign(output)
            cls.register(f'v{revision}', output)
        for name, identifier, options, entitlements in [
            ('wrong-id', IDENTIFIER + '.other', 'runtime,hard,kill', None),
            ('weak', IDENTIFIER, None, None),
            ('entitlements', IDENTIFIER, 'runtime,hard,kill', {'com.apple.security.cs.disable-library-validation': True}),
        ]:
            output = cls.work / name
            shutil.copyfile(cls.helpers['v1'], output)
            cls.command(['codesign', '--remove-signature', str(output)])
            cls.sign(output, identifier=identifier, options=options, entitlements=entitlements)
            cls.register(name, output)
        for name, revision, options in [('engine-v1', 'v1', 'runtime,hard,kill'),
                                        ('engine-v2', 'v2', 'runtime,hard,kill'), ('engine-weak', 'v1', None)]:
            output = cls.work / name
            shutil.copyfile(cls.helpers[revision], output)
            cls.command(['codesign', '--remove-signature', str(output)])
            cls.sign(output, identifier='kz.documentolog.proxypilot.openvpn', options=options)
            cls.register(name, output)
        for name, intel_source in [('mixed-weak', 'weak'), ('mixed-id', 'wrong-id')]:
            arm, intel = cls.work / (name + '-arm'), cls.work / (name + '-intel')
            cls.command(['lipo', str(cls.helpers['v1']), '-thin', 'arm64', '-output', str(arm)])
            cls.command(['lipo', str(cls.helpers[intel_source]), '-thin', 'x86_64', '-output', str(intel)])
            output = cls.work / name
            # Preserve the per-slice signatures, do NOT re-sign this combined file.
            cls.command(['lipo', '-create', str(arm), str(intel), '-output', str(output)])
            cls.register(name, output)

    @classmethod
    def sign(cls, path, identifier=IDENTIFIER, options='runtime,hard,kill', entitlements=None):
        args = ['codesign', '--force', '--sign', '-', '--identifier', identifier]
        if options:
            args += ['--options', options]
        if entitlements:
            file = cls.work / (path.name + '.plist')
            file.write_bytes(plistlib.dumps(entitlements))
            args += ['--entitlements', str(file)]
        cls.command([*args, str(path)])

    @classmethod
    def register(cls, name, path):
        cls.helpers[name] = path
        cls.pins[name] = {}
        for arch in ('arm64', 'x86_64'):
            result = cls.command(['codesign', '-d', '--verbose=4', '--arch', arch, str(path)])
            match = re.search(r'^CDHash=([a-f0-9]{40})$', result.stderr, re.M)
            if not match:
                raise AssertionError('fixture missing CDHash')
            cls.pins[name][arch] = match.group(1)

    @staticmethod
    def command(args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)
        return result

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='proxypilot-deployment-test-')
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'policy'
        self.directory.mkdir(mode=0o700)

    def description(self, helper='v1', sequence=10, data=None, fields=None):
        artifact = self.helpers[helper].read_bytes() if data is None else data
        values = dict(format='1', product='kz.documentolog.proxypilot', sequence=str(sequence), version='1.6.0', protocol='1')
        values.update({'app-arm64': '11' * 20, 'app-x86_64': '22' * 20,
                       'helper-arm64': self.pins[helper]['arm64'], 'helper-x86_64': self.pins[helper]['x86_64'],
                       'helper-sha256': hashlib.sha256(artifact).hexdigest(), 'helper-bytes': str(len(artifact))})
        values.update(fields or {})
        return ''.join(f'{key}={value}\n' for key, value in values.items()).encode(), artifact

    def run_store(self, operation, helper='v1', sequence=10, expected=10, data=None, fields=None,
                  checkpoint='none', tamper=False, engine=None, omit_engine=False, tamper_engine=False,
                  legacy_with_engine=False):
        payload, artifact = self.description(helper, sequence, data, fields)
        engine_data = self.helpers[engine].read_bytes() if engine else None
        if engine and not legacy_with_engine:
            text = payload.decode().replace('format=1\n', 'format=2\n')
            extra = {'engine-version': '2.7.7', 'engine-crypto-version': '3.5.8',
                     'engine-arm64': self.pins[engine]['arm64'], 'engine-x86_64': self.pins[engine]['x86_64'],
                     'engine-sha256': hashlib.sha256(engine_data).hexdigest(), 'engine-bytes': len(engine_data)}
            payload = (text + ''.join(f'{key}={value}\n' for key, value in extra.items())).encode()
        manifest = Path(self.temp.name) / 'manifest.txt'
        binary = Path(self.temp.name) / 'candidate'
        manifest.write_bytes(payload)
        binary.write_bytes(artifact + b'tampered' if tamper else artifact)
        arguments = [str(self.binary), operation, str(self.directory), str(manifest), str(binary), str(expected), checkpoint]
        if engine and not omit_engine:
            engine_path = Path(self.temp.name) / 'engine-candidate'
            engine_path.write_bytes(engine_data + b'tampered' if tamper_engine else engine_data)
            arguments.append(str(engine_path))
        return subprocess.run(arguments, capture_output=True, text=True, timeout=15)

    def expect(self, operation, output, **kwargs):
        result = self.run_store(operation, **kwargs)
        self.assertEqual(result.returncode, 0 if output.startswith(('sequence=', 'metadata-only', 'engine=')) else 77,
                         result.stdout + result.stderr)
        self.assertIn(output, result.stdout)
        return result

    def selected_name(self, helper):
        return 'helper-' + hashlib.sha256(self.helpers[helper].read_bytes()).hexdigest()

    def engine_name(self, engine='engine-v1'):
        return 'engine-' + hashlib.sha256(self.helpers[engine].read_bytes()).hexdigest()

    def test_engine_bootstrap_persists_complete_private_set(self):
        self.expect('bootstrap', 'sequence=10', engine='engine-v1')
        self.expect('load', 'engine=' + self.engine_name())
        selected = self.directory / self.engine_name()
        self.assertEqual(selected.read_bytes(), self.helpers['engine-v1'].read_bytes())
        self.assertEqual(stat.S_IMODE(selected.stat().st_mode), 0o700)
        self.assertEqual(selected.stat().st_uid, os.geteuid())

    def test_engine_upgrade_from_helper_only_is_atomic(self):
        self.seed()
        self.expect('prepare-commit', 'sequence=20', helper='v2', sequence=20, engine='engine-v1')
        self.expect('load', 'engine=' + self.engine_name())
        self.assertTrue((self.directory / self.selected_name('v1')).exists())
        self.assertTrue((self.directory / self.selected_name('v2')).exists())
        self.expect('commit', 'rejected:rollback', sequence=30, expected=20)

    def test_engine_only_update_and_retry_keep_complete_set(self):
        self.expect('bootstrap', 'sequence=10', engine='engine-v1')
        self.expect('commit', 'sequence=20', sequence=20, engine='engine-v2')
        self.expect('commit', 'sequence=20', sequence=20, expected=20, engine='engine-v2')
        self.expect('load', 'engine=' + self.engine_name('engine-v2'))
        self.assertTrue((self.directory / self.engine_name()).exists())

    def test_engine_missing_extra_or_tampered_bytes_never_select(self):
        for options in [dict(engine='engine-v1', omit_engine=True), dict(engine='engine-v1', tamper_engine=True),
                        dict(engine='engine-v1', legacy_with_engine=True)]:
            self.expect('bootstrap', 'rejected:invalidEngineArtifact', **options)
            self.assertFalse((self.directory / 'initialized').exists())
            self.assertFalse((self.directory / self.selected_name('v1')).exists())
        self.seed()
        before = (self.directory / 'release.json').read_bytes()
        self.expect('commit', 'rejected:invalidEngineArtifact', sequence=20, engine='engine-v1', omit_engine=True)
        self.assertEqual((self.directory / 'release.json').read_bytes(), before)

    def test_engine_invalid_signature_keeps_previous_selection(self):
        self.seed()
        self.expect('commit', 'rejected:invalidEngineArtifact', sequence=20, engine='engine-weak')
        self.expect('load', 'sequence=10')
        self.assertFalse((self.directory / self.engine_name('engine-weak')).exists())

    def test_engine_crash_between_artifacts_keeps_old_selection(self):
        self.seed()
        result = self.run_store('commit', helper='v2', sequence=20, engine='engine-v1', checkpoint='helper:after-rename')
        self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
        self.expect('load', 'sequence=10')
        self.assertFalse((self.directory / self.engine_name()).exists())
        self.expect('commit', 'sequence=20', helper='v2', sequence=20, engine='engine-v1')

    def test_engine_crash_after_staging_keeps_old_record(self):
        self.seed()
        result = self.run_store('commit', helper='v2', sequence=20, engine='engine-v1', checkpoint='engine:after-rename')
        self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
        self.expect('load', 'sequence=10')
        self.assertTrue((self.directory / self.engine_name()).exists())
        self.expect('commit', 'sequence=20', helper='v2', sequence=20, engine='engine-v1')

    def test_engine_crash_after_record_selects_both_new_files(self):
        self.seed()
        result = self.run_store('commit', helper='v2', sequence=20, engine='engine-v1', checkpoint='release.json:after-rename')
        self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
        self.expect('load', 'sequence=20')
        self.expect('load', 'engine=' + self.engine_name())
        self.expect('commit', 'rejected:rollback', expected=20)

    def test_engine_is_rechecked_at_commit_after_prepare(self):
        self.seed()
        self.expect('tamper-prepared-engine', 'rejected:invalidEngineArtifact', sequence=20, engine='engine-v1')
        self.expect('load', 'sequence=10')

    def test_engine_missing_or_corrupt_current_never_downgrades_or_repairs(self):
        self.expect('bootstrap', 'sequence=10', engine='engine-v1')
        self.expect('commit', 'sequence=20', sequence=20, engine='engine-v2')
        selected = self.directory / self.engine_name('engine-v2')
        selected.write_bytes(b'corrupt')
        self.expect('load', 'rejected:invalidState')
        self.expect('commit', 'rejected:invalidState', sequence=20, expected=20, engine='engine-v2')
        selected.unlink()
        self.expect('load', 'rejected:invalidState')
        self.assertTrue((self.directory / self.engine_name()).exists())

    def test_engine_existing_symlink_or_bad_file_is_not_repaired(self):
        self.seed()
        target = Path(self.temp.name) / 'untouched'; target.write_bytes(b'keep')
        candidate = self.directory / self.engine_name(); candidate.symlink_to(target)
        self.expect('commit', 'rejected:unsafeStorage', sequence=20, engine='engine-v1')
        self.assertEqual(target.read_bytes(), b'keep')
        candidate.unlink(); candidate.write_bytes(b'corrupt'); candidate.chmod(0o700)
        self.expect('commit', 'rejected:invalidEngineArtifact', sequence=20, engine='engine-v1')
        self.assertEqual(candidate.read_bytes(), b'corrupt')
        self.expect('load', 'sequence=10')

    def test_engine_metadata_only_api_cannot_record_a_partial_deployment(self):
        self.expect('bootstrap-metadata', 'rejected:deploymentRequired', engine='engine-v1')
        self.assertFalse((self.directory / 'initialized').exists())
        self.expect('bootstrap-metadata', 'metadata-only')
        self.expect('metadata-only', 'rejected:deploymentRequired', sequence=20, engine='engine-v1')

    def seed(self):
        self.expect('bootstrap', 'sequence=10 owner=501 artifact=' + self.selected_name('v1'))

    def test_bootstrap_selects_exact_binary_and_policy(self):
        self.seed()
        self.expect('load', 'sequence=10 owner=501 artifact=' + self.selected_name('v1'))
        artifact = self.directory / self.selected_name('v1')
        self.assertEqual(artifact.read_bytes(), self.helpers['v1'].read_bytes())
        self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o700)
        self.assertEqual(artifact.stat().st_uid, os.geteuid())

    def test_upgrade_keeps_old_binary_and_selects_new_pair(self):
        self.seed()
        self.expect('commit', 'sequence=20 owner=501 artifact=' + self.selected_name('v2'), helper='v2', sequence=20)
        self.expect('load', 'sequence=20 owner=501 artifact=' + self.selected_name('v2'))
        self.assertTrue((self.directory / self.selected_name('v1')).exists())
        self.expect('commit', 'rejected:rollback', expected=20)

    def test_metadata_only_api_cannot_break_binary_binding(self):
        self.seed()
        self.expect('metadata-only', 'rejected:deploymentRequired', helper='v2', sequence=20)
        self.expect('load', 'sequence=10')

    def test_metadata_store_is_not_silently_migrated(self):
        self.expect('bootstrap-metadata', 'metadata-only')
        self.expect('load', 'rejected:deploymentRequired')
        self.expect('commit', 'rejected:deploymentRequired', helper='v2', sequence=20)

    def test_bad_signature_and_artifact_leave_old_pair(self):
        self.seed()
        before = (self.directory / 'release.json').read_bytes()
        self.expect('bad-signature', 'rejected:invalidSignature', helper='v2', sequence=20)
        self.expect('commit', 'rejected:invalidHelperArtifact', helper='v2', sequence=20, tamper=True)
        self.assertEqual((self.directory / 'release.json').read_bytes(), before)

    def test_each_architecture_pin_is_checked(self):
        self.seed()
        for key in ('helper-arm64', 'helper-x86_64'):
            with self.subTest(key=key):
                self.expect('commit', 'rejected:invalidHelperArtifact', helper='v2', sequence=20, fields={key: 'aa' * 20})
        self.expect('load', 'sequence=10')

    def test_wrong_identifier_weak_signing_and_entitlements_rejected(self):
        self.seed()
        for helper in ('wrong-id', 'weak', 'entitlements', 'mixed-weak', 'mixed-id'):
            with self.subTest(helper=helper):
                self.expect('commit', 'rejected:invalidHelperArtifact', helper=helper, sequence=20)
        self.expect('load', 'sequence=10')

    def test_invalid_first_binary_does_not_initialize(self):
        self.expect('bootstrap', 'rejected:invalidHelperArtifact', helper='weak')
        self.assertEqual(sorted(path.name for path in self.directory.iterdir()), ['release.lock'])
        self.seed()

    def test_bad_universal_headers_fail_before_selection(self):
        self.seed()
        original = self.helpers['v2'].read_bytes()
        malformed = [b'not executable', b'#! /bin/sh\nexit 0\n', original[:40]]
        for offset, value in [(4, 3), (8, 0), (16, 0), (20, 0xffffffff), (24, 31)]:
            changed = bytearray(original)
            struct.pack_into('>I', changed, offset, value)
            malformed.append(bytes(changed))
        for data in malformed:
            self.expect('commit', 'rejected:invalidHelperArtifact', helper='v2', sequence=20, data=data)
        self.expect('load', 'sequence=10')

    def test_thin_binary_rejected_even_with_signed_matching_digest(self):
        self.seed()
        thin = Path(self.temp.name) / 'thin'
        self.command(['lipo', str(self.helpers['v2']), '-thin', 'arm64', '-output', str(thin)])
        self.expect('commit', 'rejected:invalidHelperArtifact', helper='v2', sequence=20, data=thin.read_bytes())

    def test_modified_signed_code_rejected_in_each_slice(self):
        self.seed()
        original = self.helpers['v2'].read_bytes()
        for index in range(2):
            with self.subTest(slice=index):
                offset, size = struct.unpack_from('>II', original, 8 + index * 20 + 8)
                changed = bytearray(original)
                changed[offset + min(4096, size // 2)] ^= 1
                # The fixture authority signs the new whole-file digest, so the
                # per-slice native signature check must detect the damage.
                self.expect('commit', 'rejected:invalidHelperArtifact', helper='v2', sequence=20, data=bytes(changed))
        self.expect('load', 'sequence=10')

    def test_crash_after_staging_keeps_old_pair_and_can_retry(self):
        self.seed()
        result = self.run_store('commit', helper='v2', sequence=20, checkpoint='helper:after-rename')
        self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
        self.expect('load', 'sequence=10 owner=501 artifact=' + self.selected_name('v1'))
        self.assertTrue((self.directory / self.selected_name('v2')).exists())
        self.expect('commit', 'sequence=20', helper='v2', sequence=20)

    def test_crash_before_record_replacement_keeps_old_pair(self):
        self.seed()
        result = self.run_store('commit', helper='v2', sequence=20, checkpoint='release.json:before-rename')
        self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
        self.expect('load', 'sequence=10 owner=501 artifact=' + self.selected_name('v1'))

    def test_crash_after_record_replacement_selects_complete_new_pair(self):
        self.seed()
        result = self.run_store('commit', helper='v2', sequence=20, checkpoint='release.json:after-rename')
        self.assertEqual(result.returncode, 86, result.stdout + result.stderr)
        self.expect('load', 'sequence=20 owner=501 artifact=' + self.selected_name('v2'))
        self.expect('commit', 'rejected:rollback', expected=20)

    def test_missing_or_corrupt_selected_binary_fails_closed(self):
        self.seed()
        self.expect('commit', 'sequence=20', helper='v2', sequence=20)
        selected = self.directory / self.selected_name('v2')
        selected.write_bytes(b'corrupt')
        self.expect('load', 'rejected:invalidState')
        selected.unlink()
        self.expect('load', 'rejected:invalidState')
        self.expect('bootstrap', 'rejected:alreadyInitialized')
        # No automatic downgrade to the retained old binary.
        self.assertTrue((self.directory / self.selected_name('v1')).exists())

    def test_preexisting_candidate_link_cannot_redirect_write(self):
        self.seed()
        other = Path(self.temp.name) / 'untouched'
        other.write_bytes(b'unchanged')
        (self.directory / self.selected_name('v2')).symlink_to(other)
        self.expect('commit', 'rejected:unsafeStorage', helper='v2', sequence=20)
        self.assertEqual(other.read_bytes(), b'unchanged')
        self.expect('load', 'sequence=10')

    def test_corrupt_existing_candidate_is_not_silently_repaired(self):
        self.seed()
        candidate = self.directory / self.selected_name('v2')
        candidate.write_bytes(b'corrupt')
        candidate.chmod(0o700)
        self.expect('commit', 'rejected:invalidHelperArtifact', helper='v2', sequence=20)
        self.assertEqual(candidate.read_bytes(), b'corrupt')
        self.expect('load', 'sequence=10')

    def test_selected_binary_modes_acl_and_hardlinks_are_checked(self):
        self.seed()
        selected = self.directory / self.selected_name('v1')
        selected.chmod(0o755)
        self.expect('load', 'rejected:invalidState')
        selected.chmod(0o700)
        self.command(['chmod', '+a', 'everyone allow read', str(selected)])
        self.expect('load', 'rejected:invalidState')
        self.command(['chmod', '-N', str(selected)])
        linked = Path(self.temp.name) / 'linked-artifact'
        os.link(selected, linked)
        self.expect('load', 'rejected:invalidState')
        linked.unlink()
        self.expect('load', 'sequence=10')

    def test_stale_commit_and_idempotent_retry(self):
        self.seed()
        self.expect('commit', 'sequence=10')
        self.expect('commit', 'sequence=20', helper='v2', sequence=20)
        self.expect('commit', 'rejected:staleRevision', helper='v2', sequence=30)
        self.expect('commit', 'sequence=20', helper='v2', sequence=20, expected=20)
