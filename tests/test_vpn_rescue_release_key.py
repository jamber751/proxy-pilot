"""Rescue signer/real CLI verification with a synthetic key; no Keychain API calls."""
import base64
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_vpn_release_key import MANIFEST, ROOT


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNRescueReleaseKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='pp-rescue-sign-build-')
        cls.addClassCleanup(cls.build.cleanup)
        cls.tool = Path(cls.build.name) / 'vpn-release-key'
        cls.fixture = Path(cls.build.name) / 'synthetic-signer'
        sources = [ROOT / 'app/vpn-helper' / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNReleaseTrust.swift',
            'VPNCompanionMetadata.swift', 'VPNRescueAuthorization.swift')]
        sources.append(ROOT / 'app/vpn-release-key.swift')
        for output, extra in ((cls.tool, []), (cls.fixture, ['-D', 'VPN_RELEASE_KEY_TESTING',
                str(ROOT / 'tests/vpn_rescue_release_key_checks.swift')])):
            result = subprocess.run(['swiftc', *map(str, sources), *extra, '-o', str(output)],
                                    capture_output=True, text=True, timeout=180)
            if result.returncode: raise AssertionError(result.stdout + result.stderr)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pp-rescue-sign-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        (self.base / 'previous').write_text(MANIFEST)
        (self.base / 'candidate').write_text(MANIFEST.replace('sequence=7', 'sequence=8'))
        result = self.invoke(self.fixture, 'fixture', self.base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.output = self.base / 'rescue.sig'
        self.output.write_text('keep prior signature')

    @staticmethod
    def run_command(binary, *args):
        return subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True, timeout=15)

    # Avoid unittest.TestCase.run, which owns test execution.
    def invoke(self, binary, *args): return self.run_command(binary, *args)

    def inputs(self):
        return [self.base / name for name in ('previous', 'previous.sig', 'candidate', 'candidate.sig',
                                              'transition', 'transition.sig', 'description', 'artifact')]

    def sign(self, accepted=True):
        result = self.invoke(self.fixture, 'sign', *self.inputs(), self.output)
        self.assertEqual(result.returncode, 0 if accepted else 77, result.stdout + result.stderr)
        if not accepted: self.assertEqual(self.output.read_text(), 'keep prior signature')

    def verify(self, accepted=True):
        result = self.invoke(self.tool, 'verify-rescue', *self.inputs(), self.output, self.base / 'public')
        self.assertEqual(result.returncode, 0 if accepted else 1, result.stdout + result.stderr)
        if accepted: self.assertIn('Verified rescue 7 to 8 artifact bytes', result.stdout)

    def test_roundtrip(self): self.output.unlink(); self.sign(); self.verify()
    def test_malformed_payload_not_signed_or_published(self):
        path = self.base / 'description'; original = path.read_text()
        for bad in (original + 'unknown=1\n', original.replace('format=1', 'format=01'),
                    original.replace('finish-root-owned-destination-and-cleanup', 'anything'),
                    original.replace('rescue-bytes=25', 'rescue-bytes=0'), ''):
            with self.subTest(bad=bad):
                path.write_text(bad); self.sign(accepted=False)
    def test_edge_input_tampering_not_published(self):
        for name in ('previous', 'candidate', 'transition', 'previous.sig', 'candidate.sig', 'transition.sig'):
            with self.subTest(name=name):
                path = self.base / name; original = path.read_bytes()
                path.write_bytes(original + b'bad'); self.sign(accepted=False); path.write_bytes(original)
    def test_wrong_edge_description_not_published(self):
        path = self.base / 'description'
        rows = path.read_text().splitlines()
        rows[3] = 'previous-manifest-sha256=' + 'aa' * 32
        path.write_text('\n'.join(rows) + '\n'); self.sign(accepted=False)
    def test_artifact_tampering_not_published(self):
        (self.base / 'artifact').write_bytes(b'wrong artifact'); self.sign(accepted=False)
    def test_artifact_symlink_and_directory_rejected(self):
        path = self.base / 'artifact'; path.rename(self.base / 'real-artifact')
        path.symlink_to(self.base / 'real-artifact'); self.sign(accepted=False)
        path.unlink(); path.mkdir(); self.sign(accepted=False)
    def test_oversized_sparse_artifact_rejected(self):
        with (self.base / 'artifact').open('wb') as stream: stream.truncate(32 * 1024 * 1024 + 1)
        self.sign(accepted=False)
    def test_verifier_rejects_changed_artifact(self):
        self.sign(); (self.base / 'artifact').write_bytes(b'changed'); self.verify(accepted=False)
    def test_verifier_rejects_wrong_domain(self):
        result = self.invoke(self.fixture, 'raw-sign', self.base / 'description', self.output, 'release')
        self.assertEqual(result.returncode, 0, result.stderr); self.verify(accepted=False)
    def test_verifier_rejects_signed_malformed_description(self):
        path = self.base / 'description'; path.write_text(path.read_text() + 'unknown=1\n')
        result = self.invoke(self.fixture, 'raw-sign', path, self.output, 'rescue')
        self.assertEqual(result.returncode, 0, result.stderr); self.verify(accepted=False)
    def test_verifier_rejects_wrong_public_key(self):
        self.sign(); (self.base / 'public').write_text(base64.b64encode(b'x' * 32).decode() + '\n')
        self.verify(accepted=False)


if __name__ == '__main__': unittest.main()
