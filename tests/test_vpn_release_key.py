"""Release-key tool: generate, sign and verify inside a disposable keychain.

Every test creates and deletes its own keychain file, so the developer's login
keychain is never read or written. No real release key is used or produced here.
"""
import base64
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ''.join(f'{key}={value}\n' for key, value in {
    'format': 1, 'product': 'kz.documentolog.proxypilot', 'sequence': 7, 'version': '1.6.0', 'protocol': 1,
    'app-arm64': '11' * 20, 'app-x86_64': '22' * 20, 'helper-arm64': '33' * 20, 'helper-x86_64': '44' * 20,
    'helper-sha256': '55' * 32, 'helper-bytes': 4096}.items())


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNReleaseKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='pp-key-build-', dir='/tmp')
        cls.addClassCleanup(cls.build.cleanup)
        cls.tool = Path(cls.build.name) / 'vpn-release-key'
        built = subprocess.run(['swiftc', '-target', 'arm64-apple-macosx11.0',
                                str(ROOT / 'app/vpn-helper/VPNPeerAuthentication.swift'),
                                str(ROOT / 'app/vpn-helper/VPNReleaseAuthorization.swift'),
                                str(ROOT / 'app/vpn-release-key.swift'), '-o', str(cls.tool)],
                               capture_output=True, text=True, timeout=180)
        if built.returncode:
            raise AssertionError(built.stdout + built.stderr)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pp-key-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.keychain = self.base / f'release-{uuid.uuid4().hex}.keychain'
        subprocess.run(['/usr/bin/security', 'create-keychain', '-p', 'disposable', str(self.keychain)],
                       check=True, capture_output=True, timeout=60)
        self.addCleanup(self.delete_keychain)
        self.public = self.base / 'public.txt'
        self.manifest = self.base / 'release.txt'
        self.manifest.write_text(MANIFEST)
        self.signature = self.base / 'release.sig'

    def delete_keychain(self):
        subprocess.run(['/usr/bin/security', 'delete-keychain', str(self.keychain)],
                       capture_output=True, timeout=60)

    def run_tool(self, *arguments, keychain=True):
        command = [str(self.tool), *arguments]
        if keychain:
            command += ['--keychain', str(self.keychain)]
        return subprocess.run(command, capture_output=True, text=True, timeout=60)

    def generate(self, *extra):
        result = self.run_tool('generate', str(self.public), *extra)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_generate_publishes_only_the_public_half(self):
        result = self.generate()
        published = self.public.read_text().strip()
        self.assertEqual(published, result.stdout.strip())
        self.assertEqual(len(base64.b64decode(published)), 32)
        # The keychain item exists, and its secret never reached the output.
        listed = subprocess.run(['/usr/bin/security', 'find-generic-password', '-s',
                                 'kz.documentolog.proxypilot.vpn-release', str(self.keychain)],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertNotIn('-----', result.stdout)
        self.assertEqual(result.stderr, '')

    def test_the_public_key_matches_the_stored_private_key(self):
        self.generate()
        shown = self.run_tool('public')
        self.assertEqual(shown.returncode, 0, shown.stderr)
        self.assertEqual(shown.stdout.strip(), self.public.read_text().strip())

    def test_sign_and_verify_round_trip(self):
        self.generate()
        signed = self.run_tool('sign', str(self.manifest), str(self.signature))
        self.assertEqual(signed.returncode, 0, signed.stdout + signed.stderr)
        self.assertEqual(len(base64.b64decode(self.signature.read_text().strip())), 64)
        verified = self.run_tool('verify', str(self.manifest), str(self.signature), str(self.public), keychain=False)
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
        self.assertIn('Verified sequence 7', verified.stdout)

    def test_a_changed_release_description_fails_verification(self):
        self.generate()
        self.run_tool('sign', str(self.manifest), str(self.signature))
        self.manifest.write_text(MANIFEST.replace('sequence=7', 'sequence=8'))
        verified = self.run_tool('verify', str(self.manifest), str(self.signature), str(self.public), keychain=False)
        self.assertNotEqual(verified.returncode, 0)

    def test_another_key_cannot_sign_for_this_one(self):
        self.generate()
        first = self.public.read_text()
        second = self.base / f'other-{uuid.uuid4().hex}.keychain'
        subprocess.run(['/usr/bin/security', 'create-keychain', '-p', 'disposable', str(second)],
                       check=True, capture_output=True, timeout=60)
        self.addCleanup(lambda: subprocess.run(['/usr/bin/security', 'delete-keychain', str(second)],
                                               capture_output=True, timeout=60))
        other_public = self.base / 'other-public.txt'
        subprocess.run([str(self.tool), 'generate', str(other_public), '--keychain', str(second)],
                       check=True, capture_output=True, timeout=60)
        subprocess.run([str(self.tool), 'sign', str(self.manifest), str(self.signature), '--keychain', str(second)],
                       check=True, capture_output=True, timeout=60)
        self.public.write_text(first)
        verified = self.run_tool('verify', str(self.manifest), str(self.signature), str(self.public), keychain=False)
        self.assertNotEqual(verified.returncode, 0)

    def test_an_existing_key_is_never_replaced_silently(self):
        self.generate()
        published = self.public.read_text()
        again = self.run_tool('generate', str(self.public))
        self.assertNotEqual(again.returncode, 0)
        self.assertIn('already exists', again.stderr)
        self.assertEqual(self.public.read_text(), published)
        # Rotation stays possible, but only when asked for explicitly.
        rotated = self.generate('--force')
        self.assertNotEqual(rotated.stdout.strip(), published.strip())

    def test_signing_without_a_key_refuses(self):
        result = self.run_tool('sign', str(self.manifest), str(self.signature))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('No VPN release key', result.stderr)
        self.assertFalse(self.signature.exists())

    def test_the_committed_public_key_matches_the_compiled_trust_constant(self):
        constant = (ROOT / 'app/vpn-helper/VPNReleaseTrust.swift').read_text()
        published = ROOT / 'app/vpn-release-public-key.txt'
        line = [row for row in constant.splitlines() if 'static let publicKey' in row][0]
        compiled = line.split('"')[1]
        if not published.exists():
            self.assertEqual(compiled, '', 'trust constant set without a committed public key')
            return
        self.assertEqual(compiled, published.read_text().strip())
        self.assertEqual(len(base64.b64decode(compiled)), 32)

    def test_a_build_without_a_trusted_key_authorizes_nothing(self):
        # Top-level code must live in main.swift when several files compile together.
        checker = Path(self.temp.name) / 'main.swift'
        checker.write_text('import Foundation\n'
                           'do { _ = try VPNReleaseTrust.authority(); print("accepted") }\n'
                           'catch { print("refused") }\n')
        blank = Path(self.temp.name) / 'VPNReleaseTrust.swift'
        source = (ROOT / 'app/vpn-helper/VPNReleaseTrust.swift').read_text()
        line = [row for row in source.splitlines() if 'static let publicKey' in row][0]
        blank.write_text(source.replace(line, '    static let publicKey = ""'))
        binary = Path(self.temp.name) / 'trust-check'
        built = subprocess.run(['swiftc', '-target', 'arm64-apple-macosx11.0',
                                str(ROOT / 'app/vpn-helper/VPNPeerAuthentication.swift'),
                                str(ROOT / 'app/vpn-helper/VPNReleaseAuthorization.swift'),
                                str(blank), str(checker), '-o', str(binary)],
                               capture_output=True, text=True, timeout=180)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.stdout.strip(), 'refused')
