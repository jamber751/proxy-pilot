"""Signed helper discovery receipt in a disposable public directory."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNPublicReleaseReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-public-receipt-build-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        helper = ROOT / 'app/vpn-helper'
        sources = [helper / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
            'VPNHelperProtocol.swift', 'VPNEndpointDirectory.swift',
            'VPNPublicReleaseReceipt.swift')]
        sources.append(ROOT / 'tests/vpn_public_release_receipt_checks.swift')
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0',
            *map(str, sources), '-o', str(cls.binary)], capture_output=True,
            text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, mode, expected):
        with tempfile.TemporaryDirectory(prefix='pp-public-receipt-', dir='/tmp') as folder:
            os.chmod(folder, 0o755)
            result = subprocess.run([str(self.binary), mode, folder],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), expected)

    def test_signed_roundtrip(self):
        self.run_case('roundtrip', 'receipt verified')

    def test_invalid_signature_is_rejected(self):
        self.run_case('bad-signature', 'receipt rejected')

    def test_wrong_permissions_are_rejected(self):
        self.run_case('wrong-mode', 'receipt rejected')


if __name__ == '__main__':
    unittest.main()
