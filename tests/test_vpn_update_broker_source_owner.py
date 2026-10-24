"""Actual cross-UID root inbox proof, only own disposable CI directories."""
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and os.getuid() == os.geteuid() == 0
                     and os.environ.get('GITHUB_ACTIONS') == 'true'
                     and os.environ.get('PROXYPILOT_VM_ROOT_TESTS') == '1',
                     'Explicit disposable root CI only; never elevate locally')
class VPNUpdateBrokerSourceOwnerRootTests(unittest.TestCase):
    root_vm_fixture = True

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-broker-owner-build-', dir='/private/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run(['/usr/bin/swiftc', '-target', arch + '-apple-macosx11.0',
                                 str(ROOT / 'app/vpn-helper/VPNUpdateBrokerInbox.swift'),
                                 str(ROOT / 'tests/vpn_update_broker_source_owner_checks.swift'),
                                 '-o', str(cls.binary)], capture_output=True, text=True, timeout=120)
        if result.returncode: raise AssertionError(result.stderr)

    def run_case(self, case):
        with tempfile.TemporaryDirectory(prefix='pp-broker-owner-', dir='/private/tmp') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), case, folder], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), 'cross-UID inbox checks passed')

    def test_ordinary_owned_nested_input_copies_to_root_owned_publication(self): self.run_case('ordinary-source')
    def test_foreign_owned_private_directory_is_rejected(self): self.run_case('private-directory-owner')
    def test_foreign_owned_private_file_is_rejected(self): self.run_case('private-file-owner')
    def test_writable_ordinary_source_is_rejected(self): self.run_case('writable-source')
    def test_changed_ordinary_source_is_rejected(self): self.run_case('mutable-source')


if __name__ == '__main__': unittest.main()
