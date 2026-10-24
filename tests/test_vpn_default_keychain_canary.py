"""Pure fixture canary channel/order checks plus own synthetic files, no Security APIs."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc'),'macOS Swift required')
class CanaryProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder=tempfile.TemporaryDirectory(prefix='pp-canary-pure-build-')
        cls.addClassCleanup(cls.folder.cleanup)
        folder=Path(cls.folder.name)
        source=(ROOT/'tests/vpn_legacy_password_backend_vm_checks.swift').read_text()
        proof=source.split('// BEGIN NO-KEYCHAIN FILE IDENTITY',1)[1].split('// END NO-KEYCHAIN FILE IDENTITY',1)[0]
        cls.assert_no_security(proof)
        filesystem=folder/'Filesystem.swift';filesystem.write_text('import Foundation\nimport Darwin\n'+proof)
        cls.binary=folder/'checks'
        arch='arm64' if platform.machine()=='arm64' else 'x86_64'
        result=subprocess.run(['/usr/bin/swiftc','-parse-as-library','-target',arch+'-apple-macosx11.0',
            str(ROOT/'tests/VPNDefaultKeychainCanaryProof.swift'),str(filesystem),
            str(ROOT/'tests/vpn_default_keychain_canary_checks.swift'),'-o',str(cls.binary)],capture_output=True,text=True,timeout=90)
        if result.returncode:raise AssertionError(result.stderr)
    @staticmethod
    def assert_no_security(source):
        if any(x in source for x in ('import Security','SecKeychain','SecItem','VPNPasswordWorker')):raise AssertionError('Pure helper acquired Security dependency')
    def case(self,mode):
        with tempfile.TemporaryDirectory(prefix='pp-canary-pure-files-') as folder:
            os.chmod(folder,0o700)
            result=subprocess.run([str(self.binary),mode,folder],capture_output=True,text=True,timeout=10)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,'pure private canary proof passed\n',''))
    def test_hardlink(self):self.case('hardlink')
    def test_replaced_parent(self):self.case('replaced-parent')
    def test_wrong_length(self):self.case('wrong-length')
    def test_roundtrip(self):self.case('roundtrip')
    def test_bounds(self):self.case('bounds')
    def test_shape(self):self.case('shape')
    def test_fingerprint_bounds(self):self.case('fingerprint-bounds')
    def test_channel_shape(self):self.case('channel-shape')
    def test_redacted(self):self.case('redacted')
    def test_ordered_positive(self):self.case('ordered-positive')
    def test_wrong_target(self):self.case('wrong-target')
    def test_wrong_image(self):self.case('wrong-image')
    def test_wrong_nonce(self):self.case('wrong-nonce')
    def test_missing_item(self):self.case('missing-item')
    def test_wrong_service(self):self.case('wrong-service')
    def test_wrong_account(self):self.case('wrong-account')
    def test_wrong_reference(self):self.case('wrong-reference')
    def test_wrong_owner(self):self.case('wrong-owner')
    def test_wrong_value(self):self.case('wrong-value')
    def test_race_before_value(self):self.case('race-before-value')
    def test_race_after_value(self):self.case('race-after-value')
    def test_filesystem_positive(self):self.case('filesystem-positive')
    def test_foreign_file(self):self.case('foreign-file')
    def test_ambiguous_leaf(self):self.case('ambiguous-leaf')
    def test_replace_before_value(self):self.case('replace-before-value')
    def test_replace_after_value(self):self.case('replace-after-value')
    def test_missing_file(self):self.case('missing-file')

if __name__=="__main__":unittest.main()
