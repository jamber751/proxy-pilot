"""Real private files/locks + fake kernel. No privileged APIs or network calls."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
import test_vpn_exact_fence_adapter as adapter
ROOT=adapter.ROOT
MODES=['write-order','reopen','claims','release-shared','generation','unknown-add','absent-recovery','restore-applied',
       'foreign','foreign-release','cancel-before-write','retire','unknown-delete','cancel-after-intent','expired','lock','concurrent','canonical','symlink','hardlink','lock-replaced','families']
@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc'),'macOS Swift required')
class FenceStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pp-fence-store-build-');cls.addClassCleanup(cls.temp.cleanup)
        cls.binary=Path(cls.temp.name)/'checks';arch='arm64' if platform.machine()=='arm64' else 'x86_64'
        r=subprocess.run(['/usr/bin/swiftc','-parse-as-library','-target',arch+'-apple-macosx11.0',
            *map(str,adapter.SOURCES),str(ROOT/'tests/vpn_exact_fence_store_checks.swift'),'-o',str(cls.binary)],capture_output=True,text=True,timeout=90)
        if r.returncode:raise AssertionError(r.stderr)
    def case(self,mode):
        with tempfile.TemporaryDirectory(prefix='pp-fence-store-private-') as folder:
            os.chmod(folder,0o700)
            r=subprocess.run([str(self.binary),mode,folder],capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertEqual(r.stdout,'PASS exact-fence-store-'+mode+'\n')
for mode in MODES:setattr(FenceStoreTests,'test_'+mode.replace('-','_'),lambda self,m=mode:self.case(m))
if __name__=='__main__':unittest.main()
