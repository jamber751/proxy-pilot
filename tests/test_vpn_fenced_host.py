"""Pair-aware production route boundary; synthetic interfaces and fake transport only."""
from pathlib import Path
import subprocess
import tempfile
import unittest
import test_vpn_exact_fence_adapter as pure

@unittest.skipUnless(pure.sys.platform == 'darwin' and pure.shutil.which('swiftc'), 'macOS Swift required')
class FencedHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-fenced-host-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name)/'checks'
        result = subprocess.run(['/usr/bin/swiftc','-parse-as-library',*map(str,pure.SOURCES),
            str(pure.ROOT/'tests/vpn_fenced_host_checks.swift'),'-o',str(cls.binary)],capture_output=True,text=True,timeout=90)
        if result.returncode: raise AssertionError(result.stderr)
    def case(self,mode):
        with tempfile.TemporaryDirectory(prefix='pp-fenced-host-store-') as folder:
            result = subprocess.run([str(self.binary),mode,folder],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(result.stdout,'PASS fenced-host-'+mode+'\n')
        self.assertEqual(result.stderr,'')

for mode in ('lifecycle','no-adoption','missing-fence','foreign-fence','foreign-host','fence-loss','ack-without-state',
             'unknown-write','unknown-delete','delete-ack-without-state','race','cancelled','cancelled-after-write','expired','late','delete-absent',
             'journal-shared','journal-schema','journal-lifecycle','journal-reopen','journal-unknown-add','journal-unknown-delete','journal-unknown-delete-present',
             'journal-cancel-intent','journal-stale','journal-no-retire-active','journal-foreign','journal-boot-unknown'):
    setattr(FencedHostTests,'test_'+mode.replace('-','_'),lambda self,m=mode:self.case(m))

if __name__ == '__main__': unittest.main()
