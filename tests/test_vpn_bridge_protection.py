"""Real private files + fake epoch/API/clock; no sockets or proxy/VPN changes."""
from pathlib import Path
import platform
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
MODES=('order','union','reopen','unknown-api','expired','late-api','backwards','cancelled','epoch-changed',
       'missing-after-use','corrupt-after-use','lock','lock-replaced','invalid','capacity','reentrant','concurrent',
       'symlink','hardlink','bad-mode')
@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc') and os.getuid()==os.geteuid()!=0,'ordinary macOS Swift required')
class ProtectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pp-bridge-protection-build-');cls.addClassCleanup(cls.temp.cleanup)
        cls.binary=Path(cls.temp.name)/'checks'
        arch='arm64' if platform.machine()=='arm64' else 'x86_64'
        result=subprocess.run(['/usr/bin/swiftc','-parse-as-library','-target',arch+'-apple-macosx12.0',
            str(ROOT/'app/VPNConfiguration.swift'),str(ROOT/'app/vpn-helper/VPNDNSContinuousClock.swift'),
            str(ROOT/'app/VPNBridgeProtection.swift'),str(ROOT/'tests/vpn_bridge_protection_checks.swift'),'-o',str(cls.binary)],
            capture_output=True,text=True,timeout=90)
        if result.returncode:raise AssertionError(result.stderr)
    def case(self,mode):
        with tempfile.TemporaryDirectory(prefix='pp-bridge-protection-private-') as folder:
            result=subprocess.run([str(self.binary),mode,folder],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(result.stdout,'PASS bridge-protection-'+mode+'\n');self.assertEqual(result.stderr,'')
for mode in MODES:setattr(ProtectionTests,'test_'+mode.replace('-','_'),lambda self,m=mode:self.case(m))
if __name__=='__main__':unittest.main()
