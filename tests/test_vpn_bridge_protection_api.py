"""Production HTTP/epoch/deadline protocol with fake connections only."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
MODES=('request','fragmented','wrong-epoch','credentials','peer','expired','late','backwards','cancel-before','cancel-partial',
       'unknown-write','zero-write','over-write','no-eof','publisher-order','publisher-unknown','redirect','unauthorized',
       'duplicate-length','chunked','encoded','extra','truncated','error-body','header-cap','over-read','missing-length','empty')
@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc') and os.getuid()==os.geteuid()!=0,'ordinary macOS Swift required')
class APITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pp-bridge-api-build-');cls.addClassCleanup(cls.temp.cleanup)
        cls.binary=Path(cls.temp.name)/'checks'
        arch='arm64' if platform.machine()=='arm64' else 'x86_64'
        cls.sources=[ROOT/'app/VPNConfiguration.swift',ROOT/'app/vpn-helper/VPNDNSContinuousClock.swift',
                     ROOT/'app/VPNBridgeProtection.swift',ROOT/'app/VPNBridgeProtectionAPI.swift']
        r=subprocess.run(['/usr/bin/swiftc','-parse-as-library','-target',arch+'-apple-macosx12.0',*map(str,cls.sources),
            str(ROOT/'tests/vpn_bridge_protection_api_checks.swift'),'-o',str(cls.binary)],capture_output=True,text=True,timeout=90)
        if r.returncode:raise AssertionError(r.stderr)
    def case(self,mode):
        with tempfile.TemporaryDirectory(prefix='pp-bridge-api-private-') as folder:
            r=subprocess.run([str(self.binary),mode,folder],capture_output=True,text=True,timeout=15)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr);self.assertEqual(r.stdout,'PASS bridge-api-'+mode+'\n');self.assertEqual(r.stderr,'')
for mode in MODES:setattr(APITests,'test_'+mode.replace('-','_'),lambda self,m=mode:self.case(m))
if __name__=='__main__':unittest.main()
