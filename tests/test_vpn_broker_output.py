"""Actual owned child/pipe only; never executes launchctl, a service or root."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
MODES=('legacy','small','large','fragmented','cap','duplicate','absent','utf8','nonzero','late','eof-alive','expired')
@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc') and os.getuid()==os.geteuid()!=0,'ordinary macOS SDK required')
class BrokerOutputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pp-broker-output-');cls.addClassCleanup(cls.temp.cleanup)
        cls.binary=Path(cls.temp.name)/'checks'
        sources=[ROOT/'app/VPNConfiguration.swift',ROOT/'app/VPNProfileImporter.swift']
        sources += [p for p in sorted((ROOT/'app/vpn-helper').glob('*.swift')) if p.name not in ('ServiceMain.swift','VPNRescueMain.swift')]
        sources += [ROOT/'tests/vpn_broker_output_checks.swift']
        captured={p:p.read_bytes() for p in sources}
        for p,data in captured.items():
            target=Path(cls.temp.name)/'Source'/p.relative_to(ROOT)
            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        r=subprocess.run(['/usr/bin/swiftc','-parse-as-library','-target',('arm64' if platform.machine()=='arm64' else 'x86_64')+'-apple-macosx11.0',
            '-D','VPN_BROKER_OUTPUT_TESTING','-D','VPN_SYSTEM_ACTIVATION_DIAGNOSTICS',
            *[str(Path(cls.temp.name)/'Source'/p.relative_to(ROOT)) for p in sources],'-o',str(cls.binary)],capture_output=True,text=True,timeout=180)
        if r.returncode:raise AssertionError(r.stderr)
        if any(p.read_bytes()!=data for p,data in captured.items()):raise AssertionError('Source changed during compile')
    def case(self,mode):
        r=subprocess.run([str(self.binary),'check',mode],capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(r.stdout,'PASS broker-output-'+mode+'\n');self.assertEqual(r.stderr,'')
for mode in MODES:setattr(BrokerOutputTests,'test_'+mode.replace('-','_'),lambda self,m=mode:self.case(m))
if __name__=='__main__':unittest.main()
