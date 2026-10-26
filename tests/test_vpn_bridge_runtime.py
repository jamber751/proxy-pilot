"""Pure shared-budget tests and production code compilation, no process/socket."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
MODES=('original-budget','sleep','backwards','callback','overflow','expired')
@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc') and os.getuid()==os.geteuid()>=500,'ordinary macOS compiler required')
class RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pp-runtime-budget-',dir='/tmp');cls.addClassCleanup(cls.temp.cleanup)
        folder=Path(cls.temp.name)
        sources=[ROOT/'app'/name for name in ('VPNConfiguration.swift','VPNBridgeProtection.swift','VPNBridgeProtectionAPI.swift',
            'VPNBridgeGOSTConfiguration.swift','VPNBridgeWorkerProcess.swift','VPNBridgeWorkerSupervisor.swift',
            'VPNBridgeWorkerIdentity.swift','VPNBridgeWorkerListener.swift','VPNSystemResolverWorker.swift','VPNBridgeRuntime.swift')]
        sources += [ROOT/'app/vpn-helper/VPNDNSContinuousClock.swift',ROOT/'tests/vpn_bridge_runtime_checks.swift']
        captured={p:p.read_bytes() for p in sources}
        for p,data in captured.items():(folder/p.name).write_bytes(data)
        for arch in ('arm64','x86_64'):
            r=subprocess.run(['/usr/bin/swiftc','-O','-parse-as-library','-target',arch+'-apple-macosx12.0',
                *[str(folder/p.name) for p in sources],'-o',str(folder/arch)],capture_output=True,text=True,timeout=150)
            if r.returncode:raise AssertionError(r.stderr)
        if any(p.read_bytes()!=data for p,data in captured.items()):raise AssertionError('sourceChanged')
        cls.binary=folder/platform.machine()
    def case(self,mode):
        r=subprocess.run([str(self.binary),mode],capture_output=True,text=True,timeout=5)
        self.assertEqual((r.returncode,r.stdout,r.stderr),(0,'PASS bridge-runtime-'+mode+'\n',''))
for mode in MODES:setattr(RuntimeTests,'test_'+mode.replace('-','_'),lambda self,m=mode:self.case(m))
if __name__=='__main__':unittest.main()
