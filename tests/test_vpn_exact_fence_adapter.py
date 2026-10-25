"""Production exact-fence API against fake transport only. No PF_ROUTE socket.
Real loopback index/name reads are read-only; no route/interface/DNS mutations.
"""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [ROOT/'app/VPNConfiguration.swift'] + [ROOT/'app/vpn-helper'/n for n in (
    'OpenVPNManagementEvent.swift','OpenVPNStateEvidence.swift','VPNKernelInterfaceSnapshot.swift',
    'VPNTunnelInterfaceResolver.swift','VPNRoutePlan.swift','VPNRouteJournal.swift','VPNDarwinRouteSocket.swift')]
MODES = ['codec','darwin-mask','sparse-ack','ack-without-state','install-delete','host-distinction','no-adoption','foreign','scope','wrong-address',
         'echo-miss','down','wrong-type-error','stale-error','shared-sequence','unknown-add','race','expired','late','validation']

@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'),'macOS Swift required')
class ExactFenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-exact-fence-fake-'); cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name)/'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        r = subprocess.run(['/usr/bin/swiftc','-parse-as-library','-target',arch+'-apple-macosx11.0',
            *map(str,SOURCES),str(ROOT/'tests/vpn_exact_fence_adapter_checks.swift'),'-o',str(cls.binary)],capture_output=True,text=True,timeout=90)
        if r.returncode: raise AssertionError(r.stderr)
    def case(self,mode):
        r = subprocess.run([str(self.binary),mode],capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr); self.assertEqual(r.stdout,'PASS exact-fence-'+mode+'\n')

for mode in MODES:
    setattr(ExactFenceTests,'test_'+mode.replace('-','_'),lambda self,m=mode:self.case(m))

if __name__ == '__main__': unittest.main()
