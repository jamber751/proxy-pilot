"""Synthetic interfaces + private journal files only; no network/root APIs."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
import test_vpn_exact_fence_adapter as adapter
ROOT=adapter.ROOT
MODES=('union','state-race','journal-race','boot-race','expired','failure','cancelled','invalid-retained','journal-read','codec')
@unittest.skipUnless(adapter.sys.platform=='darwin' and adapter.shutil.which('swiftc') and os.getuid()==os.geteuid()!=0,'ordinary macOS Swift required')
class RootInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pp-root-inventory-build-');cls.addClassCleanup(cls.temp.cleanup)
        cls.binary=Path(cls.temp.name)/'checks'
        sources=adapter.SOURCES+[ROOT/'app/vpn-helper'/name for name in
            ('VPNApplicationSpec.swift','VPNTunnelStateStore.swift','VPNBridgeRootInventory.swift')]
        result=subprocess.run(['/usr/bin/swiftc','-parse-as-library',*map(str,sources),
            str(ROOT/'tests/vpn_bridge_root_inventory_checks.swift'),'-o',str(cls.binary)],capture_output=True,text=True,timeout=90)
        if result.returncode:raise AssertionError(result.stderr)
    def case(self,mode):
        with tempfile.TemporaryDirectory(prefix='pp-root-inventory-private-') as folder:
            Path(folder).chmod(0o700)
            result=subprocess.run([str(self.binary),mode,folder],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(result.stdout,'PASS root-inventory-'+mode+'\n');self.assertEqual(result.stderr,'')
for mode in MODES:setattr(RootInventoryTests,'test_'+mode.replace('-','_'),lambda self,m=mode:self.case(m))
if __name__=='__main__':unittest.main()
