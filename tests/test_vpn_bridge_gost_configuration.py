"""Closed production config + real private/unlinked files; no process or network."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
MODES=('routes','direct','invalid','expired','cancelled','directory','directory-change','lifetime','capacity')

@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc') and os.getuid()==os.geteuid()>=500,'ordinary macOS compiler required')
class ConfigurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pp-bridge-config-build-',dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        folder=Path(cls.temp.name)
        sources=[ROOT/'app/VPNConfiguration.swift',ROOT/'app/vpn-helper/VPNDNSContinuousClock.swift',
                 ROOT/'app/VPNBridgeProtection.swift',ROOT/'app/VPNBridgeGOSTConfiguration.swift',
                 ROOT/'tests/vpn_bridge_gost_configuration_checks.swift']
        captured={path:path.read_bytes() for path in sources}
        for path,data in captured.items():(folder/path.name).write_bytes(data)
        for arch in ('arm64','x86_64'):
            r=subprocess.run(['/usr/bin/swiftc','-parse-as-library','-target',arch+'-apple-macosx12.0',
                *[str(folder/path.name) for path in sources],'-o',str(folder/arch)],capture_output=True,text=True,timeout=90)
            if r.returncode:raise AssertionError(r.stderr)
        if any(path.read_bytes()!=data for path,data in captured.items()):raise AssertionError('sourceChanged')
        cls.binary=folder/('arm64' if platform.machine()=='arm64' else 'x86_64')

    def case(self,mode):
        with tempfile.TemporaryDirectory(prefix='pp-config-',dir='/tmp') as folder:
            r=subprocess.run([str(self.binary),mode,os.path.realpath(folder)],capture_output=True,text=True,timeout=15)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(r.stdout,'PASS bridge-configuration-'+mode+'\n')
        self.assertEqual(r.stderr,'')

for mode in MODES:
    setattr(ConfigurationTests,'test_'+mode,lambda self,m=mode:self.case(m))
if __name__=='__main__':unittest.main()
