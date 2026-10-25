"""Own ad-hoc-signed AF_UNIX workers only; no TCP/UDP/GOST/root/network changes."""
from pathlib import Path
import json
import os
import platform
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
ROOT=Path(__file__).resolve().parents[1]
@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc') and os.getuid()==os.geteuid()!=0,'ordinary macOS SDK required')
class NativeAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pp-bridge-native-build-');cls.addClassCleanup(cls.temp.cleanup)
        cls.binary=Path(cls.temp.name)/'worker';arch='arm64' if platform.machine()=='arm64' else 'x86_64'
        sources=[ROOT/'app/VPNConfiguration.swift',ROOT/'app/vpn-helper/VPNDNSContinuousClock.swift',
                 ROOT/'app/VPNBridgeProtection.swift',ROOT/'app/VPNBridgeProtectionAPI.swift',ROOT/'tests/vpn_bridge_api_native_worker.swift']
        r=subprocess.run(['/usr/bin/swiftc','-parse-as-library','-target',arch+'-apple-macosx12.0',*map(str,sources),'-o',str(cls.binary)],capture_output=True,text=True,timeout=90)
        if r.returncode:raise AssertionError(r.stderr)
        def sign(path,name):
            subprocess.run(['/usr/bin/codesign','--force','--sign','-','--options','runtime,hard,kill','--identifier',name,str(path)],check=True,capture_output=True,timeout=20)
        sign(cls.binary,'kz.documentolog.proxypilot.test-bridge-native')
        cls.wrong=Path(cls.temp.name)/'wrong';shutil.copyfile(cls.binary,cls.wrong);cls.wrong.chmod(0o700)
        sign(cls.wrong,'kz.documentolog.proxypilot.test-bridge-wrong')
        r=subprocess.run(['/usr/bin/codesign','--display','--verbose=4','--arch',arch,str(cls.binary)],capture_output=True,text=True,check=True,timeout=10)
        hashes=re.findall(r'^CDHash=([0-9a-f]{40})$',r.stderr,re.M)
        if len(hashes)!=1:raise AssertionError('signature metadata')
        cls.cdhash=hashes[0]
    def case(self,mode):
        with tempfile.TemporaryDirectory(prefix='pp-bridge-api-native-') as directory:
            folder=Path(directory);folder.chmod(0o700)
            request=folder/'request.json'
            data={'mode':mode,'serverPassword':'a'*64,'clientPassword':('b' if mode=='wrong-credential' else 'a')*64,
                  'expectedPID':0,'expectedCDHash':self.cdhash}
            request.write_text(json.dumps(data));request.chmod(0o600)
            log=(folder/'server.log').open('x+b');os.chmod(log.name,0o600)
            server=subprocess.Popen([str(self.wrong if mode=='wrong-peer' else self.binary),'server',str(folder)],stdout=subprocess.PIPE,stderr=log)
            try:
                self.assertTrue(select.select([server.stdout],[],[],5)[0],'worker readiness')
                self.assertEqual(os.read(server.stdout.fileno(),64),b'READY\n')
                self.assertIsNone(server.poll())
                data['expectedPID']=server.pid;request.write_text(json.dumps(data));request.chmod(0o600)
                client=subprocess.run([str(self.binary),'client',str(folder)],capture_output=True,text=True,timeout=10)
                self.assertEqual(client.returncode,0,client.stdout+client.stderr)
                self.assertEqual(client.stdout,'PASS bridge-api-native-'+mode+'\n');self.assertEqual(client.stderr,'')
                self.assertIsNone(server.poll())
                end=time.monotonic()+2
                while not (folder/'witness.json').exists() and server.poll() is None and time.monotonic()<end:time.sleep(.01)
                witness=json.loads((folder/'witness.json').read_text())
                self.assertEqual(witness,{'hadRequest':mode!='wrong-peer','authorized':mode=='success','valid':mode!='wrong-peer'})
            finally:
                if server.poll() is None:
                    server.terminate()
                    try:server.wait(timeout=3)
                    except subprocess.TimeoutExpired:server.kill();server.wait(timeout=3)
                if server.stdout:server.stdout.close()
                log.close()
    def test_signed_peer_success(self):self.case('success')
    def test_wrong_credential_preserves_disk_and_refuses_output(self):self.case('wrong-credential')
    def test_wrong_signed_peer_receives_no_credentials(self):self.case('wrong-peer')
if __name__=='__main__':unittest.main()
