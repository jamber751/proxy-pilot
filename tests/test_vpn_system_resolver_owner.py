"""Real private files and a bounded signed fake; no Go worker, DNS or listener."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
MODES=('ready','certificate','certificate-changed','certificate-replaced','foreign-certificate','pin','factory-auth','factory-role','normal','force','stopped','long','hang')

@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc') and os.getuid()==os.geteuid()>=500,'ordinary macOS compiler required')
class OwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pp-resolver-owner-build-',dir='/tmp');cls.addClassCleanup(cls.temp.cleanup)
        folder=Path(cls.temp.name)
        sources=[ROOT/'app/VPNConfiguration.swift',ROOT/'app/vpn-helper/VPNDNSContinuousClock.swift',
                 ROOT/'app/VPNBridgeProtection.swift',ROOT/'app/VPNBridgeGOSTConfiguration.swift',
                 ROOT/'app/VPNBridgeWorkerProcess.swift',ROOT/'app/VPNBridgeWorkerSupervisor.swift',
                 ROOT/'app/VPNBridgeWorkerIdentity.swift',ROOT/'app/VPNSystemResolverWorker.swift',
                 ROOT/'tests/vpn_system_resolver_worker_checks.swift']
        fake=ROOT/'tests/vpn_system_resolver_fake.c'
        captured={p:p.read_bytes() for p in [*sources,fake]}
        for p,data in captured.items():(folder/p.name).write_bytes(data)
        for arch in ('arm64','x86_64'):
            cls.command(['/usr/bin/swiftc','-parse-as-library','-D','VPN_BRIDGE_WORKER_TESTING','-target',arch+'-apple-macosx12.0',*[str(folder/p.name) for p in sources],'-o',str(folder/('checks-'+arch))])
            cls.command(['/usr/bin/clang','-Wall','-Wextra','-Werror','-target',arch+'-apple-macosx12.0',str(folder/fake.name),'-o',str(folder/('fake-'+arch))])
        for name in ('checks','fake'):
            cls.command(['/usr/bin/lipo','-create',str(folder/(name+'-arm64')),str(folder/(name+'-x86_64')),'-output',str(folder/name)])
            (folder/name).chmod(0o700)
            cls.command(['/usr/bin/codesign','--force','--sign','-','--identifier','kz.documentolog.proxypilot.test-resolver-'+name,'--options','runtime,hard,kill',str(folder/name)])
        if any(p.read_bytes()!=data for p,data in captured.items()):raise AssertionError('sourceChanged')
        cls.command(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Fixture',
                     '-keyout',str(folder/'fixture.key'),'-out',str(folder/'fixture.pem')])
        (folder/'fixture.key').unlink()
        cls.binary=folder/'checks';cls.fake=folder/'fake';cls.pem=folder/'fixture.pem'
    @staticmethod
    def command(args):
        r=subprocess.run(args,capture_output=True,text=True,timeout=90)
        if r.returncode:raise AssertionError(r.stdout+r.stderr)
        return r
    def case(self,mode):
        with tempfile.TemporaryDirectory(prefix='pp-resolver-case-',dir='/tmp') as folder:
            r=self.command([str(self.binary),mode,os.path.realpath(folder),str(self.fake),str(self.pem)])
            self.assertEqual(r.stdout,'PASS resolver-owner-'+mode+'\n');self.assertEqual(r.stderr,'')
    def test_private_resolver_role_refuses_without_inherited_capabilities(self):
        r=subprocess.run([str(self.binary),'--proxypilot-private-resolver-worker-v1'],capture_output=True,timeout=5)
        self.assertEqual((r.returncode,r.stdout,r.stderr),(77,b'',b''))
    def test_parent_crash_retires_owned_fake(self):
        with tempfile.TemporaryDirectory(prefix='pp-resolver-crash-',dir='/tmp') as folder:
            process=subprocess.Popen([str(self.binary),'crash',os.path.realpath(folder),str(self.fake),str(self.pem)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                ready=process.stdout.readline().split();self.assertEqual(ready[0],'READY');child=int(ready[1])
                process.kill();process.wait(timeout=5)
                end=time.monotonic()+3
                while time.monotonic()<end:
                    try:os.kill(child,0)
                    except ProcessLookupError:break
                    time.sleep(.02)
                else:self.fail('owned fake survived parent EOF')
            finally:
                if process.poll() is None:process.kill();process.wait(timeout=5)
                process.stdout.close();process.stderr.close()
    def test_parent_crash_during_ready_wait_retires_owned_fake(self):
        with tempfile.TemporaryDirectory(prefix='pp-resolver-start-crash-',dir='/tmp') as folder:
            process=subprocess.Popen([str(self.binary),'crash-startup',os.path.realpath(folder),str(self.fake),str(self.pem)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                marker=Path(folder)/'child';end=time.monotonic()+3
                while not marker.exists() and process.poll() is None and time.monotonic()<end:time.sleep(.01)
                self.assertTrue(marker.exists());child=int(marker.read_text().split()[0])
                process.kill();process.wait(timeout=5)
                end=time.monotonic()+2
                while time.monotonic()<end:
                    try:os.kill(child,0)
                    except ProcessLookupError:break
                    time.sleep(.02)
                else:self.fail('owned fake survived startup owner EOF')
            finally:
                if process.poll() is None:process.kill();process.wait(timeout=5)
                process.stdout.close();process.stderr.close()

for mode in MODES:setattr(OwnerTests,'test_'+mode.replace('-','_'),lambda self,m=mode:self.case(m))
if __name__=='__main__':unittest.main()
