"""Owned signed supervisor + bounded C fake only. No GOST/DNS/TCP/SC/root APIs."""
from pathlib import Path
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(sys.platform=='darwin' and shutil.which('swiftc') and os.getuid()==os.geteuid()>=500,'ordinary macOS required')
class WorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='pp-bridge-worker-build-',dir='/tmp');cls.addClassCleanup(cls.temp.cleanup)
        cls.folder=Path(cls.temp.name);cls.binary=cls.folder/'worker';cls.fake=cls.folder/'fake'
        sources=[ROOT/'app/VPNBridgeWorkerProcess.swift',ROOT/'app/VPNBridgeWorkerSupervisor.swift',ROOT/'app/VPNBridgeWorkerIdentity.swift',ROOT/'tests/vpn_bridge_worker_checks.swift']
        captured={p:p.read_bytes() for p in sources}
        for p,data in captured.items():(cls.folder/p.name).write_bytes(data)
        fake=ROOT/'tests/vpn_bridge_worker_fake.c';captured[fake]=fake.read_bytes()
        (cls.folder/fake.name).write_bytes(captured[fake])
        for arch in ('arm64','x86_64'):
            cls.command(['/usr/bin/clang','-Wall','-Wextra','-Werror','-target',arch+'-apple-macosx12.0',str(cls.folder/fake.name),'-o',str(cls.folder/('fake-'+arch))])
            cls.command(['/usr/bin/swiftc','-parse-as-library','-D','VPN_BRIDGE_WORKER_TESTING','-target',arch+'-apple-macosx12.0',
                *[str(cls.folder/p.name) for p in sources],'-o',str(cls.folder/('worker-'+arch))])
        for name in ('worker','fake'):
            cls.command(['/usr/bin/lipo','-create',str(cls.folder/(name+'-arm64')),str(cls.folder/(name+'-x86_64')),'-output',str(cls.folder/name)])
            (cls.folder/name).chmod(0o700)
            cls.command(['/usr/bin/codesign','--force','--sign','-','--identifier','kz.documentolog.proxypilot.test-'+name,
                         '--options','runtime,hard,kill',str(cls.folder/name)])
        if any(p.read_bytes()!=data for p,data in captured.items()):raise AssertionError('sourceChanged')
    @staticmethod
    def command(args,env=None):
        result=subprocess.run(args,capture_output=True,text=True,timeout=90,env=env)
        if result.returncode:raise AssertionError(result.stdout+result.stderr)
        return result
    def case(self,mode):
        with tempfile.TemporaryDirectory(prefix='pp-bridge-worker-case-',dir='/tmp') as folder:
            fake=Path(folder)/'fake';shutil.copyfile(self.fake,fake);fake.chmod(0o700)
            result=self.command([str(self.binary),mode,folder,str(fake)],env={**os.environ,"PROXYPILOT_TEST_SECRET":"fixture-marker"})
            self.assertEqual(result.stdout,'PASS bridge-worker-'+mode+'\n');self.assertEqual(result.stderr,'')
    def test_stop_does_not_signal_an_unrelated_owned_process(self):
        with tempfile.TemporaryDirectory(prefix='pp-bridge-worker-sentinel-',dir='/tmp') as folder:
            marker=Path(folder)/'sentinel'
            sentinel=subprocess.Popen([str(self.fake),'-C','-'],stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env={})
            try:
                sentinel.stdin.write((str(marker)+'\nnormal\n').encode());sentinel.stdin.close()
                end=time.monotonic()+2
                while not marker.exists() and time.monotonic()<end:time.sleep(.01)
                self.assertTrue(marker.exists())
                self.case('stop');self.assertIsNone(sentinel.poll())
            finally:
                if sentinel.poll() is None:sentinel.terminate()
                sentinel.wait(timeout=3)

    def test_parent_crash_stops_owned_child(self):
        with tempfile.TemporaryDirectory(prefix='pp-bridge-worker-crash-',dir='/tmp') as folder:
            fake=Path(folder)/'fake';shutil.copyfile(self.fake,fake);fake.chmod(0o700)
            process=subprocess.Popen([str(self.binary),'crash',folder,str(fake)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                parts=process.stdout.readline().split()
                if not parts:
                    code=process.wait(timeout=3)
                    self.fail('no startup: '+str(code)+' '+process.stderr.read(1024))
                self.assertEqual(parts[0],'READY')
                child,owner=map(int,parts[1:]);process.kill();process.wait(timeout=5)
                end=time.monotonic()+4
                while time.monotonic()<end:
                    try:os.kill(child,0)
                    except ProcessLookupError:break
                    time.sleep(.02)
                else:self.fail('owned fake child survived parent EOF')
            finally:
                if process.poll() is None:process.kill();process.wait(timeout=5)
                process.stdout.close();process.stderr.close()
    def test_role_cannot_be_selected_by_flag_without_inherited_capabilities(self):
        result=subprocess.run([str(self.binary),'--proxypilot-private-bridge-worker-v1'],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,77)
    def test_production_graph_compiles_for_both_architectures_without_running(self):
        for arch in ('arm64','x86_64'):
            self.command(['/usr/bin/swiftc','-parse-as-library','-emit-library','-target',arch+'-apple-macosx12.0',
                          str(ROOT/'app/VPNBridgeWorkerProcess.swift'),str(ROOT/'app/VPNBridgeWorkerSupervisor.swift'),str(ROOT/'app/VPNBridgeWorkerIdentity.swift'),
                          '-o',str(self.folder/('production-'+arch+'.dylib'))])
for mode in ('identity','dead-owner','datagram','stop','force','drop','early-exit','named-config','changed-image','expired','production-pin'):
    setattr(WorkerTests,'test_'+mode.replace('-','_'),lambda self,m=mode:self.case(m))
if __name__=='__main__':unittest.main()
