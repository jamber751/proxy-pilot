"""Production factory with one fixed Universal image; fresh opted-in GHA VMs only.
Default is compile/refusal only, before artifact access or native worker execution.
"""
from pathlib import Path
import os
import platform
import re
import selectors
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import test_vpn_gost_resolver_vm as base
import test_vpn_bridge_gost_vm as api

ROOT=Path(__file__).resolve().parents[1]
FLAG='PROXYPILOT_VM_NATIVE_RESOLVER_OWNER'
BINARY='PROXYPILOT_VM_NATIVE_RESOLVER_CANONICAL'
BYTES=12059104
SHA256='abc84ad3900b56158ad0020a3d0647b890b0a98d860f05d47d0d0d2a5d585bf5'
MARKERS=['PASS native-resolver-factory-'+mode for mode in ('live-code-and-ca','authenticated-native-lookup','normal-stop','parent-death','all-owned-cleanup')]

def enabled():
    return base.allowed(os.getuid(),os.geteuid(),sys.platform,os.environ) and os.environ.get(FLAG)=='1'

def build_client(folder,architecture=None):
    sources=[ROOT/'app/VPNConfiguration.swift',ROOT/'app/vpn-helper/VPNDNSContinuousClock.swift',
             ROOT/'app/VPNBridgeProtection.swift',ROOT/'app/VPNBridgeGOSTConfiguration.swift',
             ROOT/'app/VPNBridgeWorkerProcess.swift',ROOT/'app/VPNBridgeWorkerSupervisor.swift',
             ROOT/'app/VPNBridgeWorkerIdentity.swift',ROOT/'app/VPNSystemResolverWorker.swift',
             ROOT/'tests/vpn_system_resolver_owner_vm.swift']
    captured={p:p.read_bytes() for p in sources}
    for p,data in captured.items():(folder/p.name).write_bytes(data)
    arch=architecture or platform.machine();binary=folder/('owner-'+arch)
    api.command(['/usr/bin/swiftc','-parse-as-library','-target',arch+'-apple-macosx12.0',
                 *[str(folder/p.name) for p in sources],'-o',str(binary)],120)
    base.require(all(p.read_bytes()==data for p,data in captured.items()),'binaryRefused')
    api.command(['/usr/bin/codesign','--force','--sign','-','--identifier','kz.documentolog.proxypilot.test-native-owner',
                 '--options','runtime,hard,kill',str(binary)],20)
    return binary

def live():
    base.require(enabled(),'guardDenied')
    base.require(bool(os.environ.get('RUNNER_TEMP')) and bool(os.environ.get(BINARY)),'binaryRefused')
    lease=base.verify_binary(os.environ['RUNNER_TEMP'],os.environ[BINARY],os.getuid(),BYTES,SHA256)
    try:run_contract(lease)
    finally:lease.close()

def run_contract(lease):
    base.require(enabled(),'guardDenied')
    import base64
    import http.client
    import ipaddress
    import json
    import secrets
    import socket
    import ssl
    import time
    def line(process,deadline):
        result=bytearray()
        with selectors.DefaultSelector() as poll:
            poll.register(process.stdout,selectors.EVENT_READ)
            while not result.endswith(b'\n'):
                remaining=deadline-time.monotonic();base.require(remaining>0,'startup')
                base.require(bool(poll.select(remaining)),'startup')
                value=os.read(process.stdout.fileno(),1)
                base.require(bool(value) and len(result)<160,'startup');result+=value
        return result.decode('ascii').strip()
    with tempfile.TemporaryDirectory(prefix='pp-native-owner-vm-',dir=os.environ['RUNNER_TEMP']) as folder:
        folder=Path(folder);folder.chmod(0o700);client=build_client(folder)
        for mode in ('normal','crash'):
            epoch=folder/mode;epoch.mkdir(mode=0o700);password=secrets.token_hex(32)
            recipe=epoch/'recipe.json';recipe.write_text(json.dumps({'password':password}));recipe.chmod(0o600)
            lease.validate();process=subprocess.Popen([str(client),str(epoch),str(lease.path)],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            try:
                ready=line(process,time.monotonic()+8).split()
                base.require(len(ready)==4 and ready[0]=='READY' and all(v.isdigit() for v in ready[1:]),'startup')
                port,child,owner=map(int,ready[1:]);base.require(1024<=port<=65535 and child>0 and owner>0 and not recipe.exists(),'startup')
                ca=epoch/'ca.pem';info=ca.lstat()
                base.require(info.st_uid==os.getuid() and info.st_mode&0o7777==0o600 and info.st_nlink==1 and 0<info.st_size<=4096,'configuration')
                context=ssl.create_default_context(cafile=str(ca))
                if mode=='normal':print(MARKERS[0],flush=True)
                connection=http.client.HTTPSConnection('127.0.0.1',port,timeout=2,context=context)
                try:
                    auth='Basic '+base64.b64encode(('proxypilot:'+password).encode()).decode()
                    connection.request('POST','/resolve',body=json.dumps({'network':'ip','host':'localhost','client':'owned-factory'}),
                        headers={'Authorization':auth,'Content-Type':'application/json'})
                    response=connection.getresponse();data=response.read(8193)
                    base.require(response.status==200 and len(data)<=8192,'decision')
                    answer=json.loads(data)
                    base.require(answer.get('ok') is True and 1<=len(answer.get('ips',[]))<=64
                                 and all(ipaddress.ip_address(ip).is_loopback for ip in answer['ips']),'decision')
                finally:connection.close()
                process.stdin.write(b'A');process.stdin.flush()
                base.require(line(process,time.monotonic()+3)=='AUTHENTICATED','decision')
                if mode=='normal':
                    print(MARKERS[1],flush=True);process.stdin.write(b'S');process.stdin.flush()
                    base.require(line(process,time.monotonic()+3)=='STOPPED','cleanup')
                    base.require(process.wait(timeout=4)==0,'cleanup')
                else:process.kill();process.wait(timeout=4)
                end=time.monotonic()+4
                while True:
                    try:os.kill(child,0)
                    except ProcessLookupError:break
                    base.require(time.monotonic()<end,'cleanup');time.sleep(.02)
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
                    probe.settimeout(.3)
                    try:probe.connect(('127.0.0.1',port))
                    except OSError:pass
                    else:raise base.Refused('cleanup')
                lease.validate();print(MARKERS[2 if mode=='normal' else 3],flush=True)
            finally:
                process.stdin.close()
                if process.poll() is None:
                    try:process.wait(timeout=4)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=4)
                diagnostic=process.stderr.read(4096);process.stdout.close();process.stderr.close()
                if diagnostic:
                    for row in diagnostic.decode('ascii',errors='replace').splitlines():
                        if re.fullmatch(r'FAIL native-resolver-owner category=(invalid|expired|transport|unavailable|cleanupUnknown|other) stage=(inputs|selection|start|validate|stop)',row):print(row,flush=True)
                    if process.returncode==0:raise base.Refused('decision')
    print(MARKERS[4],flush=True)

class PureTests(unittest.TestCase):
    def test_host_refused_before_artifact_compile_spawn_or_socket(self):
        with patch.dict(os.environ,{},clear=True),patch.object(base,'verify_binary') as artifact,patch(__name__+'.run_contract') as runtime:
            with self.assertRaisesRegex(base.Refused,'guardDenied'):live()
        artifact.assert_not_called();runtime.assert_not_called()
    def test_opt_in_is_required(self):
        with patch.object(base,'allowed',return_value=True),patch.dict(os.environ,{},clear=True):self.assertFalse(enabled())

@unittest.skipUnless(sys.platform=='darwin' and os.getuid()==os.geteuid()>=500,'ordinary macOS compiler required')
class CompileTests(unittest.TestCase):
    def test_production_cli_both_arch_build_and_inert_guard(self):
        with tempfile.TemporaryDirectory(prefix='pp-native-owner-cli-') as folder:
            for arch in ('arm64','x86_64'):
                binary=build_client(Path(folder),arch)
                if arch==platform.machine():
                    r=subprocess.run([str(binary),'/must-not-open','/must-not-open'],env={},capture_output=True,timeout=5)
                    self.assertEqual((r.returncode,r.stdout,r.stderr),(77,b'',b''))

if __name__=='__main__':
    if sys.argv[1:]==['--acceptance']:
        try:live()
        except base.Refused as error:print('FAIL native-resolver-factory category='+error.category,flush=True);raise SystemExit(1)
        except Exception:print('FAIL native-resolver-factory category=other',flush=True);raise SystemExit(1)
    else:unittest.main()
