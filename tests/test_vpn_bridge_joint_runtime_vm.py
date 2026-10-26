"""Component assembly only: prepared durable App cache, real workers, no root
authority assertion. Fresh opted-in ordinary GHA VM only; default inert.
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
import test_vpn_bridge_worker_gost_vm as gost
import test_vpn_system_resolver_owner_vm as native
ROOT=Path(__file__).resolve().parents[1]
FLAG='PROXYPILOT_VM_JOINT_BRIDGE'
MARKERS=['PASS joint-bridge-'+mode for mode in ('durable-before-ready','http','socks','normal-stop','parent-death','intent-invalidation','all-owned-cleanup')]

def enabled():
    return base.allowed(os.getuid(),os.geteuid(),sys.platform,os.environ) and os.environ.get(FLAG)=='1'

def build_client(folder,architecture=None):
    names=('VPNConfiguration.swift','VPNBridgeProtection.swift','VPNBridgeProtectionAPI.swift','VPNBridgeGOSTConfiguration.swift',
           'VPNBridgeWorkerProcess.swift','VPNBridgeWorkerSupervisor.swift','VPNBridgeWorkerIdentity.swift',
           'VPNBridgeWorkerListener.swift','VPNSystemResolverWorker.swift','VPNBridgeRuntime.swift')
    sources=[ROOT/'app'/name for name in names]+[ROOT/'app/vpn-helper/VPNDNSContinuousClock.swift',ROOT/'tests/vpn_bridge_joint_runtime_vm.swift']
    captured={p:p.read_bytes() for p in sources}
    for p,data in captured.items():(folder/p.name).write_bytes(data)
    arch=architecture or platform.machine();binary=folder/('joint-'+arch)
    api.command(['/usr/bin/swiftc','-O','-parse-as-library','-target',arch+'-apple-macosx12.0',
                 *[str(folder/p.name) for p in sources],'-o',str(binary)],150)
    base.require(all(p.read_bytes()==data for p,data in captured.items()),'binaryRefused')
    api.command(['/usr/bin/codesign','--force','--sign','-','--identifier','kz.documentolog.proxypilot.test-joint-runtime',
                 '--options','runtime,hard,kill',str(binary)],20)
    return binary

def live():
    base.require(enabled(),'guardDenied')
    base.require(bool(os.environ.get('RUNNER_TEMP')) and bool(os.environ.get(gost.BINARY)) and bool(os.environ.get(native.BINARY)),'binaryRefused')
    g=base.verify_binary(os.environ['RUNNER_TEMP'],os.environ[gost.BINARY],os.getuid(),gost.signed.SIGNED_BYTES,gost.signed.SIGNED_SHA256)
    try:
        n=base.verify_binary(os.environ['RUNNER_TEMP'],os.environ[native.BINARY],os.getuid(),native.BYTES,native.SHA256)
        try:run_contract(g,n)
        finally:n.close()
    finally:g.close()

def run_contract(gost_lease,native_lease):
    base.require(enabled(),'guardDenied')
    import json
    import secrets
    import socket
    import socketserver
    import threading
    import time
    nonce=secrets.token_bytes(24);answer=b'E'+nonce
    def exact(connection,count):
        data=b''
        while len(data)<count:
            part=connection.recv(count-len(data));base.require(bool(part),'client');data+=part
        return data
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            if exact(self.request,len(nonce))==nonce:self.request.sendall(answer)
    class IPv6(socketserver.ThreadingTCPServer):address_family=socket.AF_INET6
    servers=[]
    def line(process):
        result=bytearray();deadline=time.monotonic()+10
        with selectors.DefaultSelector() as poll:
            poll.register(process.stdout,selectors.EVENT_READ)
            while not result.endswith(b'\n'):
                remaining=deadline-time.monotonic();base.require(remaining>0 and bool(poll.select(max(.001,remaining))),'startup')
                value=os.read(process.stdout.fileno(),1);base.require(bool(value) and len(result)<160,'startup');result+=value
        return result.decode().strip()
    try:
        v4=socketserver.ThreadingTCPServer(('127.0.0.1',0),Echo);target=v4.server_address[1]
        v6=IPv6(('::1',target),Echo)
        for server in (v4,v6):
            server.daemon_threads=True;thread=threading.Thread(target=server.serve_forever);thread.start();servers.append((server,thread))
        with tempfile.TemporaryDirectory(prefix='pp-joint-vm-',dir=os.environ['RUNNER_TEMP']) as folder:
            folder=Path(folder);folder.chmod(0o700);client=build_client(folder)
            for mode in ('normal','crash','invalidate'):
                epoch=folder/mode;epoch.mkdir(mode=0o700)
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as reservation:
                    reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
                gost_lease.validate();native_lease.validate()
                process=subprocess.Popen([str(client),str(epoch),str(gost_lease.path),str(native_lease.path),str(port)],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
                try:
                    ready=line(process).split();base.require(len(ready)==5 and ready[0]=='READY' and all(v.isdigit() for v in ready[1:]),'startup')
                    bridge,resolver,go_pid,native_pid=map(int,ready[1:]);base.require(bridge==port and resolver!=bridge,'startup')
                    cache=json.loads((epoch/'protected-bridge-v1.json').read_text());base.require(cache['matchers']==['198.19.253.201/32'],'decision')
                    if mode=='normal':
                        print(MARKERS[0],flush=True)
                        for protocol in ('http','socks'):
                            with socket.create_connection(('127.0.0.1',bridge),timeout=3) as connection:
                                if protocol=='http':
                                    connection.sendall(('CONNECT localhost:'+str(target)+' HTTP/1.1\r\nHost: localhost:'+str(target)+'\r\n\r\n').encode())
                                    response=b''
                                    while not response.endswith(b'\r\n\r\n'):
                                        base.require(len(response)<8192,'client');response+=exact(connection,1)
                                    base.require(response.split(b'\r\n',1)[0].split()[1]==b'200','decision')
                                else:
                                    connection.sendall(b'\x05\x01\x00');base.require(exact(connection,2)==b'\x05\x00','client')
                                    connection.sendall(b'\x05\x01\x00\x03\x09localhost'+target.to_bytes(2,'big'))
                                    header=exact(connection,4);base.require(header[:2]==b'\x05\x00','client')
                                    length={1:4,4:16}.get(header[3]);base.require(length is not None,'client');exact(connection,length+2)
                                connection.sendall(nonce);base.require(exact(connection,len(answer))==answer,'decision')
                            print(MARKERS[1 if protocol=='http' else 2],flush=True)
                    process.stdin.write(b'A');process.stdin.flush();base.require(line(process)=='VALIDATED','decision')
                    if mode=='crash':process.kill();process.wait(timeout=5)
                    else:
                        process.stdin.write(b'S' if mode=='normal' else b'I');process.stdin.flush()
                        base.require(line(process)==('STOPPED' if mode=='normal' else 'INVALIDATED'),'cleanup')
                        base.require(process.wait(timeout=5)==0,'cleanup')
                    end=time.monotonic()+5
                    for pid in (go_pid,native_pid):
                        while True:
                            try:os.kill(pid,0)
                            except ProcessLookupError:break
                            base.require(time.monotonic()<end,'cleanup');time.sleep(.02)
                    for endpoint in (bridge,resolver):
                        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as check:
                            check.settimeout(.2)
                            try:check.connect(('127.0.0.1',endpoint))
                            except OSError:pass
                            else:raise base.Refused('cleanup')
                    print(MARKERS[3 if mode=='normal' else 4 if mode=='crash' else 5],flush=True)
                finally:
                    process.stdin.close()
                    if process.poll() is None:
                        try:process.wait(timeout=5)
                        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                    diagnostic=process.stderr.read(4096);process.stdout.close();process.stderr.close()
                    for row in diagnostic.decode('ascii',errors='replace').splitlines():
                        if re.fullmatch(r'FAIL joint-bridge category=(invalid|expired|transport|unavailable|cleanupUnknown|retired|other) stage=(inputs|activate|validate|stop|invalidate)',row):print(row,flush=True)
    finally:
        for server,thread in reversed(servers):server.shutdown();server.server_close();thread.join(timeout=3)
    print(MARKERS[6],flush=True)

class PureTests(unittest.TestCase):
    def test_host_refuses_before_any_artifact_or_runtime(self):
        with patch.dict(os.environ,{},clear=True),patch.object(base,'verify_binary') as artifact,patch(__name__+'.run_contract') as runtime:
            with self.assertRaisesRegex(base.Refused,'guardDenied'):live()
        artifact.assert_not_called();runtime.assert_not_called()
    def test_opt_in_required(self):
        with patch.object(base,'allowed',return_value=True),patch.dict(os.environ,{},clear=True):self.assertFalse(enabled())

@unittest.skipUnless(sys.platform=='darwin' and os.getuid()==os.geteuid()>=500,'ordinary macOS compiler required')
class CompileTests(unittest.TestCase):
    def test_both_arch_build_and_refusal_before_workers(self):
        with tempfile.TemporaryDirectory(prefix='pp-joint-cli-build-') as folder:
            for arch in ('arm64','x86_64'):
                binary=build_client(Path(folder),arch)
                if arch==platform.machine():
                    r=subprocess.run([str(binary),'/must-not-open','/must-not-open','/must-not-open','3129'],env={},capture_output=True,timeout=5)
                    self.assertEqual((r.returncode,r.stdout,r.stderr),(77,b'',b''))

if __name__=='__main__':
    if sys.argv[1:]==['--acceptance']:
        try:live()
        except base.Refused as error:print('FAIL joint-bridge category='+error.category,flush=True);raise SystemExit(1)
        except Exception:print('FAIL joint-bridge category=other',flush=True);raise SystemExit(1)
    else:unittest.main()
