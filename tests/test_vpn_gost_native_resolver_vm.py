"""Default inert. Fresh opted-in ordinary macOS VM only: candidate GOST ->
TLS-pinned production Cgo worker -> native localhost lookup -> owned echoes.
No system DNS/SC/proxy/VPN settings change. Scoped corporate DNS is a later gate.
"""
from pathlib import Path
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import test_vpn_gost_resolver_vm as base
import test_vpn_gost_atomic_vm as atomic
ROOT=Path(__file__).resolve().parents[1]
FLAG='PROXYPILOT_VM_NATIVE_SYSTEM_RESOLVER_TESTS'
WORKER='PROXYPILOT_VM_SYSTEM_RESOLVER_BINARY'


def enabled():
    return base.allowed(os.getuid(),os.geteuid(),sys.platform,os.environ) and os.environ.get(atomic.FLAG)=='1' and os.environ.get(FLAG)=='1'


def resolver(port,password,certificate):
    base.require(type(port) is int and 1024<=port<=65535 and re.fullmatch('[a-f0-9]{64}',password) is not None
                 and certificate.is_absolute() and certificate.name=='ca.pem','configuration')
    return {'type':'http','addr':'https://proxypilot:'+password+'@127.0.0.1:'+str(port)+'/resolve',
            'timeout':2_000_000_000,'tls':{'secure':True,'serverName':'127.0.0.1','caFile':str(certificate)}}


def verified_worker():
    base.require(bool(os.environ.get(WORKER)),'binaryRefused')
    path=Path(os.environ[WORKER]);manifest=path.parent/'verification.json'
    with manifest.open('rb') as stream:
        encoded=stream.read(8193)
    base.require(len(encoded)<=8192,'binaryRefused')
    record=json.loads(encoded)
    expected_names=('go.mod','main.go','lookup.go','build.py')
    base.require(record.get('schema')==1 and record.get('toolchain')=='go1.25.4' and record.get('minimumMacOS')=='12.0'
                 and set(record.get('sources',{}))==set(expected_names),'binaryRefused')
    for name in expected_names:
        base.require(record['sources'][name]==hashlib.sha256((ROOT/'app/vpn-system-resolver'/name).read_bytes()).hexdigest(),'binaryRefused')
    entry=record['outputs'][platform.machine()]
    base.require(type(entry['bytes']) is int and 0<entry['bytes']<=16*1024*1024
                 and re.fullmatch('[a-f0-9]{64}',entry['sha256']) is not None
                 and path.name=='system-resolver-'+platform.machine(),'binaryRefused')
    return base.verify_binary(os.environ['RUNNER_TEMP'],str(path),os.getuid(),entry['bytes'],entry['sha256'])


def live():
    base.require(enabled(),'guardDenied')
    base.require(platform.machine() in atomic.NATIVE and bool(os.environ.get('RUNNER_TEMP')) and bool(os.environ.get(atomic.BINARY)),'binaryRefused')
    size,digest=atomic.NATIVE[platform.machine()]
    gost=base.verify_binary(os.environ['RUNNER_TEMP'],os.environ[atomic.BINARY],os.getuid(),size,digest)
    try:
        worker=verified_worker()
        try:run_contract(gost,worker)
        finally:worker.close()
    finally:gost.close()


def run_contract(gost_lease,worker_lease):
    base.require(enabled(),'guardDenied')
    import secrets
    import select
    import socket
    import socketserver
    import time
    import threading
    password=secrets.token_hex(32);probe=secrets.token_bytes(24);answer=b'D'+probe
    observed={'echo':0,'proxy':0,'errors':0};mutex=threading.Lock();servers=[];children=[];logs=[]
    def stop(child):
        if child is not None and child.poll() is None:
            child.terminate()
            try:child.wait(timeout=3)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
    def exact(client,count):
        data=b''
        while len(data)<count:
            chunk=client.recv(count-len(data));base.require(bool(chunk),'client');data+=chunk
        return data
    def endpoint(address,port,kind):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.settimeout(2)
                    with mutex:observed[kind]+=1
                    if kind=='proxy':return # No onward DNS/connection, ever.
                    base.require(exact(self.request,len(probe))==probe,'request');self.request.sendall(answer)
                except Exception:
                    with mutex:observed['errors']+=1
        class Server(socketserver.ThreadingTCPServer):
            address_family=socket.AF_INET6 if address=='::1' else socket.AF_INET
            daemon_threads=False
            def server_bind(self):
                if self.address_family==socket.AF_INET6:self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
                super().server_bind()
        base.require(address in ('127.0.0.1','::1'),'configuration')
        server=Server((address,port),Handler)
        thread=threading.Thread(target=lambda:server.serve_forever(poll_interval=.05));thread.start()
        servers.append((server,thread));return server.server_address[1]
    try:
        target=endpoint('127.0.0.1',0,'echo');endpoint('::1',target,'echo');upstream=endpoint('127.0.0.1',0,'proxy')
        with tempfile.TemporaryDirectory(prefix='pp-native-resolver-',dir=os.environ['RUNNER_TEMP']) as directory:
            folder=Path(directory);folder.chmod(0o700)
            def log(name):
                stream=(folder/name).open('x+b');os.chmod(stream.name,0o600);logs.append(stream);return stream
            def launch_worker(index):
                worker_lease.validate()
                base.require(subprocess.run(['/usr/bin/codesign','--verify','--strict',str(worker_lease.path)],capture_output=True,timeout=10).returncode==0,'binaryRefused')
                child=subprocess.Popen([str(worker_lease.path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log('worker-'+str(index)+'.log'),env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'})
                children.append(child);worker_lease.validate()
                child.stdin.write(json.dumps({'password':password}).encode());child.stdin.close()
                data=b'';end=time.monotonic()+5
                while not data.endswith(b'\n'):
                    base.require(child.poll() is None and time.monotonic()<end and len(data)<4096,'startup')
                    base.require(bool(select.select([child.stdout],[],[],max(.001,end-time.monotonic()))[0]),'startup')
                    chunk=os.read(child.stdout.fileno(),512);base.require(bool(chunk),'startup');data+=chunk
                ready=json.loads(data)
                base.require(set(ready)=={'port','certificate'} and type(ready['port']) is int and 1024<=ready['port']<=65535
                             and ready['certificate'].startswith('-----BEGIN CERTIFICATE-----\n')
                             and ready['certificate'].endswith('-----END CERTIFICATE-----\n'),'startup')
                worker_lease.validate();return child,ready
            worker,ready=launch_worker(0);other,foreign=launch_worker(1);stop(other)
            for protocol in ('http','socks'):
                for mode in ('success','wrong-password','wrong-ca'):
                    ca=folder/'ca.pem';ca.write_text(foreign['certificate'] if mode=='wrong-ca' else ready['certificate']);ca.chmod(0o600)
                    supplied=(('b' if password!='b'*64 else 'a')*64 if mode=='wrong-password' else password)
                    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as reserved:
                        reserved.bind(('127.0.0.1',0));port=reserved.getsockname()[1]
                    value=base.configuration(port,'127.0.0.1:'+str(upstream),resolver(ready['port'],supplied,ca))
                    value['bypasses'][0]['matchers']=['127.0.0.1/32','::1/128'];value['log']={'level':'error'}
                    config=folder/'gost.json';config.write_text(json.dumps(value));config.chmod(0o600)
                    gost_lease.validate();worker_lease.validate();base.require(worker.poll() is None,'startup')
                    child=subprocess.Popen([str(gost_lease.path),'-C',str(config)],stdin=subprocess.DEVNULL,stdout=log(protocol+'-'+mode+'.log'),stderr=subprocess.STDOUT,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'})
                    children.append(child)
                    try:
                        end=time.monotonic()+5
                        while True:
                            base.require(child.poll() is None and worker.poll() is None,'startup')
                            try:
                                check=socket.create_connection(('127.0.0.1',port),timeout=.1);check.close();break
                            except OSError:base.require(time.monotonic()<end,'startup');time.sleep(.02)
                        success=False
                        with socket.create_connection(('127.0.0.1',port),timeout=3) as client:
                            client.settimeout(3)
                            if protocol=='http':
                                dest='localhost:'+str(target)
                                client.sendall(('CONNECT '+dest+' HTTP/1.1\r\nHost: '+dest+'\r\n\r\n').encode())
                                data=b''
                                while b'\r\n\r\n' not in data:
                                    chunk=client.recv(512)
                                    if not chunk:break
                                    data+=chunk;base.require(len(data)<=4096,'bounds')
                                if b'\r\n\r\n' in data:
                                    first,_,rest=base.decode_headers(data);success=first.startswith(('HTTP/1.1 200 ','HTTP/1.0 200 '))
                                    base.require(not success or not rest,'client')
                            else:
                                client.sendall(b'\x05\x01\x00');base.require(exact(client,2)==b'\x05\x00','client')
                                host=b'localhost';client.sendall(b'\x05\x01\x00\x03'+bytes([len(host)])+host+target.to_bytes(2,'big'))
                                result=b''
                                while len(result)<4:
                                    part=client.recv(4-len(result))
                                    if not part:break
                                    result+=part
                                if len(result)==4:
                                    base.require(result[0]==5 and result[2]==0,'client');success=result[1]==0
                                    count=exact(client,1)[0] if result[3]==3 else {1:4,4:16}.get(result[3],0)
                                    base.require(count>0,'client');exact(client,count+2)
                                else:base.require(not result,'client')
                            base.require(success==(mode=='success'),'decision')
                            if success:client.sendall(probe);base.require(exact(client,len(answer))==answer,'decision')
                        base.require(child.poll() is None and worker.poll() is None and observed['proxy']==0 and observed['errors']==0,'decision')
                        gost_lease.validate();worker_lease.validate()
                        print('PASS gost-native-resolver-'+protocol+'-'+mode,flush=True)
                    finally:stop(child)
            base.require(observed=={'echo':2,'proxy':0,'errors':0},'decision')
    finally:
        for child in reversed(children):
            stop(child)
            if child.stdout:child.stdout.close()
            if child.stdin and not child.stdin.closed:child.stdin.close()
        for server,thread in reversed(servers):server.shutdown();server.server_close();thread.join(timeout=3)
        for stream in logs:
            stream.flush();size=os.fstat(stream.fileno()).st_size;stream.close();base.require(size<=65536,'bounds')
    gost_lease.validate();worker_lease.validate()
    print('PASS gost-native-resolver-owned-cleanup',flush=True)

class PureTests(unittest.TestCase):
    def test_host_refuses_before_binary_or_worker_reads_or_process(self):
        with patch.dict(os.environ,{},clear=True),patch.object(base,'verify_binary') as binary,patch(__name__+'.verified_worker') as worker,patch('subprocess.Popen') as spawn:
            with self.assertRaisesRegex(base.Refused,'guardDenied'):live()
        binary.assert_not_called();worker.assert_not_called();spawn.assert_not_called()
    def test_native_opt_in_required(self):
        with patch.object(base,'allowed',return_value=True),patch.dict(os.environ,{atomic.FLAG:'1'},clear=True):self.assertFalse(enabled())
    def test_https_uses_custom_ca_and_verification(self):
        value=resolver(12345,'a'*64,Path('/private/tmp/owned/ca.pem'))
        self.assertEqual(value['tls'],{'secure':True,'serverName':'127.0.0.1','caFile':'/private/tmp/owned/ca.pem'})
        self.assertTrue(value['addr'].startswith('https://proxypilot:'))
        for port,password,path in ((80,'a'*64,Path('/tmp/ca.pem')),(12345,'a'*48,Path('/tmp/ca.pem')),(12345,'a'*64,Path('ca.pem'))):
            with self.assertRaises(base.Refused):resolver(port,password,path)
if __name__=='__main__':
    if sys.argv[1:]==['--acceptance']:
        try:live()
        except base.Refused as error:print('FAIL gost-native-resolver category='+error.category,flush=True);raise SystemExit(1)
        except Exception:print('FAIL gost-native-resolver category=unexpected',flush=True);raise SystemExit(1)
    else:unittest.main()
