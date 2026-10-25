"""Default is inert. Fresh opted-in ordinary-user macOS VM only:
fixed candidate pins, owned loopback echoes/fake proxy + private Unix API.
No system DNS/proxy/VPN settings and no onward target connection are used.
This proves runtime positive numeric bypass updates, not domain DNS authority.
"""
from pathlib import Path
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import test_vpn_gost_resolver_vm as base

FLAG='PROXYPILOT_VM_GOST_ATOMIC_TESTS'
BINARY='PROXYPILOT_VM_GOST_ATOMIC_BINARY'
NATIVE={
 'arm64':(33718386,'a6b84fa7a5fe9267468bafbe9c5db984f6f3cc17c9a5dd11380fb52ccc830aa8'),
 'x86_64':(36564192,'5d767d607dfc58f5a06beb8c0bbb33b5082aaa5c7b11af423f743795f74a7e9f'),
}


def configuration(port,upstream,socket_path,password,known):
    base.require(socket_path.is_absolute() and socket_path.name=='api.sock'
                 and len(os.fsencode(socket_path))<100 and len(password)==48
                 and all(c in '0123456789abcdef' for c in password)
                 and known in (['127.0.0.1/32'],['127.0.0.1/32','::1/128']), 'configuration')
    result=base.configuration(port,upstream)
    result['api']={'addr':'unix://'+str(socket_path),'auth':{'username':'owned','password':password}}
    result['bypasses'][0]['matchers']=known
    result['log']={'level':'error'}
    return result


def live():
    base.require(base.allowed(os.getuid(),os.geteuid(),sys.platform,os.environ)
                 and os.environ.get(FLAG)=='1','guardDenied')
    base.require(platform.machine() in NATIVE and bool(os.environ.get('RUNNER_TEMP'))
                 and bool(os.environ.get(BINARY)),'binaryRefused')
    size,digest=NATIVE[platform.machine()]
    lease=base.verify_binary(os.environ['RUNNER_TEMP'],os.environ[BINARY],os.getuid(),size,digest)
    try:run_contract(lease)
    finally:lease.close()


def run_contract(lease):
    base.require(base.allowed(os.getuid(),os.geteuid(),sys.platform,os.environ)
                 and os.environ.get(FLAG)=='1','guardDenied')
    import base64
    import http.client
    import secrets
    import socket
    import socketserver
    import threading
    probe=secrets.token_bytes(24); direct=b'D'+probe; proxied=b'P'+probe
    password=secrets.token_hex(24); headers={'Authorization':'Basic '+base64.b64encode(('owned:'+password).encode()).decode()}
    observed={'proxy':0,'direct':0,'errors':0};mutex=threading.Lock();servers=[];children=[]
    allowed_targets=set()
    def exact(client,count):
        result=b''
        while len(result)<count:
            chunk=client.recv(count-len(result));base.require(bool(chunk),'client');result+=chunk
        return result
    def header(client):
        result=b''
        while b'\r\n\r\n' not in result:
            chunk=client.recv(512);base.require(bool(chunk),'client');result+=chunk;base.require(len(result)<=4096,'bounds')
        return base.decode_headers(result)
    def endpoint(address,kind):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.settimeout(2)
                    if kind=='proxy':
                        first,_,rest=header(self.request);parts=first.split(' ')
                        base.require(len(parts)==3 and parts[0]=='CONNECT' and parts[2]=='HTTP/1.1'
                                     and parts[1] in allowed_targets and not rest,'request')
                        self.request.sendall(b'HTTP/1.1 200 Owned\r\n\r\n')
                    base.require(exact(self.request,len(probe))==probe,'request')
                    with mutex:observed[kind]+=1
                    self.request.sendall(proxied if kind=='proxy' else direct)
                except Exception:
                    with mutex:observed['errors']+=1
        class Server(socketserver.ThreadingTCPServer):
            address_family=socket.AF_INET6 if address=='::1' else socket.AF_INET
            daemon_threads=False
            allow_reuse_address=False
        base.require(address in ('127.0.0.1','::1'),'configuration')
        server=Server((address,0),Handler)
        thread=threading.Thread(target=lambda:server.serve_forever(poll_interval=.05));thread.start()
        servers.append((server,thread));return server.server_address[1]
    def stop(child):
        if child is not None and child.poll() is None:
            child.terminate()
            try:child.wait(timeout=3)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
    previous_mask=os.umask(0o077)
    try:
        v4=endpoint('127.0.0.1','direct');v6=endpoint('::1','direct');upstream=endpoint('127.0.0.1','proxy')
        allowed_targets.update(('127.0.0.1:'+str(v4),'[::1]:'+str(v6)))
        with tempfile.TemporaryDirectory(prefix='pp-atomic-',dir=os.environ['RUNNER_TEMP']) as directory:
            folder=Path(directory);folder.chmod(0o700);api=folder/'api.sock';config=folder/'gost.json'
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as reservation:
                reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
            class UnixAPI(http.client.HTTPConnection):
                def connect(self):
                    self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                    self.sock.settimeout(self.timeout);self.sock.connect(str(api))
            def request(method,path,data=None,authorized=True):
                client=UnixAPI('localhost',timeout=2)
                try:
                    body=None if data is None else json.dumps(data).encode()
                    fields={**headers,'Content-Type':'application/json'} if authorized else {'Authorization':'Basic invalid'}
                    client.request(method,path,body=body,headers=fields)
                    response=client.getresponse();payload=response.read(65537)
                    base.require(len(payload)<=65536,'bounds')
                    return response.status,payload
                finally:client.close()
            def launch(known):
                base.require(not api.exists(),'startup')
                config.write_text(json.dumps(configuration(port,'127.0.0.1:'+str(upstream),api,password,known)));config.chmod(0o600)
                lease.validate()
                log=(folder/('process-'+str(len(children))+'.log')).open('x+b')
                logs.append(log)
                child=subprocess.Popen([str(lease.path),'-C',str(config)],stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                    env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'})
                children.append(child);lease.validate()
                end=time.monotonic()+5
                while True:
                    base.require(child.poll() is None,'startup')
                    try:
                        code,body=request('GET','/config/bypasses/b0')
                        base.require(code==200 and json.loads(body)['data']['matchers']==known,'decision')
                        break
                    except (OSError,http.client.HTTPException):
                        base.require(time.monotonic()<end,'startup');time.sleep(.02)
                return child,log
            def connect(address,target_port,protocol,expected):
                with socket.create_connection(('127.0.0.1',port),timeout=2) as client:
                    client.settimeout(2)
                    target=('['+address+']' if ':' in address else address)+':'+str(target_port)
                    if protocol=='http':
                        client.sendall(('CONNECT '+target+' HTTP/1.1\r\nHost: '+target+'\r\n\r\n').encode())
                        first,_,rest=header(client)
                        base.require(first.startswith(('HTTP/1.1 200 ','HTTP/1.0 200 ')) and not rest,'decision')
                    else:
                        client.sendall(b'\x05\x01\x00');base.require(exact(client,2)==b'\x05\x00','client')
                        family=socket.AF_INET6 if ':' in address else socket.AF_INET
                        client.sendall(b'\x05\x01\x00'+(b'\x04' if family==socket.AF_INET6 else b'\x01')+
                            socket.inet_pton(family,address)+target_port.to_bytes(2,'big'))
                        reply=exact(client,4);base.require(reply[:3]==b'\x05\x00\x00','decision')
                        count=exact(client,1)[0] if reply[3]==3 else {1:4,4:16}.get(reply[3],0)
                        base.require(count>0,'client');exact(client,count+2)
                    client.sendall(probe);base.require(exact(client,len(direct))==(direct if expected else proxied),'decision')
            logs=[]
            try:
                child,log=launch(['127.0.0.1/32'])
                for protocol in ('http','socks'):
                    connect('127.0.0.1',v4,protocol,True);connect('::1',v6,protocol,False)
                print('PASS gost-atomic-initial-direct-and-proxy-controls',flush=True)
                code,_=request('PUT','/config/bypasses/b0',{'name':'b0','matchers':[]},False)
                base.require(code==401,'decision');connect('127.0.0.1',v4,'http',True)
                print('PASS gost-atomic-private-api-auth-refusal',flush=True)
                union=['127.0.0.1/32','::1/128']
                def update():
                    code,body=request('PUT','/config/bypasses/b0',{'name':'b0','matchers':union})
                    base.require(code==200 and json.loads(body)=={'msg':'OK'},'decision')
                update()
                for protocol in ('http','socks'):
                    connect('127.0.0.1',v4,protocol,True);connect('::1',v6,protocol,True)
                print('PASS gost-atomic-ack-follows-both-family-activation',flush=True)
                cancel=threading.Event();failures=[];workers=[];completed=[0]*4
                finish=time.monotonic()+15
                def worker(index,protocol,address,target_port):
                    try:
                        for _ in range(24):
                            if cancel.is_set():break
                            connect(address,target_port,protocol,True)
                            with mutex:completed[index]+=1
                    except Exception:
                        with mutex:failures.append(True)
                        cancel.set()
                try:
                    for protocol in ('http','socks'):
                        for address,target in (('127.0.0.1',v4),('::1',v6)):
                            thread=threading.Thread(target=worker,args=(len(workers),protocol,address,target));workers.append(thread);thread.start()
                    for _ in range(48):
                        if cancel.is_set():break
                        update()
                finally:
                    for thread in workers:thread.join(timeout=max(0,finish-time.monotonic()))
                    cancel.set()
                    for thread in workers:thread.join(timeout=3)
                base.require(not failures and completed==[24]*4 and all(not thread.is_alive() for thread in workers),'decision')
                base.require(child.poll() is None and observed['proxy']==2 and observed['errors']==0,'decision')
                print('PASS gost-atomic-concurrent-cached-literal-no-proxy-escape',flush=True)
                stop(child)
                child,log=launch(union)
                for protocol in ('http','socks'):
                    connect('127.0.0.1',v4,protocol,True);connect('::1',v6,protocol,True)
                base.require(observed['proxy']==2 and observed['direct']==107 and observed['errors']==0,'decision')
                print('PASS gost-atomic-restart-retains-known-addresses-before-listen',flush=True)
            finally:
                for child in reversed(children):stop(child)
                for log in logs:
                    log.flush();size=os.fstat(log.fileno()).st_size;log.close();base.require(size<=2*1024*1024,'bounds')
            lease.validate()
    finally:
        for child in reversed(children):stop(child)
        for server,thread in reversed(servers):server.shutdown();server.server_close();thread.join(timeout=3)
        os.umask(previous_mask)
    base.require(not observed['errors'],'cleanup')
    print('PASS gost-atomic-owned-runtime-cleanup',flush=True)


class PureTests(unittest.TestCase):
    def test_host_denied_before_binary_or_live_operations(self):
        with patch.dict(os.environ,{},clear=True),patch.object(base,'verify_binary') as binary,patch(__name__+'.run_contract') as network,patch('subprocess.Popen') as spawn:
            with self.assertRaisesRegex(base.Refused,'guardDenied'):live()
        binary.assert_not_called();network.assert_not_called();spawn.assert_not_called()
    def test_additional_atomic_flag_is_required(self):
        with patch.object(base,'allowed',return_value=True),patch.dict(os.environ,{},clear=True),patch.object(base,'verify_binary') as binary:
            with self.assertRaisesRegex(base.Refused,'guardDenied'):live()
        binary.assert_not_called()
    def test_config_has_private_authenticated_api_and_positive_numeric_matchers(self):
        value=configuration(12345,'127.0.0.1:12346',Path('/private/tmp/owned/api.sock'),'a'*48,['127.0.0.1/32'])
        self.assertEqual(value['api']['addr'],'unix:///private/tmp/owned/api.sock')
        self.assertNotIn('reverse',value['bypasses'][0]);self.assertNotIn('reload',value['bypasses'][0])
        for path in (Path('api.sock'),Path('/private/tmp/wrong'),Path('/'+'a'*100+'/api.sock')):
            with self.assertRaises(base.Refused):configuration(12345,'127.0.0.1:12346',path,'a'*48,['127.0.0.1/32'])
    def test_stock_pins_are_separate_and_not_replaced(self):
        self.assertEqual(set(NATIVE),set(base.NATIVE))
        self.assertTrue(all(NATIVE[key]!=base.NATIVE[key] for key in NATIVE))

if __name__=='__main__':
    if sys.argv[1:]==['--acceptance']:
        try:live()
        except base.Refused as error:print('FAIL gost-atomic category='+error.category,flush=True);raise SystemExit(1)
        except Exception:print('FAIL gost-atomic category=unexpected',flush=True);raise SystemExit(1)
    else:unittest.main()
