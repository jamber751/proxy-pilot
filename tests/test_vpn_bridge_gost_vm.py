"""Fresh opted-in VM: production Swift publisher -> pinned candidate GOST.

Default tests are inert. Actual exchange uses a private Unix API, signed owned
children and synthetic numeric matchers; no DNS/system/network settings change.
No connection to a resource IP is attempted. Traffic is covered separately by
atomic candidate runtime tests; this gate proves client/API interoperability.
"""
from pathlib import Path
from contextlib import ExitStack
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import test_vpn_gost_resolver_vm as base
import test_vpn_gost_atomic_vm as atomic

ROOT=Path(__file__).resolve().parents[1]
FLAG='PROXYPILOT_VM_BRIDGE_GOST_TESTS'
GROUP='proxypilot-protected-v1'


def enabled():
    return (base.allowed(os.getuid(),os.geteuid(),sys.platform,os.environ)
            and os.environ.get(atomic.FLAG)=='1' and os.environ.get(FLAG)=='1')


def configuration(port,upstream,path,password):
    base.require(path.is_absolute() and path.name=='api.sock' and len(os.fsencode(path))<100
                 and re.fullmatch('[a-f0-9]{64}',password) is not None,'configuration')
    value=base.configuration(port,upstream)
    value['api']={'addr':'unix://'+str(path),'auth':{'username':'proxypilot','password':password}}
    value['bypasses'].append({'name':GROUP,'matchers':[],'reverse':False,'whitelist':False})
    hop=value['chains'][0]['hops'][0]
    del hop['bypass'];hop['bypasses']=['b0',GROUP]
    value['log']={'level':'error'}
    return value


def command(args,timeout=90):
    result=subprocess.run(args,capture_output=True,timeout=timeout)
    base.require(result.returncode==0,'decision')
    return result


def signing_hash(path):
    result=command(['/usr/bin/codesign','--display','--verbose=4','--arch',platform.machine(),str(path)],10)
    hashes=re.findall(rb'^CDHash=([a-f0-9]{40})$',result.stderr,re.M)
    base.require(len(hashes)==1,'binaryRefused')
    return hashes[0].decode()


def build_client(folder):
    sources=[ROOT/'app/VPNConfiguration.swift',ROOT/'app/vpn-helper/VPNDNSContinuousClock.swift',
             ROOT/'app/VPNBridgeProtection.swift',ROOT/'app/VPNBridgeProtectionAPI.swift',
             ROOT/'tests/vpn_bridge_api_native_worker.swift']
    captured={p:p.read_bytes() for p in sources}
    inputs=[]
    for path,data in captured.items():
        target=folder/'Source'/path.relative_to(ROOT)
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data);inputs.append(str(target))
    worker=folder/'client'
    command(['/usr/bin/swiftc','-parse-as-library','-target',platform.machine()+'-apple-macosx12.0',*inputs,'-o',str(worker)],120)
    base.require(all(p.read_bytes()==data for p,data in captured.items()),'binaryRefused')
    command(['/usr/bin/codesign','--force','--sign','-','--options','runtime,hard,kill',
             '--identifier','kz.documentolog.proxypilot.test-bridge-gost-client',str(worker)],20)
    command(['/usr/bin/codesign','--verify','--strict',str(worker)],10)
    return worker


def live():
    # Refuse before compiling, reading a candidate, spawning or opening sockets.
    base.require(enabled(),'guardDenied')
    base.require(platform.machine() in atomic.NATIVE and bool(os.environ.get('RUNNER_TEMP'))
                 and bool(os.environ.get(atomic.BINARY)),'binaryRefused')
    size,digest=atomic.NATIVE[platform.machine()]
    lease=base.verify_binary(os.environ['RUNNER_TEMP'],os.environ[atomic.BINARY],os.getuid(),size,digest)
    try:run_contract(lease)
    finally:lease.close()


def run_contract(lease):
    base.require(enabled(),'guardDenied')
    import base64
    import http.client
    import secrets
    import socket
    import time
    with tempfile.TemporaryDirectory(prefix='pp-bridge-api-native-',dir=os.environ['RUNNER_TEMP']) as directory, ExitStack() as cleanup:
        folder=Path(directory);folder.chmod(0o700)
        worker=build_client(folder)
        # x86 Go builds may be unsigned. Sign a VM-owned COPY, never the pinned
        # artifact. Provenance is fixed source bytes -> exact copy -> codesign;
        # freeze the transformed bytes before spawn and pin the live audit peer.
        lease.validate();candidate=folder/'gost'
        shutil.copyfile(lease.path,candidate);candidate.chmod(0o700)
        base.require(candidate.stat().st_size==atomic.NATIVE[platform.machine()][0]
                     and hashlib.sha256(candidate.read_bytes()).hexdigest()==atomic.NATIVE[platform.machine()][1],'binaryRefused')
        lease.validate()
        command(['/usr/bin/codesign','--force','--sign','-','--options','runtime,hard,kill',
                 '--identifier','kz.documentolog.proxypilot.test-bridge-gost',str(candidate)],20)
        command(['/usr/bin/codesign','--verify','--strict',str(candidate)],10)
        cdhash=signing_hash(candidate)
        signed=base.verify_binary(str(folder),str(candidate),os.getuid(),candidate.stat().st_size,
                                  hashlib.sha256(candidate.read_bytes()).hexdigest())
        cleanup.callback(signed.close)
        password=secrets.token_hex(32);api=folder/'api.sock'
        authorization='Basic '+base64.b64encode(('proxypilot:'+password).encode()).decode()
        class UnixAPI(http.client.HTTPConnection):
            def connect(self):
                self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout);self.sock.connect(str(api))
        def fetch(name):
            client=UnixAPI('localhost',timeout=2)
            try:
                client.request('GET','/config/bypasses/'+name,headers={'Authorization':authorization,'Connection':'close'})
                reply=client.getresponse();body=reply.read(65537)
                base.require(reply.status==200 and len(body)<=65536,'decision')
                return json.loads(body)['data']
            finally:client.close()
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as reservation:
            reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
        config=folder/'gost.json';config.write_text(json.dumps(configuration(port,'127.0.0.1:1',api,password)));config.chmod(0o600)
        child=None
        with (folder/'gost.log').open('x+b') as log:
            os.chmod(log.name,0o600)
            try:
                signed.validate()
                child=subprocess.Popen([str(candidate),'-C',str(config)],stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                                       env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'},umask=0o077)
                end=time.monotonic()+5
                while True:
                    base.require(child.poll() is None,'startup');signed.validate()
                    try:
                        base.require(fetch(GROUP).get('matchers') in ([],None),'decision');break
                    except (OSError,http.client.HTTPException):
                        base.require(time.monotonic()<end,'startup');time.sleep(.02)
                original=fetch('b0')
                for index,mode in enumerate(('wrong-credential','success','success')):
                    request=folder/'request.json'
                    request.write_text(json.dumps({'mode':mode,'serverPassword':password,
                        'clientPassword':('b'*64 if password!='b'*64 else 'a'*64) if mode=='wrong-credential' else password,
                        'expectedPID':child.pid,'expectedCDHash':cdhash}));request.chmod(0o600)
                    signed.validate();base.require(child.poll() is None,'startup')
                    result=command([str(worker),'client',str(folder)],10)
                    base.require(result.stdout==('PASS bridge-api-native-'+mode+'\n').encode() and not result.stderr,'decision')
                    signed.validate();base.require(child.poll() is None,'startup')
                    state=fetch(GROUP)
                    expected=[] if mode=='wrong-credential' else ['198.19.253.201/32']
                    base.require((state.get('matchers') or [])==expected and fetch('b0')==original,'decision')
                    print('PASS bridge-gost-'+('auth-refusal-retains-cache' if index==0 else ('swift-publisher-ack-and-independent-user-policy' if index==1 else 'reopened-cache-republication')),flush=True)
            finally:
                if child is not None and child.poll() is None:
                    child.terminate()
                    try:child.wait(timeout=3)
                    except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
                signed.close();lease.validate()
                log.flush();base.require(os.fstat(log.fileno()).st_size<=2*1024*1024,'bounds')
    print('PASS bridge-gost-owned-runtime-cleanup',flush=True)


class PureTests(unittest.TestCase):
    def test_host_refused_before_artifact_compile_spawn_or_socket(self):
        with patch.dict(os.environ,{},clear=True),patch.object(base,'verify_binary') as artifact,patch(__name__+'.run_contract') as runtime:
            with self.assertRaisesRegex(base.Refused,'guardDenied'):live()
        artifact.assert_not_called();runtime.assert_not_called()
    def test_additional_opt_in_required(self):
        with patch.object(base,'allowed',return_value=True),patch.dict(os.environ,{atomic.FLAG:'1'},clear=True):
            self.assertFalse(enabled())
    def test_separate_positive_protected_group_and_fixed_api_credentials(self):
        value=configuration(12345,'127.0.0.1:1',Path('/private/tmp/owned/api.sock'),'a'*64)
        self.assertEqual(value['api']['auth'],{'username':'proxypilot','password':'a'*64})
        self.assertEqual(value['chains'][0]['hops'][0]['bypasses'],['b0',GROUP])
        self.assertEqual(value['bypasses'][0],{'name':'b0','matchers':['127.0.0.1/32']})
        self.assertEqual(value['bypasses'][1],{'name':GROUP,'matchers':[],'reverse':False,'whitelist':False})
    def test_invalid_api_configuration_refused(self):
        for path,password in ((Path('api.sock'),'a'*64),(Path('/tmp/wrong'),'a'*64),(Path('/tmp/api.sock'),'a'*48)):
            with self.assertRaises(base.Refused):configuration(12345,'127.0.0.1:1',path,password)

if __name__=='__main__':
    if sys.argv[1:]==['--acceptance']:
        try:live()
        except base.Refused as error:print('FAIL bridge-gost category='+error.category,flush=True);raise SystemExit(1)
        except Exception:print('FAIL bridge-gost category=unexpected',flush=True);raise SystemExit(1)
    else:unittest.main()
