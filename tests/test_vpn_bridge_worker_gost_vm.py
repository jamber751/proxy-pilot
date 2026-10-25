"""Actual signed GOST lifetime through production supervisor, fresh ordinary VM.
Default tests refuse before artifact/compile/spawn/network. No resource dial,
root, system proxy/DNS/route changes. Failed cleanup requires VM disposal.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
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
import test_vpn_gost_atomic_vm as atomic
import test_vpn_bridge_gost_vm as api
ROOT=Path(__file__).resolve().parents[1]
FLAG='PROXYPILOT_VM_BRIDGE_WORKER_GOST'
BINARY='PROXYPILOT_VM_GOST_SIGNED_BINARY'
spec=importlib.util.spec_from_file_location('pp_worker_signed_pin',ROOT/'app/vpn-bridge/sign_atomic_gost.py')
signed=importlib.util.module_from_spec(spec);spec.loader.exec_module(signed)
MARKERS=['PASS owned-gost-worker-'+mode for mode in ('initial-policy-and-live-code','normal-stop','parent-death','all-owned-cleanup')]
CONFIG_MARKERS=['PASS owned-gost-configuration-'+mode for mode in ('initial-policy-and-live-code','normal-stop','parent-death','all-owned-cleanup')]


def enabled():
    return (base.allowed(os.getuid(),os.geteuid(),sys.platform,os.environ)
            and os.environ.get(atomic.FLAG)=='1' and os.environ.get(FLAG)=='1')


def build_client(folder,architecture=None):
    sources=[ROOT/'app/VPNConfiguration.swift',ROOT/'app/vpn-helper/VPNDNSContinuousClock.swift',
             ROOT/'app/VPNBridgeProtection.swift',ROOT/'app/VPNBridgeProtectionAPI.swift',
             ROOT/'app/VPNBridgeWorkerProcess.swift',ROOT/'app/VPNBridgeWorkerSupervisor.swift',
             ROOT/'app/VPNBridgeWorkerIdentity.swift',ROOT/'app/VPNBridgeGOSTConfiguration.swift',ROOT/'tests/vpn_bridge_worker_gost_vm.swift']
    captured={path:path.read_bytes() for path in sources};inputs=[]
    for path,data in captured.items():
        target=folder/path.name;target.write_bytes(data);inputs.append(str(target))
    architecture=architecture or platform.machine()
    target=folder/('client-'+architecture)
    api.command(['/usr/bin/swiftc','-parse-as-library','-target',architecture+'-apple-macosx12.0',*inputs,'-o',str(target)],120)
    base.require(all(path.read_bytes()==data for path,data in captured.items()),'binaryRefused')
    api.command(['/usr/bin/codesign','--force','--sign','-','--identifier','kz.documentolog.proxypilot.test-owned-gost',
                 '--options','runtime,hard,kill',str(target)],20)
    return target


def live():
    base.require(enabled(),'guardDenied')
    base.require(bool(os.environ.get('RUNNER_TEMP')) and bool(os.environ.get(BINARY)),'binaryRefused')
    lease=base.verify_binary(os.environ['RUNNER_TEMP'],os.environ[BINARY],os.getuid(),signed.SIGNED_BYTES,signed.SIGNED_SHA256)
    try:run_contract(lease)
    finally:lease.close()


def run_contract(lease):
    base.require(enabled(),'guardDenied')
    import base64
    import http.client
    import secrets
    import socket
    import time
    def line(process,deadline):
        # Unbuffered binary reads avoid hiding an extra buffered result from select.
        result=bytearray()
        with selectors.DefaultSelector() as poll:
            poll.register(process.stdout,selectors.EVENT_READ)
            while not result.endswith(b'\n'):
                remaining=deadline-time.monotonic();base.require(remaining>0,'startup')
                base.require(bool(poll.select(remaining)),'startup')
                value=os.read(process.stdout.fileno(),1);base.require(bool(value) and len(result)<160,'startup');result+=value
        return result.decode('ascii').strip()
    with tempfile.TemporaryDirectory(prefix='pp-owned-gost-vm-',dir=os.environ['RUNNER_TEMP']) as directory:
        folder=Path(directory);folder.chmod(0o700);client=build_client(folder)
        for mode,production in (('normal',False),('crash',False),('normal',True),('crash',True)):
            markers=CONFIG_MARKERS if production else MARKERS
            epoch=folder/(('config-' if production else '')+mode);epoch.mkdir(mode=0o700);endpoint=epoch/'api.sock'
            base.require(len(os.fsencode(endpoint))<100,'configuration')
            password=secrets.token_hex(32)
            config=api.configuration(1,'127.0.0.1:1',endpoint,password)
            config['services'][0]['addr']='127.0.0.1:0'
            expected=['198.19.253.201/32','2001:db8:fff:fd::c9/128']
            config['bypasses'][1]['matchers']=expected
            arguments=[str(client),str(epoch),str(lease.path)]
            if production:
                # No resolver/resource lookup is requested by this lifecycle gate.
                # The production recipe still has to parse its explicit secure
                # resolver and initial policy in actual signed GOST.
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as reservation:
                    reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
                base.require(1024<=port<=65535,'configuration')
                api.command(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                    '-subj','/CN=127.0.0.1','-keyout',str(epoch/'key.pem'),'-out',str(epoch/'ca.pem')],20)
                for name in ('key.pem','ca.pem'):(epoch/name).chmod(0o600)
                path=epoch/'recipe.json'
                path.write_text(json.dumps({'port':port,'apiPassword':password,'resolverPassword':secrets.token_hex(32)}))
                arguments.append('--production-configuration')
            else:
                path=epoch/'gost.json';path.write_text(json.dumps(config))
            path.chmod(0o600)
            lease.validate();process=subprocess.Popen(arguments,
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
            try:
                ready=line(process,time.monotonic()+8).split()
                base.require(len(ready)==3 and ready[0]=='READY' and all(value.isdigit() for value in ready[1:]),'startup')
                child,owner=map(int,ready[1:]);base.require(child>0 and owner>0 and not path.exists(),'startup')
                class UnixAPI(http.client.HTTPConnection):
                    def connect(self):
                        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                        self.sock.settimeout(self.timeout);self.sock.connect(str(endpoint))
                authorization='Basic '+base64.b64encode(('proxypilot:'+password).encode()).decode()
                def fetch(group):
                    connection=UnixAPI('localhost',timeout=1)
                    try:
                        connection.request('GET','/config/bypasses/'+group,headers={'Authorization':authorization,'Connection':'close'})
                        reply=connection.getresponse();body=reply.read(65537)
                        base.require(reply.status==200 and len(body)<=65536,'decision')
                        return json.loads(body)['data']
                    finally:connection.close()
                end=time.monotonic()+5
                while True:
                    base.require(process.poll() is None,'startup');lease.validate()
                    try:
                        base.require(fetch(api.GROUP).get('matchers')==expected,'decision');break
                    except (OSError,http.client.HTTPException):
                        base.require(time.monotonic()<end,'startup');time.sleep(.02)
                base.require(fetch('b0').get('matchers')==['127.0.0.1/32'],'decision')
                process.stdin.write(b'A');process.stdin.flush()
                base.require(line(process,time.monotonic()+4)=='AUTHENTICATED','decision')
                if mode=='normal':
                    print(markers[0],flush=True)
                    process.stdin.write(b'S');process.stdin.flush()
                    base.require(line(process,time.monotonic()+4)=='STOPPED','decision')
                    base.require(process.wait(timeout=4)==0,'cleanup')
                else:
                    process.kill();process.wait(timeout=4)
                end=time.monotonic()+4
                while True:
                    try:os.kill(child,0)
                    except ProcessLookupError:break
                    base.require(time.monotonic()<end,'cleanup');time.sleep(.02)
                # Socket pathname may remain; a stopped owned listener cannot accept.
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as probe:
                    probe.settimeout(.3)
                    try:probe.connect(str(endpoint))
                    except OSError:pass
                    else:raise base.Refused('cleanup')
                lease.validate()
                print(markers[1 if mode=='normal' else 2],flush=True)
            finally:
                # Close the owner's capability, never signal a remembered GOST PID.
                if process.stdin is not None:process.stdin.close()
                if process.poll() is None:
                    try:process.wait(timeout=4)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=4)
                diagnostic=process.stderr.read(4096)
                process.stdout.close();process.stderr.close()
                if diagnostic:
                    for row in diagnostic.decode('ascii',errors='replace').splitlines():
                        if re.fullmatch(r'FAIL owned-gost-worker category=(invalid|expired|transport|unavailable|cleanupUnknown|other) stage=(inputs|selection|launch|authentication|stop)',row):
                            print(row,flush=True)
                    if process.returncode==0:raise base.Refused('decision')
    print(MARKERS[3],flush=True)
    print(CONFIG_MARKERS[3],flush=True)


class PureTests(unittest.TestCase):
    def test_host_refused_before_artifact_compile_spawn_or_socket(self):
        with patch.dict(os.environ,{},clear=True),patch.object(base,'verify_binary') as artifact,patch(__name__+'.run_contract') as runtime:
            with self.assertRaisesRegex(base.Refused,'guardDenied'):live()
            artifact.assert_not_called();runtime.assert_not_called()
    def test_extra_owned_worker_opt_in_is_required(self):
        with patch.object(base,'allowed',return_value=True),patch.dict(os.environ,{atomic.FLAG:'1'},clear=True):
            self.assertFalse(enabled())
    def test_fixed_signed_image_not_an_environment_pin(self):
        self.assertEqual(signed.SIGNED_BYTES,70633296)
        self.assertEqual(signed.SIGNED_SHA256,'28666449b54ac0e63c70073bb75844fca6471488b745240dbe401ec2cfa405e7')
        self.assertEqual(len(MARKERS),4)
        self.assertEqual(len(CONFIG_MARKERS),4)

@unittest.skipUnless(sys.platform=='darwin' and os.getuid()==os.geteuid()>=500,'ordinary macOS compiler required')
class CompileOnlyTests(unittest.TestCase):
    def test_both_arch_cli_build_and_host_refusal_before_live_io(self):
        with tempfile.TemporaryDirectory(prefix='pp-owned-gost-compile-') as directory:
            folder=Path(directory)
            for architecture in ('arm64','x86_64'):
                binary=build_client(folder,architecture)
                if architecture==platform.machine():
                    for extra in ([],['--production-configuration']):
                        result=subprocess.run([str(binary),'/must-not-open','/must-not-open',*extra],env={},capture_output=True,timeout=5)
                        self.assertEqual(result.returncode,77)
                        self.assertEqual(result.stdout,b'');self.assertEqual(result.stderr,b'')

if __name__=='__main__':
    if sys.argv[1:]==['--acceptance']:
        try:live()
        except base.Refused as error:print('FAIL owned-gost-worker category='+error.category,flush=True);raise SystemExit(1)
        except Exception:print('FAIL owned-gost-worker category=other',flush=True);raise SystemExit(1)
    else:unittest.main()
