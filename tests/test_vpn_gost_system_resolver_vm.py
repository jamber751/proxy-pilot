"""Compile/pure guards ONLY by default; no local SC/network/DNS/Keychain calls.
Opted-in fresh-root-GHA orchestration temporarily owns one random OS DNS scope;
GOST/Node/client endpoints run as the ordinary invoking runner, never root.
This proves the resolver seam, NOT production integration or WARP acceptance.
"""
from pathlib import Path
import ipaddress
import json
import os
import platform
import select
import selectors
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

import test_vpn_gost_resolver_vm as base
import test_vpn_gost_grpc_resolver_vm as grpc
import test_vpn_dns_resolver_vm as dns

ROOT = Path(__file__).resolve().parents[1]
FLAG = 'PROXYPILOT_VM_GOST_SYSTEM_RESOLVER_TESTS'
SOURCE = ROOT/'tests/vpn_gost_system_dns_owner.swift'
MARKERS = ['PASS gost-system-dns-'+protocol+'-'+mode for protocol in ('http','socks')
           for mode in ('in-cidr','out-cidr')] + ['PASS gost-system-dns-all-4-owned-cases']
CLEANUP = 'PASS gost-system-dns-owner-session-cleanup'
ROOT_FAILURES = {'guardDenied','runnerIdentity','ownerStartup','ownerCleanup','ordinaryProbe','dnsWitness','responder','outputProtocol'}


def root_allowed():
    return sys.platform == 'darwin' and os.getuid() == os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get(FLAG) == '1'


def compile_owner(folder):
    folder = Path(folder); captured = SOURCE.read_bytes()
    snapshot = folder/SOURCE.name; snapshot.write_bytes(captured)
    paths = []
    for arch in ('arm64','x86_64'):
        binary = folder/arch
        result = subprocess.run(['/usr/bin/swiftc','-parse-as-library','-target',arch+'-apple-macosx12.0',
            str(snapshot),'-framework','SystemConfiguration','-o',str(binary)],capture_output=True,text=True,timeout=60)
        if result.returncode: raise AssertionError(result.stderr)
        paths.append(str(binary))
    binary = folder/'owner'
    subprocess.run(['/usr/bin/lipo','-create',*paths,'-output',str(binary)],check=True,capture_output=True,timeout=10)
    if SOURCE.read_bytes() != captured: raise AssertionError('sourceChanged')
    return binary


class LoopbackResponder(dns.Responder):
    def response(self, packet, transport):
        data = super().response(packet,transport)
        if data is None: return None
        # Only the final fixed fixture RR address differs from the older canary.
        if data.endswith(ipaddress.ip_address('2001:db8::53').packed):
            return data[:-16]+ipaddress.ip_address('::1').packed
        if data.endswith(ipaddress.ip_address('192.0.2.53').packed):
            return data[:-4]+ipaddress.ip_address('127.0.0.1').packed
        return data # TC response has no answer bytes.


def ordinary(run):
    base.require(base.allowed(os.getuid(),os.geteuid(),sys.platform,os.environ) and os.environ.get(FLAG) == '1'
                 and str(uuid.UUID(run)) == run,'guardDenied')
    size,digest = base.native_pin(platform.machine())
    lease = base.verify_binary(os.environ['RUNNER_TEMP'],os.environ[base.BINARY],os.getuid(),size,digest)
    try: grpc.run_contract(lease,system_id=run)
    finally: lease.close()


def live():
    # Must precede sockets, temp files, SC helper, ordinary worker or getaddrinfo.
    if not root_allowed(): raise RuntimeError('guardDenied')
    import pwd
    uid,gid = int(os.environ['SUDO_UID']),int(os.environ['SUDO_GID'])
    if uid < 500 or gid < 0 or pwd.getpwuid(uid).pw_gid != gid: raise RuntimeError('runnerIdentity')
    run = str(uuid.uuid4()); responder = LoopbackResponder(run); stop = threading.Event(); errors = []
    with tempfile.TemporaryDirectory(prefix='pp-gost-osdns-',dir=os.environ['RUNNER_TEMP']) as folder:
        binary = compile_owner(folder)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp, socket.socket(socket.AF_INET,socket.SOCK_STREAM) as tcp:
            # Never reuse/take over an occupied port or alter another interface.
            udp.bind(('127.0.0.1',53)); tcp.bind(('127.0.0.1',53)); tcp.listen(8)
            with selectors.DefaultSelector() as selector:
                selector.register(udp,selectors.EVENT_READ); selector.register(tcp,selectors.EVENT_READ)
                def serve():
                    try:
                        while not stop.is_set():
                            for event,_ in selector.select(timeout=.1):
                                if event.fileobj is udp:
                                    data,peer = udp.recvfrom(4096)
                                    if not ipaddress.ip_address(peer[0]).is_loopback: continue
                                    answer = responder.response(data,'udp')
                                    if answer is not None: udp.sendto(answer,peer)
                                else:
                                    conn,peer = tcp.accept()
                                    with conn:
                                        conn.settimeout(1)
                                        if not ipaddress.ip_address(peer[0]).is_loopback: continue
                                        size = struct.unpack('!H',dns.read_exact(conn,2))[0]
                                        if not 12 <= size <= 4096: continue
                                        answer = responder.response(dns.read_exact(conn,size),'tcp')
                                        if answer is not None: conn.sendall(struct.pack('!H',len(answer))+answer)
                    except Exception: errors.append('responder')
                thread = threading.Thread(target=serve); thread.start(); owner = None
                try:
                    environment = {'PATH':os.environ['PATH'],'GITHUB_ACTIONS':'true',FLAG:'1',base.FLAG:'1',
                                   'RUNNER_TEMP':os.environ['RUNNER_TEMP'],base.BINARY:os.environ[base.BINARY]}
                    owner = subprocess.Popen([str(binary),'--hold',run],stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=environment)
                    if not select.select([owner.stdout],[],[],8)[0] or os.read(owner.stdout.fileno(),64) != b'READY\n':
                        raise RuntimeError('ownerStartup')
                    result = subprocess.run([sys.executable,str(Path(__file__).resolve()),'--ordinary',run],
                        user=uid,group=gid,extra_groups=[],env=environment,capture_output=True,text=True,timeout=40)
                    out,_ = owner.communicate(input=b'R',timeout=8)
                    if owner.returncode or out != (CLEANUP+'\n').encode(): raise RuntimeError('ownerCleanup')
                    for line in result.stdout.splitlines():
                        if line not in MARKERS and line not in {'FAIL gost-system-dns category='+c for c in base.FAILURES}:
                            raise RuntimeError('outputProtocol')
                    if result.returncode or result.stdout.splitlines() != MARKERS:
                        for line in result.stdout.splitlines(): print(line,flush=True)
                        raise RuntimeError('ordinaryProbe')
                    needed = {('udp',1,'udp'),('tcp',28,'udp'),('tcp',28,'tcp')}
                    if not needed.issubset(responder.seen): raise RuntimeError('dnsWitness')
                    for marker in MARKERS: print(marker,flush=True)
                    print(CLEANUP,flush=True)
                    print('PASS gost-system-dns-actual-A-AAAA-UDP-TCP',flush=True)
                finally:
                    if owner is not None:
                        if owner.poll() is None:
                            owner.kill(); owner.communicate(timeout=5)
                        if owner.stdin: owner.stdin.close()
                        if owner.stdout: owner.stdout.close()
                    stop.set(); thread.join(timeout=3)
                if errors or thread.is_alive(): raise RuntimeError('responder')


class PureTests(unittest.TestCase):
    def test_root_guard_denies_before_network_or_compile_or_process(self):
        with patch.dict(os.environ,{},clear=True),patch('socket.socket') as network,patch(__name__+'.compile_owner') as compiler,patch('subprocess.Popen') as child:
            with self.assertRaisesRegex(RuntimeError,'^guardDenied$'): live()
        network.assert_not_called(); compiler.assert_not_called(); child.assert_not_called()

    def test_extra_system_opt_in_refuses_before_binary_or_network(self):
        with patch.dict(os.environ,{},clear=True),patch('socket.socket') as network,patch.object(base,'verify_binary') as binary:
            with self.assertRaises(base.Refused): ordinary('12345678-1234-1234-1234-123456789abc')
            with self.assertRaises(base.Refused): grpc.run_contract(None,system_id='12345678-1234-1234-1234-123456789abc')
        binary.assert_not_called(); network.assert_not_called()

    def test_loopback_dns_response_and_tcp_fallback_are_pure(self):
        run = '12345678-1234-1234-1234-123456789abc'; r = LoopbackResponder(run)
        self.assertTrue(r.response(dns.question('udp.pp-'+run+'.test',1),'udp').endswith(b'\x7f\0\0\1'))
        self.assertTrue(r.response(dns.question('tcp.pp-'+run+'.test',28),'tcp').endswith(ipaddress.ip_address('::1').packed))
        truncated = r.response(dns.question('tcp.pp-'+run+'.test',28),'udp')
        self.assertEqual(struct.unpack('!H',truncated[2:4])[0]&0x200,0x200)
        self.assertIsNone(r.response(dns.question('foreign.test',1),'udp'))

    @unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc') and os.geteuid() != 0,'ordinary macOS compiler required')
    def test_native_both_arch_compile_pure_and_ordinary_refusal(self):
        with tempfile.TemporaryDirectory(prefix='pp-gost-osdns-pure-') as folder:
            binary = compile_owner(folder)
            pure = subprocess.run([str(binary),'--pure'],capture_output=True,timeout=5)
            self.assertEqual((pure.returncode,pure.stdout,pure.stderr),(0,b'',b''))
            for env in ({},{'GITHUB_ACTIONS':'true',FLAG:'1'}):
                denied = subprocess.run([str(binary),'--hold','12345678-1234-1234-1234-123456789abc'],env={'PATH':'/usr/bin:/bin',**env},capture_output=True,timeout=5)
                self.assertEqual((denied.returncode,denied.stdout,denied.stderr),(77,b'',b''))


if __name__ == '__main__':
    if sys.argv[1:] == ['--acceptance'] or (len(sys.argv) == 3 and sys.argv[1] == '--ordinary'):
        try:
            if sys.argv[1] == '--acceptance': live()
            else: ordinary(sys.argv[2])
        except Exception as error:
            # Closed categories only: no raw child output, query names or paths.
            category = error.category if isinstance(error,base.Refused) else (
                str(error) if isinstance(error,RuntimeError) and str(error) in ROOT_FAILURES else
                'timeout' if isinstance(error,subprocess.TimeoutExpired) else 'unexpected')
            print('FAIL gost-system-dns category='+category,flush=True); raise SystemExit(1)
    else: unittest.main()
