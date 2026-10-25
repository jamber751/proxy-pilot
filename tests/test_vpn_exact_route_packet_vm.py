"""Default compile/ordinary-user denial only: NO local network or root calls.
Actual unbound UDP/TCP packet/death proof requires explicit fresh root GHA VM flags.
Boot, WARP, production custody and release acceptance remain separate gates.
"""
from pathlib import Path
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FLAG = 'PROXYPILOT_VM_EXACT_ROUTE_PACKETS'
SUPPORT_FLAG = 'PROXYPILOT_VM_DNS_UTUN_TESTS'
SOURCES = ['vpn_exact_route_packet_vm.c', 'vpn_exact_route_pair_vm.c', 'vpn_dns_utun_vm_support.c']
MARKERS = ['PASS exact-route-udp-ipv4-active-cached-fresh-death-neighbor',
           'PASS exact-route-tcp-ipv4-established-exchange-cached-fresh-death',
           'PASS exact-route-udp-ipv6-active-cached-fresh-death-neighbor',
           'PASS exact-route-tcp-ipv6-established-exchange-cached-fresh-death']


def compile_probe(folder):
    folder = Path(folder)
    captured = {name: (ROOT/'tests'/name).read_bytes() for name in SOURCES}
    for name, data in captured.items(): (folder/name).write_bytes(data)
    paths = []
    for arch in ('arm64', 'x86_64'):
        output = folder/arch
        result = subprocess.run(['/usr/bin/clang', '-Wall', '-Wextra', '-Werror',
            '-target', arch+'-apple-macosx12.0', str(folder/SOURCES[0]), str(folder/SOURCES[2]),
            '-o', str(output)], capture_output=True, text=True, timeout=30)
        if result.returncode: raise AssertionError(result.stderr)
        paths.append(str(output))
    binary = folder/'probe'
    subprocess.run(['/usr/bin/lipo', '-create', *paths, '-output', str(binary)], check=True,
                   capture_output=True, timeout=10)
    if any((ROOT/'tests'/name).read_bytes() != data for name, data in captured.items()):
        raise AssertionError('Source changed during snapshot compile')
    (folder/'source.sha256').write_text(''.join(hashlib.sha256(data).hexdigest()+' '+name+'\n'
                                              for name, data in captured.items()))
    return binary


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('clang') and os.geteuid() != 0,
                     'Ordinary macOS compiler required')
class PureTests(unittest.TestCase):
    def test_both_architectures_and_denial_before_network_even_with_flags(self):
        with tempfile.TemporaryDirectory(prefix='pp-route-packet-compile-') as folder:
            binary = compile_probe(folder)
            pure = subprocess.run([str(binary), '--pure-packets'], capture_output=True, timeout=5,
                                  env={'PATH': '/usr/bin:/bin'})
            self.assertEqual((pure.returncode, pure.stdout, pure.stderr), (0, b'', b''))
            for extra in ({}, {'GITHUB_ACTIONS': 'true', FLAG: '1', SUPPORT_FLAG: '1'}):
                result = subprocess.run([str(binary)], capture_output=True,
                    env={'PATH': '/usr/bin:/bin', **extra}, timeout=5)
                self.assertEqual(result.returncode, 77)
                self.assertEqual(result.stdout, b''); self.assertEqual(result.stderr, b'')


def acceptance():
    if not (sys.platform == 'darwin' and os.getuid() == os.geteuid() == 0 and
            os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get(FLAG) == '1' and
            os.environ.get(SUPPORT_FLAG) == '1'):
        raise SystemExit(77)
    with tempfile.TemporaryDirectory(prefix='pp-route-packet-vm-', dir=os.environ['RUNNER_TEMP']) as folder:
        binary = compile_probe(folder)
        process = subprocess.Popen([str(binary)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'GITHUB_ACTIONS': 'true', FLAG: '1', SUPPORT_FLAG: '1'})
        try:
            out, err = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            # Only this fixture's own process group, including its interface-owning child.
            import signal
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
            raise RuntimeError('ownedProbeTimeout-VM-disposal')
        # Fixed phase names/errno/flags only, no packet/address/nonce/name logging.
        import re
        for line in out.splitlines():
            if line not in MARKERS: raise RuntimeError('unexpectedOutput')
            print(line)
        for line in err.splitlines():
            if not (re.fullmatch(r'FAIL exact-route-pair stage=[A-Za-z]+ errno=[0-9]+ flags=[0-9]+ exact=[01] fullMask=[01]', line)
                    or line == 'FAIL exact-route-udp-unresolved-VM-disposal'):
                raise RuntimeError('unexpectedDiagnostic')
            print(line, file=sys.stderr)
        if process.returncode or out.splitlines() != MARKERS: raise RuntimeError('packetProofIncomplete')


if __name__ == '__main__':
    if sys.argv[1:] == ['--acceptance']: acceptance()
    else: unittest.main()
