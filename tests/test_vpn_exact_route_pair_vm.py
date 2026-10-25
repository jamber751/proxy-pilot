"""Unprivileged compile/deny by default. Two-route viability experiment ONLY
in an explicitly opted-in fresh root GHA VM. No forwarding/no-leak claim.
"""
from pathlib import Path
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'tests/vpn_exact_route_pair_vm.c'
FLAG = 'PROXYPILOT_VM_EXACT_ROUTE_PAIR'


def compile_probe(folder):
    folder = Path(folder)
    captured = SOURCE.read_bytes(); snapshot = folder / SOURCE.name
    snapshot.write_bytes(captured)
    if SOURCE.read_bytes() != captured: raise AssertionError('Route experiment source changed')
    paths = []
    for arch in ('arm64', 'x86_64'):
        output = folder / arch
        subprocess.run(['/usr/bin/clang', '-Wall', '-Wextra', '-Werror', '-target', arch + '-apple-macosx11.0',
                        str(snapshot), '-o', str(output)], check=True, capture_output=True, timeout=30)
        paths.append(str(output))
    output = folder / 'probe'
    subprocess.run(['/usr/bin/lipo', '-create', *paths, '-output', str(output)], check=True, capture_output=True, timeout=10)
    (folder / 'source.sha256').write_text(hashlib.sha256(captured).hexdigest() + '\n')
    return output


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('clang') and os.geteuid() != 0,
                     'Ordinary macOS compiler required')
class PureTests(unittest.TestCase):
    def test_both_architectures_compile_and_ordinary_host_refuses_before_route_io(self):
        with tempfile.TemporaryDirectory(prefix='pp-route-pair-compile-') as folder:
            binary = compile_probe(folder)
            for environment in ({'PATH': '/usr/bin:/bin'},
                                {'GITHUB_ACTIONS': 'true', FLAG: '1', 'PATH': '/usr/bin:/bin'}):
                result = subprocess.run([str(binary)], capture_output=True, env=environment, timeout=5)
                self.assertEqual(result.returncode, 77)
                self.assertEqual(result.stdout, b''); self.assertEqual(result.stderr, b'')


def acceptance():
    if not (sys.platform == 'darwin' and os.getuid() == os.geteuid() == 0
            and os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get(FLAG) == '1'):
        raise SystemExit(77)
    with tempfile.TemporaryDirectory(prefix='pp-route-pair-vm-', dir=os.environ['RUNNER_TEMP']) as folder:
        binary = compile_probe(folder)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30,
            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'GITHUB_ACTIONS': 'true', FLAG: '1'})
        # The executable emits only fixed phase markers and booleans.
        print(result.stdout, end=''); print(result.stderr, end='', file=sys.stderr)
        if result.returncode != 0: raise SystemExit(1)
        if result.stdout.splitlines() != ['PASS exact-route-pair-ipv4', 'PASS exact-route-pair-ipv6']:
            raise SystemExit(1)


if __name__ == '__main__':
    if sys.argv[1:] == ['--acceptance']: acceptance()
    else: unittest.main()
