"""Default is compile/guards/pure packet checks ONLY; no local socket/if APIs.

--acceptance is explicitly opted-in fresh GitHub root VM only. The probe owns
two autoallocated utuns and documentation-address host routes, never existing
interfaces/default routes/DNS/PF. It leaves an EXPECTED protected dead-interface
route journal + receipt marker until disposable VM destruction. This Python
driver NEVER recursively removes a live namespace, on success or failure.
TCP is first-SYN selection only; lifecycle cancellation and complete no-leak /
fail-closed / resolver / answer-interposition acceptance remain OPEN.
"""
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
FLAG = 'PROXYPILOT_VM_DNS_UTUN_TESTS'
SWIFT = ROOT / 'tests/vpn_dns_utun_vm_checks.swift'
C_SOURCE = ROOT / 'tests/vpn_dns_utun_vm_support.c'


def allowed(uid, euid, environment):
    return uid == euid == 0 and environment.get('GITHUB_ACTIONS') == 'true' and environment.get(FLAG) == '1'


def compile_tool(folder, arch=None):
    arch = arch or ('arm64' if platform.machine() == 'arm64' else 'x86_64')
    target = arch + '-apple-macosx11.0'
    support = folder / ('support-' + arch + '.o')
    binary = folder / ('utun-checks-' + arch)
    subprocess.run(['/usr/bin/clang', '-target', target, '-Wall', '-Wextra', '-Werror',
                    '-c', str(C_SOURCE), '-o', str(support)], check=True, capture_output=True, text=True, timeout=30)
    names = ['OpenVPNManagementEvent.swift', 'OpenVPNStateEvidence.swift', 'VPNKernelInterfaceSnapshot.swift',
             'VPNTunnelInterfaceResolver.swift', 'VPNRoutePlan.swift', 'VPNRouteJournal.swift',
             'VPNDarwinRouteSocket.swift', 'VPNRouteTransaction.swift', 'VPNDNSPlan.swift',
             'VPNDomainNetworkPlan.swift', 'VPNLifecycleOwnership.swift', 'VPNBoundDNSUpstreamSocket.swift']
    sources = [ROOT/'app/VPNConfiguration.swift', *[ROOT/'app/vpn-helper'/name for name in names], SWIFT]
    # No TESTING flags in any production source or native probe.
    subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-target', target, *map(str, sources), str(support),
                    '-o', str(binary)], check=True, capture_output=True, text=True, timeout=120)
    return binary


PASS_MARKERS = {
    'production-configure-SIGPIPE-baseline-13-protected-EPIPE',
    'live-A-complete-route-cleanup-B-foreign-tables-preserved',
    'actual-child-SIGKILL-checkpoint-recovery-B-preserved',
    'A-death-rejected-both-families-no-own-B-nonce',
    'dead-interface-recovery-blocked-receipt-preserved',
    'B-baseline-exact-cleanup-owned-utuns-gone',
    'protected-pending-receipt-only-until-VM-disposal',
} | {transport + family + scope + ('-own-nonce-DNS-exchange' if transport == 'udp' else '-own-first-SYN-only')
     for family in ('4', '6') for transport in ('udp', 'tcp') for scope in ('n', 'b', 'a')}


def live(binary):
    if not allowed(os.getuid(), os.geteuid(), os.environ):
        raise RuntimeError('guardDenied')
    process = subprocess.Popen([str(binary), '--acceptance', str(uuid.uuid4())],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    timed_out = False
    try:
        output, _ = process.communicate(timeout=360)
    except subprocess.TimeoutExpired:
        # Only our own newly-created process group, including owned probe children.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        output, _ = process.communicate(timeout=5)
        timed_out = True
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=5)
    lines = output.splitlines()
    # Never print raw child stderr, packets, nonce names, interface names, paths
    # or any host state. Numeric diagnostics are only exact owned fixture keys.
    for line in lines:
        if line.startswith('PASS ') and line[5:] in PASS_MARKERS:
            print(line)
        elif re.fullmatch(r'API ownRoute expectedFlags=\d+ observedFlags=\d+ expectedIndex=\d+ observedIndex=\d+', line):
            print(line)
        elif re.fullmatch(r'API utun errno=\d+', line):
            print(line)
        elif re.fullmatch(r'FAIL (guardDenied|arguments|namespace|context|interface|address|route|packet|path|child|timeout|sourcePort|sigpipe|receipt|cleanup|upstream|routeAPI|unexpected)( errno=\d+)?', line):
            print(line)
        else:
            raise RuntimeError('outputProtocol')
    if timed_out:
        raise RuntimeError('ownerTimeout')
    if process.returncode:
        raise RuntimeError('ownerFailure')
    if set(lines) != {'PASS ' + marker for marker in PASS_MARKERS} or len(lines) != len(PASS_MARKERS):
        raise RuntimeError('missingProof')


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc') and shutil.which('clang'), 'macOS SDK required')
class PureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(prefix='pp-dns-utun-pure-build-')
        cls.addClassCleanup(cls.folder.cleanup)
        cls.binary = compile_tool(Path(cls.folder.name))

    def test_pure_sdk_packet_encoding_checksums_and_guard_truth_table(self):
        result = subprocess.run([str(self.binary), '--pure-checks'], env={}, capture_output=True, text=True, timeout=10)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, 'PASS pure-guards-packets-checksums\n', ''))

    def test_all_live_roles_refuse_local_or_ordinary_user_before_any_live_api(self):
        environments = [{}, {'GITHUB_ACTIONS': 'true'}, {FLAG: '1'}]
        if os.getuid() != 0 and os.geteuid() != 0:
            environments.append({'GITHUB_ACTIONS': 'true', FLAG: '1'})
        run = str(uuid.uuid4())
        roles = [['--acceptance', run], ['--operation', run, '4', 'udp', 'a'], ['--crash', run],
                 ['--death', run], ['--sigpipe-baseline'], ['--sigpipe-protected']]
        for environment in environments:
            for arguments in roles:
                result = subprocess.run([str(self.binary), *arguments], env=environment, capture_output=True, text=True, timeout=10)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (1, 'FAIL guardDenied\n', ''))

    def test_python_gate_refuses_before_child_or_compiler(self):
        complete = {'GITHUB_ACTIONS': 'true', FLAG: '1'}
        self.assertTrue(allowed(0, 0, complete))
        for ids in [(501, 501), (0, 501), (501, 0)]:
            self.assertFalse(allowed(*ids, complete))
        for missing in ({}, {'GITHUB_ACTIONS': 'true'}, {FLAG: '1'}):
            self.assertFalse(allowed(0, 0, missing))
        with patch.dict(os.environ, {}, clear=True), patch('subprocess.Popen') as child:
            with self.assertRaisesRegex(RuntimeError, '^guardDenied$'):
                live(None)
            child.assert_not_called()


if __name__ == '__main__':
    if sys.argv[1:] == ['--acceptance']:
        if not allowed(os.getuid(), os.geteuid(), os.environ):
            print('FAIL guardDenied'); sys.exit(1)
        try:
            with tempfile.TemporaryDirectory(prefix='pp-dns-utun-live-build-') as folder:
                live(compile_tool(Path(folder)))
        except Exception as error:
            category = str(error)
            print('FAIL ' + (category if category in {'guardDenied', 'ownerTimeout', 'ownerFailure', 'outputProtocol', 'missingProof'} else 'unexpected'))
            sys.exit(1)
    else:
        unittest.main()
