"""Production transport logic with fake syscalls/authority/interface table ONLY."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class BoundDNSUpstreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(prefix='pp-bound-dns-upstream-')
        cls.addClassCleanup(cls.folder.cleanup)
        cls.binary = Path(cls.folder.name) / 'checks'
        names = ['OpenVPNManagementEvent.swift', 'OpenVPNStateEvidence.swift', 'VPNKernelInterfaceSnapshot.swift',
                 'VPNTunnelInterfaceResolver.swift', 'VPNRoutePlan.swift', 'VPNRouteJournal.swift',
                 'VPNDarwinRouteSocket.swift', 'VPNRouteTransaction.swift', 'VPNDNSPlan.swift',
                 'VPNDomainNetworkPlan.swift', 'VPNLifecycleOwnership.swift', 'VPNBoundDNSUpstreamSocket.swift']
        sources = [ROOT/'app/VPNConfiguration.swift', *[ROOT/'app/vpn-helper'/name for name in names],
                   ROOT/'tests/vpn_bound_dns_upstream_socket_checks.swift']
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-target', arch+'-apple-macosx11.0',
                                 *map(str, sources), '-o', str(cls.binary)], capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise AssertionError(result.stderr)

    def case(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(result.stdout, 'bound numeric DNS upstream checks passed\n')

    def test_both_families_and_transports_have_bound_exact_endpoint_and_own_close(self): self.case('roundtrip')
    def test_binding_requires_complete_exact_plan_server_generation_and_revision(self): self.case('binding')
    def test_message_bounds_id_qr_and_data_slice_are_checked(self): self.case('messages')
    def test_expired_budget_has_zero_calls_and_busy_does_not_close_active_fd(self): self.case('budget-busy')
    def test_absolute_deadline_caps_io_and_is_not_reset_by_connect_or_retries(self): self.case('deadline')


def add_case(name):
    def run(self): self.case(name)
    setattr(BoundDNSUpstreamTests, 'test_' + name.replace('-', '_'), run)


for mode in ('lease', 'generation', 'revision', 'proof', 'configure', 'bind', 'getBinding', 'socket',
             'interfaces', 'wrong-bound', 'wrong-size', 'authority-overrun', 'authority-after-overrun', 'authority-replay'):
    add_case('setup-' + mode)
for mode in ('lease', 'generation', 'revision', 'proof', 'death', 'index', 'name', 'up', 'running', 'point', 'address', 'bound'):
    add_case('revoke-' + mode)
for mode in ('async', 'again', 'isconn', 'interrupted', 'soerror', 'stale', 'dead', 'bound', 'timeout', 'expired', 'hangup'):
    add_case('connect-' + mode)
for mode in ('udp-eintr', 'udp-again', 'tcp-partial', 'udp-short', 'udp-truncated', 'udp-eof', 'udp-id',
             'udp-qr', 'udp-timeout', 'udp-expired', 'udp-send-error', 'udp-read-error', 'tcp-zero-write',
             'tcp-invalid-frame', 'tcp-eof', 'tcp-revoke-partial', 'udp-revoke-after-read', 'udp-authority-overrun'):
    add_case(mode)


if __name__ == '__main__':
    unittest.main()
