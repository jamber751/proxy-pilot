"""Static domain/upstream route groundwork, private fake interfaces only."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNDomainNetworkPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-domain-network-plan-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        sources = [ROOT / 'app/VPNConfiguration.swift'] + [ROOT / 'app/vpn-helper' / name for name in (
            'OpenVPNManagementEvent.swift', 'OpenVPNStateEvidence.swift', 'VPNKernelInterfaceSnapshot.swift',
            'VPNTunnelInterfaceResolver.swift', 'VPNRoutePlan.swift', 'VPNRouteJournal.swift',
            'VPNDarwinRouteSocket.swift', 'VPNRouteTransaction.swift', 'VPNDNSPlan.swift', 'VPNDomainNetworkPlan.swift')]
        result = subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-D', 'VPN_ROUTE_TRANSACTION_TESTING',
                                 '-target', arch + '-apple-macosx11.0', *map(str, sources),
                                 str(ROOT / 'tests/vpn_domain_network_plan_checks.swift'), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'domain network groundwork passed\n')

    def test_both_families_and_physical_peer_bypass(self): self.run_case('hosts')
    def test_configured_prefixes_cover_planned_upstreams_without_overlap(self): self.run_case('coverage')
    def test_exact_host_identity_and_deterministic_input_order(self): self.run_case('identity')
    def test_peer_bypass_is_never_tunnel_dns_coverage(self): self.run_case('peer-conflict')
    def test_invalid_inputs_and_prefix_overlaps_are_refused(self): self.run_case('invalid')
    def test_unproven_or_physical_tunnel_interface_is_refused(self): self.run_case('interface')
    def test_exact_applied_proof_binding_and_preserved_peer(self): self.run_case('proof')
    def test_input_and_derived_route_capacity_boundaries(self): self.run_case('capacity')

    def test_new_source_has_no_system_adapter_or_runtime_gate_wiring(self):
        source = (ROOT / 'app/vpn-helper/VPNDomainNetworkPlan.swift').read_text()
        for forbidden in ('import SystemConfiguration', 'SCDynamicStore', 'socket(', 'getaddrinfo(',
                          'DNSService', 'Process(', 'posix_spawn', 'markConnected', 'releaseHold',
                          'VPNDarwinRouteSocket(', 'capture()', 'validateCurrentRuntimeCapability'):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
