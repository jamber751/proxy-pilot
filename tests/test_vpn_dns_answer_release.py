"""Pure DNS parser/release ordering; no sockets, interfaces, DNS, or root APIs."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [ROOT / 'app/VPNConfiguration.swift'] + [ROOT / 'app/vpn-helper' / name for name in (
    'OpenVPNManagementEvent.swift', 'OpenVPNStateEvidence.swift', 'VPNKernelInterfaceSnapshot.swift',
    'VPNTunnelInterfaceResolver.swift', 'VPNRoutePlan.swift', 'VPNRouteJournal.swift',
    'VPNDarwinRouteSocket.swift', 'VPNRouteTransaction.swift', 'VPNDNSPlan.swift',
    'VPNDomainNetworkPlan.swift', 'VPNLifecycleOwnership.swift', 'VPNBoundDNSUpstreamSocket.swift', 'VPNDNSContinuousClock.swift', 'VPNDNSAnswerCodec.swift', 'VPNDNSAnswerRelease.swift')]
CASES = ('a', 'aaaa', 'multi', 'cname', 'compression', 'ttl', 'zero-ttl', 'bounds',
         'question', 'headers', 'pointer-loop', 'pointer-foreign', 'malformed',
         'alias-cycle', 'alias-conflict', 'alias-depth', 'unrelated', 'family',
         'negative', 'sections', 'release', 'foreign-permit', 'other-answer',
         'revoked', 'late', 'checkpoint-failure', 'output-failure', 'one-shot',
         'lease-required', 'lease-repeat', 'deadline-during-check', 'changed-resource',
         'crash-after-checkpoint', 'deny-unknown', 'route-unknown', 'revoke-before-output',
         'wrong-route-permit', 'ttl-high-bit', 'rrset-ttl', 'compressed-cname',
         'generation', 'revision', 'mutated-corpus', 'lease-concurrent',
         'lease-suppressed-output-error', 'lease-suppressed-check-error',
         'client-remap', 'client-rd', 'client-case', 'client-domain-boundary', 'client-flags',
         'client-sections', 'client-types', 'client-bounds', 'client-release',
         'negative-nxdomain', 'negative-nodata', 'negative-cname', 'negative-wrong-zone',
         'negative-label-suffix', 'negative-no-soa', 'negative-referral', 'negative-soa-plus-ns',
         'negative-duplicate-soa', 'negative-positive-conflict', 'negative-compressed-soa',
         'negative-root-binary', 'negative-rdata-short', 'negative-rdata-tail',
         'negative-rdata-pointer', 'negative-rdata-count', 'negative-ttl', 'negative-high-bit',
         'negative-ttl-zero', 'negative-aging', 'negative-upstream-errors', 'negative-error-tail',
         'negative-error-sections', 'negative-unknown-rcode', 'negative-error-origin',
         'negative-release', 'negative-release-revoke', 'negative-release-required',
         'negative-release-fence', 'negative-checkpoint-crash', 'negative-late',
         'negative-mixed-zero-ttl', 'negative-expiry-overflow',
         'edns-question', 'edns-privacy', 'edns-z-bits', 'edns-payload', 'edns-client-version',
         'edns-badvers-lease', 'edns-upstream-version', 'edns-extended-rcode', 'edns-legacy-opt',
         'edns-legacy-upstream', 'edns-dnssec', 'edns-root-type', 'edns-query-extended',
         'edns-duplicate', 'edns-tlv-truncation', 'edns-option-count', 'edns-query-bound',
         'edns-tail', 'edns-slice', 'edns-udp-boundary', 'edns-legacy-boundary',
         'edns-tcp-independent', 'edns-upstream-tc', 'edns-upstream-oversize',
         'edns-tc-provenance', 'edns-leased-tc', 'edns-tc-revoked', 'edns-negative-opt', 'edns-inspect-complete',
         'edns-small-payload', 'edns-large-negative', 'edns-query-ad',
         'edns-response-do-positive', 'edns-response-do-error',
         'edns-response-do-negative', 'edns-response-do-lease')
CASES += ('sleep-ttl','sleep-negative-ttl','sleep-current','sleep-deny','sleep-routes','sleep-verify',
          'sleep-outputIssued','sleep-verified','sleep-zero-query','clock-release-failed','clock-release-backwards','clock-release-checkpoint-failed')

CASES += ('client-domain-descendants', 'client-domain-answer-boundary', 'client-domain-negative', 'client-domain-error', 'client-domain-badvers')


def snapshot_inputs(folder, inputs):
    folder = Path(folder) / 'Sources'
    captured = [(Path(path), Path(path).read_bytes()) for path in inputs]
    if any(path.read_bytes() != data for path, data in captured):
        raise AssertionError('DNS source changed during capture')
    result = []
    for path, data in captured:
        target = folder / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data); result.append(str(target))
    return result


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNDNSAnswerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-dns-answer-pure-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        inputs = snapshot_inputs(Path(cls.temp.name), [*SOURCES, ROOT / 'tests/vpn_dns_answer_release_checks.swift'])
        result = subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-target',
            arch + '-apple-macosx11.0', *inputs, '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, case):
        result = subprocess.run([str(self.binary), case], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'pure DNS answer checks passed\n')

for case in CASES:
    setattr(VPNDNSAnswerTests, 'test_' + case.replace('-', '_'),
            lambda self, case=case: self.run_case(case))

if __name__ == '__main__': unittest.main()
