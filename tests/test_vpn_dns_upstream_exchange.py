"""Coordinator uses the actual BoundSocket and codec with fake syscalls only."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from test_vpn_dns_answer_release import ROOT, SOURCES as BASE, snapshot_inputs

SOURCES = BASE + [ROOT/'app/vpn-helper/VPNDNSUpstreamExchange.swift']
CASES = ('udp4', 'udp6', 'tc4', 'tc6', 'oversize', 'init-pure', 'binding-uuid', 'binding-generation',
         'binding-revision', 'binding-host', 'unsupported-version', 'malformed', 'malformed-tc',
         'transport', 'tcp-tc', 'tcp-malformed', 'single-budget', 'original-deadline',
         'expired', 'pre-cancel', 'cancel-allocation', 'cancel-udp-poll', 'cancel-tcp-poll',
         'cancel-partial', 'cancel-tcp-read-poll', 'revoked', 'interface-dead', 'partial', 'poll-retry', 'poll-cancel-retry',
         'slow-positive', 'expired-positive', 'slow-negative', 'expired-negative',
         'one-shot', 'reentrant', 'concurrent', 'close-busy',
         'server-error', 'authority-overrun', 'cancel-tcp-allocation', 'poll-timeout', 'poll-zero-ready',
         'udp-aaaa', 'tc-aaaa', 'tcp-client',
         'halfclose-tcp', 'halfclose-header-eof', 'halfclose-body-eof', 'halfclose-bare', 'halfclose-err',
         'halfclose-nval', 'halfclose-write', 'halfclose-connect', 'halfclose-revoked', 'halfclose-dead',
         'halfclose-cancel', 'halfclose-postproof', 'halfclose-udp',
         'distinct-epochs', 'pair-conservative', 'sleep-before-authority', 'sleep-after-receive', 'sleep-between-legs',
         'sleep-udp-poll', 'sleep-tcp-poll', 'sleep-tcp-connect', 'clock-fail-initial', 'clock-fail-poll',
         'clock-backwards-poll', 'clock-uptime-backwards', 'clock-fail-allocation', 'clock-pair-backwards', 'clock-pair-sleep', 'sleep-original-deadline', 'clock-backwards-in-window')

CASES += ('selection-ancestor-refused', 'selection-child', 'selection-root', 'selection-stale-child', 'selection-removed-child-falls-back')

@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS SDK required')
class DNSUpstreamExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-dns-exchange-pure-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name)/'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        inputs = snapshot_inputs(Path(cls.temp.name), [*SOURCES, ROOT/'tests/vpn_dns_upstream_exchange_checks.swift'])
        result = subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-target',arch+'-apple-macosx11.0',
            *inputs,'-o',str(cls.binary)],
            capture_output=True,text=True,timeout=120)
        if result.returncode: raise AssertionError(result.stderr)
    def case(self, mode):
        result = subprocess.run([str(self.binary),mode],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(result.stdout,'pure bound DNS exchange checks passed\n')

for case in CASES:
    setattr(DNSUpstreamExchangeTests,'test_'+case.replace('-','_'),lambda self,case=case:self.case(case))
if __name__ == '__main__': unittest.main()
