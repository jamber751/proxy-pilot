"""Coordinator uses the actual BoundSocket and codec with fake syscalls only."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from test_vpn_dns_answer_release import ROOT, SOURCES as BASE

SOURCES = BASE + [ROOT/'app/vpn-helper/VPNDNSUpstreamExchange.swift']
CASES = ('udp4', 'udp6', 'tc4', 'tc6', 'oversize', 'init-pure', 'binding-uuid', 'binding-generation',
         'binding-revision', 'binding-host', 'unsupported-version', 'malformed', 'malformed-tc',
         'transport', 'tcp-tc', 'tcp-malformed', 'single-budget', 'original-deadline',
         'expired', 'pre-cancel', 'cancel-allocation', 'cancel-udp-poll', 'cancel-tcp-poll',
         'cancel-partial', 'cancel-tcp-read-poll', 'revoked', 'interface-dead', 'partial', 'poll-retry', 'poll-cancel-retry',
         'slow-positive', 'expired-positive', 'slow-negative', 'expired-negative',
         'one-shot', 'reentrant', 'concurrent', 'close-busy',
         'server-error', 'authority-overrun', 'cancel-tcp-allocation', 'poll-timeout', 'poll-zero-ready',
         'udp-aaaa', 'tc-aaaa', 'tcp-client')

@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS SDK required')
class DNSUpstreamExchangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-dns-exchange-pure-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name)/'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-target',arch+'-apple-macosx11.0',
            *map(str,SOURCES),str(ROOT/'tests/vpn_dns_upstream_exchange_checks.swift'),'-o',str(cls.binary)],
            capture_output=True,text=True,timeout=120)
        if result.returncode: raise AssertionError(result.stderr)
    def case(self, mode):
        result = subprocess.run([str(self.binary),mode],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(result.stdout,'pure bound DNS exchange checks passed\n')

for case in CASES:
    setattr(DNSUpstreamExchangeTests,'test_'+case.replace('-','_'),lambda self,case=case:self.case(case))
if __name__ == '__main__': unittest.main()
