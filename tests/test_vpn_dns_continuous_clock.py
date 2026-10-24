"""Pure injected clock/strong-type checks; no native time/sleep/network APIs."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from test_vpn_dns_answer_release import ROOT, snapshot_inputs

CLOCK = ROOT/'app/vpn-helper/VPNDNSContinuousClock.swift'

@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class ContinuousClockTests(unittest.TestCase):
    def test_public_raw_reader_is_injected_and_checked_without_constructor_io(self):
        with tempfile.TemporaryDirectory(prefix='pp-dns-clock-pure-') as folder:
            binary=Path(folder)/'checks'
            inputs=snapshot_inputs(folder,[CLOCK,ROOT/'tests/vpn_dns_continuous_clock_checks.swift'])
            subprocess.run(['/usr/bin/swiftc','-parse-as-library',*inputs,'-o',str(binary)],check=True,capture_output=True,timeout=60)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(0,'pure continuous DNS clock checks passed\n',''))

    def test_raw_uint64_and_continuous_to_dispatch_conversion_are_compile_errors(self):
        with tempfile.TemporaryDirectory(prefix='pp-dns-clock-brand-') as folder:
            path=Path(folder)/'rejected.swift'
            clock=snapshot_inputs(folder,[CLOCK])[0]
            for text in ('func rejected(_ raw: UInt64) -> VPNDNSContinuousInstant { raw }',
                         'import Dispatch\nfunc rejected(_ time: VPNDNSContinuousInstant) -> DispatchTime { DispatchTime(uptimeNanoseconds: time) }'):
                path.write_text(text)
                result=subprocess.run(['/usr/bin/swiftc','-typecheck',clock,str(path)],capture_output=True,text=True,timeout=60)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('cannot convert',result.stderr)
