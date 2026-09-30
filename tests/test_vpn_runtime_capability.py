"""The route-only build must reject split-DNS intent before process launch."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNRuntimeCapabilityTests(unittest.TestCase):
    def test_route_only_runtime_scope_is_explicit(self):
        with tempfile.TemporaryDirectory(prefix='pp-vpn-capability-', dir='/tmp') as folder:
            binary = Path(folder) / 'checks'
            arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
            result = subprocess.run([
                'swiftc', '-target', f'{arch}-apple-macosx11.0',
                str(ROOT / 'app/VPNConfiguration.swift'),
                str(ROOT / 'app/vpn-helper/VPNApplicationSpec.swift'),
                str(ROOT / 'tests/vpn_runtime_capability_checks.swift'),
                '-o', str(binary),
            ], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), 'runtime capability gate passed')

    def test_production_coordinator_checks_before_profile_open(self):
        source = (ROOT / 'app/vpn-helper/VPNTunnelCoordinator.swift').read_text()
        capability = source.index('validateCurrentRuntimeCapability()')
        ready = source.index('return .ready(generation:', capability)
        self.assertLess(capability, ready)
        self.assertIn('return .blocked(.splitDNSUnavailable)', source[capability:ready])


if __name__ == '__main__':
    unittest.main()
