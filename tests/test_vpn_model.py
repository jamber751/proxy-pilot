"""Compile and exercise the VPN UI model against disposable local stores."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNModelTests(unittest.TestCase):
    def test_model_state_and_persistence(self):
        with tempfile.TemporaryDirectory(prefix='proxypilot-vpn-model-build-') as build_dir:
            binary = Path(build_dir) / 'vpn-model-checks'
            sources = [ROOT / 'app' / name for name in (
                'VPNConfiguration.swift', 'VPNProfileImporter.swift', 'VPNStore.swift', 'VPNModel.swift'
            )]
            built = subprocess.run([
                'swiftc', '-target',
                'arm64-apple-macosx11.0' if platform.machine() == 'arm64' else 'x86_64-apple-macosx11.0',
                *map(str, sources), str(ROOT / 'tests/vpn_model_checks.swift'), '-o', str(binary)
            ], capture_output=True, text=True, timeout=90)
            self.assertEqual(built.returncode, 0, built.stderr)
            with tempfile.TemporaryDirectory(prefix='proxypilot-vpn-model-state-') as state_dir:
                result = subprocess.run([str(binary), state_dir], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('vpn-model:', result.stdout)
            self.assertIn('checks passed', result.stdout)


if __name__ == '__main__':
    unittest.main()
