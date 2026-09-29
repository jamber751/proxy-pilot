"""Bounded cleanup contract for the root-private Broker namespace."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "app/vpn-helper"


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("swiftc"),
                     "macOS Swift required")
class VPNUpdateBrokerStateRemovalTests(unittest.TestCase):
    def test_refusals_and_partial_inbox_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="pp-broker-remove-build-") as temporary:
            binary = Path(temporary) / "checks"
            sources = [
                HELPER / "VPNLifecycleOwnership.swift",
                HELPER / "VPNUpdateBrokerInbox.swift",
                HELPER / "VPNUpdateBrokerStateRemoval.swift",
                ROOT / "tests/vpn_update_broker_state_removal_checks.swift",
            ]
            built = subprocess.run(
                ["swiftc", "-target", "arm64-apple-macosx11.0",
                 "-module-cache-path", str(Path(temporary) / "ModuleCache"),
                 *map(str, sources), "-o", str(binary)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            for case in ("unknown", "symlink", "mode", "partial"):
                with self.subTest(case=case):
                    result = subprocess.run([str(binary), case], capture_output=True,
                                            text=True, timeout=60)
                    self.assertEqual(result.returncode, 0,
                                     result.stdout + result.stderr)
                    self.assertEqual(result.stdout.strip(), f"{case} check passed")


if __name__ == "__main__":
    unittest.main()
