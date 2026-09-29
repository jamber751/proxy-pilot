"""Descriptor-only bounded local staging for a verified companion image."""
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
class VPNCompanionStagingTests(unittest.TestCase):
    def test_streaming_bounds_hash_descriptor_and_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="pp-companion-staging-") as temporary:
            binary = Path(temporary) / "checks"
            result = subprocess.run([
                "swiftc", "-parse-as-library", "-target", "arm64-apple-macosx11.0",
                "-module-cache-path", str(Path(temporary) / "ModuleCache"),
                str(HELPER / "VPNPeerAuthentication.swift"),
                str(HELPER / "VPNReleaseAuthorization.swift"),
                str(HELPER / "VPNReleaseTrust.swift"),
                str(HELPER / "VPNCompanionMetadata.swift"),
                str(HELPER / "VPNCompanionStaging.swift"),
                str(ROOT / "tests/vpn_companion_staging_checks.swift"),
                "-o", str(binary),
            ], capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            checked = subprocess.run([str(binary)], capture_output=True,
                                     text=True, timeout=30)
            self.assertEqual(checked.returncode, 0,
                             checked.stdout + checked.stderr)
            self.assertEqual(checked.stdout.strip(),
                             "vpn companion staging checks passed")

    def test_public_result_exposes_only_a_borrowed_descriptor(self):
        source = (HELPER / "VPNCompanionStaging.swift").read_text()
        result = source[source.index("final class VPNDownloadedCompanion"):]
        result = result[:result.index("final class VPNCompanionStaging")]
        self.assertIn("withFileDescriptor", result)
        for forbidden in ("var path", "func path", "var url", "func url"):
            self.assertNotIn(forbidden.lower(), result.lower())


if __name__ == "__main__":
    unittest.main()
