"""Fixed-name bounded fetch and VPN-key verification of companion sidecars."""
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
class VPNCompanionMetadataFetcherTests(unittest.TestCase):
    def test_native_two_sidecar_fetch_signature_and_binding(self):
        with tempfile.TemporaryDirectory(prefix="pp-metadata-fetch-") as temporary:
            binary = Path(temporary) / "checks"
            names = ["VPNPeerAuthentication", "VPNReleaseAuthorization",
                     "VPNReleaseTrust", "VPNCompanionMetadata",
                     "VPNCompanionMetadataFetcher"]
            built = subprocess.run([
                "swiftc", "-parse-as-library", "-D",
                "VPN_COMPANION_METADATA_FETCHER_TESTING",
                "-target", "arm64-apple-macosx11.0",
                "-module-cache-path", str(Path(temporary) / "ModuleCache"),
                *[str(HELPER / f"{name}.swift") for name in names],
                str(ROOT / "tests/vpn_companion_metadata_fetcher_checks.swift"),
                "-o", str(binary),
            ], capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            checked = subprocess.run([str(binary)], capture_output=True,
                                     text=True, timeout=60)
            self.assertEqual(checked.returncode, 0,
                             checked.stdout + checked.stderr)
            self.assertEqual(checked.stdout.strip(),
                             "vpn companion metadata fetcher checks passed")

    def test_wire_still_has_no_transport_or_vpn_authority(self):
        wire = (ROOT / "app/update-worker/UpdateWire.swift").read_text()
        self.assertIn("jointReleaseID", wire)
        for forbidden in ('"artifactURL"', '"downloadURL"', '"sha256"',
                          '"artifactBytes"', '"fromSequence"', '"toSequence"',
                          '"path"', '"destination"'):
            self.assertNotIn(forbidden, wire)


if __name__ == "__main__":
    unittest.main()
