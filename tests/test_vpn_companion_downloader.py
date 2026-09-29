"""Ephemeral bounded HTTPS transport into descriptor-only staging."""
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
class VPNCompanionDownloaderTests(unittest.TestCase):
    def test_native_transport_failures_and_redirect_policy(self):
        with tempfile.TemporaryDirectory(prefix="pp-companion-download-") as temporary:
            binary = Path(temporary) / "checks"
            sources = [
                "VPNPeerAuthentication", "VPNReleaseAuthorization",
                "VPNReleaseTrust", "VPNCompanionMetadata",
                "VPNCompanionStaging", "VPNCompanionDownloader",
            ]
            built = subprocess.run([
                "swiftc", "-parse-as-library", "-D",
                "VPN_COMPANION_DOWNLOADER_TESTING",
                "-target", "arm64-apple-macosx11.0",
                "-module-cache-path", str(Path(temporary) / "ModuleCache"),
                *[str(HELPER / f"{name}.swift") for name in sources],
                str(ROOT / "tests/vpn_companion_downloader_checks.swift"),
                "-o", str(binary),
            ], capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            checked = subprocess.run([str(binary)], capture_output=True,
                                     text=True, timeout=60)
            self.assertEqual(checked.returncode, 0,
                             checked.stdout + checked.stderr)
            self.assertEqual(checked.stdout.strip(),
                             "vpn companion downloader checks passed")

    def test_production_session_is_ephemeral_and_has_no_custom_trust(self):
        source = (HELPER / "VPNCompanionDownloader.swift").read_text()
        for required in (
            "URLSessionConfiguration.ephemeral", "urlCache = nil",
            "httpCookieStorage = nil", "urlCredentialStorage = nil",
            'host == "github.com"',
            'host == "release-assets.githubusercontent.com"',
            'setValue("identity", forHTTPHeaderField: "Accept-Encoding")',
        ):
            self.assertIn(required, source)
        for forbidden in ("didReceive challenge", "serverTrust", "http://"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
