"""Pure signed VPN update-transition verification; no root, Keychain, VPN, or network."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("swiftc"), "macOS Swift required")
class VPNUpdateTransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="proxypilot-vpn-transition-")
        cls.addClassCleanup(cls.build.cleanup)
        directory = Path(cls.build.name)
        sources = [ROOT / "app/vpn-helper/VPNPeerAuthentication.swift",
                   ROOT / "app/vpn-helper/VPNReleaseAuthorization.swift",
                   ROOT / "tests/vpn_update_transition_checks.swift"]
        slices = []
        for arch in ("arm64", "x86_64"):
            output = directory / arch
            module_cache = directory / f"module-cache-{arch}"
            result = subprocess.run(
                ["swiftc", "-target", f"{arch}-apple-macosx11.0",
                 "-module-cache-path", str(module_cache), *map(str, sources), "-o", str(output)],
                capture_output=True, text=True, timeout=90)
            if result.returncode:
                raise AssertionError(result.stderr)
            slices.append(str(output))
        cls.binary = directory / "transition-checks"
        subprocess.run(["lipo", "-create", *slices, "-output", str(cls.binary)],
                       check=True, capture_output=True, timeout=10)

    def check(self, group):
        result = subprocess.run([str(self.binary), group], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("checks passed", result.stdout)

    def test_exact_transition_and_opaque_matching(self): self.check("valid")
    def test_transition_signature_domain_key_and_limits(self): self.check("signature")
    def test_canonical_record_and_signed_alternate_fields(self): self.check("grammar")
    def test_source_destination_substitution_and_replay(self): self.check("substitution")
    def test_candidate_inherits_all_release_advancement_rules(self): self.check("candidate")
    def test_source_authority_and_trust_floor_behavior(self): self.check("authority")


if __name__ == "__main__":
    unittest.main()
