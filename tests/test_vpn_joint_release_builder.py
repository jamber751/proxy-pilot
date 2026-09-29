"""Fail-closed local assembly contract; never invokes the signing script."""
from pathlib import Path
import os
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "app/build-joint-release.sh"


class VPNJointReleaseBuilderTests(unittest.TestCase):
    def test_shell_syntax_and_no_external_mutation(self):
        result = subprocess.run(["zsh", "-n", str(SCRIPT)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        source = SCRIPT.read_text()
        for forbidden in ("gh release", "git tag", "git push", "installer ",
                          "sudo ", "launchctl "):
            self.assertNotIn(forbidden, source)
        self.assertIn("No tag, upload, installation or system change", source)

    def test_exact_sequence_key_and_artifact_chain(self):
        source = SCRIPT.read_text()
        required = [
            '"$KEY_TOOL" public',
            '"$KEY_TOOL" verify "$PREVIOUS_MANIFEST"',
            "PROXYPILOT_VPN_RELEASE_SEQUENCE=\"$SEQUENCE\"",
            "vpn-package/package.py\" prepare",
            '"$KEY_TOOL" sign ',
            "prepare-update",
            "sign-transition",
            "build-companion",
            "prepare-companion-metadata",
            "sign-companion",
            "verify-companion-artifact",
        ]
        positions = [source.index(value) for value in required]
        self.assertEqual(positions, sorted(positions))

    def test_script_is_executable_and_output_is_no_overwrite(self):
        self.assertTrue(os.access(SCRIPT, os.X_OK))
        source = SCRIPT.read_text()
        self.assertIn('! -e "$OUTPUT" && ! -L "$OUTPUT"', source)
        self.assertIn('mkdir -m 700 "$OUTPUT"', source)
        self.assertNotIn("--clobber", source)


if __name__ == "__main__":
    unittest.main()
