"""Two-phase release stays draft until exact local artifacts verify."""
from pathlib import Path
import os
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release.yml"
VERIFY = ROOT / "app/verify-release-candidate.sh"


class ReleaseWorkflowGateTests(unittest.TestCase):
    def test_prepare_creates_only_a_draft_and_finalize_publishes_last(self):
        source = WORKFLOW.read_text()
        self.assertIn("- prepare\n          - finalize", source)
        self.assertIn("Create the draft only", source)
        self.assertIn("--verify-tag --draft", source)
        self.assertNotIn("gh release upload", source)
        self.assertNotIn("--clobber", source)
        publish = 'gh release edit "$RELEASE_TAG" --draft=false --latest'
        self.assertIn(publish, source)
        self.assertEqual(source.rstrip().splitlines()[-1].strip(), publish)

    def test_finalize_checks_snapshot_bytes_and_full_candidate(self):
        source = WORKFLOW.read_text()
        required = [
            "assets-before.tsv",
            "verify-release-asset-snapshot.py",
            "gh release download",
            "verify-release-candidate.sh",
            "assets-after.tsv",
            'cmp "$RUNNER_TEMP/assets-before.tsv" "$RUNNER_TEMP/assets-after.tsv"',
            'gh release edit "$RELEASE_TAG" --draft=false --latest',
        ]
        positions = [source.index(value) for value in required]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("SPARKLE_PRIVATE_KEY", source)

    def test_candidate_verifier_is_executable_read_only_and_complete(self):
        self.assertTrue(os.access(VERIFY, os.X_OK))
        source = VERIFY.read_text()
        for required in (
            "verify-companion-artifact", "verify-engine-sources",
            "verify-transition", "--vpn-support-verify-update",
            "verify-update.swift", "/usr/bin/diff -qr",
            "vpn-release-sequence.txt", "Install ProxyPilot + VPN Support.pkg",
            "--vpn-support-verify-first-install", "--vpn-support-first-install",
        ):
            self.assertIn(required, source)
        for forbidden in (
            " sign-transition", " sign-companion", "gh release", "git tag",
            "installer -pkg", "sudo ", "launchctl ",
        ):
            self.assertNotIn(forbidden, source)

    def test_snapshot_allowlist_has_all_nine_fixed_assets(self):
        source = (ROOT / "app/verify-release-asset-snapshot.py").read_text()
        for suffix in (
            ".dmg", ".zip", "appcast.xml", "-vpn-joint.dmg",
            "-vpn-joint.metadata", "-vpn-joint.metadata.sig",
            "-vpn-release.manifest", "-vpn-release.sig",
            "-vpn-engine-sources.tar.gz",
        ):
            self.assertIn(suffix, source)
        self.assertIn('state != "uploaded"', source)
        self.assertIn('sha256:[0-9a-f]{64}', source)


if __name__ == "__main__":
    unittest.main()
