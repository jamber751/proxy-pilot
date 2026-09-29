"""Real read-only DMG mount through the descriptor-only production boundary."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("hdiutil")
                     and shutil.which("swiftc"), "macOS tools required")
class VPNJointArtifactMountTests(unittest.TestCase):
    def test_read_only_fixed_layout_mount(self):
        with tempfile.TemporaryDirectory(prefix="pp-joint-mount-") as temporary:
            root = Path(temporary)
            payload = root / "Payload"
            payload.mkdir(mode=0o700)
            (payload / "ProxyPilot.app").mkdir(mode=0o700)
            names = {
                "vpn-helper", "vpn-engine", "vpn-release.manifest",
                "vpn-release.sig", "vpn-previous-release.manifest",
                "vpn-previous-release.sig", "vpn-update-transition",
                "vpn-update-transition.sig",
            }
            for name in names:
                (payload / name).write_bytes(name.encode())
            image = root / "joint.dmg"
            built = subprocess.run([
                "/usr/bin/hdiutil", "create", "-quiet", "-fs", "APFS",
                "-format", "UDZO", "-srcfolder", str(payload), str(image),
            ], capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            binary = root / "checks"
            compiled = subprocess.run([
                "swiftc", "-target", "arm64-apple-macosx11.0",
                "-module-cache-path", str(root / "ModuleCache"),
                str(ROOT / "app/vpn-helper/VPNJointArtifactMount.swift"),
                str(ROOT / "tests/vpn_joint_artifact_mount_checks.swift"),
                "-o", str(binary),
            ], capture_output=True, text=True, timeout=120)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            result = subprocess.run([str(binary), str(image)], capture_output=True,
                                    text=True, timeout=90)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(),
                             "joint artifact mount check passed")

    def test_source_surface_accepts_only_file_descriptor_and_deadline(self):
        source = (ROOT / "app/vpn-helper/VPNJointArtifactMount.swift").read_text()
        start = source.index("func open(")
        end = source.index(") throws", start)
        surface = source[start:end]
        self.assertIn("artifactFile: Int32", surface)
        self.assertIn("deadline: UInt64", surface)
        for forbidden in ("String", "URL", "path", "destination", "command"):
            self.assertNotIn(forbidden, surface)
        self.assertIn('"-readonly"', source)
        self.assertIn("MNT_RDONLY", source)


if __name__ == "__main__":
    unittest.main()
