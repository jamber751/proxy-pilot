"""Release-side contract for the read-only VPN joint companion image."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "vpn_packager", ROOT / "app/vpn-package/package.py")
PACKAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGER)


class VPNCompanionPackagerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pp-companion-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.stage = self.root / "stage"
        self.payload = self.stage / "Payload"
        self.payload.mkdir(parents=True, mode=0o700)
        (self.payload / "ProxyPilot.app").mkdir(mode=0o700)
        for name in ({"vpn-helper", "vpn-engine", "vpn-release.manifest",
                      "vpn-release.sig"} | PACKAGER.JOINT_FILES):
            (self.payload / name).write_bytes(name.encode())
        self.original_verify = PACKAGER.verify
        self.original_run = PACKAGER.run
        self.calls = []
        PACKAGER.verify = lambda payload, action=None: (
            "2.0.0" if payload == self.payload and action == "update" else None)

        def fake_run(*args):
            self.calls.append(tuple(map(str, args)))
            if args[1] == "create":
                Path(args[-1]).write_bytes(b"read-only-image")
            return ""
        PACKAGER.run = fake_run
        self.addCleanup(setattr, PACKAGER, "verify", self.original_verify)
        self.addCleanup(setattr, PACKAGER, "run", self.original_run)

    def test_exact_format2_joint_layout_is_atomically_published(self):
        output = self.root / "ProxyPilot-2.0.0-vpn-joint.dmg"
        PACKAGER.build_companion(self.stage, output)
        self.assertEqual(output.read_bytes(), b"read-only-image")
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        create = next(call for call in self.calls if call[1] == "create")
        self.assertIn("-format", create)
        self.assertIn("UDZO", create)
        self.assertIn("-srcfolder", create)
        self.assertEqual(Path(create[create.index("-srcfolder") + 1]), self.payload)
        self.assertTrue(any(call[1] == "verify" for call in self.calls))

    def test_missing_extra_or_helper_only_layout_is_refused_before_hdiutil(self):
        for name in ("vpn-engine", "vpn-update-transition.sig"):
            with self.subTest(name=name):
                path = self.payload / name
                data = path.read_bytes(); path.unlink()
                with self.assertRaisesRegex(ValueError, "exact format-2"):
                    PACKAGER.build_companion(self.stage, self.root / f"{name}.dmg")
                path.write_bytes(data)
        (self.payload / "profile.ovpn").write_text("forbidden")
        with self.assertRaisesRegex(ValueError, "exact format-2"):
            PACKAGER.build_companion(self.stage, self.root / "extra.dmg")
        self.assertEqual(self.calls, [])

    def test_output_is_new_absolute_dmg_and_never_overwritten(self):
        existing = self.root / "existing.dmg"
        existing.write_bytes(b"keep")
        with self.assertRaises(ValueError):
            PACKAGER.build_companion(self.stage, existing)
        self.assertEqual(existing.read_bytes(), b"keep")
        with self.assertRaises(ValueError):
            PACKAGER.build_companion(self.stage, self.root / "wrong.zip")
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
