"""Durable unified-broker transaction receipt and recovery checks."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / "app/vpn-helper/VPNUpdateBrokerTransactionStore.swift"
FIXTURE = ROOT / "tests/vpn_update_broker_transaction_store_checks.swift"


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("swiftc"),
                     "macOS Swift required")
class VPNUpdateBrokerTransactionStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="pp-broker-transaction-build-")
        cls.addClassCleanup(cls.build.cleanup)
        cls.binary = Path(cls.build.name) / "checks"
        result = subprocess.run([
            "swiftc", "-D", "VPN_UPDATE_BROKER_TRANSACTION_STORE_TESTING",
            "-target", "arm64-apple-macosx11.0",
            "-module-cache-path", str(Path(cls.build.name) / "ModuleCache"),
            str(STORE), str(FIXTURE), "-o", str(cls.binary),
        ], capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    def check(self, name):
        with tempfile.TemporaryDirectory(prefix=f"pp-broker-transaction-{name}-") as root:
            path = Path(root) / "private"
            result = subprocess.run([str(self.binary), name, str(path)],
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), f"{name} checks passed")

    def test_identity_idempotence_busy_and_monotonic_progress(self):
        self.check("roundtrip")

    def test_crash_checkpoints_are_recoverable_and_idempotent(self):
        self.check("before-rename")
        self.check("after-rename")

    def test_corruption_noncanonical_and_extra_bytes_fail_closed(self):
        self.check("corrupt")
        self.check("reserved")
        self.check("extra")

    def test_links_and_writable_record_fail_closed(self):
        self.check("linked")
        self.check("symlink")
        self.check("writable")

    def test_directory_must_be_preopened_private_owned_and_local(self):
        self.check("unsafe-directory")
        source = STORE.read_text()
        self.assertIn("MNT_LOCAL", source)
        self.assertIn("attributes.st_uid == owner", source)
        self.assertNotIn("URL(", source)

    def test_fixed_canonical_format_durable_replace_and_authority_warning(self):
        source = STORE.read_text()
        for required in ("byteCount = 128", "identity.count == 32", "O_NOFOLLOW",
                         "fsync(file)", "renameat", "fsync(directory)",
                         "st_nlink == 1", "NEVER authorization",
                         "revalidate the exact"):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
