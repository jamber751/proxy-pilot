"""Protected update-journal state, crash, and hostile-file checks."""

import base64
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    sys.platform == "darwin" and shutil.which("swiftc"), "macOS Swift required"
)
class VPNUpdateJournalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="proxypilot-journal-build-")
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.work = Path(cls.tmp.name)
        cls.helpers = {}
        cls.pins = {}
        for n in (1, 2):
            thin = []
            for arch in ("arm64", "x86_64"):
                p = cls.work / f"h{n}-{arch}"
                cls.cmd(
                    [
                        "xcrun",
                        "clang",
                        "-target",
                        f"{arch}-apple-macosx11.0",
                        f"-DFIXTURE_REVISION={n}",
                        str(ROOT / "tests/vpn-deployment/HelperFixture.c"),
                        "-o",
                        str(p),
                    ]
                )
                thin.append(str(p))
            p = cls.work / f"h{n}"
            cls.cmd(["lipo", "-create", *thin, "-output", str(p)])
            cls.cmd(
                [
                    "codesign",
                    "--force",
                    "--sign",
                    "-",
                    "--identifier",
                    "kz.documentolog.proxypilot.vpn-helper",
                    "--options",
                    "runtime,hard,kill",
                    str(p),
                ]
            )
            cls.helpers[n] = p
            cls.pins[n] = {}
            for arch in ("arm64", "x86_64"):
                r = cls.cmd(["codesign", "-d", "--verbose=4", "--arch", arch, str(p)])
                cls.pins[n][arch] = re.search(
                    r"^CDHash=([a-f0-9]{40})$", r.stderr, re.M
                ).group(1)
        sources = [
            ROOT / "app/vpn-helper" / x
            for x in (
                "VPNPeerAuthentication.swift",
                "VPNReleaseAuthorization.swift",
                "VPNHelperArtifact.swift",
                "VPNReleaseStore.swift",
            )
        ]
        slices = []
        for arch in ("arm64", "x86_64"):
            p = cls.work / f"check-{arch}"
            cls.cmd(
                [
                    "swiftc",
                    "-D",
                    "VPN_RELEASE_STORE_TESTING",
                    "-target",
                    f"{arch}-apple-macosx11.0",
                    *map(str, sources),
                    str(ROOT / "tests/vpn_update_journal_checks.swift"),
                    "-o",
                    str(p),
                ]
            )
            slices.append(str(p))
        cls.binary = cls.work / "checks"
        cls.cmd(["lipo", "-create", *slices, "-output", str(cls.binary)])
        cls.cmd(
            [
                "codesign",
                "--force",
                "--sign",
                "-",
                "--options",
                "runtime,hard,kill",
                str(cls.binary),
            ]
        )

    @staticmethod
    def cmd(args):
        env = os.environ.copy()
        cache = (
            Path(args[-1]).parent / "module-cache"
            if args
            else Path(tempfile.gettempdir()) / "proxypilot-journal-cache"
        )
        cache.mkdir(parents=True, exist_ok=True)
        env["CLANG_MODULE_CACHE_PATH"] = str(cache)
        env["SWIFT_MODULECACHE_PATH"] = str(cache)
        r = subprocess.run(args, capture_output=True, text=True, timeout=90, env=env)
        if r.returncode:
            raise AssertionError(r.stderr)
        return r

    def setUp(self):
        self.t = tempfile.TemporaryDirectory(prefix="proxypilot-journal-")
        self.addCleanup(self.t.cleanup)
        self.dir = Path(self.t.name) / "policy"
        self.dir.mkdir(mode=0o700)
        self.man = []
        for n, seq in ((1, 10), (2, 20)):
            data = self.helpers[n].read_bytes()
            p = Path(self.t.name) / f"m{n}"
            fields = {
                "format": "1",
                "product": "kz.documentolog.proxypilot",
                "sequence": str(seq),
                "version": f"1.{seq}.0",
                "protocol": "1",
                "app-arm64": f"{n:02x}" * 20,
                "app-x86_64": f"{n+2:02x}" * 20,
                "helper-arm64": self.pins[n]["arm64"],
                "helper-x86_64": self.pins[n]["x86_64"],
                "helper-sha256": hashlib.sha256(data).hexdigest(),
                "helper-bytes": str(len(data)),
            }
            p.write_bytes("".join(f"{k}={v}\n" for k, v in fields.items()).encode())
            self.man.append(p)
        self.zero = "00000000-0000-0000-0000-000000000000"
        self.run_journal("bootstrap", ok=True)

    def run_journal(self, op, checkpoint="none", tid=None, rev=0, ok=False):
        r = subprocess.run(
            [
                str(self.binary),
                op,
                str(self.dir),
                str(self.man[0]),
                str(self.man[1]),
                str(self.helpers[1]),
                str(self.helpers[2]),
                checkpoint,
                tid or self.zero,
                str(rev),
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if ok:
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def prepare(self, checkpoint="none"):
        r = self.run_journal("prepare", checkpoint)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return re.search(r"id=([A-F0-9-]+)", r.stdout).group(1)

    def test_happy_lifecycle_across_processes_and_selector_recovery(self):
        tid = self.prepare()
        self.assertIn("canCancelOrReplace", self.run_journal("load", ok=True).stdout)
        self.run_journal("pending", tid=tid, rev=0, ok=True)
        self.assertIn("inspectApplication", self.run_journal("load", ok=True).stdout)
        self.run_journal("select", tid=tid, rev=1, ok=True)
        self.assertIn("selected=20", self.run_journal("load-selected", ok=True).stdout)
        self.run_journal("complete", tid=tid, rev=2, ok=True)
        self.assertIn("updateInProgress", self.run_journal("ordinary-prepare").stdout)
        self.run_journal("retire", tid=tid, rev=3, ok=True)
        self.assertIn("journal=none", self.run_journal("load", ok=True).stdout)
        receipt = self.run_journal("load-cleanup", ok=True).stdout
        self.assertIn("cleanup=completed revision=3", receipt)
        self.assertIn(f"id={tid}", receipt)
        self.assertIn("owner=501 previous=10 selected=20", receipt)
        # Read-only selected state remains available, but every deployment or
        # joint-update mutation waits for a future cleanup coordinator.
        self.assertIn("selected=20", self.run_journal("load-selected", ok=True).stdout)
        for op in (
            "ordinary-commit",
            "ordinary-prepare",
            "metadata-accept",
            "bootstrap-again",
            "prepare",
        ):
            self.assertIn("cleanupPending", self.run_journal(op).stdout)

    def test_cancel_terminal_blocks_until_retired(self):
        tid = self.prepare()
        self.run_journal("cancel", tid=tid, rev=0, ok=True)
        for op in (
            "ordinary-commit",
            "ordinary-prepare",
            "metadata-accept",
            "bootstrap-again",
            "prepare",
        ):
            self.assertIn("updateInProgress", self.run_journal(op).stdout)
        self.assertNotEqual(self.run_journal("pending", tid=tid, rev=1).returncode, 0)
        self.run_journal("retire", tid=tid, rev=1, ok=True)

    def test_stale_identity_revision_phase_and_old_token_are_rejected(self):
        tid = self.prepare()
        self.assertIn(
            "staleRevision",
            self.run_journal("pending", tid=str(uuid.uuid4()), rev=0).stdout,
        )
        self.assertIn(
            "staleRevision", self.run_journal("pending", tid=tid, rev=1).stdout
        )
        self.assertIn(
            "invalidUpdateJournal", self.run_journal("select", tid=tid, rev=0).stdout
        )
        # A separately seeded store proves a token prepared before journal creation cannot commit afterwards.
        self.run_journal("cancel", tid=tid, rev=0, ok=True)
        self.run_journal("retire", tid=tid, rev=1, ok=True)
        self.assertIn("updateInProgress", self.run_journal("old-token").stdout)
        out = self.run_journal("load", ok=True).stdout
        old_token_id = re.search(r"id=([A-F0-9-]+)", out).group(1)
        self.run_journal("cancel", tid=old_token_id, rev=0, ok=True)
        self.run_journal("retire", tid=old_token_id, rev=1, ok=True)
        tid = self.prepare()
        self.run_journal("pending", tid=tid, rev=0, ok=True)
        self.assertIn(
            "invalidUpdateJournal", self.run_journal("cancel", tid=tid, rev=1).stdout
        )

    def test_bad_edge_and_strict_damaged_journal_fail_closed(self):
        self.assertIn("invalidSignature", self.run_journal("bad-edge").stdout)
        tid = self.prepare()
        j = self.dir / "update.json"
        original = j.read_bytes()

        def canonical(value):
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
            return encoded.replace("/", "\\/").encode()

        self.assertEqual(canonical(json.loads(original)), original)
        for mutate in (
            "unknown",
            "schema",
            "owner",
            "candidateSignature",
            "transitionSignature",
        ):
            data = json.loads(original)
            if mutate == "unknown":
                data["unknown"] = 1
            elif mutate == "schema":
                data["schema"] = 2
            elif mutate == "owner":
                data["owner"] = 502
            else:
                raw = bytearray(base64.b64decode(data[mutate]))
                raw[0] ^= 1
                data[mutate] = base64.b64encode(raw).decode()
            j.write_bytes(canonical(data))
            self.assertIn("invalidUpdateJournal", self.run_journal("load").stdout)
            j.write_bytes(original)
        for helper in (self.helpers[1], self.helpers[2]):
            artifact = self.dir / (
                "helper-" + hashlib.sha256(helper.read_bytes()).hexdigest()
            )
            saved = artifact.read_bytes()
            artifact.write_bytes(b"bad")
            self.assertIn("invalidUpdateJournal", self.run_journal("load").stdout)
            artifact.write_bytes(saved)
        for old, new in (
            (b'"revision":0', b'"revision":2'),
            (b'"phase":"prepared"', b'"phase":"completed"'),
        ):
            self.assertIn(old, original)
            j.write_bytes(original.replace(old, new))
            self.assertIn("invalidUpdateJournal", self.run_journal("load").stdout)
        # Correct phase/revision pairs still fail against the wrong selector A.
        for phase, revision in (("selected", 2), ("completed", 3)):
            data = json.loads(original)
            data.update(phase=phase, revision=revision)
            j.write_bytes(canonical(data))
            self.assertIn("invalidUpdateJournal", self.run_journal("load").stdout)
        j.write_bytes(original)

    def test_crash_windows_reconcile_without_rollback(self):
        r = self.run_journal("prepare", checkpoint="update.json:before-rename")
        self.assertEqual(r.returncode, 86)
        self.assertFalse((self.dir / "update.json").exists())
        tid = self.prepare()
        r = self.run_journal(
            "pending", checkpoint="update.json:after-rename", tid=tid, rev=0
        )
        self.assertEqual(r.returncode, 86)
        self.assertIn("replacementPending", self.run_journal("load", ok=True).stdout)
        r = self.run_journal(
            "select", checkpoint="release.json:after-rename", tid=tid, rev=1
        )
        self.assertEqual(r.returncode, 86)
        out = self.run_journal("load", ok=True).stdout
        self.assertIn("replacementPending", out)
        self.assertIn("selected=20", out)
        self.assertIn("recoverCandidate", out)
        journal = self.dir / "update.json"
        pending = journal.read_bytes()
        # Exact B is already selected: a well-shaped prepared/A record cannot
        # erase the irreversible boundary or permit cancellation again.
        journal.write_bytes(pending.replace(b'"phase":"replacementPending"', b'"phase":"prepared"')
                            .replace(b'"revision":1', b'"revision":0'))
        self.assertIn("invalidUpdateJournal", self.run_journal("load").stdout)
        journal.write_bytes(pending)
        self.run_journal("select", tid=tid, rev=1, ok=True)

    def test_retirement_checkpoints_and_hostile_files_locks_modes(self):
        tid = self.prepare()
        self.run_journal("cancel", tid=tid, rev=0, ok=True)
        r = self.run_journal(
            "retire", checkpoint="update.json:before-unlink", tid=tid, rev=1
        )
        self.assertEqual(r.returncode, 86)
        self.assertTrue((self.dir / "update.json").exists())
        r = self.run_journal(
            "retire", checkpoint="update.json:after-unlink", tid=tid, rev=1
        )
        self.assertEqual(r.returncode, 86)
        self.assertFalse((self.dir / "update.json").exists())
        tid = self.prepare()
        j = self.dir / "update.json"
        j.chmod(0o644)
        self.assertIn("unsafeStorage", self.run_journal("load").stdout)
        j.chmod(0o600)
        with (self.dir / "release.lock").open("r+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertIn("busy", self.run_journal("load").stdout)
        target = Path(self.t.name) / "target"
        target.write_bytes(b"keep")
        j.unlink()
        j.symlink_to(target)
        self.assertIn("unsafeStorage", self.run_journal("load").stdout)
        self.assertEqual(target.read_bytes(), b"keep")

    def test_completed_retirement_persists_receipt_before_unlink_and_retries(self):
        tid = self.prepare()
        self.run_journal("pending", tid=tid, rev=0, ok=True)
        self.run_journal("select", tid=tid, rev=1, ok=True)
        self.run_journal("complete", tid=tid, rev=2, ok=True)
        terminal = json.loads((self.dir / "update.json").read_bytes())

        # A crash before the cleanup rename leaves only the terminal journal.
        r = self.run_journal(
            "retire", checkpoint="cleanup.json:before-rename", tid=tid, rev=3
        )
        self.assertEqual(r.returncode, 86)
        self.assertTrue((self.dir / "update.json").exists())
        self.assertFalse((self.dir / "cleanup.json").exists())

        # A crash after the durable receipt commit leaves both records. A retry
        # verifies their exact equality and finishes the ordered unlink.
        r = self.run_journal(
            "retire", checkpoint="cleanup.json:after-commit", tid=tid, rev=3
        )
        self.assertEqual(r.returncode, 86)
        self.assertTrue((self.dir / "update.json").exists())
        self.assertTrue((self.dir / "cleanup.json").exists())
        self.assertEqual(json.loads((self.dir / "cleanup.json").read_bytes())["journal"], terminal)
        self.run_journal("retire", tid=tid, rev=3, ok=True)
        self.assertFalse((self.dir / "update.json").exists())
        self.assertTrue((self.dir / "cleanup.json").exists())
        attributes = (self.dir / "cleanup.json").stat()
        self.assertEqual(attributes.st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(attributes.st_mode), 0o600)
        # Retrying after unlink is also successful and re-syncs the directory.
        self.run_journal("retire", tid=tid, rev=3, ok=True)

    def test_completed_retirement_retry_after_unlink_checkpoint(self):
        tid = self.prepare()
        self.run_journal("pending", tid=tid, rev=0, ok=True)
        self.run_journal("select", tid=tid, rev=1, ok=True)
        self.run_journal("complete", tid=tid, rev=2, ok=True)
        r = self.run_journal(
            "retire", checkpoint="update.json:after-unlink", tid=tid, rev=3
        )
        self.assertEqual(r.returncode, 86)
        self.assertFalse((self.dir / "update.json").exists())
        self.assertTrue((self.dir / "cleanup.json").exists())
        self.run_journal("retire", tid=tid, rev=3, ok=True)

    def test_cleanup_receipt_phase_machine_is_ordered_and_idempotent(self):
        tid = self.prepare()
        self.run_journal("pending", tid=tid, rev=0, ok=True)
        self.run_journal("select", tid=tid, rev=1, ok=True)
        self.run_journal("complete", tid=tid, rev=2, ok=True)
        self.run_journal("retire", tid=tid, rev=3, ok=True)
        first = self.run_journal("cleanup-app", tid=tid, rev=3, ok=True)
        self.assertIn("cleanup=applicationRetired", first.stdout)
        refused = self.run_journal("cleanup-update", tid=str(uuid.uuid4()), rev=3)
        self.assertIn("staleRevision", refused.stdout)
        second = self.run_journal("cleanup-update", tid=tid, rev=3, ok=True)
        self.assertIn("cleanup=updateRetired", second.stdout)
        # GC authorization is deliberately owned by the coordinator; a receipt
        # cannot be retired directly from the pre-GC phase.
        refused = self.run_journal("cleanup-retire", tid=tid, rev=3)
        self.assertIn("invalidCleanupReceipt", refused.stdout)

    def test_cleanup_receipt_is_canonical_and_revalidates_all_evidence(self):
        tid = self.prepare()
        self.run_journal("pending", tid=tid, rev=0, ok=True)
        self.run_journal("select", tid=tid, rev=1, ok=True)
        self.run_journal("complete", tid=tid, rev=2, ok=True)
        self.run_journal("retire", tid=tid, rev=3, ok=True)
        receipt = self.dir / "cleanup.json"
        original = receipt.read_bytes()

        def canonical(value):
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
            return encoded.replace("/", "\\/").encode()

        self.assertEqual(canonical(json.loads(original)), original)
        mutations = []
        extra = json.loads(original)
        extra["unknown"] = 1
        mutations.append(canonical(extra))
        wrong_owner = json.loads(original)
        wrong_owner["journal"]["owner"] = 502
        mutations.append(canonical(wrong_owner))
        bad_edge = json.loads(original)
        raw = bytearray(base64.b64decode(bad_edge["journal"]["transitionSignature"]))
        raw[0] ^= 1
        bad_edge["journal"]["transitionSignature"] = base64.b64encode(raw).decode()
        mutations.append(canonical(bad_edge))
        bad_candidate = json.loads(original)
        raw = bytearray(base64.b64decode(bad_candidate["journal"]["candidateSignature"]))
        raw[0] ^= 1
        bad_candidate["journal"]["candidateSignature"] = base64.b64encode(raw).decode()
        mutations.append(canonical(bad_candidate))
        wrong_phase = json.loads(original)
        wrong_phase["journal"].update(phase="selected", revision=2)
        mutations.append(canonical(wrong_phase))
        for damaged in mutations:
            receipt.write_bytes(damaged)
            self.assertIn("invalidCleanupReceipt", self.run_journal("load-cleanup").stdout)
            # Runtime/read-only selection is intentionally not gated by cleanup.
            self.assertIn("selected=20", self.run_journal("load-selected", ok=True).stdout)
            self.assertIn("invalidCleanupReceipt", self.run_journal("ordinary-prepare").stdout)
            receipt.write_bytes(original)

        # Stored A and B artifacts are part of receipt validation.
        for helper in (self.helpers[1], self.helpers[2]):
            artifact = self.dir / ("helper-" + hashlib.sha256(helper.read_bytes()).hexdigest())
            saved = artifact.read_bytes()
            artifact.write_bytes(b"bad")
            self.assertIn("invalidCleanupReceipt", self.run_journal("load-cleanup").stdout)
            artifact.write_bytes(saved)

        # The receipt is historical evidence only when exact B remains selected.
        selected = self.dir / "release.json"
        selected_b = selected.read_bytes()
        evidence = json.loads(original)["journal"]
        selected_a = {
            "schema": 2,
            "owner": evidence["owner"],
            "payload": evidence["previousPayload"],
            "signature": evidence["previousSignature"],
        }
        selected.write_bytes(canonical(selected_a))
        self.assertIn("invalidCleanupReceipt", self.run_journal("load-cleanup").stdout)
        selected.write_bytes(selected_b)


if __name__ == "__main__":
    unittest.main()
