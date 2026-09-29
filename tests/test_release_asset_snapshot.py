"""Fail-closed two-phase GitHub draft snapshot validation."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_asset_snapshot", ROOT / "app/verify-release-asset-snapshot.py")
SNAPSHOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SNAPSHOT)


class ReleaseAssetSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pp-release-assets-")
        self.root = Path(self.temporary.name)
        self.assets = self.root / "assets"; self.assets.mkdir()
        self.rows = []
        for index, name in enumerate(SNAPSHOT.expected("2.0.0"), 1):
            data = (name + "\n").encode()
            (self.assets / name).write_bytes(data)
            self.rows.append(
                f"{index}\t{name}\t{len(data)}\tuploaded\tsha256:"
                + hashlib.sha256(data).hexdigest())
        self.snapshot = self.root / "snapshot.tsv"
        self.snapshot.write_text("\n".join(self.rows) + "\n")

    def tearDown(self):
        self.temporary.cleanup()

    def test_exact_snapshot_and_downloaded_bytes(self):
        rows = SNAPSHOT.load_snapshot(self.snapshot, "2.0.0")
        SNAPSHOT.verify_files(self.assets, rows)

    def test_missing_duplicate_extra_or_incomplete_assets_are_refused(self):
        variants = [
            self.rows[:-1],
            self.rows + [self.rows[0]],
            self.rows + ["99\textra\t1\tuploaded\tsha256:" + "a" * 64],
            [line.replace("\tuploaded\t", "\tnew\t")
             if index == 0 else line for index, line in enumerate(self.rows)],
            [line.rsplit("\t", 1)[0] + "\t" if index == 0 else line
             for index, line in enumerate(self.rows)],
        ]
        for index, lines in enumerate(variants):
            with self.subTest(index=index):
                path = self.root / f"bad-{index}.tsv"
                path.write_text("\n".join(lines) + "\n")
                with self.assertRaises(ValueError):
                    SNAPSHOT.load_snapshot(path, "2.0.0")

    def test_changed_size_hash_link_or_file_set_is_refused(self):
        rows = SNAPSHOT.load_snapshot(self.snapshot, "2.0.0")
        name = next(iter(rows))
        (self.assets / name).write_bytes(b"changed")
        with self.assertRaises(ValueError):
            SNAPSHOT.verify_files(self.assets, rows)
        (self.assets / name).unlink()
        (self.assets / name).symlink_to(self.assets / next(iter(set(rows) - {name})))
        with self.assertRaises((OSError, ValueError)):
            SNAPSHOT.verify_files(self.assets, rows)


if __name__ == "__main__":
    unittest.main()
