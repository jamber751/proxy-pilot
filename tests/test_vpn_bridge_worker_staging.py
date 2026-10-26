"""Reject unreviewed release inputs before signing or image execution."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('stage_workers', ROOT / 'app/vpn-bridge/stage_workers.py')
staging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(staging)


class StagingTests(unittest.TestCase):
    def test_bad_bytes_clean_partial_assembly_without_signing(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(staging, 'inspect') as signing:
            folder = Path(folder)
            source = folder / 'input'; source.write_bytes(b'unreviewed'); source.chmod(0o700)
            with self.assertRaises(ValueError):
                staging.stage(source, source, folder / 'output')
            self.assertFalse((folder / 'output').exists())
            signing.assert_not_called()

    def test_source_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(staging, 'inspect') as signing:
            folder = Path(folder)
            source = folder / 'input'; source.write_bytes(b'unreviewed'); source.chmod(0o700)
            link = folder / 'link'; link.symlink_to(source)
            with self.assertRaises(OSError):
                staging.stage(link, source, folder / 'output')
            self.assertFalse((folder / 'output').exists())
            signing.assert_not_called()

    def test_existing_output_is_never_deleted_or_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder); output = folder / 'output'; output.mkdir()
            sentinel = output / 'gost'; sentinel.write_bytes(b'prior output')
            with self.assertRaises(FileExistsError):
                staging.stage(folder / 'missing', folder / 'missing', output)
            self.assertEqual(sentinel.read_bytes(), b'prior output')

    def test_fixed_images_match_production_selection_and_live_identity(self):
        source = (ROOT / 'app/VPNBridgeWorkerProcess.swift').read_text()
        identity = (ROOT / 'app/VPNBridgeWorkerIdentity.swift').read_text()
        import re
        digests = [bytes(int(v, 16) for v in re.findall(r'0x([0-9a-f]{2})', block)).hex()
                   for block in re.findall(r'digest:Data\(\[([^]]+)\]', source)]
        for size, digest, identifier, hashes in staging.IMAGES.values():
            self.assertIn(digest, digests)
            self.assertIn('bytes:' + str(size), source)
            self.assertIn(identifier, identity)
            for value in hashes.values():self.assertIn(value, identity)


if __name__ == '__main__':unittest.main()
