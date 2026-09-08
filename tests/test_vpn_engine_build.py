"""Offline build-boundary checks; never compile, install or connect a VPN."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('vpn_engine_build', ROOT / 'app/vpn-engine/build.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class VPNEngineBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pp-engine-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def archive(self, entries):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            for name, kind in entries:
                info = tarfile.TarInfo(name)
                if kind == 'file':
                    info.size = 4; info.mode = 0o4755
                    archive.addfile(info, io.BytesIO(b'test'))
                else:
                    info.type = {'link': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE,
                                 'device': tarfile.CHRTYPE, 'directory': tarfile.DIRTYPE}[kind]
                    info.linkname = '/tmp/do-not-touch'
                    archive.addfile(info)
        return output.getvalue()

    def test_extracts_regular_files_without_special_permissions(self):
        data = self.archive([('source', 'directory'), ('source/configure', 'file')])
        folder = builder.extract(data, self.base / 'out', 'source')
        self.assertEqual((folder / 'configure').read_bytes(), b'test')
        self.assertEqual((folder / 'configure').stat().st_mode & 0o7777, 0o700)

    def test_checks_all_names_before_creating_output(self):
        for name in ('../outside', '/outside', 'source/../../outside', 'other/file', 'source\\file'):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    builder.extract(self.archive([('source/ok', 'file'), (name, 'file')]), self.base / 'out', 'source')
                self.assertFalse((self.base / 'out').exists())

    def test_rejects_links_and_special_files(self):
        for kind in ('link', 'hardlink', 'device'):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                builder.extract(self.archive([('source/file', kind)]), self.base / 'out', 'source')
        self.assertFalse((self.base / 'out').exists())

    def test_rejects_duplicate_names(self):
        with self.assertRaises(ValueError):
            builder.extract(self.archive([('source/file', 'file'), ('source/./file', 'file')]), self.base / 'out', 'source')

    def test_root_must_be_a_directory(self):
        with self.assertRaises(ValueError):
            builder.extract(self.archive([('source', 'file')]), self.base / 'out', 'source')
        self.assertFalse((self.base / 'out').exists())

    def test_expansion_limit_is_checked_before_extraction(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            info = tarfile.TarInfo('source/oversized')
            info.size = 512 * 1024 * 1024 + 1
            archive.addfile(info)
        with self.assertRaises(ValueError):
            builder.extract(output.getvalue(), self.base / 'out', 'source')
        self.assertFalse((self.base / 'out').exists())

    def test_does_not_overwrite_an_existing_extraction(self):
        folder = self.base / 'out'; folder.mkdir()
        (folder / 'keep').write_text('keep')
        with self.assertRaises(FileExistsError):
            builder.extract(self.archive([('source/file', 'file')]), folder, 'source')
        self.assertEqual(list(folder.iterdir()), [folder / 'keep'])

    def test_digest_matches_exact_archive_bytes(self):
        path = self.base / 'source.tar.gz'; path.write_bytes(b'archive')
        digest = hashlib.sha256(b'archive').hexdigest()
        self.assertEqual(builder.archive_bytes(path, digest), b'archive')
        path.write_bytes(b'changed')
        with self.assertRaises(ValueError): builder.archive_bytes(path, digest)

    def test_rejects_symlink_source(self):
        path = self.base / 'source'; path.write_bytes(b'archive')
        link = self.base / 'link'; link.symlink_to(path)
        with self.assertRaises(OSError): builder.archive_bytes(link, hashlib.sha256(b'archive').hexdigest())

    def test_rejects_fifo_without_waiting_for_input(self):
        path = self.base / 'fifo'; os.mkfifo(path)
        with self.assertRaises(ValueError): builder.archive_bytes(path, '00' * 32)

    def test_rejects_empty_or_oversized_source(self):
        path = self.base / 'source'; path.touch()
        with self.assertRaises(ValueError): builder.archive_bytes(path, hashlib.sha256(b'').hexdigest())
        with path.open('wb') as stream: stream.truncate(100 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError): builder.archive_bytes(path, '00' * 32)

    def test_build_refuses_existing_output_before_reading_sources(self):
        folder = self.base / 'out'; folder.mkdir()
        (folder / 'keep').write_text('keep')
        with self.assertRaises(ValueError): builder.build(self.base / 'absent', folder, 1)
        self.assertEqual((folder / 'keep').read_text(), 'keep')

    def test_build_refuses_relative_paths(self):
        with self.assertRaises(ValueError): builder.build(Path('sources'), self.base / 'out', 1)
        self.assertFalse((self.base / 'out').exists())

    def test_bad_source_does_not_create_output(self):
        source = self.base / 'openvpn-2.7.7.tar.gz'; source.write_bytes(b'not the reviewed source')
        with self.assertRaises(ValueError): builder.build(self.base, self.base / 'out', 1)
        self.assertFalse((self.base / 'out').exists())
