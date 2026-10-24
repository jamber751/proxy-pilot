"""Offline build-boundary checks; never compile, install or connect a VPN."""
import hashlib
import gzip
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

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

    def timestamp_archive(self, entries):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz', format=tarfile.PAX_FORMAT) as archive:
            for name, timestamp, content in entries:
                info = tarfile.TarInfo(name)
                info.mtime = timestamp
                if content is None:
                    info.type = tarfile.DIRTYPE
                else:
                    info.size = len(content)
                archive.addfile(info, None if content is None else io.BytesIO(content))
        return output.getvalue()

    def test_release_timestamps_prevent_maintainer_regeneration_across_write_seconds(self):
        # Like the release tar, generated aclocal.m4 precedes its inputs. Simulate
        # extraction crossing a second without sleeps. Dropping mtime restoration
        # makes make invoke the forbidden regeneration recipe in both cases.
        copy = shutil.copyfileobj
        for generated_time in (1788419994, 1788419995):
            with self.subTest(generated_time=generated_time):
                writes = []
                def copy_with_fresh_time(source, output):
                    copy(source, output)
                    output.flush()
                    writes.append(Path(output.name).name)
                    fresh = (1800000000 + len(writes)) * 10**9
                    os.utime(output.name, ns=(fresh, fresh))
                data = self.timestamp_archive([
                    ('source/aclocal.m4', generated_time, b'generated\n'),
                    ('source/configure.ac', 1788419994, b'input\n'),
                    ('source/m4', 1788419994, None),
                    ('source/m4/libtool.m4', 1788419994, b'macro\n'),
                    ('source/Makefile', 1788419994,
                     b'aclocal.m4: configure.ac m4/libtool.m4\n\t@echo unexpected > regenerated\n\t@false\n'),
                ])
                with mock.patch.object(builder.shutil, 'copyfileobj', side_effect=copy_with_fresh_time):
                    folder = builder.extract(data, self.base / str(generated_time), 'source')
                self.assertLess(writes.index('aclocal.m4'), writes.index('configure.ac'))
                result = subprocess.run(['/usr/bin/make', 'aclocal.m4'], cwd=folder,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((folder / 'regenerated').exists())
                self.assertEqual((folder / 'aclocal.m4').stat().st_mtime_ns, generated_time * 10**9)
                self.assertEqual((folder / 'configure.ac').stat().st_mtime_ns, 1788419994 * 10**9)

    def test_restores_explicit_directory_and_fractional_file_times_after_children(self):
        data = self.timestamp_archive([
            ('source', 1500000000, None),
            ('source/nested', 1500000001, None),
            ('source/nested/file', 1500000002.125, b'content'),
        ])
        folder = builder.extract(data, self.base / 'out', 'source')
        self.assertEqual(folder.stat().st_mtime_ns, 1500000000 * 10**9)
        self.assertEqual((folder / 'nested').stat().st_mtime_ns, 1500000001 * 10**9)
        self.assertEqual((folder / 'nested/file').stat().st_mtime_ns, 1500000002125000000)

    def test_invalid_timestamps_rejected_before_any_output(self):
        for timestamp in (-1, float('nan'), float('inf'), -float('inf'), 2**63):
            with self.subTest(timestamp=timestamp):
                data = self.timestamp_archive([
                    ('source/valid', 1500000000, b'valid'),
                    ('source/invalid', timestamp, b'invalid'),
                ])
                with self.assertRaises(ValueError):
                    builder.extract(data, self.base / 'out', 'source')
                self.assertFalse((self.base / 'out').exists())

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
        # A header is enough: extract() must reject the declared expansion
        # before it reads file contents. Python 3.14 correctly refuses to make
        # a non-empty regular member without a fileobj, so build the same
        # bounded 512-byte tar header directly instead of allocating 512 MiB.
        info = tarfile.TarInfo('source/oversized')
        info.size = 512 * 1024 * 1024 + 1
        output = gzip.compress(info.tobuf(format=tarfile.PAX_FORMAT))
        with self.assertRaises(ValueError):
            builder.extract(output, self.base / 'out', 'source')
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
