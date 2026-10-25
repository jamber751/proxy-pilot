"""Build-tool refusal checks only; never signs/executes GOST or opens sockets."""
from pathlib import Path
import hashlib
import importlib.util
import os
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('pp_signed_candidate',ROOT/'app/vpn-bridge/sign_atomic_gost.py')
signer=importlib.util.module_from_spec(spec);spec.loader.exec_module(signer)

class SignedCandidateGuards(unittest.TestCase):
    def test_platform_and_root_refused_before_file_access(self):
        for platform,uid in (('linux',501),('darwin',0)):
            with self.subTest(platform=platform,uid=uid),patch.object(signer.sys,'platform',platform),\
                    patch.object(signer.os,'getuid',return_value=uid),patch.object(signer.os,'geteuid',return_value=uid),\
                    patch.object(signer.os,'open') as opened:
                with self.assertRaises(ValueError):signer.prepare('/source','/destination')
                opened.assert_not_called()

    @unittest.skipIf(os.getuid()==0,'ordinary private file test')
    def test_relative_paths_refused_before_reading_or_signing(self):
        with patch.object(signer.sys,'platform','darwin'),patch.object(signer.os,'open') as opened:
            for source,destination in (('relative','/absolute'),('/absolute','relative')):
                with self.assertRaises(ValueError):signer.prepare(source,destination)
            opened.assert_not_called()

    @unittest.skipIf(os.getuid()==0,'ordinary private file test')
    def test_invalid_sources_never_create_output_or_invoke_signer(self):
        with tempfile.TemporaryDirectory(prefix='pp-sign-guard-') as folder:
            root=Path(folder);source=root/'source';source.write_bytes(b'bad')
            link=root/'link';link.symlink_to(source)
            hard=root/'hard';os.link(source,hard)
            with patch.object(signer.sys,'platform','darwin'),patch.object(signer,'run') as command:
                for index,path in enumerate((source,link,hard)):
                    destination=root/('output-'+str(index))
                    with self.assertRaises((ValueError,OSError)):signer.prepare(path,destination)
                    self.assertFalse(destination.exists())
                hard.unlink()
                with source.open('wb') as stream:stream.truncate(signer.UNSIGNED_BYTES)
                destination=root/'bad-hash'
                with self.assertRaises(ValueError):signer.prepare(source,destination)
                self.assertFalse(destination.exists());command.assert_not_called()

    @unittest.skipIf(os.getuid()==0,'ordinary private file test')
    def test_existing_output_is_never_reused(self):
        with tempfile.TemporaryDirectory(prefix='pp-sign-existing-') as folder:
            root=Path(folder);source=root/'source';source.write_bytes(b'test')
            destination=root/'output';destination.mkdir(mode=0o700);marker=destination/'marker';marker.write_text('keep')
            with patch.object(signer.sys,'platform','darwin'),patch.object(signer,'UNSIGNED_BYTES',4),\
                    patch.object(signer,'UNSIGNED_SHA256',hashlib.sha256(b'test').hexdigest()),patch.object(signer,'run') as command:
                with self.assertRaises(FileExistsError):signer.prepare(source,destination)
                command.assert_not_called();self.assertEqual(marker.read_text(),'keep')

    def test_complete_fixed_signed_and_unsigned_pins(self):
        self.assertEqual(signer.UNSIGNED_BYTES,70287474)
        self.assertEqual(signer.SIGNED_BYTES,70633296)
        self.assertRegex(signer.UNSIGNED_SHA256,r'^[a-f0-9]{64}$')
        self.assertRegex(signer.SIGNED_SHA256,r'^[a-f0-9]{64}$')
        self.assertEqual(set(signer.SIGNED_CDHASH),{'arm64','x86_64'})
        for value in signer.SIGNED_CDHASH.values():self.assertRegex(value,r'^[a-f0-9]{40}$')

if __name__=='__main__':unittest.main()
