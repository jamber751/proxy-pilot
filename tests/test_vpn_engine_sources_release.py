"""Exact published VPN engine source bundle and signed-release binding."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "vpn_package_sources", ROOT / "app/vpn-package/package.py")
PACKAGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGER)


class VPNEngineSourcesReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pp-vpn-sources-")
        self.root = Path(self.temporary.name)
        self.original_here = PACKAGER.HERE
        PACKAGER.HERE = self.root / "app/vpn-package"
        recipe = self.root / "app/vpn-engine"
        recipe.mkdir(parents=True)
        (PACKAGER.HERE).mkdir()
        self.build = b"#!/usr/bin/env python3\nprint('reviewed')\n"
        (recipe / "build.py").write_bytes(self.build)
        self.upstream = {
            "openvpn": self.upstream_archive(
                "openvpn", "1.0", {"COPYING": b"vpn-copying\n",
                                     "COPYRIGHT.GPL": b"vpn-gpl\n"}),
            "openssl": self.upstream_archive(
                "openssl", "2.0", {"LICENSE.txt": b"ssl-license\n"}),
        }
        self.lock = {
            "openvpn": {"version": "1.0", "sha256": hashlib.sha256(
                self.upstream["openvpn"]).hexdigest()},
            "openssl": {"version": "2.0", "sha256": hashlib.sha256(
                self.upstream["openssl"]).hexdigest()},
        }
        self.lock_bytes = (json.dumps(self.lock, separators=(",", ":"))
                           + "\n").encode()
        (recipe / "sources.json").write_bytes(self.lock_bytes)
        self.manifest = self.root / "release.manifest"
        self.manifest.write_text(
            "format=2\nproduct=kz.documentolog.proxypilot\nsequence=10\n"
            "version=2.0.0\nengine-version=1.0\nengine-crypto-version=2.0\n"
            + "engine-sha256=" + "aa" * 32 + "\n")

    def tearDown(self):
        PACKAGER.HERE = self.original_here
        self.temporary.cleanup()

    @staticmethod
    def upstream_archive(name, version, files):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz",
                          format=tarfile.USTAR_FORMAT) as archive:
            for filename, data in files.items():
                info = tarfile.TarInfo(f"{name}-{version}/{filename}")
                info.size = len(data); info.mode = 0o600
                archive.addfile(info, io.BytesIO(data))
        return output.getvalue()

    def files(self, provenance=None):
        provenance = provenance or {
            "sources": self.lock, "minimumOS": "11.0",
            "architectures": ["arm64", "x86_64"],
            "binarySHA256": "aa" * 32,
        }
        return {
            "EngineSources/sources/sources.json": self.lock_bytes,
            "EngineSources/sources/build.py": self.build,
            "EngineSources/sources/openvpn-1.0.tar.gz": self.upstream["openvpn"],
            "EngineSources/sources/openssl-2.0.tar.gz": self.upstream["openssl"],
            "EngineSources/OpenVPN-COPYING.txt": b"vpn-copying\n",
            "EngineSources/OpenVPN-GPL-2.0.txt": b"vpn-gpl\n",
            "EngineSources/OpenSSL-LICENSE.txt": b"ssl-license\n",
            "EngineSources/provenance.json": (json.dumps(provenance) + "\n").encode(),
        }

    def outer(self, name, files, link=None):
        path = self.root / name
        with tarfile.open(path, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for filename, data in files.items():
                info = tarfile.TarInfo(filename); info.size = len(data); info.mode = 0o600
                archive.addfile(info, io.BytesIO(data))
            if link:
                info = tarfile.TarInfo(link); info.type = tarfile.SYMTYPE
                info.linkname = "/tmp/escape"
                archive.addfile(info)
        return path

    def test_exact_sources_match_signed_engine_release(self):
        archive = self.outer("sources.tar.gz", self.files())
        PACKAGER.verify_engine_sources_archive(
            archive, self.manifest, "2.0.0")

    def test_wrong_provenance_source_or_release_is_refused(self):
        bad = self.files(dict(
            sources=self.lock, minimumOS="11.0",
            architectures=["arm64", "x86_64"], binarySHA256="bb" * 32))
        with self.assertRaises(ValueError):
            PACKAGER.verify_engine_sources_archive(
                self.outer("bad-provenance.tar.gz", bad),
                self.manifest, "2.0.0")
        changed = self.files()
        changed["EngineSources/sources/openvpn-1.0.tar.gz"] += b"x"
        with self.assertRaises(ValueError):
            PACKAGER.verify_engine_sources_archive(
                self.outer("bad-source.tar.gz", changed),
                self.manifest, "2.0.0")
        with self.assertRaises(ValueError):
            PACKAGER.verify_engine_sources_archive(
                self.outer("wrong-version.tar.gz", self.files()),
                self.manifest, "2.0.1")

    def test_links_traversal_and_extra_files_are_refused(self):
        with self.assertRaises(ValueError):
            PACKAGER.verify_engine_sources_archive(
                self.outer("link.tar.gz", self.files(),
                           "EngineSources/sources/link"),
                self.manifest, "2.0.0")
        extra = self.files(); extra["EngineSources/extra"] = b"no"
        with self.assertRaises(ValueError):
            PACKAGER.verify_engine_sources_archive(
                self.outer("extra.tar.gz", extra), self.manifest, "2.0.0")
        traversal = self.files(); traversal["../escape"] = b"no"
        with self.assertRaises(ValueError):
            PACKAGER.verify_engine_sources_archive(
                self.outer("traversal.tar.gz", traversal),
                self.manifest, "2.0.0")


if __name__ == "__main__":
    unittest.main()
