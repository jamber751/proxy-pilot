#!/usr/bin/env python3
"""Validate one immutable GitHub draft asset snapshot and downloaded bytes."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat


def expected(version):
    prefix = f"ProxyPilot-{version}"
    return {
        f"{prefix}.dmg": 1024 * 1024 * 1024,
        f"{prefix}.zip": 1024 * 1024 * 1024,
        "appcast.xml": 1024 * 1024,
        f"{prefix}-vpn-joint.dmg": 768 * 1024 * 1024,
        f"{prefix}-vpn-joint.metadata": 512,
        f"{prefix}-vpn-joint.metadata.sig": 89,
        f"{prefix}-vpn-release.manifest": 4096,
        f"{prefix}-vpn-release.sig": 89,
        f"{prefix}-vpn-engine-sources.tar.gz": 220 * 1024 * 1024,
    }


def load_snapshot(path, version):
    rows = {}
    for raw in path.read_text().splitlines():
        fields = raw.split("\t")
        if len(fields) != 5:
            raise ValueError("Malformed release asset snapshot")
        identity, name, size_text, state, digest = fields
        if name in rows or not identity.isdigit() or state != "uploaded":
            raise ValueError("Duplicate or incomplete release asset")
        try: size = int(size_text)
        except ValueError: raise ValueError("Invalid release asset size")
        rows[name] = (identity, size, digest)
    limits = expected(version)
    if set(rows) != set(limits):
        raise ValueError("Release draft has missing or unexpected assets")
    for name, (_, size, digest) in rows.items():
        if not 0 < size <= limits[name]:
            raise ValueError("Release asset size is outside its bound")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("Release asset has no canonical SHA-256 digest")
    return rows


def verify_files(directory, rows):
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
        raise ValueError("Expected an absolute ordinary asset directory")
    actual = {entry.name for entry in directory.iterdir()}
    if actual != set(rows):
        raise ValueError("Downloaded asset set changed")
    for name, (_, expected_size, expected_digest) in rows.items():
        path = directory / name
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != expected_size:
                raise ValueError("Downloaded release asset metadata changed")
            digest = hashlib.sha256()
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block: break
                digest.update(block)
        finally:
            os.close(descriptor)
        if "sha256:" + digest.hexdigest() != expected_digest:
            raise ValueError("Downloaded release asset digest changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--assets", type=Path)
    args = parser.parse_args()
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", args.version):
        parser.error("Expected canonical version")
    try:
        rows = load_snapshot(args.snapshot, args.version)
        if args.assets: verify_files(args.assets, rows)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"Verified immutable draft snapshot for ProxyPilot {args.version}")


if __name__ == "__main__":
    main()
