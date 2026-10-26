"""Freeze the reviewed Universal bridge images. Never execute or re-sign them."""
from pathlib import Path
import hashlib
import os
import re
import stat
import subprocess
import sys

# Same fixed images selected by VPNBridgeWorkerSelection/Identity in production.
IMAGES = {
    'gost': (70633296, '28666449b54ac0e63c70073bb75844fca6471488b745240dbe401ec2cfa405e7',
             'kz.documentolog.proxypilot.bridge.gost',
             {'arm64': 'f853a72a626e8b59dd768dc3b011b3d617626602',
              'x86_64': 'a29dc60b0d6ffb7de83e24cbaa91528c6aef7fb0'}),
    'system-resolver': (12059104, 'abc84ad3900b56158ad0020a3d0647b890b0a98d860f05d47d0d0d2a5d585bf5',
                        'kz.documentolog.proxypilot.system-resolver',
                        {'arm64': '7a9452fca18d77d7dfa8894b550d73b2797c9387',
                         'x86_64': 'bc859eaa7dbae1cd550060e54c6a7cf8e2089022'}),
}


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def inspect(arguments):
    result = subprocess.run(arguments, capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError('signatureRefused')
    return (result.stdout + result.stderr).decode('utf-8', errors='strict')


def snapshot(source, destination, name):
    size, digest, identifier, hashes = IMAGES[name]
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not (stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid in (0, os.getuid()) and before.st_mode & 0o022 == 0
                and before.st_mode & 0o111 and before.st_size == size):
            raise ValueError('imageRefused')
        output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            sha = hashlib.sha256()
            remaining = size
            while remaining:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError('imageChanged')
                sha.update(chunk)
                remaining -= len(chunk)
                view = memoryview(chunk)
                while view:
                    count = os.write(output, view)
                    if count <= 0:
                        raise ValueError('copyRefused')
                    view = view[count:]
            if os.read(fd, 1) or sha.hexdigest() != digest:
                raise ValueError('imageRefused')
            if identity(os.fstat(fd)) != identity(before) or identity(os.lstat(source)) != identity(before):
                raise ValueError('imageChanged')
            os.fchmod(output, 0o755)
            os.fsync(output)
        finally:
            os.close(output)
    finally:
        os.close(fd)
    # Inspect the frozen copy, never a source path that could have been swapped.
    inspect(['/usr/bin/codesign', '--verify', '--strict', '--all-architectures', str(destination)])
    for arch, expected in hashes.items():
        info = inspect(['/usr/bin/codesign', '-d', '--verbose=4', '--arch', arch, str(destination)])
        if (re.findall(r'^Identifier=(.+)$', info, re.M) != [identifier]
                or re.findall(r'^CDHash=([a-f0-9]{40})$', info, re.M) != [expected]):
            raise ValueError('signatureRefused')
    if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
        raise ValueError('imageChanged')


def stage(gost, resolver, destination):
    if sys.platform != 'darwin' or os.getuid() != os.geteuid() or os.getuid() < 500:
        raise ValueError('ordinaryMacOSBuilderRequired')
    paths = [Path(value) for value in (gost, resolver, destination)]
    if any(not path.is_absolute() for path in paths):
        raise ValueError('absolutePathsRequired')
    gost, resolver, destination = paths
    destination.mkdir(mode=0o700)  # Exclusive: never overwrite a prior assembly.
    try:
        snapshot(gost, destination / 'gost', 'gost')
        snapshot(resolver, destination / 'system-resolver', 'system-resolver')
    except BaseException:
        for name in IMAGES:
            (destination / name).unlink(missing_ok=True)
        destination.rmdir()
        raise


if __name__ == '__main__':
    try:
        if len(sys.argv) != 4:
            raise ValueError('argumentsRefused')
        stage(*sys.argv[1:])
    except Exception:
        print('Bridge image staging refused', file=sys.stderr)
        raise SystemExit(1)
