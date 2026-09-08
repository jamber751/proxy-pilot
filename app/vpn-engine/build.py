#!/usr/bin/env python3
"""Offline, unprivileged Universal engine build. No install, profile or tunnel.

Input archives must already match the reviewed source lock. The output is a new
directory; dependencies are built locally, never found in Homebrew/PATH. Source
and license material accompanies the candidate, which is NOT enrolled in the
privileged helper's release manifest by this tool.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C',
       'SOURCE_DATE_EPOCH': '1788429817', 'ZERO_AR_DATE': '1',
       'MACOSX_DEPLOYMENT_TARGET': '11.0'}


def archive_bytes(path, digest):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 100 * 1024 * 1024:
            raise ValueError('Expected a bounded regular source archive')
        data = stream.read(100 * 1024 * 1024 + 1)
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('Source archive checksum mismatch')
    return data


def extract(data, folder, root):
    # Validate the whole archive before creating anything. No links, devices,
    # duplicate names, traversal or unbounded expansion, even for a pinned input.
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        members, names, total = [], set(), 0
        for member in archive:
            total += member.size
            if len(members) >= 30000 or member.size < 0 or total > 512 * 1024 * 1024:
                raise ValueError('Source archive is too large')
            name = PurePosixPath(member.name)
            if (not name.parts or name.parts[0] != root or name.is_absolute()
                    or '..' in name.parts or '\\' in member.name or name in names
                    or not (member.isfile() or member.isdir())
                    or (len(name.parts) == 1 and not member.isdir())):
                raise ValueError('Unsafe source archive entry')
            names.add(name)
            members.append(member)
        folder.mkdir(mode=0o700)
        for member in members:
            destination = folder.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, destination.open('xb') as output:
                    shutil.copyfileobj(source, output)
                destination.chmod(0o700 if member.mode & 0o111 else 0o600)
        return folder / root


def run(args, cwd, env, log):
    with log.open('a') as stream:
        result = subprocess.run(list(map(str, args)), cwd=cwd, env=env,
                                stdout=stream, stderr=subprocess.STDOUT, timeout=1200)
    if result.returncode:
        raise ValueError(f'{Path(str(args[0])).name} failed; see {log}')


def capture(args):
    return subprocess.check_output(list(map(str, args)), env=ENV, text=True, stderr=subprocess.STDOUT, timeout=30)


def check_binary(binary):
    if set(capture(['/usr/bin/lipo', '-archs', binary]).split()) != {'arm64', 'x86_64'}:
        raise ValueError('Expected exactly two architectures')
    for arch in ('arm64', 'x86_64'):
        headers = capture(['/usr/bin/otool', '-arch', arch, '-l', binary])
        if not re.search(r'\bminos 11\.0\b', headers):
            raise ValueError('Unexpected deployment target')
        if 'cmd LC_RPATH' in headers:
            raise ValueError('Runtime library search paths are forbidden')
        dependencies = capture(['/usr/bin/otool', '-arch', arch, '-L', binary])
        paths = re.findall(r'^\s+(\S+) \(compatibility version', dependencies, re.M)
        if not paths or any(not p.startswith(('/usr/lib/', '/System/Library/Frameworks/')) for p in paths):
            raise ValueError('Non-system dynamic dependency')
        if any('libssl' in p or 'libcrypto' in p for p in paths):
            raise ValueError('Crypto dependency must be statically linked')
        signature = capture(['/usr/bin/codesign', '-d', '--verbose=4', '--arch', arch, binary])
        flags = re.search(r'flags=0x([0-9a-f]+)', signature)
        if ('Identifier=kz.documentolog.proxypilot.openvpn\n' not in signature or not flags
                or int(flags.group(1), 16) & 0x10300 != 0x10300):
            raise ValueError('Missing engine code-signing protections')
    capture(['/usr/bin/codesign', '--verify', '--strict', binary])


def build(sources, output, jobs):
    if not sources.is_absolute() or not output.is_absolute() or output.exists() or output.is_symlink():
        raise ValueError('Use absolute inputs and a new output directory')
    lock_bytes, script_bytes = (HERE / 'sources.json').read_bytes(), Path(__file__).read_bytes()
    lock = json.loads(lock_bytes)
    blobs = {name: archive_bytes(sources / f'{name}-{item["version"]}.tar.gz', item['sha256'])
             for name, item in lock.items()}
    output.mkdir(mode=0o700)
    sdk = capture(['/usr/bin/xcrun', '--sdk', 'macosx', '--show-sdk-path']).strip()
    clang = capture(['/usr/bin/xcrun', '--find', 'clang']).strip()
    slices = []
    for arch in ('arm64', 'x86_64'):
        print(f'Building {arch} crypto and engine', flush=True)
        work = output / arch; work.mkdir(mode=0o700)
        ssl = extract(blobs['openssl'], work / 'crypto-source', 'openssl-' + lock['openssl']['version'])
        vpn = extract(blobs['openvpn'], work / 'vpn-source', 'openvpn-' + lock['openvpn']['version'])
        # Constant configured paths prevent temporary directory names entering
        # libcrypto. DESTDIR below stages everything in this new local directory.
        stage = work / 'crypto-stage'
        prefix = stage / 'proxypilot-build/crypto'
        flags = f'-O2 -arch {arch} -isysroot {sdk} -mmacosx-version-min=11.0'
        env = dict(ENV, CC=clang, CFLAGS=flags, LDFLAGS=f'-arch {arch} -isysroot {sdk} -mmacosx-version-min=11.0')
        log = work / 'build.log'
        run(['/usr/bin/perl', ssl / 'Configure', f'darwin64-{arch}-cc',
             '--prefix=/proxypilot-build/crypto', '--libdir=lib',
             '--openssldir=/Library/Application Support/ProxyPilot/VPN/openssl',
             'no-shared', 'no-module', 'no-dso', 'no-engine', 'no-autoload-config',
             'no-legacy', 'no-comp', 'no-tests', 'no-docs'], ssl, env, log)
        run(['/usr/bin/make', f'-j{jobs}', 'build_sw'], ssl, env, log)
        run(['/usr/bin/make', 'DESTDIR=' + str(stage), 'install_sw'], ssl, env, log)
        env.update(OPENSSL_CFLAGS=f'-I{prefix}/include',
                   OPENSSL_LIBS=f'{prefix}/lib/libssl.a {prefix}/lib/libcrypto.a', PKG_CONFIG='/usr/bin/false')
        run([vpn / 'configure', f'--host={arch}-apple-darwin', '--prefix=/proxypilot-build',
             '--with-crypto-library=openssl', '--without-openssl-engine',
             '--disable-lzo', '--disable-lz4', '--disable-plugins', '--disable-plugin-auth-pam',
             '--disable-plugin-down-root', '--disable-pkcs11', '--disable-dco',
             '--disable-dns-updown-by-default', '--disable-unit-tests'], vpn, env, log)
        run(['/usr/bin/make', f'-j{jobs}'], vpn, env, log)
        slices.append(vpn / 'src/openvpn/openvpn')
    artifact = output / 'artifact'; artifact.mkdir(mode=0o700)
    binary = artifact / 'openvpn'
    capture(['/usr/bin/lipo', '-create', *slices, '-output', binary])
    binary.chmod(0o700)
    capture(['/usr/bin/codesign', '--force', '--sign', '-', '--identifier',
             'kz.documentolog.proxypilot.openvpn', '--options', 'runtime,hard,kill', binary])
    check_binary(binary)
    version = capture([binary, '--version'])
    if f'OpenVPN {lock["openvpn"]["version"]}' not in version or f'OpenSSL {lock["openssl"]["version"]}' not in version:
        raise ValueError('Runtime version mismatch')
    (artifact / 'version.txt').write_text(version)
    # Non-network upstream self-test mode, with fresh internal test keys. Never
    # loads the user's profile or opens a TUN interface; no test keys go to disk.
    for cipher in ('AES-128-GCM', 'AES-256-GCM', 'CHACHA20-POLY1305', 'AES-128-CBC', 'AES-256-CBC'):
        run([binary, '--test-crypto', '--cipher', cipher, '--verb', '3'], artifact, ENV, artifact / 'crypto-check.log')
    strings = capture(['/usr/bin/strings', binary])
    if str(output) in strings or '/opt/homebrew/' in strings:
        raise ValueError('Build-specific or Homebrew path embedded in engine')
    source_output = artifact / 'sources'; source_output.mkdir()
    for name, item in lock.items():
        (source_output / f'{name}-{item["version"]}.tar.gz').write_bytes(blobs[name])
    (source_output / 'sources.json').write_bytes(lock_bytes)
    (source_output / 'build.py').write_bytes(script_bytes)
    for name, source in [('OpenVPN-COPYING.txt', vpn / 'COPYING'),
                         ('OpenVPN-GPL-2.0.txt', vpn / 'COPYRIGHT.GPL'),
                         ('OpenSSL-LICENSE.txt', ssl / 'LICENSE.txt')]:
        shutil.copyfile(source, artifact / name)
    provenance = dict(sources=lock, minimumOS='11.0', architectures=['arm64', 'x86_64'],
                      sdk=sdk, compiler=capture([clang, '--version']),
                      binarySHA256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                      note='Candidate only; not installed or authorized by the VPN helper')
    (artifact / 'provenance.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print(f'Built {artifact}. No VPN started; no system installation.', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--jobs', type=int, choices=range(1, 9), default=4)
    args = parser.parse_args()
    if sys.platform != 'darwin' or os.getuid() == 0 or os.getuid() != os.geteuid():
        parser.error('Build as an ordinary macOS user')
    try:
        build(args.sources, args.output, args.jobs)
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
