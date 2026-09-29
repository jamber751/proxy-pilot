#!/usr/bin/env python3
"""Prepare separately signed VPN sidecars and build a scripts-only package.

Never installs, launches a GUI/helper, elevates, signs a release or accesses keys.
Only the candidate app's explicit non-mutating verification mode is executed.
"""
import argparse
import base64
import binascii
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import uuid

HERE = Path(__file__).resolve().parent
APP_ID = 'kz.documentolog.proxypilot'
SAFE_ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
JOINT_FILES = {'vpn-previous-release.manifest', 'vpn-previous-release.sig',
               'vpn-update-transition', 'vpn-update-transition.sig'}


def regular_bytes(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError('Expected a bounded regular artifact file')
        data = stream.read(limit + 1)
    if len(data) != info.st_size or len(data) > limit: raise ValueError('Artifact changed while reading')
    return data


def source_material(directory):
    """Exact corresponding sources and license bytes, never arbitrary siblings."""
    if (not directory.is_absolute() or directory.is_symlink() or not directory.is_dir()
            or (directory / 'sources').is_symlink() or not (directory / 'sources').is_dir()):
        raise ValueError('Expected a local engine artifact/source directory')
    recipe = HERE.parent / 'vpn-engine'
    lock_bytes = regular_bytes(directory / 'sources/sources.json', 16384)
    if lock_bytes != (recipe / 'sources.json').read_bytes(): raise ValueError('Unreviewed engine source lock')
    lock = json.loads(lock_bytes)
    build_bytes = regular_bytes(directory / 'sources/build.py', 1024 * 1024)
    if build_bytes != (recipe / 'build.py').read_bytes(): raise ValueError('Unexpected engine build recipe')
    files = {'sources/sources.json': lock_bytes, 'sources/build.py': build_bytes}
    licenses = {'openvpn': [('COPYING', 'OpenVPN-COPYING.txt'), ('COPYRIGHT.GPL', 'OpenVPN-GPL-2.0.txt')],
                'openssl': [('LICENSE.txt', 'OpenSSL-LICENSE.txt')]}
    for name, item in lock.items():
        archive_name = f'{name}-{item["version"]}.tar.gz'
        data = regular_bytes(directory / 'sources' / archive_name, 100 * 1024 * 1024)
        if hashlib.sha256(data).hexdigest() != item['sha256']: raise ValueError('Engine source checksum mismatch')
        files['sources/' + archive_name] = data
        # Archives match the reviewed hash before parsing; nothing is extracted
        # to the filesystem or executed. Notices must match their upstream text.
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            for source_name, notice_name in licenses[name]:
                member = archive.getmember(f'{name}-{item["version"]}/{source_name}')
                if not member.isfile() or not 0 < member.size <= 1024 * 1024: raise ValueError('Invalid license member')
                with archive.extractfile(member) as source: expected = source.read()
                notice = regular_bytes(directory / notice_name, 1024 * 1024)
                if notice != expected: raise ValueError('License notice does not match corresponding source')
                files[notice_name] = notice
    provenance = regular_bytes(directory / 'provenance.json', 16384)
    record = json.loads(provenance)
    if (not isinstance(record, dict) or record.get('sources') != lock or record.get('minimumOS') != '11.0'
            or record.get('architectures') != ['arm64', 'x86_64']):
        raise ValueError('Engine provenance does not match reviewed inputs')
    files['provenance.json'] = provenance
    return lock, record, files


def engine_candidate(directory):
    lock, record, sources = source_material(directory)
    data = regular_bytes(directory / 'openvpn', 64 * 1024 * 1024)
    if record.get('binarySHA256') != hashlib.sha256(data).hexdigest(): raise ValueError('Engine provenance checksum mismatch')
    return data, lock, sources


def check_engine_binary(path):
    # Only the repository's reviewed static checker is loaded. Never execute the
    # candidate's own version command or any script carried in its source bundle.
    spec = importlib.util.spec_from_file_location('vpn_engine_builder', HERE.parent / 'vpn-engine/build.py')
    builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
    builder.check_binary(path)


def run(*args):
    result = subprocess.run(list(map(str, args)), env=SAFE_ENV, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise ValueError(f'{Path(str(args[0])).name} failed: {result.stderr.strip()}')
    return result.stdout + result.stderr


def version_of(app):
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    version = info.get('CFBundleVersion', '')
    if (info.get('CFBundleIdentifier') != APP_ID or info.get('CFBundleShortVersionString') != version
            or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version)
            or any(int(part) > 2**63 - 1 for part in version.split('.'))
            or info.get('CFBundleExecutable') != 'ProxyPilot' or info.get('LSMinimumSystemVersion') != '11.0'
            or info.get('ProxyPilotVPNInstaller') is not True):
        raise ValueError('Unexpected app identity, version or minimum system')
    return version


def release_sequence_of(app):
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    sequence = info.get('ProxyPilotVPNReleaseSequence')
    if (not isinstance(sequence, int) or isinstance(sequence, bool)
            or sequence <= 0 or sequence > 2**63 - 1):
        raise ValueError('Expected a sealed positive VPN release sequence')
    return sequence


def pins(path, identifier):
    run('/usr/bin/codesign', '--verify', '--deep', '--strict', path)
    result = {}
    for architecture in ('arm64', 'x86_64'):
        output = run('/usr/bin/codesign', '-d', '--verbose=4', '--arch', architecture, path)
        digest = re.search(r'^CDHash=([a-f0-9]{40})$', output, re.M)
        flags = re.search(r'flags=0x([a-f0-9]+)', output)
        if (f'Identifier={identifier}\n' not in output or digest is None or flags is None
                or int(flags.group(1), 16) & 0x10300 != 0x10300):
            raise ValueError('Expected exact Universal hardened app/helper identity')
        result[architecture] = digest.group(1)
    return result


def new_path(path):
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise ValueError('Output must be a new absolute path; never overwrite a release')


def prepare(app, helper, sequence, output, engine_artifact=None):
    new_path(output)
    if (not app.is_absolute() or app.name != 'ProxyPilot.app' or app.is_symlink()
            or not helper.is_absolute() or not helper.is_file() or helper.is_symlink()):
        raise ValueError('Expected an app bundle and regular helper file at absolute paths')
    if not re.fullmatch(r'[1-9][0-9]{0,18}', sequence) or int(sequence) > 2**63 - 1:
        raise ValueError('Expected a canonical positive release sequence')
    version = version_of(app)
    if release_sequence_of(app) != int(sequence):
        raise ValueError('App VPN release sequence does not match package sequence')
    app_pins, helper_pins = pins(app, APP_ID), pins(helper, APP_ID + '.vpn-helper')
    executable = app / 'Contents/MacOS/ProxyPilot'
    if 'Sparkle.framework' in run('/usr/bin/otool', '-L', executable):
        raise ValueError('Installer app must use the isolated updater')
    data = regular_bytes(helper, 32 * 1024 * 1024)
    engine = engine_candidate(engine_artifact) if engine_artifact is not None else None
    output.mkdir(mode=0o700)
    payload = output / 'Payload'; payload.mkdir(mode=0o700)
    run('/usr/bin/ditto', '--noextattr', '--norsrc', app, payload / 'ProxyPilot.app')
    shutil.copyfile(helper, payload / 'vpn-helper'); (payload / 'vpn-helper').chmod(0o700)
    # Pin the completed signed app, then keep the manifest outside its seal.
    if pins(payload / 'ProxyPilot.app', APP_ID) != app_pins: raise ValueError('App changed while copying')
    if pins(payload / 'vpn-helper', APP_ID + '.vpn-helper') != helper_pins: raise ValueError('Helper changed while copying')
    if (payload / 'vpn-helper').read_bytes() != data: raise ValueError('Helper bytes changed while copying')
    fields = dict(format=1, product=APP_ID, sequence=sequence, version=version, protocol=1)
    fields.update({'app-arm64': app_pins['arm64'], 'app-x86_64': app_pins['x86_64'],
                   'helper-arm64': helper_pins['arm64'], 'helper-x86_64': helper_pins['x86_64'],
                   'helper-sha256': hashlib.sha256(data).hexdigest(), 'helper-bytes': len(data)})
    if engine is not None:
        binary, lock, sources = engine
        path = payload / 'vpn-engine'; path.write_bytes(binary); path.chmod(0o700)
        check_engine_binary(path)
        engine_pins = pins(path, APP_ID + '.openvpn')
        fields['format'] = 2
        fields.update({'engine-version': lock['openvpn']['version'], 'engine-crypto-version': lock['openssl']['version'],
                       'engine-arm64': engine_pins['arm64'], 'engine-x86_64': engine_pins['x86_64'],
                       'engine-sha256': hashlib.sha256(binary).hexdigest(), 'engine-bytes': len(binary)})
        # Separate distribution material; never copied to /Library or into the
        # app's seal, and never mixed with personal staging files.
        for name, content in sources.items():
            target = output / 'EngineSources' / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(content); target.chmod(0o600)
    (payload / 'vpn-release.manifest').write_text(''.join(f'{key}={value}\n' for key, value in fields.items()))
    (payload / 'vpn-release.manifest').chmod(0o600)
    (payload / 'vpn-release.sig').touch(mode=0o600)  # Signing tool replaces this fixed file.
    print('Prepared unsigned sidecars. Sign vpn-release.manifest separately; nothing installed.')


def verify(payload, action=None, allow_joint=False):
    expected = {'ProxyPilot.app', 'vpn-helper', 'vpn-release.manifest', 'vpn-release.sig'}
    if (payload / 'vpn-engine').exists() or (payload / 'vpn-engine').is_symlink(): expected.add('vpn-engine')
    actual = set(os.listdir(payload))
    if action == 'update': expected |= JOINT_FILES
    allowed = [expected]
    if allow_joint and action != 'update': allowed.append(expected | JOINT_FILES)
    if actual not in allowed:
        raise ValueError('Unexpected package files; never include profiles or staging leftovers')
    app = payload / 'ProxyPilot.app'
    version = version_of(app)
    pins(app, APP_ID)
    mode = '--vpn-support-verify-update' if action == 'update' else '--vpn-support-verify'
    run(app / 'Contents/MacOS/ProxyPilot', mode)
    return version


def prepare_update(stage, previous_manifest, previous_signature):
    if not stage.is_absolute() or stage.is_symlink() or not stage.is_dir():
        raise ValueError('Expected an existing absolute private stage')
    payload = stage / 'Payload'
    verify(payload)
    if any((payload / name).exists() or (payload / name).is_symlink() for name in JOINT_FILES):
        raise ValueError('Update sidecars already exist; never overwrite release input')
    previous = regular_bytes(previous_manifest, 4096)
    encoded = regular_bytes(previous_signature, 89)
    try:
        text = encoded.decode('ascii')
        if len(text) != 89 or not text.endswith('\n'):
            raise ValueError('non-canonical signature')
        decoded = base64.b64decode(text[:-1], validate=True)
    except (UnicodeDecodeError, ValueError, binascii.Error):
        raise ValueError('Invalid previous release signature encoding')
    if len(decoded) != 64 or base64.b64encode(decoded).decode('ascii') + '\n' != text:
        raise ValueError('Invalid previous release signature encoding')
    (payload / 'vpn-previous-release.manifest').write_bytes(previous)
    (payload / 'vpn-previous-release.sig').write_bytes(encoded)
    (payload / 'vpn-previous-release.manifest').chmod(0o600)
    (payload / 'vpn-previous-release.sig').chmod(0o600)
    for name in ('vpn-update-transition', 'vpn-update-transition.sig'):
        (payload / name).touch(mode=0o600)
    print('Prepared update sidecars. Sign the exact transition separately; nothing installed.')


def build(stage, action, output):
    new_path(output)
    if action not in ('install', 'update', 'remove'): raise ValueError('Unknown fixed action')
    if not stage.is_absolute() or stage.is_symlink(): raise ValueError('Expected an absolute staging directory')
    payload = stage / 'Payload'
    version = verify(payload, action=action, allow_joint=True)
    if (payload / 'vpn-engine').exists():
        lock, record, _ = source_material(stage / 'EngineSources')
        engine_data = regular_bytes(payload / 'vpn-engine', 64 * 1024 * 1024)
        values = dict(line.split('=', 1) for line in regular_bytes(payload / 'vpn-release.manifest', 4096).decode().splitlines())
        if (record.get('binarySHA256') != hashlib.sha256(engine_data).hexdigest()
                or values.get('engine-version') != lock['openvpn']['version']
                or values.get('engine-crypto-version') != lock['openssl']['version']):
            raise ValueError('Signed engine does not match corresponding source material')
    # Private scratch only; pkgbuild must never copy arbitrary staging siblings.
    with tempfile.TemporaryDirectory(prefix='pp-vpn-package-') as temporary:
        scripts = Path(temporary) / 'Scripts'; scripts.mkdir(mode=0o700)
        copied = scripts / 'Payload'; copied.mkdir(mode=0o700)
        run('/usr/bin/ditto', '--noextattr', '--norsrc', payload / 'ProxyPilot.app', copied / 'ProxyPilot.app')
        sidecars = ['vpn-helper', 'vpn-release.manifest', 'vpn-release.sig']
        if (payload / 'vpn-engine').exists(): sidecars.append('vpn-engine')
        if action == 'update': sidecars += sorted(JOINT_FILES)
        for name in sidecars:
            shutil.copyfile(payload / name, copied / name)
            (copied / name).chmod(0o700 if name in ('vpn-helper', 'vpn-engine') else 0o600)
        if verify(copied, action=action) != version: raise ValueError('Package changed while copying')
        preinstall = (HERE / 'preinstall').read_text()
        if action == 'update':
            preinstall = preinstall.replace('--vpn-support-verify', '--vpn-support-verify-update')
        (scripts / 'preinstall').write_text(preinstall)
        (scripts / 'postinstall').write_text((HERE / 'postinstall.in').read_text().replace('@ACTION@', action))
        for name in ('preinstall', 'postinstall'): (scripts / name).chmod(0o755)
        run('/usr/bin/codesign', '--verify', '--deep', '--strict', copied / 'ProxyPilot.app')
        run('/usr/bin/pkgbuild', '--nopayload', '--identifier', APP_ID + '.vpn-support.' + action,
            '--version', version, '--compression', 'legacy', '--min-os-version', '11.0',
            '--scripts', scripts, output)
    print(f'Built {action} package. Nothing installed: {output}')


def build_companion(stage, output):
    """Build one read-only joint-update artifact; never install or mount it."""
    new_path(output)
    if output.suffix != '.dmg' or not output.parent.is_absolute() or not output.parent.is_dir():
        raise ValueError('Companion output must be a new absolute .dmg in an existing directory')
    if not stage.is_absolute() or stage.is_symlink() or not stage.is_dir():
        raise ValueError('Expected an existing absolute private stage')
    payload = stage / 'Payload'
    version = verify(payload, action='update')
    actual = set(os.listdir(payload))
    expected = {'ProxyPilot.app', 'vpn-helper', 'vpn-engine',
                'vpn-release.manifest', 'vpn-release.sig'} | JOINT_FILES
    if actual != expected:
        raise ValueError('Companion requires the exact format-2 joint layout')

    temporary = output.parent / f'.{output.name}.{uuid.uuid4()}.tmp.dmg'
    try:
        run('/usr/bin/hdiutil', 'create', '-quiet', '-fs', 'APFS',
            '-format', 'UDZO', '-imagekey', 'zlib-level=9',
            '-volname', 'ProxyPilot VPN Update', '-srcfolder', payload, temporary)
        run('/usr/bin/hdiutil', 'verify', '-quiet', temporary)
        descriptor = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 768 * 1024 * 1024:
                raise ValueError('Companion image is not a bounded regular file')
            digest = hashlib.sha256()
            while True:
                block = os.read(descriptor, 1024 * 1024)
                if not block: break
                digest.update(block)
        finally:
            os.close(descriptor)
        temporary.chmod(0o600)
        # Atomic no-overwrite publication. A concurrent release cannot replace
        # an artifact that already acquired the final name.
        os.link(temporary, output, follow_symlinks=False)
        temporary.unlink()
        published = os.open(output, os.O_RDONLY | os.O_NOFOLLOW)
        try: os.fsync(published)
        finally: os.close(published)
        parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        if temporary.exists() or temporary.is_symlink(): temporary.unlink()
    print(f'Built companion joint artifact {version}: {output}')
    print(f'sha256={digest.hexdigest()}')
    print(f'bytes={info.st_size}')


def prepare_companion_metadata(stage, companion, output):
    """Bind one verified joint payload to one immutable transport image."""
    new_path(output)
    if (output.suffix != '.metadata' or not output.parent.is_dir()
            or not stage.is_absolute() or stage.is_symlink() or not stage.is_dir()
            or not companion.is_absolute() or companion.is_symlink()
            or not companion.is_file()):
        raise ValueError('Expected private stage, regular companion and new absolute .metadata output')
    payload = stage / 'Payload'
    version = verify(payload, action='update')
    expected_name = f'ProxyPilot-{version}-vpn-joint.dmg'
    if companion.name != expected_name:
        raise ValueError('Companion filename does not match the verified release version')

    def fields(name, limit):
        text = regular_bytes(payload / name, limit).decode('ascii')
        lines = text.splitlines()
        if not lines or not text.endswith('\n'):
            raise ValueError('Expected canonical signed release records')
        result = {}
        for line in lines:
            if line.count('=') != 1:
                raise ValueError('Expected canonical signed release records')
            key, value = line.split('=', 1)
            if not key or key in result: raise ValueError('Expected canonical signed release records')
            result[key] = value
        return result

    previous = fields('vpn-previous-release.manifest', 4096)
    candidate = fields('vpn-release.manifest', 4096)
    transition = fields('vpn-update-transition', 512)
    if (candidate.get('version') != version
            or transition.get('from-sequence') != previous.get('sequence')
            or transition.get('to-sequence') != candidate.get('sequence')):
        raise ValueError('Signed transition does not match companion metadata inputs')
    from_sequence, to_sequence = previous.get('sequence', ''), candidate.get('sequence', '')
    if (not re.fullmatch(r'[1-9][0-9]{0,18}', from_sequence)
            or not re.fullmatch(r'[1-9][0-9]{0,18}', to_sequence)
            or int(to_sequence) <= int(from_sequence)
            or int(to_sequence) > 2**63 - 1):
        raise ValueError('Expected a canonical forward companion transition')

    descriptor = os.open(companion, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not 0 < info.st_size <= 768 * 1024 * 1024):
            raise ValueError('Expected one bounded companion artifact')
        digest = hashlib.sha256()
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block: break
            digest.update(block)
    finally:
        os.close(descriptor)
    metadata = (f'format=1\nproduct={APP_ID}\nversion={version}\n'
                f'from-sequence={from_sequence}\nto-sequence={to_sequence}\n'
                f'artifact-sha256={digest.hexdigest()}\nartifact-bytes={info.st_size}\n').encode()
    if len(metadata) > 512: raise ValueError('Companion metadata is oversized')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(output, flags, 0o600)
    try:
        view = memoryview(metadata)
        while view:
            written = os.write(descriptor, view)
            if written <= 0: raise OSError('Cannot write companion metadata')
            view = view[written:]
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor); output.unlink(missing_ok=True)
        raise
    else:
        os.close(descriptor)
    parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(parent)
    finally: os.close(parent)
    print(f'Prepared companion metadata: {output}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    candidate = modes.add_parser('prepare')
    candidate.add_argument('--app', type=Path, required=True)
    candidate.add_argument('--helper', type=Path, required=True)
    candidate.add_argument('--engine-artifact', type=Path, help='Complete pinned engine builder artifact directory')
    candidate.add_argument('--sequence', required=True)
    candidate.add_argument('--output', type=Path, required=True)
    update = modes.add_parser('prepare-update')
    update.add_argument('--stage', type=Path, required=True)
    update.add_argument('--previous-manifest', type=Path, required=True)
    update.add_argument('--previous-signature', type=Path, required=True)
    package = modes.add_parser('build')
    package.add_argument('--stage', type=Path, required=True)
    package.add_argument('--action', choices=('install', 'update', 'remove'), required=True)
    package.add_argument('--output', type=Path, required=True)
    companion = modes.add_parser('build-companion')
    companion.add_argument('--stage', type=Path, required=True)
    companion.add_argument('--output', type=Path, required=True)
    metadata = modes.add_parser('prepare-companion-metadata')
    metadata.add_argument('--stage', type=Path, required=True)
    metadata.add_argument('--companion', type=Path, required=True)
    metadata.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0: parser.error('Build as an ordinary user, never root')
    try:
        if args.mode == 'prepare': prepare(args.app, args.helper, args.sequence, args.output, args.engine_artifact)
        elif args.mode == 'prepare-update': prepare_update(args.stage, args.previous_manifest, args.previous_signature)
        elif args.mode == 'build': build(args.stage, args.action, args.output)
        elif args.mode == 'build-companion': build_companion(args.stage, args.output)
        else: prepare_companion_metadata(args.stage, args.companion, args.output)
    except (ValueError, OSError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error: parser.error(str(error))


if __name__ == '__main__': main()
