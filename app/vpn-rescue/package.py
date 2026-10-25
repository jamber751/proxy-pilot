#!/usr/bin/env python3
"""Assemble a local, exact two-leg VPN repair package; never install or publish.

prepare emits unsigned statements without accessing keys. Only the explicit
sign command invokes the existing release-signing tool. build requires every
signature and the rescue executable's non-mutating package verifier to succeed.
"""
import argparse
import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
APP_ID = 'kz.documentolog.proxypilot'
RESCUE_ID = APP_ID + '.vpn-rescue'
INSTALL_PATH = Path('/Library/Application Support/ProxyPilot/Rescue')
SAFE_ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
METADATA = {'source-release.manifest', 'source-release.sig', 'first-transition',
            'first-transition.sig', 'finish-first', 'finish-first.sig',
            'prepare-second', 'prepare-second.sig', 'finish-second', 'finish-second.sig'}
CANDIDATE = {'ProxyPilot.app', 'vpn-release.manifest', 'vpn-release.sig', 'vpn-helper',
             'vpn-previous-release.manifest', 'vpn-previous-release.sig',
             'vpn-update-transition', 'vpn-update-transition.sig'}
OPERATIONS = {'finish-first': 'finish-root-owned-destination-and-cleanup',
              'prepare-second': 'prepare-root-owned-update-and-authorize-replacement',
              'finish-second': 'finish-root-owned-destination-and-cleanup'}
_spec = importlib.util.spec_from_file_location('vpn_standard_package', HERE.parent / 'vpn-package/package.py')
joint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(joint)


def run(*args):
    result = subprocess.run(list(map(str, args)), env=SAFE_ENV, capture_output=True,
                            text=True, timeout=180)
    if result.returncode:
        raise ValueError(f'{Path(str(args[0])).name} failed: {result.stderr.strip()}')
    return result.stdout + result.stderr


def regular_bytes(path, limit):
    if not path.is_absolute() or path.is_symlink():
        raise ValueError('Expected an absolute regular input without a symlink')
    return joint.regular_bytes(path, limit)


def directory(path):
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise ValueError('Expected an absolute directory without a symlink')


def tool(path):
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError('Expected an absolute regular executable signing tool')


def public_key(path):
    data = regular_bytes(path, 45)
    try:
        key = base64.b64decode(data[:-1], validate=True)
    except ValueError as error:
        raise ValueError('Invalid public key') from error
    if len(key) != 32 or base64.b64encode(key) + b'\n' != data:
        raise ValueError('Expected a canonical public key')
    return data


def exact_names(path, names):
    directory(path)
    if set(os.listdir(path)) != names:
        raise ValueError('Unexpected repair package files')


def candidate_names(path):
    expected = CANDIDATE | ({'vpn-engine'} if (path / 'vpn-engine').exists() else set())
    exact_names(path, expected)
    for name in expected - {'ProxyPilot.app'}:
        regular_bytes(path / name, 64 * 1024 * 1024 if name == 'vpn-engine'
                            else 32 * 1024 * 1024 if name == 'vpn-helper'
                            else 4096)
    if (path / 'ProxyPilot.app').is_symlink():
        raise ValueError('Candidate app must not be a symlink')
    return expected


def record(path, limit):
    return joint.canonical_record(regular_bytes(path, limit))


def statement(operation, previous, candidate, transition, artifact, pins):
    """Unsigned canonical codec; native signature verifiers remain authoritative."""
    if operation not in set(OPERATIONS.values()):
        raise ValueError('Unknown fixed rescue operation')
    fields = [('format', '1'), ('product', APP_ID), ('operation', operation),
              ('previous-manifest-sha256', hashlib.sha256(previous).hexdigest()),
              ('candidate-manifest-sha256', hashlib.sha256(candidate).hexdigest()),
              ('transition-sha256', hashlib.sha256(transition).hexdigest()),
              ('rescue-sha256', hashlib.sha256(artifact).hexdigest()),
              ('rescue-bytes', str(len(artifact))), ('rescue-arm64', pins['arm64']),
              ('rescue-x86_64', pins['x86_64'])]
    return ''.join(f'{key}={value}\n' for key, value in fields).encode('ascii')


def inputs(root, name):
    metadata, candidate = root / 'Metadata', root / 'Candidate'
    if name == 'finish-first':
        return [metadata / 'source-release.manifest', metadata / 'source-release.sig',
                candidate / 'vpn-previous-release.manifest', candidate / 'vpn-previous-release.sig',
                metadata / 'first-transition', metadata / 'first-transition.sig',
                metadata / name, root / 'Executable/vpn-rescue']
    return [candidate / 'vpn-previous-release.manifest', candidate / 'vpn-previous-release.sig',
            candidate / 'vpn-release.manifest', candidate / 'vpn-release.sig',
            candidate / 'vpn-update-transition', candidate / 'vpn-update-transition.sig',
            metadata / name, root / 'Executable/vpn-rescue']


def verify_releases(root, key_tool, public):
    tool(key_tool); public_key(public)
    candidate, metadata = root / 'Candidate', root / 'Metadata'
    for manifest, signature in ((metadata / 'source-release.manifest', metadata / 'source-release.sig'),
                                (candidate / 'vpn-previous-release.manifest', candidate / 'vpn-previous-release.sig'),
                                (candidate / 'vpn-release.manifest', candidate / 'vpn-release.sig')):
        regular_bytes(manifest, 4096); regular_bytes(signature, 89)
        run(key_tool, 'verify', manifest, signature, public)
    for name in ('finish-first', 'finish-second'):
        args = inputs(root, name)
        regular_bytes(args[4], 512); regular_bytes(args[5], 89)
        run(key_tool, 'verify-transition', *args[:6], public)


def verify_candidate(path, key_tool, public):
    """Static candidate checks; never execute an app carried by the package."""
    names = candidate_names(path)
    for prefix in ('vpn-previous-release', 'vpn-release'):
        run(key_tool, 'verify', path / (prefix + '.manifest'), path / (prefix + '.sig'), public)
    run(key_tool, 'verify-transition', path / 'vpn-previous-release.manifest',
        path / 'vpn-previous-release.sig', path / 'vpn-release.manifest', path / 'vpn-release.sig',
        path / 'vpn-update-transition', path / 'vpn-update-transition.sig', public)
    release = record(path / 'vpn-release.manifest', 4096)
    app = path / 'ProxyPilot.app'
    info = plistlib.loads(regular_bytes(app / 'Contents/Info.plist', 1024 * 1024))
    version = joint.version_of(app)
    if (release.get('version') != version
            or str(joint.release_sequence_of(app)) != release.get('sequence')
            or info.get('ProxyPilotVPNRootOwnedUpdateExecutor') != '1'):
        raise ValueError('Final candidate sealed identity or capability mismatch')
    app_pins = joint.pins(app, APP_ID)
    if any(release.get('app-' + arch) != app_pins[arch] for arch in app_pins):
        raise ValueError('Candidate app does not match signed release pins')
    for name, prefix, identifier, limit in (
            ('vpn-helper', 'helper', APP_ID + '.vpn-helper', 32 * 1024 * 1024),
            ('vpn-engine', 'engine', APP_ID + '.openvpn', 64 * 1024 * 1024)):
        if name not in names:
            if prefix == 'engine' and release.get('format') == '2':
                raise ValueError('Signed engine is missing')
            continue
        data = regular_bytes(path / name, limit)
        pins = joint.pins(path / name, identifier)
        if (release.get(prefix + '-bytes') != str(len(data))
                or release.get(prefix + '-sha256') != hashlib.sha256(data).hexdigest()
                or any(release.get(prefix + '-' + arch) != pins[arch] for arch in pins)):
            raise ValueError('Candidate helper/engine does not match signed release')
    return version


def validate_unsigned(root, key_tool, public):
    exact_names(root, {'Executable', 'Metadata', 'Candidate'})
    exact_names(root / 'Executable', {'vpn-rescue'})
    exact_names(root / 'Metadata', METADATA)
    candidate_names(root / 'Candidate')
    verify_releases(root, key_tool, public)
    version = verify_candidate(root / 'Candidate', key_tool, public)
    artifact = regular_bytes(root / 'Executable/vpn-rescue', 32 * 1024 * 1024)
    pins = joint.pins(root / 'Executable/vpn-rescue', RESCUE_ID)
    for name, operation in OPERATIONS.items():
        args = inputs(root, name)
        expected = statement(operation, regular_bytes(args[0], 4096),
            regular_bytes(args[2], 4096), regular_bytes(args[4], 512), artifact, pins)
        if regular_bytes(root / 'Metadata' / name, 2048) != expected:
            raise ValueError('Rescue statement does not match exact package inputs')
    return version


def copy_candidate(source, destination):
    names = candidate_names(source)
    destination.mkdir(mode=0o700)
    run('/usr/bin/ditto', '--noextattr', '--norsrc', source / 'ProxyPilot.app', destination / 'ProxyPilot.app')
    joint.normalize_application_permissions(destination / 'ProxyPilot.app')
    for name in names - {'ProxyPilot.app'}:
        content = regular_bytes(source / name, 64 * 1024 * 1024 if name == 'vpn-engine'
                                     else 32 * 1024 * 1024 if name == 'vpn-helper' else 4096)
        (destination / name).write_bytes(content)
        (destination / name).chmod(0o700 if name in ('vpn-helper', 'vpn-engine') else 0o600)


def verify_engine_material(stage, candidate):
    if not (candidate / 'vpn-engine').exists():
        return
    lock, provenance, _ = joint.source_material(stage / 'EngineSources')
    release = record(candidate / 'vpn-release.manifest', 4096)
    binary = regular_bytes(candidate / 'vpn-engine', 64 * 1024 * 1024)
    if (provenance.get('binarySHA256') != hashlib.sha256(binary).hexdigest()
            or release.get('engine-sha256') != provenance.get('binarySHA256')
            or release.get('engine-version') != lock['openvpn']['version']
            or release.get('engine-crypto-version') != lock['openssl']['version']):
        raise ValueError('Signed engine does not match its corresponding source material')


def copy_engine_sources(source, destination):
    _, _, files = joint.source_material(source)
    destination.mkdir(mode=0o700)
    # source_material returns only reviewed recipe/archive/license bytes. Never
    # copy unrelated siblings merely because expected source files were valid.
    for name, data in files.items():
        target = destination / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target.write_bytes(data); target.chmod(0o600)


def prepare(rescue, source_manifest, source_signature, first_transition, first_signature,
            candidate_stage, key_tool, public, output):
    joint.new_path(output); directory(candidate_stage); tool(key_tool); public_key(public)
    artifact = regular_bytes(rescue, 32 * 1024 * 1024)
    rescue_pins = joint.pins(rescue, RESCUE_ID)
    source = candidate_stage / 'Payload'
    candidate_names(source)
    verify_candidate(source, key_tool, public)
    verify_engine_material(candidate_stage, source)
    first_files = {'source-release.manifest': regular_bytes(source_manifest, 4096),
                   'source-release.sig': regular_bytes(source_signature, 89),
                   'first-transition': regular_bytes(first_transition, 512),
                   'first-transition.sig': regular_bytes(first_signature, 89)}
    output.mkdir(mode=0o700)
    root = output / 'Rescue'; root.mkdir(mode=0o700)
    executable, metadata = root / 'Executable', root / 'Metadata'
    executable.mkdir(mode=0o700); metadata.mkdir(mode=0o700)
    (executable / 'vpn-rescue').write_bytes(artifact); (executable / 'vpn-rescue').chmod(0o700)
    copy_candidate(source, root / 'Candidate')
    for name, data in first_files.items():
        (metadata / name).write_bytes(data); (metadata / name).chmod(0o600)
    for name, operation in OPERATIONS.items():
        args = inputs(root, name)
        payload = statement(operation, regular_bytes(args[0], 4096),
            regular_bytes(args[2], 4096), regular_bytes(args[4], 512), artifact, rescue_pins)
        (metadata / name).write_bytes(payload); (metadata / name).chmod(0o600)
        (metadata / (name + '.sig')).touch(mode=0o600)
    if (source / 'vpn-engine').exists():
        copy_engine_sources(candidate_stage / 'EngineSources', output / 'EngineSources')
    validate_unsigned(root, key_tool, public)
    print(f'Prepared unsigned local repair package: {output}')


def verify(stage, key_tool, public):
    directory(stage)
    root = stage / 'Rescue'
    version = validate_unsigned(root, key_tool, public)
    verify_engine_material(stage, root / 'Candidate')
    for name in OPERATIONS:
        signature = root / 'Metadata' / (name + '.sig')
        regular_bytes(signature, 89)
        command = 'verify-rescue-preparation' if name == 'prepare-second' else 'verify-rescue'
        run(key_tool, command, *inputs(root, name), signature, public)
    run(root / 'Executable/vpn-rescue', 'verify-package', root)
    return version


def sign(stage, key_tool, public, keychain=None):
    directory(stage)
    root = stage / 'Rescue'
    validate_unsigned(root, key_tool, public)
    pending = []
    for name in OPERATIONS:
        signature = root / 'Metadata' / (name + '.sig')
        info = signature.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Signature destination must be the existing regular placeholder')
        if info.st_size:
            regular_bytes(signature, 89)
            command = 'verify-rescue-preparation' if name == 'prepare-second' else 'verify-rescue'
            run(key_tool, command, *inputs(root, name), signature, public)
        else:
            pending.append((name, signature))
    # Validate every destination and existing signature before any Keychain
    # request or new signature publication. Partial signing can resume safely.
    if keychain is not None and (not keychain.is_absolute() or keychain.is_symlink()):
        raise ValueError('Expected an existing absolute Keychain path without a symlink')
    extra = ['--keychain', keychain] if keychain is not None else []
    if run(key_tool, 'public', *extra).strip() != public_key(public).decode().strip():
        raise ValueError('Existing signing key does not match expected public key; never rotate it')
    for name, signature in pending:
        command = 'sign-rescue-preparation' if name == 'prepare-second' else 'sign-rescue'
        run(key_tool, command, *inputs(root, name), signature, *extra)
        signature.chmod(0o600)
    verify(stage, key_tool, public)
    print('Signed and verified all exact repair statements. Nothing installed.')


def copy_root(source, destination):
    directory(source)
    run('/usr/bin/ditto', '--noextattr', '--norsrc', source, destination)
    for child in ('Executable', 'Metadata', 'Candidate'):
        (destination / child).chmod(0o700)
    destination.chmod(0o700)


def build(stage, key_tool, public, output):
    joint.new_path(output)
    version = verify(stage, key_tool, public)
    with tempfile.TemporaryDirectory(prefix='pp-vpn-rescue-package-') as work:
        work = Path(work)
        payload, scripts = work / 'Root', work / 'Scripts'
        scripts.mkdir(mode=0o700)
        target = payload / INSTALL_PATH.relative_to('/')
        target.parent.mkdir(mode=0o700, parents=True)
        (payload / 'Library').chmod(0o755)
        (payload / 'Library/Application Support').chmod(0o755)
        copy_root(stage / 'Rescue', target)
        copy_root(stage / 'Rescue', scripts / 'Rescue')
        for copied in (target, scripts / 'Rescue'):
            validate_unsigned(copied, key_tool, public)
            run(copied / 'Executable/vpn-rescue', 'verify-package', copied)
        for name in ('preinstall', 'postinstall'):
            shutil.copyfile(HERE / name, scripts / name)
            (scripts / name).chmod(0o755)
        if (stage / 'EngineSources').exists():
            copy_engine_sources(stage / 'EngineSources', scripts / 'EngineSources')
        # Candidate C is inert repair material. Installer must never relocate
        # its matching bundle identifier onto the live /Applications app.
        components = work / 'components.plist'
        components.write_bytes(plistlib.dumps([{
            'RootRelativeBundlePath': str(INSTALL_PATH.relative_to('/') / 'Candidate/ProxyPilot.app'),
            'BundleIsRelocatable': False, 'BundleIsVersionChecked': False,
            'BundleHasStrictIdentifier': True, 'BundleOverwriteAction': 'upgrade',
        }]))
        run('/usr/bin/pkgbuild', '--root', payload, '--install-location', '/',
            '--component-plist', components,
            '--ownership', 'recommended', '--identifier', RESCUE_ID, '--version', version,
            '--compression', 'legacy', '--min-os-version', '12.0', '--scripts', scripts, output)
    print(f'Built local repair package. Nothing installed: {output}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    prepare_mode = modes.add_parser('prepare')
    for name in ('rescue', 'source-manifest', 'source-signature', 'first-transition',
                 'first-signature', 'candidate-stage', 'output'):
        prepare_mode.add_argument('--' + name, type=Path, required=True)
    for name in ('sign', 'verify', 'build'):
        mode = modes.add_parser(name)
        mode.add_argument('--stage', type=Path, required=True)
        if name == 'sign': mode.add_argument('--keychain', type=Path)
        if name == 'build': mode.add_argument('--output', type=Path, required=True)
    for mode in modes.choices.values():
        mode.add_argument('--key-tool', type=Path, required=True)
        mode.add_argument('--public-key', type=Path, default=HERE.parent / 'vpn-release-public-key.txt')
    args = parser.parse_args()
    if os.geteuid() == 0: parser.error('Assemble as an ordinary user, never root')
    try:
        if args.mode == 'prepare':
            prepare(args.rescue, args.source_manifest, args.source_signature,
                    args.first_transition, args.first_signature, args.candidate_stage,
                    args.key_tool, args.public_key, args.output)
        elif args.mode == 'sign': sign(args.stage, args.key_tool, args.public_key, args.keychain)
        elif args.mode == 'verify':
            verify(args.stage, args.key_tool, args.public_key)
            print('Verified complete local repair package.')
        else: build(args.stage, args.key_tool, args.public_key, args.output)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        parser.error(str(error))


if __name__ == '__main__': main()
