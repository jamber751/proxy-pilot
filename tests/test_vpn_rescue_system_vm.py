"""Actual Installer/system-launchd rescue in a fresh disposable macOS CI VM.

Builds synthetic releases and production code with only its public trust constant
changed. Frozen139 uses its full SHA-pinned production source graph. The C app is
a signed probe-only bundle using the production read-only frontend entry; this
does not claim GUI or live corporate VPN/OTP acceptance. Never run root on a host.
"""
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'app/vpn-helper'
REVISION = 'e80b8be8dcf85d985b960ac5e1b4726469b5bce9'
SAFE_ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
SYSTEM_BASE = Path('/Library/Application Support/ProxyPilot')
PUBLIC_ENDPOINT = Path('/Library/Application Support/kz.documentolog.proxypilot.vpn')
APPLICATION = Path('/Applications/ProxyPilot.app')
PACKAGE_ID = 'kz.documentolog.proxypilot.vpn-rescue'
LABELS = ('kz.documentolog.proxypilot.vpn-helper', 'kz.documentolog.proxypilot.vpn-recovery',
          'kz.documentolog.proxypilot.vpn-update-broker')
PLISTS = tuple(Path('/Library/LaunchDaemons') / (name + '.plist') for name in LABELS)


def command(arguments, *, timeout=300, accepted=(0,), env=None):
    result = subprocess.run(list(map(str, arguments)), env=env or SAFE_ENV,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode not in accepted:
        # All artifacts and input below are synthetic. Avoid dumping unrelated
        # install.log/launchd environment or any profile/state payload.
        raise AssertionError(f'{Path(str(arguments[0])).name} exit={result.returncode}\n'
                             + result.stdout[-4000:] + result.stderr[-4000:])
    return result


def code_pins(path):
    pins = {}
    for arch in ('arm64', 'x86_64'):
        result = command(['/usr/bin/codesign', '-d', '--verbose=4', '--arch', arch, path])
        match = re.search(r'^CDHash=([a-f0-9]{40})$', result.stderr, re.M)
        if not match: raise AssertionError('Missing architecture signature')
        pins[arch] = match[1]
    return pins


def compile_universal(sources, output, *, flags=(), compiler='/usr/bin/swiftc', optimize=True):
    slices = []
    for arch in ('arm64', 'x86_64'):
        target = output.with_name(output.name + '-' + arch)
        options = ['-O', '-parse-as-library'] if optimize and compiler.endswith('swiftc') else []
        command([compiler, *options, *flags, '-target', arch + '-apple-macosx11.0', *sources, '-o', target], timeout=600)
        slices.append(target)
    command(['/usr/bin/lipo', '-create', *slices, '-output', output])
    output.chmod(0o700)


def sign(path, identifier):
    command(['/usr/bin/codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
             '--identifier', identifier, path])


def inject_trust(path, public):
    original = path.read_text()
    changed, count = re.subn(r'(static let publicKey = ")[A-Za-z0-9+/=]+(")',
                            lambda match: match[1] + public + match[2], original)
    if count != 1: raise AssertionError('Unexpected trust declaration')
    path.write_text(changed)


def snapshot_current(output):
    app = output / 'current/app'; (app / 'vpn-helper').mkdir(parents=True, mode=0o700)
    for name in ('VPNConfiguration.swift', 'VPNProfileImporter.swift', 'vpn-release-key.swift'):
        shutil.copyfile(ROOT / 'app' / name, app / name)
    for source in sorted(HELPER.glob('*.swift')):
        shutil.copyfile(source, app / 'vpn-helper' / source.name)
    shutil.copyfile(HELPER / 'build.sh', app / 'vpn-helper/build.sh')
    for folder, names in (('vpn-rescue', ('build.sh', 'package.py', 'preinstall', 'postinstall')),
                          ('vpn-package', ('package.py',)),
                          ('vpn-engine', ('build.py', 'sources.json'))):
        destination = app / folder; destination.mkdir(mode=0o700)
        for name in names: shutil.copyfile(ROOT / 'app' / folder / name, destination / name)
    return app


def snapshot_frozen(output, public):
    manifest = ROOT / 'tests/fixtures/vpn-frozen139-production-sources.sha256'
    expected = {}
    for row in manifest.read_text().splitlines():
        digest, name = row.split('  ', 1); expected[name] = digest
    helper_names = command(['git', '-c', 'safe.directory=' + str(ROOT), '-C', ROOT,
                            'ls-tree', '-r', '--name-only', REVISION, 'app/vpn-helper']).stdout.splitlines()
    names = {'app/VPNConfiguration.swift', 'app/VPNProfileImporter.swift', 'app/vpn-helper/build.sh'}
    names |= {name for name in helper_names if name.endswith('.swift')}
    if names != set(expected): raise AssertionError('Frozen production graph differs from pinned manifest')
    frozen = output / 'frozen'
    for name in sorted(names):
        result = subprocess.run(['git', '-c', 'safe.directory=' + str(ROOT), '-C', str(ROOT),
                                 'show', REVISION + ':' + name], capture_output=True, timeout=30, check=True)
        if hashlib.sha256(result.stdout).hexdigest() != expected[name]:
            raise AssertionError('Frozen source SHA256 mismatch')
        destination = frozen / name; destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination.write_bytes(result.stdout)
    inject_trust(frozen / 'app/vpn-helper/VPNReleaseTrust.swift', public)
    shutil.copyfile(manifest, output / 'frozen-production-before-trust.sha256')
    return frozen / 'app'


def make_app(path, binary, version, sequence, *, capable=False):
    contents = path / 'Contents'
    (contents / 'MacOS').mkdir(parents=True, mode=0o755)
    (contents / 'Resources').mkdir(mode=0o755)
    (contents / 'Resources/data.txt').write_text('Synthetic release ' + str(sequence))
    shutil.copyfile(binary, contents / 'MacOS/ProxyPilot'); (contents / 'MacOS/ProxyPilot').chmod(0o755)
    info = dict(CFBundleIdentifier='kz.documentolog.proxypilot', CFBundleExecutable='ProxyPilot',
                CFBundlePackageType='APPL', CFBundleVersion=version, CFBundleShortVersionString=version,
                CFBundleName='ProxyPilot', LSMinimumSystemVersion='11.0', ProxyPilotVPNInstaller=True,
                ProxyPilotVPNReleaseSequence=sequence)
    if capable: info['ProxyPilotVPNRootOwnedUpdateExecutor'] = '1'
    (contents / 'Info.plist').write_bytes(plistlib.dumps(info))
    for item in (path, *path.rglob('*')):
        item.chmod(0o755 if item.is_dir() else 0o644)
    (contents / 'MacOS/ProxyPilot').chmod(0o755)
    sign(path, 'kz.documentolog.proxypilot')


def phase(name):
    print('System rescue build: ' + name, flush=True)


def semantic_preflight(seed, output):
    """Production signature/parser/edge checks before expensive compilation.

    Bounded synthetic bytes are used only for pure record validation here;
    they are never packaged or described as actual engine source provenance.
    """
    base = output / 'SemanticPreflight'; base.mkdir(mode=0o700)
    (base / 'CandidateStage/Payload').mkdir(parents=True, mode=0o700)
    blob = base / 'bounded-input'; blob.write_bytes(b'synthetic semantic input')
    inputs = {name: str(blob) for name in ('helperB', 'helperC', 'engineB')}
    for name in ('appA', 'appB', 'appC', 'helperB', 'helperC', 'engineB'):
        for arch in ('arm64', 'x86_64'): inputs[name + '-' + arch] = 'a' * 40
    (base / 'input.json').write_text(json.dumps(inputs))
    command([seed, 'materials', base])


def build_real_engine(app, output):
    """Fetch reviewed archives, verify their exact hashes, then build offline."""
    source = output / 'EngineArchives'; source.mkdir(mode=0o700)
    lock = json.loads((app / 'vpn-engine/sources.json').read_text())
    for name, item in lock.items():
        phase('download reviewed ' + name + ' source')
        archive = source / (name + '-' + item['version'] + '.tar.gz')
        command(['/usr/bin/curl', '--disable', '--fail', '--location', '--proto', '=https',
                 '--proto-redir', '=https', '--connect-timeout', '30', '--max-time', '300',
                 '--max-filesize', str(100 * 1024 * 1024), '--output', archive, item['url']], timeout=320)
        if (not archive.is_file() or archive.is_symlink()
                or not 0 < archive.stat().st_size <= 100 * 1024 * 1024
                or hashlib.sha256(archive.read_bytes()).hexdigest() != item['sha256']):
            raise AssertionError('Reviewed engine source checksum mismatch')
    phase('build Universal OpenSSL/OpenVPN and run nonnetwork crypto checks')
    try:
        command(['/usr/bin/python3', app / 'vpn-engine/build.py', '--sources', source,
                 '--output', output / 'EngineBuild', '--jobs', '4'], timeout=2400)
    except (AssertionError, subprocess.TimeoutExpired):
        # These are our unprivileged, source-only compiler logs. Preserve the
        # actual error before CI discards the runner; never inspect system logs.
        for arch in ('arm64', 'x86_64'):
            log = output / 'EngineBuild' / arch / 'build.log'
            try:
                descriptor = os.open(log, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, 'rb') as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode): continue
                    stream.seek(max(0, info.st_size - 8192))
                    tail = stream.read(8192).decode('utf-8', errors='replace')
                print('System rescue engine build log tail (' + arch + '):\n' + tail, flush=True)
            except OSError:
                print('System rescue engine build log unavailable (' + arch + ')', flush=True)
        raise
    return output / 'EngineBuild/artifact'


def copy_engine_material(app, artifact, candidate_stage):
    # Use the production reader's exact allowlist rather than copying unrelated
    # build logs/binaries into the corresponding GPL source material.
    import importlib.util
    spec = importlib.util.spec_from_file_location('system_vm_joint_package', app / 'vpn-package/package.py')
    joint = importlib.util.module_from_spec(spec); spec.loader.exec_module(joint)
    _, provenance, files = joint.source_material(artifact)
    if provenance['binarySHA256'] != hashlib.sha256((artifact / 'openvpn').read_bytes()).hexdigest():
        raise AssertionError('Real engine binary/provenance mismatch')
    for name, data in files.items():
        destination = candidate_stage / 'EngineSources' / name
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination.write_bytes(data); destination.chmod(0o600)


def build_fixtures(output, *, compile_only=False):
    if sys.platform != 'darwin' or os.geteuid() == 0: raise AssertionError('Build only as an ordinary macOS user')
    if not compile_only and (os.environ.get('GITHUB_ACTIONS') != 'true'
                             or os.environ.get('PROXYPILOT_VM_SYSTEM_RESCUE_BUILD') != '1'):
        raise AssertionError('Package execution/assembly belongs to the disposable VM build step')
    if not output.is_absolute() or output.exists() or output.is_symlink(): raise AssertionError('New absolute build directory required')
    os.umask(0o077); output.mkdir(mode=0o700)
    app = snapshot_current(output); helper = app / 'vpn-helper'
    seed = output / 'system-seed'
    seed_sources = [helper / (name + '.swift') for name in (
        'VPNPeerAuthentication', 'VPNReleaseAuthorization', 'VPNHelperArtifact', 'VPNReleaseStore',
        'VPNLifecycleOwnership', 'VPNActivationBudget', 'VPNDirectoryProvisioner',
        'VPNEndpointDirectory', 'VPNHelperProtocol')]
    phase('compile small release seed and semantic verifier')
    compile_universal([*seed_sources, ROOT / 'tests/vpn_rescue_system_seed.swift'], seed)
    phase('verify synthetic A/B/C releases and both exact transitions')
    semantic_preflight(seed, output)
    public = command([seed, 'public']).stdout.strip()
    if len(base64.b64decode(public, validate=True)) != 32: raise AssertionError('Invalid synthetic public key')
    inject_trust(helper / 'VPNReleaseTrust.swift', public)
    frozen = snapshot_frozen(output, public)
    engine_artifact = None if compile_only else build_real_engine(app, output)
    phase('compile frozen139 helper')
    command(['/bin/zsh', frozen / 'vpn-helper/build.sh', output / 'frozen-helper'], timeout=900)
    phase('compile current helper')
    command(['/bin/zsh', helper / 'build.sh', output / 'current-helper'], timeout=900)
    phase('compile production rescue entry')
    command(['/bin/zsh', app / 'vpn-rescue/build.sh', output / 'rescue'], timeout=900)
    phase('compile signed installed-C read-only probe')
    probe = output / 'probe'
    probe_sources = [app / 'VPNConfiguration.swift', app / 'VPNProfileImporter.swift']
    probe_sources += [path for path in sorted(helper.glob('*.swift')) if path.name != 'ServiceMain.swift']
    compile_universal([*probe_sources, ROOT / 'tests/vpn_rescue_system_probe_main.swift'], probe)
    inert_source = output / 'inert.c'; inert_source.write_text('int main(void) { return 86; }\n')
    inert = output / 'inert'; compile_universal([inert_source], inert, compiler='/usr/bin/clang', optimize=False)
    # Compile-only mode exercises code generation without downloads or engine
    # packaging. Its inert bytes never receive GPL provenance or enter a pkg.
    engine_b = (engine_artifact / 'openvpn') if engine_artifact else output / 'compile-only-engine'
    if engine_artifact is None:
        shutil.copyfile(inert, engine_b); engine_b.chmod(0o700)
        sign(engine_b, 'kz.documentolog.proxypilot.openvpn')
    materials = output / 'Input'; materials.mkdir(mode=0o700)
    apps = materials / 'Apps'; apps.mkdir(mode=0o700)
    make_app(apps / 'A/ProxyPilot.app', inert, '1.6.0', 137)
    make_app(apps / 'B/ProxyPilot.app', inert, '1.7.0', 139)
    candidate = materials / 'CandidateStage/Payload'; candidate.mkdir(parents=True, mode=0o700)
    make_app(candidate / 'ProxyPilot.app', probe, '1.8.0', 141, capable=True)
    helper_b = output / 'frozen-helper/vpn-helper'; helper_c = output / 'current-helper/vpn-helper'
    shutil.copyfile(helper_c, candidate / 'vpn-helper'); (candidate / 'vpn-helper').chmod(0o700)
    inputs = {'helperB': str(helper_b), 'helperC': str(helper_c), 'engineB': str(engine_b)}
    for name, path in (('appA', apps / 'A/ProxyPilot.app'), ('appB', apps / 'B/ProxyPilot.app'),
                       ('appC', candidate / 'ProxyPilot.app'), ('helperB', helper_b), ('helperC', helper_c), ('engineB', engine_b)):
        for arch, pin in code_pins(path).items(): inputs[name + '-' + arch] = pin
    (materials / 'input.json').write_text(json.dumps(inputs, sort_keys=True))
    if compile_only:
        print('Compiled production graph artifacts only; no native entry, Installer or root operation executed.')
        return
    phase('verify actual signed fixture releases and transitions')
    command([seed, 'materials', materials])
    shutil.copyfile(engine_b, candidate / 'vpn-engine'); (candidate / 'vpn-engine').chmod(0o700)
    copy_engine_material(app, engine_artifact, materials / 'CandidateStage')
    first_payload = materials / 'FirstPayload'; first_payload.mkdir(mode=0o700)
    shutil.copytree(apps / 'B/ProxyPilot.app', first_payload / 'ProxyPilot.app')
    for source, name in ((helper_b, 'vpn-helper'), (engine_b, 'vpn-engine'),
                         (materials / 'source-release.manifest', 'vpn-previous-release.manifest'),
                         (materials / 'source-release.sig', 'vpn-previous-release.sig'),
                         (materials / 'first-transition', 'vpn-update-transition'),
                         (materials / 'first-transition.sig', 'vpn-update-transition.sig'),
                         (candidate / 'vpn-previous-release.manifest', 'vpn-release.manifest'),
                         (candidate / 'vpn-previous-release.sig', 'vpn-release.sig')):
        shutil.copyfile(source, first_payload / name)
        (first_payload / name).chmod(0o700 if name in ('vpn-helper', 'vpn-engine') else 0o600)
    phase('compile synthetic package signing tool')
    key_tool = output / 'synthetic-key-tool'
    key_sources = [helper / (name + '.swift') for name in (
        'VPNPeerAuthentication', 'VPNReleaseAuthorization', 'VPNReleaseTrust', 'VPNCompanionMetadata',
        'VPNRescueAuthorization', 'VPNRescuePreparationAuthorization')]
    compile_universal([*key_sources, app / 'vpn-release-key.swift', ROOT / 'tests/vpn_rescue_package_signer.swift'],
                      key_tool, flags=['-D', 'VPN_RELEASE_KEY_TESTING'])
    public_file = output / 'public-key'; public_file.write_text(public + '\n')
    phase('prepare and sign exact rescue capsule')
    assembler = app / 'vpn-rescue/package.py'; stage = output / 'PackageStage'
    command(['/usr/bin/python3', assembler, 'prepare', '--rescue', output / 'rescue/vpn-rescue',
             '--source-manifest', materials / 'source-release.manifest', '--source-signature', materials / 'source-release.sig',
             '--first-transition', materials / 'first-transition', '--first-signature', materials / 'first-transition.sig',
             '--candidate-stage', materials / 'CandidateStage', '--key-tool', key_tool,
             '--public-key', public_file, '--output', stage], timeout=300)
    command(['/usr/bin/python3', assembler, 'sign', '--stage', stage, '--key-tool', key_tool, '--public-key', public_file])
    phase('build real Installer package')
    package = output / 'repair.pkg'
    command(['/usr/bin/python3', assembler, 'build', '--stage', stage, '--key-tool', key_tool,
             '--public-key', public_file, '--output', package], timeout=300)
    # A second fully valid, separately signed capsule differs only in its first
    # exact edge. Preinstall must preserve it instead of superseding its material.
    foreign_materials = output / 'ForeignInput'; foreign_materials.mkdir(mode=0o700)
    shutil.copytree(materials / 'CandidateStage', foreign_materials / 'CandidateStage')
    foreign_inputs = dict(inputs, sourceSequence='138')
    (foreign_materials / 'input.json').write_text(json.dumps(foreign_inputs, sort_keys=True))
    command([seed, 'materials', foreign_materials])
    foreign_stage = output / 'ForeignPackageStage'
    command(['/usr/bin/python3', assembler, 'prepare', '--rescue', output / 'rescue/vpn-rescue',
             '--source-manifest', foreign_materials / 'source-release.manifest', '--source-signature', foreign_materials / 'source-release.sig',
             '--first-transition', foreign_materials / 'first-transition', '--first-signature', foreign_materials / 'first-transition.sig',
             '--candidate-stage', foreign_materials / 'CandidateStage', '--key-tool', key_tool,
             '--public-key', public_file, '--output', foreign_stage], timeout=300)
    command(['/usr/bin/python3', assembler, 'sign', '--stage', foreign_stage, '--key-tool', key_tool, '--public-key', public_file])
    fixture = dict(schema=1, owner=os.getuid(), materials=str(materials), seed=str(seed), probe=str(probe),
                   retainedRescue=str(stage / 'Rescue'), foreignRescue=str(foreign_stage / 'Rescue'), package=str(package),
                   packageSHA256=hashlib.sha256(package.read_bytes()).hexdigest(),
                   candidatePins=code_pins(candidate / 'ProxyPilot.app'),
                   sourcePins=code_pins(apps / 'A/ProxyPilot.app'), intermediatePins=code_pins(apps / 'B/ProxyPilot.app'))
    (output / 'fixture.json').write_text(json.dumps(fixture, sort_keys=True))
    print('Built synthetic Installer and actual production rescue/system helper artifacts. Nothing installed.')


REPAIR_PHASES = {'verifyInputs', 'firstReplace', 'cleanup', 'secondPrepare', 'secondReplace',
                 'waitRecovery', 'reconcileBroker', 'verifyFinal', 'retireRecovery', 'success'}
REPAIR_ERROR_CATEGORIES = {'liveIdentity', 'preparationIdentity', 'directory', 'store', 'broker',
                           'destinationStage', 'destinationExchange', 'protectedSwap', 'cleanup',
                           'installedResult', 'launchd', 'authorization', 'ownership', 'package',
                           'state', 'timeout', 'other'}


def repair_tokens(text):
    """Return only fixed diagnostics; never expose raw Installer log lines."""
    events = []
    pattern = r'ProxyPilot VPN repair (?:phase: ([A-Za-z]+)|failure category: ([A-Za-z]+)|could not be completed\.)'
    for match in re.finditer(pattern, text):
        if match.group(1) in REPAIR_PHASES: events.append(match.group(1))
        elif match.group(2) in REPAIR_ERROR_CATEGORIES: events.append('failure:' + match.group(2))
        elif match.group(1) is None and match.group(2) is None: events.append('repairRejected')
    return events


def launchd_diagnostics(text):
    """Whitelist fields only. Unknown strings and all raw paths are suppressed."""
    result = {}
    for field, key in (('pid', 'pid'), ('runs', 'runs'), ('last exit code', 'lastExitCode'),
                       ('last exit status', 'lastExitStatus'), ('spawn error', 'spawnErrno'),
                       ('last spawn error', 'spawnErrno'), ('last terminating signal', 'terminatingSignal')):
        match = re.search(r'^\s*' + field + r' = (-?(?:0x[0-9a-fA-F]{1,8}|[0-9]{1,10}))(?=\s|$)', text, re.M)
        if match:
            value = match[1]
            result[key] = int(value, 16 if '0x' in value else 10)
    if re.search(r'^\s*last exit (?:code|status) = \(never exited\)\s*$', text, re.M):
        result['lastExit'] = 'neverExited'
    state = re.search(r'^\s*state = ([a-z ]+)\s*$', text, re.M)
    if state and state[1].strip() in {'running', 'waiting', 'not running', 'exited', 'spawn scheduled',
                                     'spawn pending', 'spawned', 'initializing', 'throttled'}:
        result['state'] = state[1].strip()
    signal = re.search(r'^\s*last terminating signal = (SIG[A-Z0-9]+)\s*$', text, re.M)
    if signal and signal[1] in {'SIGKILL', 'SIGTERM', 'SIGABRT', 'SIGSEGV', 'SIGBUS', 'SIGILL', 'SIGTRAP'}:
        result['terminatingSignal'] = signal[1]
    if 'terminatingSignal' not in result:
        signal_number = re.search(r'^\s*last terminating signal = (?:Killed|Terminated|Abort trap): ([0-9]{1,3})\s*$', text, re.M)
        if signal_number: result['terminatingSignal'] = int(signal_number[1])
    return result


def helper_program_diagnostics(program, known):
    # An unrecognized program is classified without stat/open/codesign on its
    # path. Known keys come only from B/C manifests at the fixed service root.
    if program is None: return {'release': 'absent'}
    if program not in known: return {'release': 'unknown'}
    release, pins = known[program]
    result = {'release': release, 'filePresent': False}
    try:
        facts = os.lstat(program)
        result.update(filePresent=True, regular=stat.S_ISREG(facts.st_mode), rootOwned=facts.st_uid == 0,
                      privateMode=stat.S_IMODE(facts.st_mode) == 0o700, singleLink=facts.st_nlink == 1)
        if result['regular']:
            try: result['pinsMatch'] = code_pins(Path(program)) == pins
            except (AssertionError, OSError, subprocess.TimeoutExpired): result['pinsMatch'] = False
    except OSError: pass
    return result


def known_helper_programs(materials):
    result = {}
    payload = materials / 'CandidateStage/Payload'
    for release, name in (('B', 'vpn-previous-release.manifest'), ('C', 'vpn-release.manifest')):
        record = (payload / name).read_text()
        digest = re.search(r'^helper-sha256=([0-9a-f]{64})$', record, re.M)
        pins = {arch: re.search(r'^helper-' + arch + r'=([0-9a-f]{40})$', record, re.M)
                for arch in ('arm64', 'x86_64')}
        if not digest or not all(pins.values()): raise AssertionError('Invalid fixture helper metadata')
        path = str(SYSTEM_BASE / 'VPN' / ('helper-' + digest[1]))
        result[path] = (release, {arch: match[1] for arch, match in pins.items()})
    return result


def install_log_cursor():
    if not root_vm_enabled(): raise AssertionError('Installer log diagnostics require disposable system VM')
    try:
        descriptor = os.open('/var/log/install.log', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode): return None
            return info.st_dev, info.st_ino, info.st_size
    except OSError: return None


def install_log_tokens(cursor):
    if not root_vm_enabled(): raise AssertionError('Installer log diagnostics require disposable system VM')
    try:
        descriptor = os.open('/var/log/install.log', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode): return []
            same = cursor is not None and (info.st_dev, info.st_ino) == cursor[:2] and info.st_size >= cursor[2]
            # A rotated/replaced file can contain tokens from an earlier case.
            # Missing diagnostics are preferable to attributing those to this run.
            if cursor is not None and not same: return []
            start = cursor[2] if same else 0
            stream.seek(max(start, info.st_size - 1024 * 1024))
            text = stream.read(1024 * 1024).decode('utf-8', errors='replace')
        return repair_tokens(text)
    except OSError: return []


def root_vm_enabled():
    return (sys.platform == 'darwin' and os.getuid() == 0 and os.geteuid() == 0
            and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('PROXYPILOT_VM_SYSTEM_RESCUE_TESTS') == '1')


@unittest.skipUnless(root_vm_enabled(), 'explicit fresh disposable macOS system VM only')
class VPNRescueSystemVMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_root = Path(os.environ.get('PROXYPILOT_SYSTEM_RESCUE_FIXTURE', ''))
        if not fixture_root.is_absolute() or fixture_root.is_symlink(): raise AssertionError('Absolute fixture root required')
        cls.fixture = json.loads((fixture_root / 'fixture.json').read_text())
        if cls.fixture['schema'] != 1 or not 500 <= cls.fixture['owner'] < 2**32 - 1: raise AssertionError('Invalid fixture owner')
        cls.materials = Path(cls.fixture['materials']); cls.seed = Path(cls.fixture['seed']); cls.package = Path(cls.fixture['package'])
        cls.probe = Path(cls.fixture['probe'])
        cls.known_helpers = known_helper_programs(cls.materials)
        if hashlib.sha256(cls.package.read_bytes()).hexdigest() != cls.fixture['packageSHA256']:
            raise AssertionError('Prepared Installer changed')

    def setUp(self):
        for path in (SYSTEM_BASE, PUBLIC_ENDPOINT, APPLICATION, *PLISTS):
            if os.path.lexists(path): self.fail('System VM is not fresh; refusing existing ProxyPilot paths')
        if list(Path('/Applications').glob('.ProxyPilot.vpn-update*')):
            self.fail('System VM has existing replacement material; refusing setup')
        for label in LABELS:
            result = subprocess.run(['/bin/launchctl', 'print', 'system/' + label], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 113, 'Existing or unknown system job; refusing VM setup')
        receipt = subprocess.run(['/usr/sbin/pkgutil', '--pkg-info', PACKAGE_ID], capture_output=True, text=True, timeout=30)
        self.assertEqual(receipt.returncode, 1, 'Existing or unknown Installer receipt; refusing VM setup')
        SYSTEM_BASE.mkdir(mode=0o700)
        self.base_identity = (SYSTEM_BASE.stat().st_dev, SYSTEM_BASE.stat().st_ino)
        self.addCleanup(self.cleanup_own_system_fixture)
        service = SYSTEM_BASE / 'VPN'; service.mkdir(mode=0o700)
        update = SYSTEM_BASE / 'Update'; update.mkdir(mode=0o700)
        self.copy_root_app(self.materials / 'Apps/A/ProxyPilot.app', APPLICATION)
        for name, app in (('current', 'B'), ('candidate', 'A'), ('executor', 'A')):
            slot = update / name; slot.mkdir(mode=0o700)
            self.copy_root_app(self.materials / ('Apps/' + app + '/ProxyPilot.app'), slot / 'ProxyPilot.app')
        desired = 'on' if self._testMethodName.endswith('_on') else 'off'
        environment = dict(SAFE_ENV, GITHUB_ACTIONS='true', PROXYPILOT_VM_SYSTEM_RESCUE_TESTS='1')
        command([self.seed, 'seed', self.materials, str(self.fixture['owner']), desired], env=environment)
        self.initial_transaction = str(uuid.UUID(json.loads((service / 'update.json').read_text())['transactionID'])).lower()
        self.assertFalse((Path('/Applications') / '.ProxyPilot.vpn-update').exists())
        command([self.probe, '--vm-seed-broker'], env=environment)
        old_broker = subprocess.run(['/bin/launchctl', 'print', 'system/' + LABELS[2]],
                                    capture_output=True, text=True, timeout=10)
        self.assertEqual(old_broker.returncode, 0)
        match = re.search(r'^\s*pid = (\d+)', old_broker.stdout, re.M)
        self.assertIsNotNone(match); self.old_broker_pid = int(match[1])
        self.old_broker_program = plistlib.loads(PLISTS[2].read_bytes())['ProgramArguments'][0]
        self.assertIn('helper-', Path(self.old_broker_program).name)
        if 'phase6' in self._testMethodName:
            self.assertEqual(code_pins(APPLICATION), self.fixture['sourcePins'])
            shutil.rmtree(APPLICATION)
            self.copy_root_app(self.materials / 'Apps/B/ProxyPilot.app', APPLICATION)
            stage = Path('/Applications/.ProxyPilot.vpn-update'); stage.mkdir(mode=0o700)
            self.copy_root_app(self.materials / 'Apps/A/ProxyPilot.app', stage / 'ProxyPilot.app')
            temporary = tempfile.TemporaryDirectory(prefix='pp-system-first-payload-')
            self.addCleanup(temporary.cleanup)
            private_payload = Path(temporary.name) / 'Payload'
            self.copy_root_app(self.materials / 'FirstPayload', private_payload)
            command([self.probe, '--vm-seed-completed-broker', private_payload], env=environment)
            journal = json.loads((service / 'update.json').read_text())
            self.assertEqual((journal['phase'], journal['revision']), ('completed', 3))
            broker = (SYSTEM_BASE / 'Broker/update-broker-transaction.bin').read_bytes()
            self.assertEqual((len(broker), int.from_bytes(broker[10:12], 'big')), (128, 6))

    @staticmethod
    def copy_root_app(source, target):
        shutil.copytree(source, target, symlinks=True)
        for path in (target, *target.rglob('*')): os.chown(path, 0, 0, follow_symlinks=False)

    def cleanup_own_system_fixture(self):
        if not SYSTEM_BASE.exists(): return
        identity = (SYSTEM_BASE.stat().st_dev, SYSTEM_BASE.stat().st_ino)
        if identity != self.base_identity: raise AssertionError('Fixture namespace changed; refusing teardown')
        known_pids = set()
        for label in LABELS:
            current = subprocess.run(['/bin/launchctl', 'print', 'system/' + label],
                                     capture_output=True, text=True, timeout=30)
            match = re.search(r'^\s*pid = (\d+)', current.stdout, re.M)
            if match: known_pids.add(int(match[1]))
            command(['/bin/launchctl', 'bootout', 'system/' + label], accepted=(0, 3, 36, 113), timeout=30)
        deadline = time.monotonic() + 20
        while True:
            live = set()
            for pid in known_pids:
                try: os.kill(pid, 0); live.add(pid)
                except ProcessLookupError: pass
            loaded = [subprocess.run(['/bin/launchctl', 'print', 'system/' + label],
                                     capture_output=True, timeout=10).returncode for label in LABELS]
            if not live and loaded == [113] * len(LABELS): break
            if time.monotonic() >= deadline: raise AssertionError('Fixture jobs/processes remain; refusing teardown')
            time.sleep(0.1)
        for path in PLISTS:
            if path.exists(): path.unlink()
        if os.path.lexists(PUBLIC_ENDPOINT):
            info = PUBLIC_ENDPOINT.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o755:
                raise AssertionError('Unexpected public endpoint; refusing teardown')
            allowed = {'helper.sock', 'update-broker.sock', 'release-receipt.json'}
            if {path.name for path in PUBLIC_ENDPOINT.iterdir()} - allowed:
                raise AssertionError('Unknown public endpoint entry; refusing teardown')
            for name in ('helper.sock', 'update-broker.sock'):
                path = PUBLIC_ENDPOINT / name
                if not os.path.lexists(path): continue
                info = path.lstat()
                if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
                    raise AssertionError('Unexpected socket type/owner; refusing teardown')
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    connection.settimeout(1)
                    try: connection.connect(str(path))
                    except OSError as error:
                        if error.errno not in (errno.ECONNREFUSED, errno.ENOENT): raise
                    else: raise AssertionError('Socket still answers; refusing teardown')
                finally: connection.close()
                if os.path.lexists(path): path.unlink()
            environment = dict(SAFE_ENV, GITHUB_ACTIONS='true', PROXYPILOT_VM_SYSTEM_RESCUE_TESTS='1')
            command([self.seed, 'cleanup-endpoint'], env=environment)
        if APPLICATION.exists():
            metadata = plistlib.loads((APPLICATION / 'Contents/Info.plist').read_bytes())
            if metadata.get('CFBundleIdentifier') != 'kz.documentolog.proxypilot' or metadata.get('CFBundleVersion') not in ('1.6.0', '1.7.0', '1.8.0'):
                raise AssertionError('Unknown installed application; refusing teardown')
            if code_pins(APPLICATION) not in [self.fixture[key] for key in ('sourcePins', 'intermediatePins', 'candidatePins')]:
                raise AssertionError('Installed identity differs from seeded artifacts; refusing teardown')
            shutil.rmtree(APPLICATION)
        transactions = {getattr(self, 'initial_transaction', '')}
        service = SYSTEM_BASE / 'VPN'
        for name in ('update.json', 'cleanup.json'):
            record = service / name
            if not record.exists(): continue
            value = json.loads(record.read_text())
            if name == 'cleanup.json': value = value['journal']
            transactions.add(str(uuid.UUID(value['transactionID'])).lower())
        retired = SYSTEM_BASE / 'Retired'
        if retired.exists():
            for path in retired.iterdir(): transactions.add(str(uuid.UUID(path.name)).lower())
        allowed_stages = {'.ProxyPilot.vpn-update'} | {
            '.ProxyPilot.vpn-update.retired-' + transaction for transaction in transactions if transaction}
        # Original absence plus the owned store's transaction identities binds
        # cleanup to this fixture, rather than deleting arbitrary prefix matches.
        for path in Path('/Applications').glob('.ProxyPilot.vpn-update*'):
            if path.is_symlink() or path.name not in allowed_stages or path.stat().st_uid != 0:
                raise AssertionError('Unexpected replacement material; refusing teardown')
            shutil.rmtree(path)
        shutil.rmtree(SYSTEM_BASE)
        command(['/usr/sbin/pkgutil', '--forget', PACKAGE_ID], accepted=(0, 1), timeout=30)

    def state_summary(self):
        service = SYSTEM_BASE / 'VPN'
        result = {}
        for name in ('preparation.json', 'update.json', 'cleanup.json'):
            path = service / name
            if not path.exists(): result[name] = 'absent'; continue
            try:
                value = json.loads(path.read_text())
                result[name] = {key: value.get(key) for key in ('phase', 'revision')}
            except (ValueError, OSError): result[name] = 'unreadable'
        result['rescuePresent'] = (SYSTEM_BASE / 'Rescue').exists()
        result['destinationStagePresent'] = Path('/Applications/.ProxyPilot.vpn-update').exists()
        result['brokerBackupPresent'] = (SYSTEM_BASE / 'Broker/update-broker-rescue-rotation.bin').exists()
        for key, app in (('installedRelease', APPLICATION),
                         ('destinationStageRelease', Path('/Applications/.ProxyPilot.vpn-update/ProxyPilot.app'))):
            if not app.exists(): result[key] = 'absent'; continue
            try:
                pins = code_pins(app)
                result[key] = next((release for release, known in (
                    ('A', self.fixture['sourcePins']), ('B', self.fixture['intermediatePins']),
                    ('C', self.fixture['candidatePins'])) if pins == known), 'unknown')
            except (AssertionError, OSError, subprocess.TimeoutExpired): result[key] = 'unreadable'
        try:
            selected = json.loads((service / 'release.json').read_text())
            payload = base64.b64decode(selected['payload'], validate=True).decode('ascii')
            sequence = re.search(r'^sequence=([0-9]{1,19})$', payload, re.M)
            result['selectedSequence'] = int(sequence[1]) if sequence else 'invalid'
        except (ValueError, KeyError, OSError): result['selectedSequence'] = 'unreadable'
        try:
            budget = json.loads((service / 'activation.json').read_text())
            result['budget'] = {'desired': budget['desired'] if type(budget.get('desired')) is bool else 'invalid',
                                'failures': budget['failures'] if type(budget.get('failures')) is int else 'invalid'}
        except (ValueError, KeyError, OSError): result['budget'] = 'absentOrUnreadable'
        for role, label in zip(('helper', 'recovery', 'broker'), LABELS):
            try:
                job = subprocess.run(['/bin/launchctl', 'print', 'system/' + label],
                                     capture_output=True, text=True, timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                result[role] = {'queryStatus': 'unavailable'}
                continue
            values = {'present': job.returncode == 0, 'queryStatus': job.returncode}
            values.update(launchd_diagnostics(job.stdout))
            loaded = re.search(r'^\s*program = (.+?)\s*$', job.stdout, re.M)
            values['loadedProgram'] = helper_program_diagnostics(loaded[1] if loaded else None, self.known_helpers)
            # Only our three fixed plist files are read. Their unknown program
            # values are never followed, opened or printed.
            try:
                plist = plistlib.loads(PLISTS[LABELS.index(label)].read_bytes())
                args = plist.get('ProgramArguments')
                program = plist.get('Program')
                if program is None and isinstance(args, list) and args and isinstance(args[0], str): program = args[0]
                values['plistProgram'] = helper_program_diagnostics(program if isinstance(program, str) else None,
                                                                    self.known_helpers)
            except (OSError, ValueError, plistlib.InvalidFileException): values['plistProgram'] = {'release': 'unreadable'}
            result[role] = values
        return result

    def install(self):
        cursor = install_log_cursor()
        result = subprocess.run(['/usr/sbin/installer', '-dumplog', '-pkg', str(self.package), '-target', '/'],
                                env=SAFE_ENV, capture_output=True, text=True, timeout=420)
        events = {'command': repair_tokens(result.stdout + result.stderr),
                  'installLog': install_log_tokens(cursor)}
        print('System rescue Installer diagnostics: ' + repr(events), flush=True)
        self.assertEqual(result.returncode, 0, str(self.state_summary()) + '\nrepair events=' + repr(events))
        return result

    def assert_clean_c(self, desired):
        service = SYSTEM_BASE / 'VPN'
        selected = json.loads((service / 'release.json').read_text())
        payload = base64.b64decode(selected['payload']).decode()
        self.assertIn('sequence=141\n', payload)
        for name in ('preparation.json', 'update.json', 'cleanup.json'): self.assertFalse((service / name).exists())
        self.assertEqual({path.name for path in (SYSTEM_BASE / 'Update').iterdir()}, {'lifecycle.lock'})
        self.assertEqual(list((SYSTEM_BASE / 'Retired').iterdir()), [])
        self.assertFalse((SYSTEM_BASE / 'Rescue').exists())
        self.assertFalse((SYSTEM_BASE / 'Broker/update-broker-rescue-rotation.bin').exists())
        if 'phase6' in self._testMethodName:
            broker = (SYSTEM_BASE / 'Broker/update-broker-transaction.bin').read_bytes()
            self.assertEqual((len(broker), int.from_bytes(broker[10:12], 'big')), (128, 7))
        self.assertEqual(code_pins(APPLICATION), self.fixture['candidatePins'])
        child = command([APPLICATION / 'Contents/MacOS/ProxyPilot', '--vpn-verify-update-result'], accepted=(40, 41), timeout=15)
        self.assertEqual(child.returncode, 40 if desired else 41)
        budget = json.loads((service / 'activation.json').read_text()) if (service / 'activation.json').exists() else {'desired': True, 'failures': 0}
        self.assertEqual(budget['desired'], desired)
        if desired: self.assertEqual(budget['failures'], 0)
        # Recovery self-bootout is asynchronous; wait boundedly before asserting
        # no stale system job/description remains after successful repair.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            result = subprocess.run(['/bin/launchctl', 'print', 'system/' + LABELS[1]], capture_output=True, timeout=10)
            if result.returncode == 113: break
            time.sleep(0.1)
        self.assertEqual(result.returncode, 113)
        self.assertFalse(PLISTS[1].exists())
        helper = subprocess.run(['/bin/launchctl', 'print', 'system/' + LABELS[0]], capture_output=True, text=True, timeout=10)
        self.assertEqual(helper.returncode, 0 if desired else 113)
        match = re.search(r'^\s*pid = (\d+)', helper.stdout, re.M)
        helper_pid = int(match[1]) if match else None
        broker = subprocess.run(['/bin/launchctl', 'print', 'system/' + LABELS[2]], capture_output=True, text=True, timeout=10)
        self.assertEqual(broker.returncode, 0)
        match = re.search(r'^\s*pid = (\d+)', broker.stdout, re.M)
        self.assertIsNotNone(match)
        broker_pid = int(match[1])
        fields = dict(line.split('=', 1) for line in payload.splitlines())
        expected_program = str(service / ('helper-' + fields['helper-sha256']))
        self.assertEqual(plistlib.loads(PLISTS[2].read_bytes())['ProgramArguments'][0], expected_program)
        self.assertNotEqual(expected_program, self.old_broker_program)
        self.assertNotEqual(broker_pid, self.old_broker_pid)
        return helper_pid, broker_pid

    def exercise(self, desired):
        self.install()
        pids = self.assert_clean_c(desired)
        inode = APPLICATION.stat().st_ino
        self.install()
        self.assertEqual(APPLICATION.stat().st_ino, inode, 'Idempotent reinstall replaced an already valid C')
        self.assertEqual(self.assert_clean_c(desired), pids, 'Idempotent reinstall restarted helper/broker')

    def test_real_installer_repairs_pending137_through139_to_c_desired_off(self): self.exercise(False)
    def test_real_installer_repairs_pending137_through139_to_c_desired_on(self): self.exercise(True)

    def test_real_installer_resumes_identical_retained_rescue_desired_off(self):
        # A failed prior invocation retains this exact signed capsule. Actual
        # preinstall must admit equality without treating a directory ID as an
        # input hash or overwriting different rescue material.
        self.copy_root_app(Path(self.fixture['retainedRescue']), SYSTEM_BASE / 'Rescue')
        self.exercise(False)

    def test_real_installer_recovers_completed_service_and_broker_phase6_desired_on(self): self.exercise(True)

    def test_preinstall_preserves_different_valid_retained_rescue(self):
        self.copy_root_app(Path(self.fixture['foreignRescue']), SYSTEM_BASE / 'Rescue')
        service = SYSTEM_BASE / 'VPN'
        before = {name: (service / name).read_bytes() for name in ('release.json', 'update.json')}
        def material_snapshot():
            root = SYSTEM_BASE / 'Rescue'
            values = {}
            for path in (root, *root.rglob('*')):
                info = path.lstat()
                values[str(path.relative_to(root))] = (info.st_ino, info.st_mode, info.st_uid,
                    info.st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
            return values
        source = material_snapshot()
        result = subprocess.run(['/usr/sbin/installer', '-pkg', str(self.package), '-target', '/'],
                                env=SAFE_ENV, capture_output=True, text=True, timeout=120)
        self.assertNotEqual(result.returncode, 0, 'Preinstall overwrote different authorized rescue material')
        self.assertEqual({name: (service / name).read_bytes() for name in before}, before)
        self.assertEqual(material_snapshot(), source)
        self.assertEqual(code_pins(APPLICATION), self.fixture['sourcePins'])
        self.assertFalse(Path('/Applications/.ProxyPilot.vpn-update').exists())


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] in ('--build', '--compile-only'):
        build_fixtures(Path(sys.argv[2]), compile_only=sys.argv[1] == '--compile-only')
    else:
        unittest.main()
