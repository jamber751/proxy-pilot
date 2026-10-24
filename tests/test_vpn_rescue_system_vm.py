"""Actual Installer/system-launchd rescue in a fresh disposable macOS CI VM.

Builds synthetic releases from production code with a synthetic public trust
constant and closed activation-diagnostic output enabled for current code only.
No authentication or lifecycle policy is replaced. Frozen139 uses its unchanged
full SHA-pinned production source graph. The C app is
a signed probe-only bundle using the production read-only frontend entry; this
does not claim GUI or live corporate VPN/OTP acceptance. Never run root on a host.
"""
import base64
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import selectors
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
    phase('enable closed current-code activation diagnostics; frozen139 unchanged')
    for script, anchor in ((app / 'vpn-helper/build.sh', '-D VPN_RECOVERY_DAEMON_ENTRY'),
                           (app / 'vpn-rescue/build.sh', '-D VPN_RESCUE_SYSTEM_ENTRY')):
        text = script.read_text()
        if text.count(anchor) != 1: raise AssertionError('Current diagnostic build anchor changed')
        script.write_text(text.replace(anchor, anchor + ' -D VPN_SYSTEM_ACTIVATION_DIAGNOSTICS'))
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
    compile_universal([*probe_sources, ROOT / 'tests/vpn_rescue_system_probe_main.swift'], probe,
                      flags=['-D', 'VPN_INSTALLED_UPDATE_RESULT_DIAGNOSTICS', '-D', 'VPN_SYSTEM_ACTIVATION_DIAGNOSTICS'])
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
    successor = materials / 'SuccessorStage/Payload'; successor.mkdir(parents=True, mode=0o700)
    make_app(successor / 'ProxyPilot.app', probe, '1.9.0', 142, capable=True)
    helper_b = output / 'frozen-helper/vpn-helper'; helper_c = output / 'current-helper/vpn-helper'
    shutil.copyfile(helper_c, candidate / 'vpn-helper'); (candidate / 'vpn-helper').chmod(0o700)
    inputs = {'helperB': str(helper_b), 'helperC': str(helper_c), 'engineB': str(engine_b)}
    for name, path in (('appA', apps / 'A/ProxyPilot.app'), ('appB', apps / 'B/ProxyPilot.app'),
                       ('appC', candidate / 'ProxyPilot.app'), ('appD', successor / 'ProxyPilot.app'),
                       ('helperB', helper_b), ('helperC', helper_c), ('engineB', engine_b)):
        for arch, pin in code_pins(path).items(): inputs[name + '-' + arch] = pin
    (materials / 'input.json').write_text(json.dumps(inputs, sort_keys=True))
    if compile_only:
        print('Compiled production graph artifacts only; no native entry, Installer or root operation executed.')
        return
    phase('verify actual signed fixture releases and transitions')
    command([seed, 'materials', materials])
    shutil.copyfile(engine_b, candidate / 'vpn-engine'); (candidate / 'vpn-engine').chmod(0o700)
    copy_engine_material(app, engine_artifact, materials / 'CandidateStage')
    for source, name in ((helper_c, 'vpn-helper'), (engine_b, 'vpn-engine')):
        shutil.copyfile(source, successor / name); (successor / name).chmod(0o700)
    copy_engine_material(app, engine_artifact, materials / 'SuccessorStage')
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
    for arch in ('arm64', 'x86_64'): foreign_inputs.pop('appD-' + arch)
    (foreign_materials / 'input.json').write_text(json.dumps(foreign_inputs, sort_keys=True))
    command([seed, 'materials', foreign_materials])
    foreign_stage = output / 'ForeignPackageStage'
    command(['/usr/bin/python3', assembler, 'prepare', '--rescue', output / 'rescue/vpn-rescue',
             '--source-manifest', foreign_materials / 'source-release.manifest', '--source-signature', foreign_materials / 'source-release.sig',
             '--first-transition', foreign_materials / 'first-transition', '--first-signature', foreign_materials / 'first-transition.sig',
             '--candidate-stage', foreign_materials / 'CandidateStage', '--key-tool', key_tool,
             '--public-key', public_file, '--output', foreign_stage], timeout=300)
    command(['/usr/bin/python3', assembler, 'sign', '--stage', foreign_stage, '--key-tool', key_tool, '--public-key', public_file])
    fixture = dict(schema=2, owner=os.getuid(), materials=str(materials), seed=str(seed), probe=str(probe),
                   retainedRescue=str(stage / 'Rescue'), foreignRescue=str(foreign_stage / 'Rescue'), package=str(package),
                   packageSHA256=hashlib.sha256(package.read_bytes()).hexdigest(),
                   candidatePins=code_pins(candidate / 'ProxyPilot.app'),
                   successorPins=code_pins(successor / 'ProxyPilot.app'),
                   sourcePins=code_pins(apps / 'A/ProxyPilot.app'), intermediatePins=code_pins(apps / 'B/ProxyPilot.app'))
    (output / 'fixture.json').write_text(json.dumps(fixture, sort_keys=True))
    print('Built synthetic Installer and actual production rescue/system helper artifacts. Nothing installed.')


REPAIR_PHASES = {'verifyInputs', 'firstReplace', 'cleanup', 'secondPrepare', 'secondReplace',
                 'secondPending', 'protectedReady', 'protectedExchanged', 'protectedSynced', 'protectedValidated', 'destinationStaged',
                 'waitRecovery', 'reconcileBroker', 'verifyFinal', 'retireRecovery', 'success'}
REPAIR_ERROR_CATEGORIES = {'liveIdentity', 'preparationIdentity', 'directory', 'store', 'broker',
                           'destinationStage', 'destinationExchange', 'protectedSwap', 'cleanup',
                           'destinationLayout', 'destinationStorage', 'destinationUncertain',
                           'protectedStorage', 'protectedLayout', 'protectedExecutor', 'protectedRename', 'protectedUncertain',
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


ACTIVATION_LOG_DIRECTORY = Path('/private/tmp/kz.documentolog.proxypilot-vpn-activation-diagnostics')
ACTIVATION_ROLES = {'helper', 'finalizer', 'runtime', 'journal', 'readinessPolicy'}
ACTIVATION_STAGES = {'openStore', 'selection', 'journal', 'identity', 'runtime', 'budget', 'receipt',
                     'endpoint', 'listener', 'ready', 'charge', 'drain', 'start', 'readiness', 'finalValidation',
                     'budgetSuccess', 'complete', 'helperPath', 'description', 'bootstrap', 'connect', 'readinessPolicy'}
ACTIVATION_EVENTS = {'enter', 'complete', 'failure'}
ACTIVATION_CATEGORIES = {'none', 'storeBusy', 'storeState', 'activationOff', 'activationExhausted',
                         'activationState', 'launchTimeout', 'launchFailed', 'launchStorage', 'launchCleanup', 'readiness',
                         'readinessTimeout', 'readinessTransport', 'readinessResponse', 'endpoint',
                         'identity', 'journal', 'application', 'directory', 'other'}
ACTIVATION_ELAPSED = {'lt50', 'lt250', 'lt1000', 'lt2000', 'lt5000', 'ge5000'}


def activation_tokens(text):
    if not isinstance(text, str): return []
    result = []
    for row in text.splitlines():
        matched = re.fullmatch(r'ProxyPilot VPN activation role: ([A-Za-z]+); stage: ([A-Za-z]+); event: ([A-Za-z]+); category: ([A-Za-z]+); elapsed: ([A-Za-z0-9]+)', row)
        if not matched: continue
        values = matched.groups()
        if all(value in allowed for value, allowed in zip(values, (ACTIVATION_ROLES, ACTIVATION_STAGES,
                ACTIVATION_EVENTS, ACTIVATION_CATEGORIES, ACTIVATION_ELAPSED))):
            result.append(':'.join(values))
    return result


def activation_log_diagnostics(folder=ACTIVATION_LOG_DIRECTORY, owner=0, identity=None):
    result = {}; directory = -1
    try:
        directory = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(directory)
        if identity is not None and (info.st_dev, info.st_ino) != identity:
            return {'record': 'changed'}
        if info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
            return {'record': 'unsafe'}
        for name in ('helper.log', 'recovery.log'):
            descriptor = -1
            try:
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
                before = os.fstat(descriptor)
                if not stat.S_ISREG(before.st_mode) or before.st_uid != owner or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600:
                    result[name] = {'record': 'unsafe'}; continue
                offset = max(0, before.st_size - 65536)
                os.lseek(descriptor, offset, os.SEEK_SET)
                data = bytearray()
                while len(data) < 65536:
                    chunk = os.read(descriptor, 65536 - len(data))
                    if not chunk: break
                    data.extend(chunk)
                after = os.fstat(descriptor)
                named = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                        or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
                        or after.st_nlink != 1 or after.st_uid != owner or stat.S_IMODE(after.st_mode) != 0o600
                        or after.st_size < before.st_size):
                    result[name] = {'record': 'changed'}; continue
                text = data.decode('utf-8', errors='replace')
                if offset: text = text.partition(chr(10))[2]
                tokens = activation_tokens(text)
                result[name] = {'record': 'valid', 'truncated': offset > 0 or len(tokens) > 96, 'events': tokens[-96:]}
            except FileNotFoundError: result[name] = {'record': 'absent'}
            except OSError: result[name] = {'record': 'unreadable'}
            finally:
                if descriptor >= 0: os.close(descriptor)
    except FileNotFoundError: result = {'record': 'absent'}
    except OSError: result = {'record': 'unreadable'}
    finally:
        if directory >= 0: os.close(directory)
    return result


INSTALLED_RESULT_STAGES = {'openStore', 'snapshot', 'installedIdentity', 'selfIdentity',
                           'readiness', 'offState', 'finalSnapshot', 'finalSelfIdentity',
                           'finalInstalledIdentity'}
INSTALLED_RESULT_CATEGORIES = {'storeBusy', 'store', 'state', 'changed', 'applicationIdentity',
                               'selfIdentity', 'directory', 'budget', 'runtime', 'timeout', 'other'}


def installed_result_tokens(text):
    if isinstance(text, bytes): text = text.decode('utf-8', errors='replace')
    if not isinstance(text, str): return []
    return [stage + ':' + category for stage, category in re.findall(
        r'^ProxyPilot VPN installed result phase: ([A-Za-z]+); category: ([A-Za-z]+)$', text, re.M)
        if stage in INSTALLED_RESULT_STAGES and category in INSTALLED_RESULT_CATEGORIES]


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


def broker_record_projection(data, kind):
    """Fixed numeric diagnostics, NOT transaction authority or a recovery codec.

    Never expose the inbox digest, journal UUID or arbitrary stored bytes.
    Validate the production framing/checksum before projecting known fields.
    """
    sizes = {'status': 48, 'transaction': 128}
    magics = {'status': b'PPBS\0\0\0\1', 'transaction': b'PPBT\0\0\0\1'}
    if kind not in sizes: raise ValueError('Unknown broker diagnostic kind')
    def number(start, end): return int.from_bytes(data[start:end], 'big')
    if len(data) != sizes[kind] or data[:8] != magics[kind] or number(8, 10) != 1:
        return {'record': 'invalid'}
    checksum = 0xcbf29ce484222325
    for value in data[:-8]: checksum = ((checksum ^ value) * 0x100000001b3) & (2**64 - 1)
    if number(len(data) - 8, len(data)) != checksum: return {'record': 'invalid'}
    phases = ('accepted', 'checking', 'ready', 'installing', 'complete', 'failed', 'busy', 'stale')
    if kind == 'status':
        state, revision = number(10, 12), number(32, 40)
        if not 1 <= state <= len(phases) or data[12:16] != bytes(4) or revision == 0:
            return {'record': 'invalid'}
        return {'record': 'valid', 'state': phases[state - 1], 'fromSequence': number(16, 24),
                'toSequence': number(24, 32), 'revision': revision}
    phases = ('accepted', 'authorized', 'prepared', 'handoffStarted', 'handoffComplete',
              'rotatingBroker', 'complete', 'failed')
    recoveries = ('inboxRetained', 'journalRetained', 'executorCommitted', 'complete', 'failed')
    rotations = ('notStarted', 'pending', 'complete')
    phase, recovery, rotation, flags = number(10, 12), number(12, 14), number(14, 16), number(16, 20)
    start, target, revision = number(56, 64), number(64, 72), number(72, 80)
    if (not 1 <= phase <= len(phases) or not 1 <= recovery <= len(recoveries)
            or not 1 <= rotation <= len(rotations) or flags not in (0, 1)
            or data[20:24] != bytes(4) or data[106:120] != bytes(14)
            or not 0 < start < target or revision == 0
            or (flags == 0 and data[80:106] != bytes(26))
            or (flags == 1 and (number(96, 104) == 0 or not 1 <= number(104, 106) <= 8))
            or (phase >= 3 and phase != 8 and flags == 0)
            or (phase == 7 and (recovery != 4 or rotation != 3))
            or (phase == 8 and recovery != 5)):
        return {'record': 'invalid'}
    result = {'record': 'valid', 'phase': phases[phase - 1], 'recovery': recoveries[recovery - 1],
              'rotation': rotations[rotation - 1], 'fromSequence': start, 'toSequence': target,
              'revision': revision, 'hasJournal': flags == 1}
    if flags == 1:
        result.update(journalRevision=number(96, 104), journalPhase=number(104, 106))
    return result


def broker_record_diagnostics(directory, kind):
    names = {'status': 'update-broker-status.bin', 'transaction': 'update-broker-transaction.bin'}
    if kind not in names: raise ValueError('Unknown broker diagnostic kind')
    parent = descriptor = None
    try:
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(parent)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            return {'record': 'unsafe'}
        descriptor = os.open(names[kind], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            return {'record': 'unsafe'}
        data = os.read(descriptor, 129)
        return broker_record_projection(data, kind)
    except FileNotFoundError: return {'record': 'absent'}
    except OSError: return {'record': 'unreadable'}
    finally:
        if descriptor is not None: os.close(descriptor)
        if parent is not None: os.close(parent)


def broker_inbox_diagnostics(directory):
    """Top-level counts only; never print/open an opaque inbox pathname."""
    descriptor = None
    try:
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            return {'record': 'unsafe'}
        result = {'record': 'observed', 'published': 0, 'preparing': 0}
        with os.scandir(descriptor) as entries:
            for index, entry in enumerate(entries):
                if index >= 4096: return {'record': 'overBudget'}
                if re.fullmatch(r'inbox-[0-9a-f]{64}', entry.name): result['published'] += 1
                elif re.fullmatch(r'\.inbox-[0-9a-f]{64}\.preparing', entry.name): result['preparing'] += 1
        return result
    except FileNotFoundError: return {'record': 'absent'}
    except OSError: return {'record': 'unreadable'}
    finally:
        if descriptor is not None: os.close(descriptor)


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


def ordinary_owner_launch_parameters(owner):
    """Launch the real installed frontend as the trusted ordinary fixture owner.

    Only disposable root CI may request the identity drop; the child gets no
    inherited root groups or testing socket/policy substitution.
    """
    if not root_vm_enabled() or type(owner) is not int or not 500 <= owner < 2**32 - 1:
        raise AssertionError('Disposable system VM owner required')
    account = pwd.getpwuid(owner)

    def drop_identity():
        os.initgroups(account.pw_name, account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(owner)
        if (os.getuid() != owner or os.geteuid() != owner or os.getgid() != account.pw_gid
                or os.getegid() != account.pw_gid):
            raise AssertionError('Ordinary owner identity drop failed')

    environment = dict(SAFE_ENV, GITHUB_ACTIONS='true', PROXYPILOT_VM_SYSTEM_RESCUE_TESTS='1')
    return dict(env=environment, preexec_fn=drop_identity)


def ordinary_owner_command(owner, arguments, *, timeout=30):
    return subprocess.run(list(map(str, arguments)), **ordinary_owner_launch_parameters(owner),
                          capture_output=True, text=True, timeout=timeout)


# Public SDK sys/proc_info.h fixed-width structures. Only vnode identity and
# process incarnation are inspected; no process paths or arbitrary FD contents.
# https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h
# The fast ordinary test compares sizes/offsets with the installed SDK, then
# observes ONLY its own private SCM_RIGHTS fixture; live callers are root-VM gated.
class ProcFDInfo(ctypes.Structure):
    _fields_ = [('fd', ctypes.c_int32), ('kind', ctypes.c_uint32)]


class ProcFileInfo(ctypes.Structure):
    _fields_ = [('flags', ctypes.c_uint32), ('status', ctypes.c_uint32), ('offset', ctypes.c_int64),
                ('kind', ctypes.c_int32), ('guardFlags', ctypes.c_uint32)]


class VInfoStat(ctypes.Structure):
    _fields_ = [('device', ctypes.c_uint32), ('mode', ctypes.c_uint16), ('links', ctypes.c_uint16),
                ('inode', ctypes.c_uint64), ('uid', ctypes.c_uint32), ('gid', ctypes.c_uint32)] + [
                (name, ctypes.c_int64) for name in ('atime', 'atimeNS', 'mtime', 'mtimeNS',
                                                 'ctime', 'ctimeNS', 'birth', 'birthNS', 'size', 'blocks')] + [
                ('blockSize', ctypes.c_int32), ('flags', ctypes.c_uint32), ('generation', ctypes.c_uint32),
                ('rdev', ctypes.c_uint32), ('spare', ctypes.c_int64 * 2)]


class VNodeInfo(ctypes.Structure):
    _fields_ = [('stat', VInfoStat), ('kind', ctypes.c_int32), ('pad', ctypes.c_int32), ('fsid', ctypes.c_int32 * 2)]


class VNodeFDInfo(ctypes.Structure):
    _fields_ = [('file', ProcFileInfo), ('vnode', VNodeInfo)]


class ProcBSDInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in ('flags', 'status', 'exitStatus', 'pid', 'parent',
                'uid', 'gid', 'realUID', 'realGID', 'savedUID', 'savedGID', 'reserved')] + [
                ('command', ctypes.c_char * 16), ('name', ctypes.c_char * 32)] + [
                (name, ctypes.c_uint32) for name in ('files', 'group', 'jobCount', 'tty', 'ttyGroup')] + [
                ('nice', ctypes.c_int32), ('startSeconds', ctypes.c_uint64), ('startMicroseconds', ctypes.c_uint64)]


def private_process_api():
    library = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    library.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]
    library.proc_pidinfo.restype = ctypes.c_int
    library.proc_pidfdinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    library.proc_pidfdinfo.restype = ctypes.c_int
    library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    library.proc_pidpath.restype = ctypes.c_int
    return library


def private_process_stamp(api, pid, expected_uid):
    info = ProcBSDInfo()
    if (type(pid) is not int or pid <= 0
            or api.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info)) != ctypes.sizeof(info)
            or info.pid != pid or info.uid != expected_uid or info.realUID != expected_uid):
        raise AssertionError('Owned process incarnation unavailable')
    return (pid, info.startSeconds, info.startMicroseconds)


def private_received_directory(api, pid, device, inode):
    maximum = 1024
    entries = (ProcFDInfo * maximum)()
    size = api.proc_pidinfo(pid, 1, 0, entries, ctypes.sizeof(entries))
    if size <= 0 or size >= ctypes.sizeof(entries) or size % ctypes.sizeof(ProcFDInfo):
        raise AssertionError('Owned descriptor list unavailable')
    for entry in entries[:size // ctypes.sizeof(ProcFDInfo)]:
        if entry.kind != 1 or entry.fd < 0:  # PROX_FDTYPE_VNODE only
            continue
        info = VNodeFDInfo()
        count = api.proc_pidfdinfo(pid, entry.fd, 1, ctypes.byref(info), ctypes.sizeof(info))
        if count != ctypes.sizeof(info):
            continue  # concurrent close of an unrelated descriptor
        observed = info.vnode.stat
        if (stat.S_ISDIR(observed.mode) and observed.device == (device & 0xffffffff)
                and observed.inode == inode):
            return True
    return False


def own_probe_marker(process, expected, deadline):
    """Only the caller-owned pipe; bounded fixed markers, never raw child logs."""
    data = b''
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while len(data) < len(expected):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise AssertionError('Owned probe marker timeout')
            part = os.read(process.stdout.fileno(), len(expected) - len(data))
            if not part:
                raise AssertionError('Owned probe exited before marker')
            data += part
    if data != expected or process.poll() is not None:
        raise AssertionError('Owned probe marker rejected')


@unittest.skipUnless(root_vm_enabled(), 'explicit fresh disposable macOS system VM only')
class VPNRescueSystemVMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_root = Path(os.environ.get('PROXYPILOT_SYSTEM_RESCUE_FIXTURE', ''))
        if not fixture_root.is_absolute() or fixture_root.is_symlink(): raise AssertionError('Absolute fixture root required')
        cls.fixture = json.loads((fixture_root / 'fixture.json').read_text())
        if cls.fixture['schema'] != 2 or not 500 <= cls.fixture['owner'] < 2**32 - 1: raise AssertionError('Invalid fixture owner')
        cls.materials = Path(cls.fixture['materials']); cls.seed = Path(cls.fixture['seed']); cls.package = Path(cls.fixture['package'])
        cls.probe = Path(cls.fixture['probe'])
        cls.known_helpers = known_helper_programs(cls.materials)
        if hashlib.sha256(cls.package.read_bytes()).hexdigest() != cls.fixture['packageSHA256']:
            raise AssertionError('Prepared Installer changed')

    def setUp(self):
        for path in (SYSTEM_BASE, PUBLIC_ENDPOINT, APPLICATION, ACTIVATION_LOG_DIRECTORY, *PLISTS):
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
        self.activation_log_identity = None
        self.addCleanup(self.cleanup_own_system_fixture)
        ACTIVATION_LOG_DIRECTORY.mkdir(mode=0o700)
        self.activation_log_identity = (ACTIVATION_LOG_DIRECTORY.stat().st_dev, ACTIVATION_LOG_DIRECTORY.stat().st_ino)
        for name in ('helper.log', 'recovery.log'):
            descriptor = os.open(ACTIVATION_LOG_DIRECTORY / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
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
            if metadata.get('CFBundleIdentifier') != 'kz.documentolog.proxypilot' or metadata.get('CFBundleVersion') not in ('1.6.0', '1.7.0', '1.8.0', '1.9.0'):
                raise AssertionError('Unknown installed application; refusing teardown')
            if code_pins(APPLICATION) not in [self.fixture[key] for key in ('sourcePins', 'intermediatePins', 'candidatePins', 'successorPins')]:
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
        if self.activation_log_identity is not None:
            info = ACTIVATION_LOG_DIRECTORY.lstat()
            if (info.st_dev, info.st_ino) != self.activation_log_identity or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                raise AssertionError('Owned diagnostic namespace changed; refusing teardown')
            if {path.name for path in ACTIVATION_LOG_DIRECTORY.iterdir()} != {'helper.log', 'recovery.log'}:
                raise AssertionError('Unknown diagnostic entry; refusing teardown')
            for name in ('helper.log', 'recovery.log'):
                path = ACTIVATION_LOG_DIRECTORY / name; info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                    raise AssertionError('Owned diagnostic file changed; refusing teardown')
                path.unlink()
            ACTIVATION_LOG_DIRECTORY.rmdir()
        command(['/usr/sbin/pkgutil', '--forget', PACKAGE_ID], accepted=(0, 1), timeout=30)

    def state_summary(self):
        service = SYSTEM_BASE / 'VPN'
        result = {'activationEvents': activation_log_diagnostics(identity=self.activation_log_identity)}
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
        for kind in ('status', 'transaction'):
            result['broker' + kind.title()] = broker_record_diagnostics(SYSTEM_BASE / 'Broker', kind)
        result['brokerInbox'] = broker_inbox_diagnostics(SYSTEM_BASE / 'Broker')
        for key, app in (('installedRelease', APPLICATION),
                         ('destinationStageRelease', Path('/Applications/.ProxyPilot.vpn-update/ProxyPilot.app')),
                         ('protectedCurrentRelease', SYSTEM_BASE / 'Update/current/ProxyPilot.app'),
                         ('protectedCandidateRelease', SYSTEM_BASE / 'Update/candidate/ProxyPilot.app'),
                         ('protectedExecutorRelease', SYSTEM_BASE / 'Update/executor/ProxyPilot.app')):
            # Never inspect a symlink substituted for a fixed diagnostic slot.
            if app.is_symlink() or (key.startswith('protected') and app.parent.is_symlink()):
                result[key] = 'unsafe'; continue
            if not os.path.lexists(app): result[key] = 'absent'; continue
            try:
                pins = code_pins(app)
                result[key] = next((release for release, known in (
                    ('A', self.fixture['sourcePins']), ('B', self.fixture['intermediatePins']),
                    ('C', self.fixture['candidatePins']), ('D', self.fixture['successorPins'])) if pins == known), 'unknown')
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

    def _assert_installed_result(self, desired):
        try:
            child = subprocess.run([str(APPLICATION / 'Contents/MacOS/ProxyPilot'), '--vpn-verify-update-result'],
                                   env=SAFE_ENV, capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired as error:
            raise AssertionError('Installed result timeout; state=' + repr(self.state_summary())
                                 + '; resultEvents=' + repr(installed_result_tokens(error.stderr))) from None
        events = installed_result_tokens(child.stderr)
        if child.returncode != (40 if desired else 41):
            self.fail('Installed result rejected; exit=' + str(child.returncode)
                      + '; state=' + repr(self.state_summary()) + '; resultEvents=' + repr(events))

    def assert_clean_c(self, desired):
        return self.assert_clean_release(desired, 141, self.fixture['candidatePins'])

    def assert_clean_release(self, desired, sequence, pins):
        service = SYSTEM_BASE / 'VPN'
        selected = json.loads((service / 'release.json').read_text())
        payload = base64.b64decode(selected['payload']).decode()
        self.assertIn('sequence=' + str(sequence) + '\n', payload)
        for name in ('preparation.json', 'update.json', 'cleanup.json'): self.assertFalse((service / name).exists())
        self.assertEqual({path.name for path in (SYSTEM_BASE / 'Update').iterdir()}, {'lifecycle.lock'})
        self.assertEqual(list((SYSTEM_BASE / 'Retired').iterdir()), [])
        self.assertFalse((SYSTEM_BASE / 'Rescue').exists())
        self.assertFalse((SYSTEM_BASE / 'Broker/update-broker-rescue-rotation.bin').exists())
        if 'phase6' in self._testMethodName:
            broker = (SYSTEM_BASE / 'Broker/update-broker-transaction.bin').read_bytes()
            self.assertEqual((len(broker), int.from_bytes(broker[10:12], 'big')), (128, 7))
        self.assertEqual(code_pins(APPLICATION), pins)
        self._assert_installed_result(desired)
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

    def ordinary_update_after_repair(self, desired):
        # Original rescue + idempotent reinstall gate still runs in full before
        # the ordinary owner is permitted to submit a separately signed D.
        self.exercise(desired)
        successor = self.materials / 'SuccessorStage/Payload'
        self.assertEqual(code_pins(successor / 'ProxyPilot.app'), self.fixture['successorPins'])
        owner = self.fixture['owner']
        submitted = ordinary_owner_command(owner, [APPLICATION / 'Contents/MacOS/ProxyPilot',
                                                   '--vm-submit-update', successor])
        outcome = submitted.stdout.strip()
        safe_outcome = outcome if outcome in ('submit:ready', 'submit:indeterminate') else 'unexpected'
        print('Ordinary update submission: ' + json.dumps({'exit': submitted.returncode,
              'outcome': safe_outcome}), flush=True)
        print('Ordinary broker after submission: ' + json.dumps({
            'status': broker_record_diagnostics(SYSTEM_BASE / 'Broker', 'status'),
            'transaction': broker_record_diagnostics(SYSTEM_BASE / 'Broker', 'transaction'),
            'inbox': broker_inbox_diagnostics(SYSTEM_BASE / 'Broker')}), flush=True)
        self.assertIn(submitted.returncode, (0, 75), self.state_summary())
        self.assertNotEqual(safe_outcome, 'unexpected', self.state_summary())
        self.assert_successor_installed(desired)

    def assert_successor_installed(self, desired, submitter=None, deadline=None):
        if deadline is None:
            deadline = time.monotonic() + 300
        self.assertLess(time.monotonic(), deadline, 'Successor observation budget expired')
        owner = self.fixture['owner']
        service = SYSTEM_BASE / 'VPN'
        installed = False
        last_status = 'notObserved'
        while time.monotonic() < deadline:
            if submitter is not None:
                self.assertIsNone(submitter.poll(), 'Own ordinary submitter exited before D completion')
            # Re-execute the actual installed D; an old C process or a `.ready`
            # submit response cannot attest to D's installed startup status.
            if code_pins(APPLICATION) == self.fixture['successorPins']:
                observed = ordinary_owner_command(owner, [APPLICATION / 'Contents/MacOS/ProxyPilot',
                                                           '--vm-update-status'])
                last_status = observed.stdout.strip()
                self.assertIn(last_status, ('status:idle', 'status:verifying', 'status:installed',
                                            'status:failed', 'status:unavailable'))
                self.assertNotEqual(last_status, 'status:failed', self.state_summary())
                retired = all(not (service / name).exists() for name in
                              ('preparation.json', 'update.json', 'cleanup.json'))
                if observed.returncode == 0 and last_status == 'status:installed' and retired:
                    installed = True; break
            time.sleep(1)
        self.assertTrue(installed, str(self.state_summary()) + '; ordinaryStatus=' + last_status)
        self.assert_clean_release(desired, 142, self.fixture['successorPins'])
        transaction = (SYSTEM_BASE / 'Broker/update-broker-transaction.bin').read_bytes()
        self.assertEqual((len(transaction), int.from_bytes(transaction[10:12], 'big')), (128, 7))
        observed = ordinary_owner_command(owner, [APPLICATION / 'Contents/MacOS/ProxyPilot', '--vm-update-status'])
        self.assertEqual((observed.returncode, observed.stdout.strip()), (0, 'status:installed'))
        self.assertLess(time.monotonic(), deadline, 'Successor observation budget expired')

    def test_z_ordinary_owner_update_completes_without_ready_receiver(self):
        # Eighth case; the original seven retain the real production Client API.
        # This private sender exercises an actual broken response channel only.
        if not root_vm_enabled(): raise AssertionError('Disposable root VM required')
        self.exercise(False)
        successor = self.materials / 'SuccessorStage/Payload'
        self.assertEqual(code_pins(successor / 'ProxyPilot.app'), self.fixture['successorPins'])
        candidate = successor.stat()
        self.assertEqual((candidate.st_uid, stat.S_IMODE(candidate.st_mode)), (self.fixture['owner'], 0o700))
        broker = self.state_summary()['broker']
        for origin in ('loadedProgram', 'plistProgram'):
            self.assertEqual(broker[origin]['release'], 'C')
            self.assertTrue(broker[origin].get('pinsMatch'))
            self.assertTrue(broker[origin].get('rootOwned'))
        broker_pid = broker.get('pid')
        api = private_process_api()
        stamp = private_process_stamp(api, broker_pid, 0)
        expected_programs = [name for name, (release, _) in self.known_helpers.items() if release == 'C']
        self.assertEqual(len(expected_programs), 1)
        process_path = ctypes.create_string_buffer(4096)
        self.assertGreater(api.proc_pidpath(broker_pid, process_path, len(process_path)), 0)
        self.assertEqual(process_path.value, os.fsencode(expected_programs[0]), 'Broker executable identity differs')
        self.assertEqual(private_process_stamp(api, broker_pid, 0), stamp)
        self.assertFalse(private_received_directory(api, broker_pid, candidate.st_dev, candidate.st_ino))
        process = subprocess.Popen([str(APPLICATION / 'Contents/MacOS/ProxyPilot'),
                                    '--vm-submit-without-reply', str(successor)],
                                   **ordinary_owner_launch_parameters(self.fixture['owner']),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            probe_stamp = private_process_stamp(api, process.pid, self.fixture['owner'])
            wire_deadline = time.monotonic() + 20  # existing client budget
            own_probe_marker(process, b'submit:partial-frame-sent\n', wire_deadline)
            # Production receive authenticates peer/live code and socket before
            # recvmsg installs SCM_RIGHTS. Observing the unique candidate vnode
            # therefore proves that boundary, without any source/policy bypass.
            barrier_deadline = min(wire_deadline, time.monotonic() + 1.5)
            observed = False
            while time.monotonic() < barrier_deadline:
                self.assertEqual(private_process_stamp(api, broker_pid, 0), stamp)
                if private_received_directory(api, broker_pid, candidate.st_dev, candidate.st_ino):
                    observed = True; break
            self.assertTrue(observed, 'Authenticated partial-frame descriptor barrier not observed')
            self.assertEqual(private_process_stamp(api, process.pid, self.fixture['owner']), probe_stamp)
            # One shared observation budget begins before releasing G. The
            # child's existing post-close 300s lifetime starts later, so it
            # covers this deadline without extending our observation budget.
            completion_deadline = time.monotonic() + 300
            process.stdin.write(b'G'); process.stdin.flush()
            own_probe_marker(process, b'submit:reply-socket-closed\n', wire_deadline)
            # Observe the SAME broker reach handoffStarted. A crash/restart that
            # happens to resume the transaction must not mask a SIGPIPE failure.
            handed_off = False
            while time.monotonic() < completion_deadline:
                self.assertEqual(private_process_stamp(api, broker_pid, 0), stamp)
                progress = broker_record_diagnostics(SYSTEM_BASE / 'Broker', 'transaction')
                if (progress.get('record') == 'valid' and progress.get('fromSequence') == 141
                        and progress.get('toSequence') == 142 and progress.get('phase') == 'handoffStarted'):
                    self.assertEqual(private_process_stamp(api, broker_pid, 0), stamp)
                    handed_off = True; break
            self.assertTrue(handed_off, 'Original authenticated broker handoff not observed')
            print('Ordinary lost-reply proof: ' + json.dumps({'authenticatedDescriptorObserved': True,
                  'replySocketClosed': True, 'sameBrokerHandoffObserved': True, 'ordinaryProbeAlive': True}), flush=True)
            self.assert_successor_installed(False, submitter=process, deadline=completion_deadline)
            self.assertEqual(private_process_stamp(api, process.pid, self.fixture['owner']), probe_stamp)
            process.stdin.write(b'Q'); process.stdin.flush()
            self.assertEqual(process.wait(timeout=5), 0, 'Own ordinary probe failed after D completion')
        finally:
            # Popen owns this unreaped child, so its PID cannot be reused before
            # poll/wait. Never signal a launchd process or arbitrary discovered PID.
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=3)
            process.stdin.close(); process.stdout.close()

    def test_z_ordinary_owner_updates_repaired_c_desired_off(self): self.ordinary_update_after_repair(False)
    def test_z_ordinary_owner_updates_repaired_c_desired_on(self): self.ordinary_update_after_repair(True)


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] in ('--build', '--compile-only'):
        build_fixtures(Path(sys.argv[2]), compile_only=sys.argv[1] == '--compile-only')
    else:
        unittest.main()
