"""Real current-default Keychain APIs ONLY in a fresh explicitly opted-in GHA VM.
Local tests compile/check guards and synthetic files; they never call those APIs.
Declared private source delta: fixture parent + ownership-canary helper after
unchanged genuine worker dispatch. No production factory/backend/wire hooks.
"""
from pathlib import Path
import hashlib
import json
import os
import platform
import plistlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

from test_vpn_password_frontend import ROOT, snapshot_frontend_sources
from test_vpn_legacy_password_backend import SOURCES

PARENT_FLAG = 'VPN_DEFAULT_KEYCHAIN_VM_PARENT'
ROLE = '--vpn-default-keychain-vm'
OPT_IN = b'PROXYPILOT-DISPOSABLE-DEFAULT-KEYCHAIN-01'
COMPLETE = b'POSITIVE-RESTORED-AND-DELETED'
PRESERVED = b'EXPECTED-UNKNOWN-PRESERVED'
TRACE_STAGES = {
    **{step: {'targetAnchor', 'expectedDefault', 'begin', 'setAPI', 'resultDefault', 'definite'}
       for step in ('setA', 'setB', 'restore')},
    **{step: {'verifyCanary'} for step in ('deleteA', 'deleteB')},
    **{step: {'requireDefault', 'prepare', 'begin', 'dispatch', 'locatorProof', 'children', 'ledger', 'definite', 'refreshAnchor'}
       for step in ('addA', 'addB')},
}
TRACE_ERRORS = {'invalid', 'denied', 'unavailable', 'transport', 'timeout',
                'storageUnavailable', 'staleRevision', 'invalidConfiguration', 'receiptBusy',
                'guardFailed', 'checkFailed', 'apiFailed', 'ambiguous', 'other'}
ANCHOR_ROLES = {'standalone', 'target', 'expected', 'actual'}
ANCHOR_FAILURES = {'heldStat', 'heldIdentity', 'heldLink', 'namedStat', 'namedIdentity', 'namedRegular'}
STEPS = {'baseline', 'path', 'createA', 'createB', 'setA', 'setB', 'addA', 'addB', 'readA', 'readB',
         'otherRead', 'otherDelete', 'deleteA', 'deleteB', 'restore', 'removeA', 'removeB'}


def fixture_source():
    source = (ROOT / 'tests/vpn_legacy_password_backend_vm_checks.swift').read_text()
    proof = source.split('// BEGIN NO-KEYCHAIN FILE IDENTITY', 1)[1].split('// END NO-KEYCHAIN FILE IDENTITY', 1)[0]
    if any(value in proof for value in ('SecKeychain', 'SecItem', 'VPNPasswordWorker')):
        raise AssertionError('Reusable filesystem proof acquired a Security dependency')
    return ((ROOT / 'tests/vpn_default_keychain_frontend_vm.swift').read_text() + '\n' + proof + '\n'
            + (ROOT / 'tests/VPNDefaultKeychainCanaryProof.swift').read_text())


def prepare_snapshot(snapshot):
    original = snapshot_frontend_sources(snapshot)
    snapshot = Path(snapshot)
    main = snapshot / 'app/main.swift'
    anchor = 'if let status = VPNPasswordWorker.runIfRequested(arguments: CommandLine.arguments) { exit(status) }'
    text = main.read_text()
    if text.count(anchor) != 1: raise AssertionError('Genuine worker dispatch changed')
    hook = ('\n#if ' + PARENT_FLAG + '\n'
            'if let status = VPNDefaultKeychainVMEntry.runIfRequested(arguments: CommandLine.arguments) { exit(status) }\n'
            '#endif')
    main.write_text(text.replace(anchor, anchor + hook))
    fixture = snapshot / 'app/VMDefaultKeychainParent.swift'
    fixture.write_text(fixture_source())
    builder = snapshot / 'app/build.sh'
    text = builder.read_text()
    anchor = 'SOURCES=("$HERE/main.swift"'
    if text.count(anchor) != 1: raise AssertionError('Frontend source graph anchor changed')
    text = text.replace(anchor, anchor + ' "$HERE/VMDefaultKeychainParent.swift"')
    anchor = 'LINK_FLAGS+=(-D VPN_INSTALLER_ENTRY)'
    if text.count(anchor) != 1: raise AssertionError('Installer graph flag anchor changed')
    text = text.replace(anchor, 'LINK_FLAGS+=(-D VPN_INSTALLER_ENTRY -D ' + PARENT_FLAG + ')')
    builder.write_text(text)
    delta = {'app/main.swift', 'app/build.sh', 'app/VMDefaultKeychainParent.swift'}
    for name, digest in original.items():
        if name not in delta and hashlib.sha256((snapshot / name).read_bytes()).hexdigest() != digest:
            raise AssertionError('Unapproved acceptance source delta')
    for name in ('VPNPasswordWorker.swift', 'VPNPasswordWorkerWire.swift', 'VPNPasswordWorkerIdentity.swift',
                 'VPNLegacyPasswordBackend.swift', 'VPNPasswordWorkerSession.swift'):
        if hashlib.sha256((snapshot / 'app' / name).read_bytes()).hexdigest() != original['app/' + name]:
            raise AssertionError('Genuine worker or factory changed')
    receipt = {'schema': 1, 'original': original, 'declaredDelta': sorted(delta),
               'productionFactoryUnchanged': True,
               'pathProofSHA256': hashlib.sha256(fixture_source().encode()).hexdigest(),
               'canaryProofSHA256': hashlib.sha256((ROOT/'tests/VPNDefaultKeychainCanaryProof.swift').read_bytes()).hexdigest(),
               'fixtureOwnershipCanaryOnly': True}
    (snapshot.parent / 'source-receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2))
    return receipt


def command(arguments, timeout=30):
    result = subprocess.run(list(map(str, arguments)), capture_output=True, text=True, timeout=timeout)
    if result.returncode: raise AssertionError(result.stdout[-1000:] + result.stderr[-4000:])
    return result


def pins(app):
    result = {}
    for arch in ('arm64', 'x86_64'):
        text = command(['/usr/bin/codesign', '-d', '--verbose=4', '--arch', arch, app]).stderr
        found = re.search(r'^CDHash=([0-9a-f]{40})$', text, re.M)
        if not found: raise AssertionError('Missing private image code hash')
        result[arch] = found[1]
    return result


def build_frontends(folder):
    """Build/sign ONLY. Does not run an app or any Keychain API."""
    folder = Path(folder)
    if not folder.is_absolute() or folder.is_symlink(): raise AssertionError('Private absolute build directory required')
    folder.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = folder.lstat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700 or any(folder.iterdir()):
        raise AssertionError('New empty owned private build directory required')
    snapshot = folder / 'Source'; prepare_snapshot(snapshot)
    output = folder / 'BuildC'
    environment = dict(os.environ, PROXYPILOT_VPN_INSTALLER='1', PROXYPILOT_VPN_RELEASE_SEQUENCE='140',
                       PROXYPILOT_ISOLATED_UPDATER='1')
    process = subprocess.Popen(['zsh', str(snapshot / 'app/build.sh'), str(output)], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try: stdout, stderr = process.communicate(timeout=900)
    except subprocess.TimeoutExpired:
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        process.communicate(timeout=10)
        raise AssertionError('Own compile-only frontend build exceeded its bounded budget')
    (folder / 'build.log').write_text(stdout + stderr)
    if process.returncode: raise AssertionError(stdout[-1000:] + stderr[-5000:])
    first = output / 'ProxyPilot.app'
    second = folder / 'BuildD/ProxyPilot.app'
    second.parent.mkdir(mode=0o700)
    shutil.copytree(first, second, symlinks=True)
    info_path = second / 'Contents/Info.plist'
    info = plistlib.loads(info_path.read_bytes())
    info['CFBundleVersion'] = info['CFBundleShortVersionString'] = '9.9.142'
    info_path.write_bytes(plistlib.dumps(info))
    command(['/usr/bin/codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
             '--identifier', 'kz.documentolog.proxypilot', second])
    for app in (first, second): command(['/usr/bin/codesign', '--verify', '--deep', '--strict', app])
    first_pins, second_pins = pins(first), pins(second)
    if not all(first_pins[arch] != second_pins[arch] for arch in ('arm64', 'x86_64')):
        raise AssertionError('Cross-image fixture requires distinct hardened code hashes')
    for app in (first, second):
        text = command(['/usr/bin/lipo', '-archs', app / 'Contents/MacOS/ProxyPilot']).stdout
        if set(text.split()) != {'arm64', 'x86_64'}: raise AssertionError('Universal private frontend required')
    (folder / 'images.json').write_text(json.dumps({'C': first_pins, 'D': second_pins}, sort_keys=True))
    return first / 'Contents/MacOS/ProxyPilot', second / 'Contents/MacOS/ProxyPilot'


def safe_events(text):
    result = []
    for row in text.splitlines():
        found = re.fullmatch(r'default-keychain-vm:phase=([A-Za-z]+):status=(-?[0-9]{1,10})', row)
        if found and found[1] in STEPS and -(2**31) <= int(found[2]) < 2**31:
            result.append('phase=' + found[1] + ':status=' + found[2]); continue
        trace = re.fullmatch(r'default-keychain-vm:boundary=([A-Za-z]+):stage=([A-Za-z]+):event=(begin|ok|fail)(?::category=([A-Za-z]+))?', row)
        if trace and trace[2] in TRACE_STAGES.get(trace[1], set()):
            if (trace[3] == 'fail' and trace[4] in TRACE_ERRORS) or (trace[3] != 'fail' and trace[4] is None):
                result.append(row); continue
        anchor = re.fullmatch(r'default-keychain-vm:anchor=([A-Za-z]+):failure=([A-Za-z]+)', row)
        if anchor and anchor[1] in ANCHOR_ROLES and anchor[2] in ANCHOR_FAILURES:
            result.append(row); continue
        if row in ('default-keychain-vm:outcome=failed', 'default-keychain-vm:outcome=restored-and-clean',
                   'default-keychain-vm:outcome=preserved-unknown', 'default-keychain-vm:cross-read=allowed',
                   'default-keychain-vm:cross-read=fallback', 'default-keychain-vm:cross-delete=positive',
                   'default-keychain-vm:cross-delete=unavailable-retained'):
            result.append(row)
    return result[-256:]


def read_marker(folder, name):
    descriptor = -1
    try:
        descriptor = os.open(Path(folder) / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 128:
            return b'unsafe'
        data = os.read(descriptor, 129)
        return data if len(data) == info.st_size else b'unsafe'
    except FileNotFoundError: return None
    except OSError: return b'unsafe'
    finally:
        if descriptor >= 0: os.close(descriptor)


def cleanup_allowed(folder, identity, quiescent):
    folder = Path(folder)
    if not quiescent: return False
    try:
        info = folder.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700 or (info.st_dev, info.st_ino) != identity:
            return False
        if read_marker(folder, 'unknown-rpc') is not None or read_marker(folder, 'default-not-restored') is not None:
            return False
        if read_marker(folder, 'complete') != COMPLETE: return False
        return all(not os.path.lexists(folder / directory / leaf) for directory, leaf in
                   (('A', 'first.keychain'), ('A', 'first.keychain-db'), ('B', 'second.keychain'), ('B', 'second.keychain-db')))
    except OSError: return False


class GenuineDefaultSourceGuardTests(unittest.TestCase):
    def test_private_delta_keeps_genuine_worker_factory_and_release_unchanged(self):
        with tempfile.TemporaryDirectory(prefix='pp-default-source-') as folder:
            receipt = prepare_snapshot(Path(folder) / 'Source')
            source = Path(folder) / 'Source/app'
            main = (source / 'main.swift').read_text()
            self.assertLess(main.index('VPNPasswordWorker.runIfRequested'), main.index('VPNDefaultKeychainVMEntry.runIfRequested'))
            self.assertLess(main.index('VPNDefaultKeychainVMEntry.runIfRequested'), main.index('VPNInstallationEntry.runIfRequested'))
            self.assertTrue(receipt['productionFactoryUnchanged'])
            for name in ('VPNPasswordWorker.swift', 'VPNLegacyPasswordBackend.swift'):
                self.assertEqual((source / name).read_bytes(), (ROOT / 'app' / name).read_bytes())
            self.assertNotIn(PARENT_FLAG, (ROOT / 'app/build.sh').read_text())
            self.assertNotIn('VPNDefaultKeychainVMEntry', (ROOT / 'app/main.swift').read_text())
            self.assertNotIn('VPN_PASSWORD_WORKER_TESTING', (source / 'build.sh').read_text())
            self.assertNotIn('VPN_LEGACY_PASSWORD_BACKEND_TESTING', (source / 'build.sh').read_text())
        fixture = fixture_source()
        for forbidden in ('SecKeychainSetSearchList', 'SecKeychainCopySearchList', 'SecKeychainUnlock',
                          'SecAccessCreate', 'SecTrustedApplication', 'testPrivateWorker', 'testRunIfRequested'):
            self.assertNotIn(forbidden, fixture)
        entry = fixture.split('static func runIfRequested(arguments:', 1)[1].split('static func check(', 1)[0]
        self.assertLess(entry.index('GITHUB_ACTIONS'), entry.index('Root.open('))
        self.assertLess(entry.index('PROXYPILOT_VM_DEFAULT_KEYCHAIN_TESTS'), entry.index('runFresh('))

    def test_closed_boundary_and_anchor_categories_are_exactly_whitelisted(self):
        accepted = []
        for step, stages in TRACE_STAGES.items():
            for stage in stages:
                prefix = 'default-keychain-vm:boundary=' + step + ':stage=' + stage
                accepted += [prefix + ':event=begin', prefix + ':event=ok']
                accepted += [prefix + ':event=fail:category=' + category for category in TRACE_ERRORS]
        accepted += ['default-keychain-vm:anchor=' + role + ':failure=' + failure
                     for role in ANCHOR_ROLES for failure in ANCHOR_FAILURES]
        for row in accepted:
            self.assertEqual(safe_events(row), [row])
        rejected = [
            'default-keychain-vm:boundary=addA:stage=prepare:event=fail',
            'default-keychain-vm:boundary=addA:stage=prepare:event=ok:category=denied',
            'default-keychain-vm:boundary=addA:stage=setAPI:event=begin',
            'default-keychain-vm:boundary=baseline:stage=prepare:event=begin',
            'default-keychain-vm:boundary=addA:stage=PRIVATE:event=begin',
            'default-keychain-vm:boundary=addA:stage=prepare:event=fail:category=PRIVATE',
            'default-keychain-vm:anchor=PRIVATE:failure=heldLink',
            'default-keychain-vm:anchor=expected:failure=PRIVATE',
        ]
        rejected += [row + ' /private/path item secret' for row in accepted]
        rejected += [row + ':path=/private/path' for row in accepted]
        for row in rejected:
            self.assertEqual(safe_events(row), [])
        self.assertEqual(safe_events('\n'.join(['default-keychain-vm:anchor=expected:failure=heldLink'] * 300)),
                         ['default-keychain-vm:anchor=expected:failure=heldLink'] * 256)

    def test_diagnostics_wrap_existing_calls_without_changing_unknown_custody(self):
        fixture = fixture_source()
        add = fixture.split('static func add(_ root:', 1)[1].split('static func delete(_ root:', 1)[0]
        for first, second in [('requireDefault', 'prepare'), ('prepare', 'begin'), ('begin', 'dispatch'),
                              ('dispatch', 'locatorProof'), ('locatorProof', 'children'),
                              ('children', 'ledger'), ('ledger', 'definite'), ('definite', 'refreshAnchor')]:
            self.assertLess(add.index('trace(step, .' + first + ')'), add.index('trace(step, .' + second + ')'))
        self.assertEqual(add.count('VPNPasswordWorkerSession.prepare('), 1)
        self.assertEqual(add.count('session.addOnce('), 1)
        self.assertEqual(add.count('root.begin(step)'), 1)
        self.assertEqual(add.count('root.definite(step)'), 1)
        self.assertEqual(fixture.count('SecKeychainSetDefault('), 1)
        anchor = fixture.split('func validate(role:', 1)[1].split('func matches(', 1)[0]
        self.assertEqual(anchor.count('fstat(descriptor'), 1)
        self.assertEqual(anchor.count('lstat(name'), 1)
        for required in ('same(held, attributes)', 'held.st_nlink == 1', 'same(held, named)',
                         'named.st_mode & S_IFMT == S_IFREG'):
            self.assertIn(required, anchor)
        trace = fixture.split('static func trace<T>', 1)[1].split('static func anchorCheck(', 1)[0]
        for forbidden in ('SecKeychain', 'VPNPasswordWorker.prepare', 'String(describing:', '.localizedDescription'):
            self.assertNotIn(forbidden, trace)
        self.assertIn('throw error', trace)

    def test_ownership_canary_is_private_explicit_and_never_acknowledges_unknown_delete(self):
        fixture=fixture_source()
        helper=(ROOT/'tests/VPNDefaultKeychainCanaryProof.swift').read_text()
        for forbidden in ('import Security', 'SecItem', 'SecKeychain', 'Process('):
            self.assertNotIn(forbidden,helper)
        create=fixture.split('static func createCanary(',1)[1].split('static func canaryOwner(',1)[0]
        self.assertIn('kSecUseKeychain as String:keychain',create)
        self.assertEqual(create.count('SecItemAdd('),1)
        self.assertNotIn('SecKeychainCopyDefault',create)
        verify=fixture.split('static func verifyCanary(',1)[1].split('static func create(_ root:',1)[0]
        self.assertLess(verify.index('VPNDefaultCanaryProof.verify('),verify.index('SecKeychainOpen('))
        self.assertLess(verify.index('identity.validateProcess(getppid())'),verify.index('SecKeychainOpen('))
        self.assertIn('identity.requireSameProcess(parentPID',verify)
        self.assertLess(verify.index('canaryOwner(found)'),verify.index('SecKeychainItemCopyAttributesAndData('))
        for required in ('kSecMatchSearchList as String:[reference]', 'kSecMatchItemList as String:[request.persistentReference]',
                         'kSecReturnData as String:false', 'requiredLeaf:leaf'):
            self.assertIn(required,verify)
        deletion=fixture.split('static func delete(_ root:',1)[1].split('static func remove(_ root:',1)[0]
        for first,second in [('== .deleted','try joinChildren()'), ('try joinChildren()', 'store.load()'),
                             ('store.load()', 'refreshAfterConfirmedDelete'), ('refreshAfterConfirmedDelete','root.definite(step)')]:
            self.assertLess(deletion.index(first),deletion.index(second))
        refresh=fixture.split('static func refreshAfterConfirmedDelete(',1)[1].split('static func verifyCanary(',1)[0]
        self.assertLess(refresh.index('DefaultAnchor('),refresh.index('child.run()'))
        self.assertLess(refresh.index('validateProcess('),refresh.index('channel('))
        self.assertLess(refresh.index('terminationStatus == 0'),refresh.index('adoptVerifiedCanaryAnchor'))
        self.assertNotIn('root.remove(',refresh)
        self.assertIn('EXPECTED-UNKNOWN-PRESERVED',fixture)
        self.assertNotIn('SecKeychainCopySignature',fixture)
        self.assertNotIn('SecKeychainGetDLDBHandle',fixture)

    def test_two_sentinels_and_positive_completion_are_required_for_file_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='pp-default-custody-') as folder:
            root = Path(folder); root.chmod(0o700)
            for name in ('A', 'B'): (root / name).mkdir(mode=0o700)
            info = root.stat(); identity = (info.st_dev, info.st_ino)
            self.assertFalse(cleanup_allowed(root, identity, True))
            complete = root / 'complete'; complete.write_bytes(COMPLETE); complete.chmod(0o600)
            self.assertTrue(cleanup_allowed(root, identity, True))
            for name in ('unknown-rpc', 'default-not-restored'):
                marker = root / name; marker.write_bytes(b'owned'); marker.chmod(0o600)
                self.assertFalse(cleanup_allowed(root, identity, True)); marker.unlink()
            self.assertFalse(cleanup_allowed(root, identity, False))
            self.assertFalse(cleanup_allowed(root, (0, 0), True))
            target = root / 'A/first.keychain'; target.write_bytes(b'ordinary synthetic file, NOT Keychain')
            self.assertFalse(cleanup_allowed(root, identity, True))

    def test_closed_events_never_expose_paths_credentials_or_unknown_stage(self):
        text = '\n'.join(['PRIVATE /path password', 'default-keychain-vm:phase=restore:status=0',
                          'default-keychain-vm:phase=PRIVATE:status=0',
                          'default-keychain-vm:phase=restore:status=0 PRIVATE',
                          'default-keychain-vm:outcome=preserved-unknown'])
        self.assertEqual(safe_events(text), ['phase=restore:status=0', 'default-keychain-vm:outcome=preserved-unknown'])


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class GenuineDefaultNativeGuardTests(unittest.TestCase):
    def test_no_optin_refuses_before_any_api(self):
        with tempfile.TemporaryDirectory(prefix='pp-default-guard-') as folder:
            folder = Path(folder)
            fixture = folder / 'Parent.swift'; fixture.write_text(fixture_source())
            main = folder / 'main.swift'; main.write_text('import Darwin\nexit(VPNDefaultKeychainVMEntry.runIfRequested(arguments: CommandLine.arguments) ?? 64)\n')
            names = SOURCES + ['VPNPasswordWorkerSession.swift', 'VPNPasswordPersistenceCoordinator.swift',
                               'VPNPasswordCleanupCoordinator.swift', 'vpn-helper/VPNHelperProtocol.swift']
            arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
            binary = folder / 'guard'
            result = subprocess.run(['/usr/bin/swiftc', '-D', 'VPN_INSTALLER_ENTRY', '-target', arch + '-apple-macosx11.0',
                                     *[str(ROOT / 'app' / name) for name in names], str(fixture), str(main), '-o', str(binary)],
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            for partial in ({}, {'GITHUB_ACTIONS':'true'}, {'PROXYPILOT_VM_DEFAULT_KEYCHAIN_TESTS':'1'}):
                for action in ('roundtrip', 'canary-first', 'canary-second'):
                    result = subprocess.run([str(binary), ROLE, action, '/does/not/exist', 'unused'],
                                            env=dict(partial, PATH='/usr/bin:/bin:/usr/sbin:/sbin'), capture_output=True, timeout=8)
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (77, b'', b''))


@unittest.skipUnless(os.environ.get('PROXYPILOT_VM_DEFAULT_KEYCHAIN_TESTS') == '1',
                     'Real default preference operations require explicit disposable-GHA opt-in')
class GenuineDefaultKeychainVMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get('GITHUB_ACTIONS') != 'true' or sys.platform != 'darwin' or os.getuid() != os.geteuid() or os.geteuid() < 500:
            raise AssertionError('Fresh disposable GHA ordinary-user guard refused')
        cls.build = Path(tempfile.mkdtemp(prefix='pp-default-keychain-build-', dir='/private/tmp'))
        cls.preserve_build = True
        cls.saw_retained = False
        cls.first, cls.second = build_frontends(cls.build)
        cls.addClassCleanup(lambda: shutil.rmtree(cls.build) if not cls.preserve_build else None)

    def setUp(self):
        # The workflow deliberately gives each scenario a separate VM. Never
        # run another preference case after an unknown operation in this VM.
        self.assertFalse(self.__class__.saw_retained, 'Prior unknown operation requires VM disposal; refusing any further API case')

    def own_writers(self, group):
        result = subprocess.run(['/bin/ps', '-axo', 'pgid=,uid=,stat='], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0)
        for line in result.stdout.splitlines():
            fields = line.split()
            if not fields or fields[0] != str(group): continue
            self.assertEqual(len(fields), 3); self.assertEqual(fields[1], str(os.geteuid()))
            if not fields[2].startswith('Z'): return True
        return False

    def run_case(self, action):
        self.__class__.preserve_build = True
        root = Path(tempfile.mkdtemp(prefix='pp-default-keychain-vm-', dir='/private/tmp'))
        root.chmod(0o700)
        for name in ('A', 'B'): (root / name).mkdir(mode=0o700)
        (root / 'opt-in').write_bytes(OPT_IN); (root / 'opt-in').chmod(0o600)
        info = root.stat(); identity = (info.st_dev, info.st_ino)
        process = subprocess.Popen([str(self.first), ROLE, action, str(root), str(self.second)],
                                   env=dict(os.environ, GITHUB_ACTIONS='true', PROXYPILOT_VM_DEFAULT_KEYCHAIN_TESTS='1'),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        quiescent = False; clean = False
        try:
            stdout, stderr = process.communicate(timeout=120)
            events = safe_events(stdout + '\n' + stderr)
            print('Genuine default Keychain evidence: ' + repr(events), flush=True)
            rpc = read_marker(root, 'unknown-rpc')
            phase = rpc.decode('ascii') if rpc is not None and rpc in {name.encode() for name in STEPS} else ('absent' if rpc is None else 'unsafe')
            print('Genuine default custody: ' + repr({'rpc': phase,
                  'defaultOutstanding': read_marker(root, 'default-not-restored') is not None,
                  'positiveComplete': read_marker(root, 'complete') == COMPLETE}), flush=True)
            self.assertEqual(process.returncode, 0, repr(events))
            if 'default-keychain-vm:outcome=preserved-unknown' in events:
                self.assertEqual(action, 'crossrelease')
                self.assertEqual(read_marker(root, 'preserved-unknown'), PRESERVED)
                self.assertEqual(read_marker(root, 'unknown-rpc'), b'otherDelete')
                self.assertEqual(read_marker(root, 'default-not-restored'), b'OWNED-DEFAULT-LEASE')
                self.assertIsNone(read_marker(root, 'complete'))
                print('Cross-image result: expected unknown retained until VM disposal; no restoration or positive deletion claim.', flush=True)
            else:
                self.assertIn('default-keychain-vm:outcome=restored-and-clean', events)
                self.assertEqual(read_marker(root, 'complete'), COMPLETE)
                clean = True
        finally:
            if process.poll() is None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                process.communicate(timeout=5)
            deadline = time.monotonic() + 7
            while self.own_writers(process.pid) and time.monotonic() < deadline: time.sleep(0.02)
            quiescent = not self.own_writers(process.pid)
            if clean and cleanup_allowed(root, identity, quiescent):
                shutil.rmtree(root)
                self.__class__.preserve_build = self.__class__.saw_retained
            else:
                self.__class__.saw_retained = True
                self.__class__.preserve_build = True
                # Process exit never proves a securityd RPC was cancelled.
                print('Disposable Keychain fixture and app images retained for VM disposal.', flush=True)
            self.assertTrue(quiescent, 'Own child remains; fixture retained')
            if clean: self.assertFalse(root.exists(), 'Positive cleanup proof incomplete; fixture retained')

    def test_genuine_default_factory_roundtrip_restores_exact_prior(self): self.run_case('roundtrip')
    def test_genuine_cross_image_access_and_unknown_custody(self): self.run_case('crossrelease')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--compile-only':
        first, second = build_frontends(Path(sys.argv[2]))
        # Negative guard only, without the GHA opt-in or any private fixture.
        for image in (first, second):
            result = subprocess.run([str(image), ROLE, 'roundtrip', '/does/not/exist', 'unused'],
                                    env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}, capture_output=True, timeout=8)
            if (result.returncode, result.stdout, result.stderr) != (77, b'', b''):
                raise SystemExit('Private frontend guard failed')
        print('Private genuine frontend C/D compiled/signed; no Keychain API executed.')
    else: unittest.main()
