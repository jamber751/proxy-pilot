"""Disposable, static tests for protected staged application validation."""
import os
from pathlib import Path
import plistlib
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'app/vpn-helper'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}
APP_ID = 'kz.documentolog.proxypilot'
REAL_CANDIDATE = os.environ.get('PROXYPILOT_STAGED_APP_CANDIDATE')


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNStagedApplicationTests(unittest.TestCase):
    @classmethod
    def command(cls, args):
        result = subprocess.run(args, env=ENV, capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise AssertionError(f'exit={result.returncode}\n{result.stdout}{result.stderr}')
        return result

    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise unittest.SkipTest('ownership fixture must not run as root')
        cls.temporary = tempfile.TemporaryDirectory(prefix='pp-staged-build-', dir='/tmp')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.build = Path(cls.temporary.name)
        source = cls.build / 'fixture.c'; source.write_text('int main(void) { return 86; }\n')
        cls.slices = {}
        for arch in ('arm64', 'x86_64'):
            cls.slices[arch] = cls.build / arch
            cls.command(['clang', '-target', arch + '-apple-macosx11.0', str(source), '-o', str(cls.slices[arch])])
        cls.universal = cls.build / 'universal'
        cls.command(['lipo', '-create', *map(str, cls.slices.values()), '-output', str(cls.universal)])
        cls.checker = cls.build / 'checks'
        sanitize = ['-sanitize=address'] if os.environ.get('PP_STAGED_ASAN') == '1' else []
        cls.command(['swiftc', *sanitize, str(HELPER / 'VPNPeerAuthentication.swift'),
                     str(HELPER / 'VPNReleaseAuthorization.swift'),
                     str(HELPER / 'VPNStagedApplication.swift'),
                     str(ROOT / 'tests/vpn_staged_application_checks.swift'), '-o', str(cls.checker)])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-staged-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.stage = self.work / 'stage'; self.stage.mkdir(mode=0o700)
        self.app = self.stage / 'ProxyPilot.app'; self.make_app()

    def make_app(self, identifier=APP_ID, version='1.6.0', executable='ProxyPilot',
                 package_type='APPL', thin=False, entitlements=None):
        app = self.app
        (app / 'Contents/MacOS').mkdir(parents=True)
        (app / 'Contents/Resources').mkdir()
        (app / 'Contents/Resources/data.txt').write_text('sealed resource')
        shutil.copyfile(self.slices['arm64'] if thin else self.universal, app / 'Contents/MacOS/ProxyPilot')
        (app / 'Contents/MacOS/ProxyPilot').chmod(0o755)
        info = {'CFBundleIdentifier': identifier, 'CFBundleExecutable': executable,
                'CFBundlePackageType': package_type, 'CFBundleVersion': version,
                'CFBundleShortVersionString': version, 'CFBundleName': 'ProxyPilot'}
        (app / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
        nested = app / 'Contents/Helpers/Nested.app/Contents/MacOS'; nested.mkdir(parents=True)
        shutil.copyfile(self.universal, nested / 'Nested'); (nested / 'Nested').chmod(0o755)
        nested_info = {'CFBundleIdentifier': APP_ID + '.nested', 'CFBundleExecutable': 'Nested',
                       'CFBundlePackageType': 'APPL', 'CFBundleVersion': '1', 'CFBundleShortVersionString': '1'}
        (nested.parent / 'Info.plist').write_bytes(plistlib.dumps(nested_info))
        self.sign(nested.parent.parent, APP_ID + '.nested')
        framework = app / 'Contents/Frameworks/Fixture.framework'
        (framework / 'Versions/A/Resources').mkdir(parents=True)
        (framework / 'Versions/A/Resources/value.txt').write_text('value')
        shutil.copyfile(self.universal, framework / 'Versions/A/Fixture')
        (framework / 'Versions/A/Fixture').chmod(0o755)
        framework_info = {'CFBundleIdentifier': APP_ID + '.fixture.framework',
                          'CFBundleExecutable': 'Fixture', 'CFBundlePackageType': 'FMWK',
                          'CFBundleVersion': '1', 'CFBundleShortVersionString': '1'}
        (framework / 'Versions/A/Resources/Info.plist').write_bytes(plistlib.dumps(framework_info))
        os.symlink('A', framework / 'Versions/Current')
        os.symlink('Versions/Current/Fixture', framework / 'Fixture')
        os.symlink('Versions/Current/Resources', framework / 'Resources')
        self.sign(framework, APP_ID + '.fixture.framework')
        self.sign(app, identifier, entitlements)

    def sign(self, path, identifier, entitlements=None):
        args = ['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill', '--identifier', identifier]
        if entitlements:
            file = self.work / 'entitlements.plist'; file.write_bytes(plistlib.dumps(entitlements))
            args += ['--entitlements', str(file)]
        self.command([*args, str(path)])

    def pins(self):
        result = {}
        for arch in ('arm64', 'x86_64'):
            text = self.command(['codesign', '-d', '--verbose=4', '--arch', arch, str(self.app)]).stderr
            result[arch] = next(line[7:] for line in text.splitlines() if line.startswith('CDHash='))
        return result

    def check(self, operation='inspect', pins=None, version='1.6.0', expected=None):
        pins = pins or self.pins()
        args = [str(self.checker), operation, str(self.stage), pins['arm64'], pins['x86_64'], version]
        if expected: args.append(expected)
        self.command(args)

    def rebuild(self, **options):
        shutil.rmtree(self.app); self.make_app(**options)

    def reset_stage(self):
        shutil.rmtree(self.stage)
        self.stage.mkdir(mode=0o700)
        self.make_app()

    def test_valid_match_and_revalidation(self):
        self.check(); self.check('revalidate')

    def test_installed_policy_allows_parent_siblings_but_binds_owner(self):
        (self.stage / 'Other.app').mkdir()
        self.check('inspect-installed')
        self.check('wrong-installed-owner', expected='unsafeStorage')

    def test_resource_and_nested_tampering(self):
        pins = self.pins()
        for relative in ('Contents/Resources/data.txt', 'Contents/Helpers/Nested.app/Contents/MacOS/Nested'):
            with self.subTest(relative=relative):
                path = self.app / relative; original = path.read_bytes(); path.write_bytes(original + b'x')
                self.check(pins=pins, expected='invalidSignature'); path.write_bytes(original)

    def test_wrong_and_swapped_architecture_pins(self):
        pins = self.pins()
        self.check(pins={'arm64': pins['x86_64'], 'x86_64': pins['arm64']}, expected='invalidSignature')
        self.check(pins={'arm64': '00' * 20, 'x86_64': pins['x86_64']}, expected='invalidSignature')

    def test_fixed_bundle_metadata(self):
        original = self.pins()
        for options in ({'identifier': 'invalid.example'}, {'version': '1.6.1'},
                        {'package_type': 'BNDL'}):
            with self.subTest(options=options):
                self.rebuild(**options); self.check(pins=original, expected='invalidBundle')
        self.rebuild()
        plist = self.app / 'Contents/Info.plist'
        info = plistlib.loads(plist.read_bytes()); info['CFBundleExecutable'] = 'Other'
        plist.write_bytes(plistlib.dumps(info))
        self.check(pins=original, expected='invalidBundle')

    def test_entitlements_and_thin_code(self):
        self.rebuild(entitlements={'com.apple.security.network.client': True})
        self.check(expected='invalidSignature')
        self.rebuild(thin=True)
        self.check(pins={'arm64': '00' * 20, 'x86_64': '11' * 20}, expected='invalidBundle')

    def test_modes_and_hardlinks(self):
        pins = self.pins(); resource = self.app / 'Contents/Resources/data.txt'
        os.chmod(self.stage, 0o770); self.check(pins=pins, expected='unsafeStorage'); os.chmod(self.stage, 0o700)
        os.chmod(resource, 0o666); self.check(pins=pins, expected='unsafeStorage'); os.chmod(resource, 0o644)
        link = self.app / 'Contents/Resources/hardlink'; os.link(resource, link)
        self.check(pins=pins, expected='unsafeStorage'); link.unlink()

    def test_fixed_main_executable_must_be_owner_executable(self):
        pins = self.pins()
        executable = self.app / 'Contents/MacOS/ProxyPilot'
        executable.chmod(0o644)
        self.check(pins=pins, expected='unsafeStorage')

    def test_acl_is_rejected(self):
        resource = self.app / 'Contents/Resources/data.txt'; pins = self.pins()
        acl = subprocess.run(['chmod', '+a', f'{pwd.getpwuid(os.getuid()).pw_name} allow read', str(resource)], env=ENV,
                             capture_output=True, text=True)
        if acl.returncode:
            self.skipTest('filesystem cannot create fixture ACL: ' + acl.stderr.strip())
        self.addCleanup(subprocess.run, ['chmod', '-N', str(resource)], env=ENV, capture_output=True)
        self.check(pins=pins, expected='unsafeStorage')

    def test_entry_size_depth_and_special_node_limits(self):
        pins = self.pins(); resources = self.app / 'Contents/Resources'
        sparse = resources / 'oversized'; sparse.touch(); os.truncate(sparse, 257 * 1024 * 1024)
        self.check(pins=pins, expected='limitExceeded'); sparse.unlink()
        fifo = resources / 'fifo'; os.mkfifo(fifo)
        self.check(pins=pins, expected='unsafeStorage'); fifo.unlink()
        deep = resources
        for index in range(50):
            deep /= str(index); deep.mkdir()
        self.check(pins=pins, expected='limitExceeded')

    def test_physical_entry_count_limit(self):
        pins = self.pins()
        flood = self.app / 'Contents/Resources/entry-flood'; flood.mkdir()
        for index in range(10001):
            (flood / str(index)).touch()
        self.check(pins=pins, expected='limitExceeded')

    def test_internal_framework_links_and_bad_links(self):
        self.check(); link = self.app / 'Contents/Frameworks/Fixture.framework/Resources'
        for target in ('/tmp', '../../../../../../tmp', 'cycle', 'Versions/A/missing'):
            with self.subTest(target=target):
                link.unlink(); os.symlink(target, link)
                cycle = link.parent / 'cycle'
                if target == 'cycle': os.symlink('Resources', cycle)
                self.check(pins=self.pins(), expected='invalidBundle')
                link.unlink()
                if cycle.is_symlink(): cycle.unlink()
                os.symlink('Versions/Current/Resources', link)

    def test_stale_receipts_detect_changes(self):
        for operation in ('resource-after', 'bundle-after', 'parent-after'):
            with self.subTest(operation=operation):
                self.reset_stage()
                if operation != 'resource-after':
                    shutil.copytree(self.app, self.stage / 'Replacement.app', symlinks=True)
                expected = 'invalidSignature' if operation == 'resource-after' else 'changed'
                self.check(operation, expected=expected)

    def test_harness_has_no_install_or_execution_path(self):
        source = (ROOT / 'tests/vpn_staged_application_checks.swift').read_text()
        self.assertNotIn('/Applications', source); self.assertNotIn('exec', source)

    @unittest.skipUnless(REAL_CANDIDATE, 'set PROXYPILOT_STAGED_APP_CANDIDATE to an absolute built .app')
    def test_optional_real_built_candidate_copy(self):
        candidate = Path(REAL_CANDIDATE)
        self.assertTrue(candidate.is_absolute())
        self.assertEqual(candidate.name, 'ProxyPilot.app')
        shutil.rmtree(self.app)
        shutil.copytree(candidate, self.app, symlinks=True)
        info = plistlib.loads((self.app / 'Contents/Info.plist').read_bytes())
        self.check(version=info['CFBundleVersion'])
        self.check('revalidate', version=info['CFBundleVersion'])


if __name__ == '__main__': unittest.main()
