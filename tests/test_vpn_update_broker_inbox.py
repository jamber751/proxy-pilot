"""Filesystem contract for the root-private broker inbox.

Only disposable current-user directories are used. They stand in for the
production root-owned 0700 parent; no system path, service, app or key is used.
"""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
import os


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/vpn_update_broker_inbox_checks.swift'
INBOX = ROOT / 'app/vpn-helper/VPNUpdateBrokerInbox.swift'


def native_swift_target(machine=None):
    architecture = platform.machine() if machine is None else machine
    if architecture not in ('arm64', 'x86_64'):
        raise ValueError('Unsupported native test architecture')
    return architecture + '-apple-macosx11.0'


def assert_real_signed_app_survives_inbox(testcase, app):
    """Reuse an already built app. Compile/run only our disposable inbox probe."""
    app = Path(app)
    testcase.assertTrue(app.is_absolute() and app.is_dir() and not app.is_symlink())
    with tempfile.TemporaryDirectory(prefix='pp-real-inbox-build-') as temporary:
        binary = Path(temporary) / 'real-checks'
        compiled = subprocess.run(
            ['swiftc', '-target', native_swift_target(),
             '-module-cache-path', str(Path(temporary) / 'ModuleCache'),
             str(INBOX), str(ROOT / 'tests/vpn_update_broker_real_app_checks.swift'),
             '-o', str(binary)], capture_output=True, text=True, timeout=120)
        testcase.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        result = subprocess.run([str(binary), str(app)], capture_output=True, text=True, timeout=180)
        testcase.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        testcase.assertEqual(result.stdout.strip(), 'real app inbox check passed')


class VPNUpdateBrokerInboxContractSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = FIXTURE.read_text()

    def test_execution_target_matches_each_native_runner(self):
        self.assertEqual(native_swift_target('arm64'), 'arm64-apple-macosx11.0')
        self.assertEqual(native_swift_target('x86_64'), 'x86_64-apple-macosx11.0')
        with self.assertRaises(ValueError): native_swift_target('unknown')

    def test_contract_accepts_descriptors_not_paths(self):
        start = self.source.index('protocol VPNUpdateBrokerInboxDriving')
        end = self.source.index('\n}', start)
        surface = self.source[start:end]
        self.assertIn('trustedParent: Int32', surface)
        self.assertIn('sourceDirectory: Int32', surface)
        for forbidden in ('URL', 'path:', 'destination:', 'name:', 'argv', 'shell'):
            self.assertNotIn(forbidden, surface)

    def test_contract_has_exact_fixed_layout(self):
        for name in ('ProxyPilot.app', 'vpn-helper', 'vpn-engine',
                     'vpn-release.manifest', 'vpn-release.sig',
                     'vpn-previous-release.manifest', 'vpn-previous-release.sig',
                     'vpn-update-transition', 'vpn-update-transition.sig'):
            self.assertIn(f'"{name}"', self.source)
        for rejection in ('symlink', 'hardlink', 'special', 'unexpectedSibling',
                          'missingEntry'):
            self.assertIn(rejection, self.source)

    def test_contract_requires_bounds_and_source_revalidation(self):
        for requirement in ('maximumEntries', 'maximumBytes', 'maximumDepth',
                            'sourceChanged', 'mutateSource', 'publishedCount',
                            'containerMode', 'allNodesOwnedByEffectiveUser',
                            'anyGroupOrWorldWritableNode'):
            self.assertIn(requirement, self.source)

    def test_contract_requires_durable_crash_boundaries(self):
        for point in ('afterCopy:vpn-helper', 'beforePublish', 'afterPublish'):
            self.assertIn(f'"{point}"', self.source)
        for requirement in ('syncedNames', 'parentSynced', 'alreadyPublished'):
            self.assertIn(requirement, self.source)

    def test_contract_requires_content_identity_and_conflict_refusal(self):
        self.assertIn('same.identity == repeated.identity', self.source)
        self.assertIn('.rejectedConflict', self.source)
        self.assertIn('corruptPublished', self.source)
        self.assertIn('publishedSnapshot', self.source)


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS symlink proof required')
class SparkleFrameworkLinkProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(prefix='pp-framework-link-proof-')
        cls.addClassCleanup(cls.folder.cleanup)
        source = (ROOT / 'tests/vpn_update_broker_real_app_checks.swift').read_text()
        proof = source.split('// BEGIN PURE FRAMEWORK LINK CHECK', 1)[1].split('// END PURE FRAMEWORK LINK CHECK', 1)[0]
        for forbidden in ('Process(', 'codesign', 'VPNUpdateBrokerInbox', 'import Security'):
            if forbidden in proof: raise AssertionError('Pure link proof acquired executable/API behavior')
        wrapper = r"""
@main enum LinkChecks {
    static func main() {
        do {
            let app = URL(fileURLWithPath: CommandLine.arguments[1])
            let links = try SparkleFrameworkLinkProof.capture(app)
            guard !links.isEmpty else { exit(78) }
            print("framework link proof passed")
        } catch { exit(77) }
    }
}
"""
        file = Path(cls.folder.name) / 'Checks.swift'; file.write_text('import Darwin\nimport Foundation\n' + proof + wrapper)
        cls.binary = Path(cls.folder.name) / 'checks'
        result = subprocess.run(['swiftc', '-parse-as-library', '-target', native_swift_target(),
                                 str(file), '-o', str(cls.binary)], capture_output=True, text=True, timeout=60)
        if result.returncode: raise AssertionError(result.stdout + result.stderr)

    def check_app(self, app, accepted):
        result = subprocess.run([str(self.binary), str(app)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0 if accepted else 77, result.stdout + result.stderr)

    def test_actual_relative_framework_links_are_required_in_root_or_nested_helper(self):
        with tempfile.TemporaryDirectory(prefix='pp-framework-links-') as folder:
            app = Path(folder) / 'Owned.app'; app.mkdir(mode=0o700)
            self.check_app(app, False)
            for location in ('Contents/Frameworks/Sparkle.framework',
                             'Contents/Helpers/ProxyPilot Updater.app/Contents/Frameworks/Sparkle.framework'):
                framework = app / location
                for version in ('A', 'B'):
                    concrete = framework / 'Versions' / version; concrete.mkdir(parents=True, exist_ok=True)
                    (concrete / 'Sparkle').write_bytes(b'synthetic native bytes, never executed')
                    current = framework / 'Versions/Current'; binary = framework / 'Sparkle'
                    current.symlink_to(version); binary.symlink_to('Versions/Current/Sparkle')
                    self.check_app(app, True)
                    current.unlink(); current.write_bytes(version.encode()); self.check_app(app, False); current.unlink()
                    current.symlink_to(version); binary.unlink(); binary.write_bytes(b'same file but no link')
                    self.check_app(app, False); binary.unlink(); binary.symlink_to('Versions/Current/Sparkle')
                    for invalid in ('../' + version, '/' + version, version + '/./', version + '\n', '.', '..', 'Ｂ', 'missing'):
                        current.unlink(); current.symlink_to(invalid); self.check_app(app, False)
                    current.unlink(); current.symlink_to(version)
                    binary.unlink(); binary.symlink_to('Versions/' + version + '/Sparkle')
                    self.check_app(app, False)  # Same resolved bytes, wrong exact symlink target.
                    binary.unlink(); current.unlink()
                shutil.rmtree(framework)

    def test_shared_real_probe_verifies_source_and_publication_without_running_app(self):
        source = (ROOT / 'tests/vpn_update_broker_real_app_checks.swift').read_text()
        self.assertIn('try verifySignature(input)', source)
        self.assertIn('try verifySignature(stagedApp)', source)
        self.assertIn('try verifySignature(copied)', source)
        self.assertIn('SparkleFrameworkLinkProof.capture(copied) == expectedLinks', source)
        self.assertIn('SparkleFrameworkLinkProof.capture(stagedApp) == expectedLinks', source)
        self.assertEqual(source.count('process.executableURL ='), 1)
        self.assertIn('URL(fileURLWithPath: "/usr/bin/codesign")', source)
        self.assertIn('["--verify", "--deep", "--strict", app.path]', source)
        frontend = (ROOT / 'tests/test_vpn_password_frontend.py').read_text()
        body = frontend.split('def test_already_built_signed_frontend_preserves_sparkle_links_in_real_inbox', 1)[1].split('    def ', 1)[0]
        self.assertIn('assert_real_signed_app_survives_inbox(self, self.app)', body)
        for forbidden in ('Popen', 'build.sh', 'PROXYPILOT_BROKER_REAL_APP', 'Applications/'):
            self.assertNotIn(forbidden, body)


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'),
                     'macOS Swift required')
class VPNUpdateBrokerInboxProductionBindingTests(unittest.TestCase):
    def test_production_inbox_satisfies_contract(self):
        self.assertTrue(
            INBOX.is_file(),
            'app/vpn-helper/VPNUpdateBrokerInbox.swift is required',
        )
        with tempfile.TemporaryDirectory(prefix='pp-update-inbox-build-') as temporary:
            binary = Path(temporary) / 'inbox-checks'
            compiled = subprocess.run(
                ['swiftc', '-D', 'VPN_UPDATE_BROKER_INBOX_TESTING',
                 '-target', native_swift_target(),
                 '-module-cache-path', str(Path(temporary) / 'ModuleCache'),
                 str(INBOX), str(FIXTURE), '-o', str(binary)],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            for group in ('layout', 'bounds', 'mutable', 'durability', 'retry',
                          'retirement'):
                with self.subTest(group=group):
                    result = subprocess.run([str(binary), group], capture_output=True,
                                            text=True, timeout=60)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(result.stdout.strip(), f'{group} checks passed')

    @unittest.skipUnless(os.environ.get('PROXYPILOT_BROKER_REAL_APP'),
                         'set PROXYPILOT_BROKER_REAL_APP for signed bundle acceptance')
    def test_real_signed_app_with_framework_links_survives_inbox(self):
        assert_real_signed_app_survives_inbox(self, Path(os.environ['PROXYPILOT_BROKER_REAL_APP']))


if __name__ == '__main__':
    unittest.main()
