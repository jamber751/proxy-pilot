"""Real Security APIs: explicitly opted-in fresh disposable GHA VM ONLY.

Importing this module or compiling its fixture never executes a Keychain API.
No local defaults/search lists, user keychains, VPN, root, or settings mutation.
"""
from pathlib import Path
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from test_vpn_legacy_password_backend import ROOT, SOURCES


def build_fixture(folder, arch):
    binaries = []
    for name, extra in [('checks', []), ('different', ['-D', 'DIFFERENT_BACKEND_BUILD'])]:
        binary = Path(folder) / name
        result = subprocess.run(['/usr/bin/swiftc', '-parse-as-library',
            '-D', 'VPN_PASSWORD_WORKER_TESTING', '-D', 'VPN_LEGACY_PASSWORD_BACKEND_TESTING',
            *extra, '-target', arch + '-apple-macosx11.0',
            *[str(ROOT / 'app' / name) for name in SOURCES],
            str(ROOT / 'tests/vpn_legacy_password_backend_vm_checks.swift'), '-o', str(binary)],
            capture_output=True, text=True, timeout=120)
        if result.returncode: raise AssertionError(result.stderr)
        subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                        '--identifier', 'kz.documentolog.proxypilot', str(binary)],
                       check=True, capture_output=True, timeout=20)
        binaries.append(binary)
    return binaries


class VMFixtureDiagnosticsTests(unittest.TestCase):
    def test_diagnostics_only_emit_closed_stage_numeric_status_and_boolean(self):
        source = (ROOT / 'tests/vpn_legacy_password_backend_vm_checks.swift').read_text()
        body = source.split('private static func evidence(', 1)[1].split('    static func check(', 1)[0]
        self.assertIn('phase: Evidence', body)
        self.assertIn('status: OSStatus?', body)
        self.assertIn('value: Bool?', body)
        self.assertIn('phase.rawValue', body)
        for forbidden in ('.path', '.description', '.localizedDescription', 'String(describing:',
                          'persistentReference', 'envelope', 'secret', 'dictionary', 'account', 'login'):
            self.assertNotIn(forbidden, body)
        for expected in ('.searchList, status:', '.defaultKeychain, status:', '.getPath, status:',
                         '.initialInteraction, status:', '.createKeychain, status:',
                         '.createdPathIsDB, value:', '.createdPathIsBase, value:'):
            self.assertIn('evidence(' + expected, source)


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS filesystem proof required')
class VMFixturePathProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='pp-file-proof-build-')
        cls.addClassCleanup(cls.build.cleanup)
        source = (ROOT / 'tests/vpn_legacy_password_backend_vm_checks.swift').read_text()
        helper = source.split('// BEGIN NO-KEYCHAIN FILE IDENTITY', 1)[1].split('// END NO-KEYCHAIN FILE IDENTITY', 1)[0]
        for forbidden in ('import Security', 'SecKeychain', 'SecItem', 'VPNPasswordWorker'):
            if forbidden in helper: raise AssertionError('Pure file helper includes a Security dependency')
        wrapper = """
@main enum FileProofChecks {
    enum Failure: Error { case check }
    static func main() throws {
        guard CommandLine.arguments.count == 4 else { throw Failure.check }
        let directory = open(CommandLine.arguments[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        defer { if directory >= 0 { close(directory) } }
        let proof = VPNPrivateKeychainPathProof.inspect(actual: CommandLine.arguments[1],
            directory: directory, intendedName: "first.keychain-db")
        guard proof.accepted == (CommandLine.arguments[3] == "true") else { throw Failure.check }
        print("owned file proof passed")
    }
}
"""
        file = Path(cls.build.name) / 'Checks.swift'
        file.write_text('import Darwin\nimport Foundation\n' + helper + wrapper)
        cls.binary = Path(cls.build.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-target', arch + '-apple-macosx11.0',
            str(file), '-o', str(cls.binary)], capture_output=True, text=True, timeout=60)
        if result.returncode: raise AssertionError(result.stderr)

    def test_alias_requires_exact_known_file_and_private_parent(self):
        with tempfile.TemporaryDirectory(prefix='pp file proof [owned] ') as folder:
            root = Path(folder)
            private = root / 'private'; private.mkdir(mode=0o700)
            intended = private / 'first.keychain-db'
            intended.write_bytes(b'ordinary synthetic filesystem file; NOT a keychain')
            intended.chmod(0o600)
            other = private / 'second.keychain-db'; other.write_bytes(b'other'); other.chmod(0o600)
            alias = root / 'parent-alias'; alias.symlink_to(private, target_is_directory=True)
            leaf = private / 'leaf-alias'; leaf.symlink_to(intended)
            foreign_dir = root / 'foreign'; foreign_dir.mkdir(mode=0o700)
            foreign = foreign_dir / 'first.keychain-db'; foreign.write_bytes(b'foreign'); foreign.chmod(0o600)
            cases = [(intended, private, True), (alias / intended.name, private, True),
                     (leaf, private, False), (other, private, False), (foreign, private, False),
                     (private / 'absent', private, False), (intended, alias, False)]
            for actual, directory, accepted in cases:
                with self.subTest(kind=('accepted' if accepted else 'refused')):
                    result = subprocess.run([str(self.binary), str(actual), str(directory), str(accepted).lower()],
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            hardlink = private / 'hardlink'; os.link(intended, hardlink)
            result = subprocess.run([str(self.binary), str(intended), str(private), 'false'],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            hardlink.unlink()
            intended.chmod(0o620)
            result = subprocess.run([str(self.binary), str(intended), str(private), 'false'],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


@unittest.skipUnless(os.environ.get('PROXYPILOT_VM_PASSWORD_BACKEND_TESTS') == '1',
                     'Real Keychain operations require explicit disposable-GHA opt-in')
class VPNLegacyPasswordBackendVMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # No skip on an opted-in but incorrectly configured runner.
        if os.environ.get('GITHUB_ACTIONS') != 'true' or sys.platform != 'darwin' or os.getuid() != os.geteuid() or os.geteuid() < 500:
            raise AssertionError('Disposable GHA ordinary-user guard refused')
        cls.folder = tempfile.TemporaryDirectory(prefix='pp-private-backend-build-')
        cls.addClassCleanup(cls.folder.cleanup)
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        cls.binary, cls.different = build_fixture(cls.folder.name, arch)

    def writers(self, group):
        result = subprocess.run(['/bin/ps', '-axo', 'pgid=,uid=,stat='], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, 'Private process inspection failed')
        live = False
        for row in result.stdout.splitlines():
            fields = row.split()
            if not fields or fields[0] != str(group): continue
            self.assertEqual(len(fields), 3)
            self.assertEqual(fields[1], str(os.geteuid()), 'Private group owner changed')
            if not fields[2].startswith('Z'): live = True
        return live

    def run_case(self, name):
        # Retain this disposable directory if writer quiescence cannot be
        # positively proved. Auto-cleanup must never remove a live Add target.
        folder = tempfile.mkdtemp(prefix='pp-private-backend-')
        os.chmod(folder, 0o700)
        process = subprocess.Popen([str(self.binary), name, folder, str(self.different)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        quiescent = False
        try:
            out, err = process.communicate(timeout=40)
            self.assertEqual(process.returncode, 0, out + err)
            self.assertIn('private backend checks passed', out)
            self.assertFalse((Path(folder) / 'Store/private-unknown-api').exists(),
                             'Unknown Security API operation; disposable fixture retained')
        finally:
            try:
                if process.poll() is None:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    process.communicate(timeout=5)
                deadline = time.monotonic() + 7
                while self.writers(process.pid) and time.monotonic() < deadline:
                    time.sleep(0.02)
                if self.writers(process.pid):
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    deadline = time.monotonic() + 1
                    while self.writers(process.pid) and time.monotonic() < deadline:
                        time.sleep(0.02)
                quiescent = not self.writers(process.pid)
                self.assertTrue(quiescent, 'Own private worker did not finish; fixture retained')
            finally:
                # An exited/killed child does NOT cancel a securityd RPC.
                # Unknown Add/Delete receipts retain target+whole fixture even
                # after process quiescence; only GHA VM disposal reclaims it.
                unknown = (Path(folder) / 'Store/private-unknown-api').exists()
                if quiescent and not unknown:
                    shutil.rmtree(folder)

    def test_original_locator_ignores_changed_private_add_target_and_decoy(self): self.run_case('roundtrip')
    def test_locked_private_keychain_keeps_manual_fallback_and_obligation(self): self.run_case('locked')
    def test_missing_renamed_original_has_no_fallback_or_ack(self): self.run_case('missing')
    def test_replaced_original_has_no_fallback_or_ack(self): self.run_case('replaced')
    def test_malformed_real_private_item_cannot_yield_secret_or_ack(self): self.run_case('malformed')
    def test_different_adhoc_build_cannot_silently_read_original_item(self): self.run_case('denied-version')

if __name__ == '__main__': unittest.main()
