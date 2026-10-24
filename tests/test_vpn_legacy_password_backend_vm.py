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
