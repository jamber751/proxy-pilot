"""Actual hardened same-executable child IPC, synthetic backend only. No Keychain."""
import json
import os
from pathlib import Path
import platform
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc') and os.geteuid() >= 500,
                     'Ordinary macOS user and Swift required')
class VPNPasswordWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='pp-password-worker-build-')
        cls.addClassCleanup(cls.build.cleanup)
        folder = Path(cls.build.name)
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        names = ['VPNConfiguration.swift', 'VPNProfileImporter.swift', 'VPNStore.swift',
                 'VPNPasswordWorkerWire.swift', 'VPNPasswordWorkerIdentity.swift', 'VPNPasswordWorker.swift',
                 'vpn-helper/VPNPeerAuthentication.swift', 'vpn-helper/VPNApplicationSpec.swift',
                 'vpn-helper/VPNTunnelStateStore.swift', 'vpn-helper/OpenVPNManagementEvent.swift',
                 'vpn-helper/OpenVPNStateEvidence.swift',
                 'vpn-helper/OpenVPNTransientCredential.swift']
        sources = [ROOT / 'app' / name for name in names] + [ROOT / 'tests/vpn_password_worker_checks.swift']
        cls.binary = folder / 'checks'
        cls.different = folder / 'different'
        for output, extra in ((cls.binary, []), (cls.different, ['-D', 'DIFFERENT_WORKER_BUILD'])):
            result = subprocess.run(['/usr/bin/swiftc', '-parse-as-library', '-D', 'VPN_PASSWORD_WORKER_TESTING',
                                     *extra, '-target', arch + '-apple-macosx11.0', *map(str, sources), '-o', str(output)],
                                    capture_output=True, text=True, timeout=120)
            if result.returncode: raise AssertionError(result.stderr)
            subprocess.run(['/usr/bin/codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                            '--identifier', 'kz.documentolog.proxypilot', str(output)],
                           check=True, capture_output=True, timeout=20)
        cls.copied = folder / 'same-code-different-inode'
        shutil.copyfile(cls.binary, cls.copied); cls.copied.chmod(0o700)

    def finish_own_group(self, group):
        # posix_spawn's worker inherits this freshly created private session /
        # process group even though it redirects its stdio. Parent completion
        # therefore is not evidence that its child stopped writing the fixture.
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline:
            try:
                os.killpg(group, 0)
            except ProcessLookupError:
                return
            time.sleep(0.02)
        # Only the isolated group this test created; no machine-wide matching.
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            try:
                os.killpg(group, 0)
            except ProcessLookupError:
                break
            time.sleep(0.02)
        self.fail('Own password-worker fixture exceeded bounded exit wait')

    def run_case(self, case, extra=(), folder=None):
        if folder is None:
            with tempfile.TemporaryDirectory(prefix='pp-password-worker-') as temporary:
                return self.run_case(case, extra, temporary)
        os.chmod(folder, 0o700)
        process = subprocess.Popen([str(self.binary), case, str(folder), *map(str, extra)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        preserve_child = False
        try:
            out, err = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, out + err)
            if case != 'parent-death': self.assertIn('worker checks passed', out)
            # This case deliberately exits before the child settles. Its caller
            # owns the group until the actual persisted-result assertions finish.
            preserve_child = case == 'parent-death'
            return process.pid
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass  # The owned group exited between poll and signal.
                process.communicate(timeout=5)
            if not preserve_child:
                self.finish_own_group(process.pid)

    def test_real_child_add_read_delete_and_no_second_add(self): self.run_case('roundtrip')
    def test_eof_before_go_has_no_backend_call(self): self.run_case('before-go')
    def test_truncated_go_has_no_backend_call(self): self.run_case('truncated')
    def test_wrong_nonce_has_no_backend_call(self): self.run_case('wrong-nonce')
    def test_replayed_full_go_executes_only_one_add(self): self.run_case('replay')
    def test_unwired_backend_refuses_before_store_dispatch(self): self.run_case('unavailable')
    def test_different_live_code_is_rejected(self): self.run_case('wrong-peer', [self.different])
    def test_same_code_at_different_executable_inode_is_rejected(self): self.run_case('wrong-peer', [self.copied])
    def test_prepared_child_is_bound_to_store_directory(self): self.run_case('foreign-store')
    def test_not_found_is_not_deletion_proof(self): self.run_case('not-found-delete')
    def test_soft_timeout_child_late_completion_preserves_new_grant(self): self.run_case('late')
    def test_child_retries_busy_store_only_after_security_result(self):
        for _ in range(3):
            self.run_case('busy')

    def test_observer_retries_only_storage_contention(self): self.run_case('observer')
    def test_child_crash_after_fake_add_leaves_pending(self): self.run_case('commit-crash')
    def test_throwing_initializers_close_once_and_do_not_close_reused_fd(self): self.run_case('fd-ownership')
    def test_expired_monotonic_deadline_never_underflows(self): self.run_case('expired-deadline')

    def test_wrong_direct_parent_is_denied_without_storage(self):
        result = subprocess.run([str(self.binary), '--vpn-password-worker-v1'], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 77)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'')

    def test_parent_death_after_go_child_still_settles_own_add(self):
        with tempfile.TemporaryDirectory(prefix='pp-password-worker-') as folder:
            group = self.run_case('parent-death', folder=folder)
            try:
                deadline = time.monotonic() + 7
                while time.monotonic() < deadline:
                    state = json.loads((Path(folder) / 'state.json').read_text())
                    if state['passwordLedger']['active']['writeState'] == 'settled': break
                    time.sleep(0.02)
                self.assertEqual(state['passwordLedger']['active']['writeState'], 'settled')
                self.assertEqual((Path(folder) / 'events').read_text(), 'add\n')
            finally:
                self.finish_own_group(group)


if __name__ == '__main__': unittest.main()
