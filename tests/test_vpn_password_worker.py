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

    def own_group_has_writers(self, group):
        # Darwin can reject signal 0 for an exited/hardened child. Positively
        # observe only our group, with no command/path output or global kills.
        result = subprocess.run(['/bin/ps', '-axo', 'pgid=,uid=,stat='],
                                capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0, 'Cannot inspect own worker group')
        live = False
        for row in result.stdout.splitlines():
            fields = row.split()
            if not fields or fields[0] != str(group):
                continue
            self.assertEqual(len(fields), 3, 'Malformed own worker group observation')
            self.assertEqual(fields[1], str(os.geteuid()), 'Private worker group owner changed')
            if not fields[2].startswith('Z'):
                live = True
        return live

    def finish_own_group(self, group):
        # A child redirects stdio and can outlive its parent. Wait for positive
        # no-live-writer proof before deleting the private fixture directory.
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline:
            if not self.own_group_has_writers(group):
                return
            time.sleep(0.02)
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            return
        except PermissionError:
            if not self.own_group_has_writers(group):
                return
            raise
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            if not self.own_group_has_writers(group):
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
    def test_backend_inout_cannot_retarget_accepted_go_late_settlement(self): self.run_case('mutated-late-add')
    def test_child_retries_busy_store_only_after_security_result(self):
        for _ in range(3):
            self.run_case('busy')

    def test_observer_retries_only_storage_contention(self): self.run_case('observer')
    def test_maximum_valid_locator_wire_budget(self): self.run_case('wire-bounds')
    def test_closed_v2_locator_and_operation_shapes(self): self.run_case('wire-invalid')
    def test_add_missing_locator_remains_pending(self): self.run_case('missing-locator')
    def test_add_invalid_locator_remains_pending(self): self.run_case('invalid-locator')
    def test_generic_api_denial_is_not_no_io_proof(self): self.run_case('generic-denied')
    def test_definite_no_io_is_distinct_terminal_without_second_add(self): self.run_case('noio')
    def test_stale_locator_read_never_returns_replacement_secret(self): self.run_case('stale-read')
    def test_late_positive_delete_settles_only_captured_item(self): self.run_case('late-delete')
    def test_late_delete_cannot_acknowledge_changed_locator(self): self.run_case('changed-delete-locator')

    def test_legacy_or_unknown_worker_role_is_refused_before_storage(self):
        for role in ('--vpn-password-worker-v1', '--vpn-password-worker-v3', '--vpn-password-worker'):
            result = subprocess.run([str(self.binary), role], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 64)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr, b'')
    def test_child_crash_after_fake_add_leaves_pending(self): self.run_case('commit-crash')
    def test_throwing_initializers_close_once_and_do_not_close_reused_fd(self): self.run_case('fd-ownership')
    def test_expired_monotonic_deadline_never_underflows(self): self.run_case('expired-deadline')

    def test_wrong_direct_parent_is_denied_without_storage(self):
        result = subprocess.run([str(self.binary), '--vpn-password-worker-v2'], capture_output=True, timeout=10)
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
