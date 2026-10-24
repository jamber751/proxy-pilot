"""Unprivileged checks for redacted disposable-VM launchd diagnostics."""
from pathlib import Path
import os
import stat
import tempfile
import unittest
from unittest.mock import patch, Mock, call
from types import SimpleNamespace

import test_vpn_rescue_system_vm as vm


class RescueSystemDiagnosticTests(unittest.TestCase):
    @staticmethod
    def broker_record(kind):
        data = bytearray(48 if kind == 'status' else 128)
        data[:8] = b'PPBS\0\0\0\1' if kind == 'status' else b'PPBT\0\0\0\1'
        data[8:10] = (1).to_bytes(2, 'big')
        if kind == 'status':
            data[10:12] = (6).to_bytes(2, 'big')
            for start, value in ((16, 141), (24, 142), (32, 9)):
                data[start:start+8] = value.to_bytes(8, 'big')
        else:
            data[10:12] = (7).to_bytes(2, 'big')
            data[12:14] = (4).to_bytes(2, 'big')
            data[14:16] = (3).to_bytes(2, 'big')
            data[16:20] = (1).to_bytes(4, 'big')
            data[24:56] = b'PRIVATE-INBOX-IDENTITY'.ljust(32, b'!')
            data[80:96] = b'PRIVATE-JOURNAL!'
            for start, value in ((56, 139), (64, 141), (72, 12), (96, 3)):
                data[start:start+8] = value.to_bytes(8, 'big')
            data[104:106] = (4).to_bytes(2, 'big')
        return RescueSystemDiagnosticTests.checksum_record(data)

    @staticmethod
    def checksum_record(data):
        data = bytearray(data)
        value = 0xcbf29ce484222325
        for byte in data[:-8]: value = ((value ^ byte) * 0x100000001b3) & (2**64 - 1)
        data[-8:] = value.to_bytes(8, 'big')
        return bytes(data)

    def test_broker_projection_exposes_only_valid_fixed_numeric_progress(self):
        self.assertEqual(vm.broker_record_projection(self.broker_record('status'), 'status'), {
            'record': 'valid', 'state': 'failed', 'fromSequence': 141, 'toSequence': 142, 'revision': 9})
        result = vm.broker_record_projection(self.broker_record('transaction'), 'transaction')
        self.assertEqual(result, {'record': 'valid', 'phase': 'complete', 'recovery': 'complete',
            'rotation': 'complete', 'fromSequence': 139, 'toSequence': 141, 'revision': 12,
            'hasJournal': True, 'journalRevision': 3, 'journalPhase': 4})
        self.assertNotIn('PRIVATE', str(result))

    def test_broker_projection_rejects_corruption_and_unknown_enums_without_bytes(self):
        for kind in ('status', 'transaction'):
            good = self.broker_record(kind)
            for data in (b'private', good[:-1], good + b'private', bytes([good[0] ^ 1]) + good[1:]):
                self.assertEqual(vm.broker_record_projection(data, kind), {'record': 'invalid'})
            for offset in (10, 12, 20) if kind == 'transaction' else (10, 12):
                bad = bytearray(good); bad[offset] = 255
                self.assertEqual(vm.broker_record_projection(self.checksum_record(bad), kind), {'record': 'invalid'})
        with self.assertRaises(ValueError): vm.broker_record_projection(b'', 'private')

    def test_broker_record_reader_rejects_symlinks_links_and_writable_files(self):
        with tempfile.TemporaryDirectory(prefix='pp-broker-diagnostics-') as folder:
            root = Path(folder); root.chmod(0o700)
            record = root / 'update-broker-status.bin'
            self.assertEqual(vm.broker_record_diagnostics(root, 'status'), {'record': 'absent'})
            record.write_bytes(self.broker_record('status')); record.chmod(0o600)
            self.assertEqual(vm.broker_record_diagnostics(root, 'status')['state'], 'failed')
            record.chmod(0o644)
            self.assertEqual(vm.broker_record_diagnostics(root, 'status'), {'record': 'unsafe'})
            record.chmod(0o600); os.link(record, root / 'extra-link')
            self.assertEqual(vm.broker_record_diagnostics(root, 'status'), {'record': 'unsafe'})
            record.unlink(); record.symlink_to(root / 'extra-link')
            with patch.object(vm.os, 'read', side_effect=AssertionError('symlink content read')):
                self.assertEqual(vm.broker_record_diagnostics(root, 'status'), {'record': 'unreadable'})
            root.chmod(0o755)
            self.assertEqual(vm.broker_record_diagnostics(root, 'status'), {'record': 'unsafe'})

    def test_unknown_broker_kind_never_opens_a_path(self):
        with patch.object(vm.os, 'open', side_effect=AssertionError('unknown path opened')):
            with self.assertRaises(ValueError): vm.broker_record_diagnostics(Path('/unused'), 'private')

    def test_broker_inbox_reports_counts_without_opening_or_printing_names(self):
        with tempfile.TemporaryDirectory(prefix='pp-broker-counts-') as folder:
            root = Path(folder); root.chmod(0o700)
            (root / ('inbox-' + 'a' * 64)).symlink_to('/private/unrelated')
            (root / ('.inbox-' + 'b' * 64 + '.preparing')).mkdir()
            (root / 'PRIVATE-DO-NOT-LOG').write_text('PRIVATE-CONTENTS')
            result = vm.broker_inbox_diagnostics(root)
            self.assertEqual(result, {'record': 'observed', 'published': 1, 'preparing': 1})
            self.assertNotIn('PRIVATE', str(result))
            root.chmod(0o755)
            self.assertEqual(vm.broker_inbox_diagnostics(root), {'record': 'unsafe'})
            root.chmod(0o700)

    def test_ordinary_owner_launch_requires_disposable_vm_before_spawning(self):
        with patch.object(vm, 'root_vm_enabled', return_value=False), patch.object(vm.subprocess, 'run') as run:
            with self.assertRaises(AssertionError): vm.ordinary_owner_command(501, ['unused'])
            run.assert_not_called()
        with patch.object(vm, 'root_vm_enabled', return_value=True), patch.object(vm.subprocess, 'run') as run:
            for owner in (0, 499, True, '501', 2**32 - 1):
                with self.assertRaises(AssertionError): vm.ordinary_owner_command(owner, ['unused'])
            run.assert_not_called()

    def test_ordinary_owner_launch_drops_groups_and_both_uids_in_child_only(self):
        account = SimpleNamespace(pw_name='synthetic-fixture-owner', pw_gid=20)
        result = SimpleNamespace(returncode=0, stdout='submit:ready')
        with patch.object(vm, 'root_vm_enabled', return_value=True), \
             patch.object(vm.pwd, 'getpwuid', return_value=account), \
             patch.object(vm.subprocess, 'run', return_value=result) as run:
            self.assertIs(vm.ordinary_owner_command(501, ['fixed-installed-probe', '--vm-submit-update']), result)
            kwargs = run.call_args.kwargs
            self.assertEqual(kwargs['env'], dict(vm.SAFE_ENV, GITHUB_ACTIONS='true',
                                                PROXYPILOT_VM_SYSTEM_RESCUE_TESTS='1'))
            ordering = Mock()
            with patch.object(vm.os, 'initgroups', ordering.groups), \
                 patch.object(vm.os, 'setgid', ordering.gid), patch.object(vm.os, 'setuid', ordering.uid), \
                 patch.object(vm.os, 'getuid', return_value=501), patch.object(vm.os, 'geteuid', return_value=501), \
                 patch.object(vm.os, 'getgid', return_value=20), patch.object(vm.os, 'getegid', return_value=20):
                kwargs['preexec_fn']()
            self.assertEqual(ordering.mock_calls, [call.groups(account.pw_name, 20), call.gid(20), call.uid(501)])

    def test_final_recovery_retirement_token_suppresses_unrelated_log_content(self):
        self.assertEqual(vm.repair_tokens(
            'unrelated /private/secret\nProxyPilot VPN repair phase: retireRecovery\n'
            'ProxyPilot VPN repair phase: protectedExchanged\n'
            'ProxyPilot VPN repair phase: arbitraryPrivateValue\n'
            'ProxyPilot VPN repair failure category: protectedUncertain\n'
            'ProxyPilot VPN repair failure category: destinationUncertain\n'
            'ProxyPilot VPN repair failure category: launchd\n'),
            ['retireRecovery', 'protectedExchanged', 'failure:protectedUncertain', 'failure:destinationUncertain', 'failure:launchd'])

    def test_numeric_exit_spawn_and_fixed_state(self):
        raw = ('state = spawn scheduled\nruns = 5\nlast exit code = 0x4b\n'
               'spawn error = 0x2 (private details suppressed)\nlast terminating signal = SIGKILL\n'
               'program = /private/secret\nenvironment = PASSWORD\n')
        self.assertEqual(vm.launchd_diagnostics(raw), {
            'state': 'spawn scheduled', 'runs': 5, 'lastExitCode': 75,
            'spawnErrno': 2, 'terminatingSignal': 'SIGKILL'})

    def test_never_exited_and_unrecognized_values(self):
        self.assertEqual(vm.launchd_diagnostics('last exit code = (never exited)\n'),
                         {'lastExit': 'neverExited'})
        self.assertEqual(vm.launchd_diagnostics('state = PRIVATE\nspawn error = SECRET\n'), {})
        self.assertEqual(vm.launchd_diagnostics('last terminating signal = Killed: 9\n'), {'terminatingSignal': 9})

    def test_unknown_program_is_never_opened(self):
        with patch.object(vm.os, 'lstat', side_effect=AssertionError('unknown path read')):
            self.assertEqual(vm.helper_program_diagnostics('/private/secret', {}), {'release': 'unknown'})

    def test_known_program_reports_only_fixed_identity_facts(self):
        program = str(vm.SYSTEM_BASE / 'VPN' / ('helper-' + 'a' * 64))
        pins = {'arm64': 'b' * 40, 'x86_64': 'c' * 40}
        facts = SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=0, st_nlink=1)
        with patch.object(vm.os, 'lstat', return_value=facts), patch.object(vm, 'code_pins', return_value=pins) as code:
            self.assertEqual(vm.helper_program_diagnostics(program, {program: ('C', pins)}), {
                'release': 'C', 'filePresent': True, 'regular': True, 'rootOwned': True,
                'privateMode': True, 'singleLink': True, 'pinsMatch': True})
            code.assert_called_once_with(Path(program))

    def test_known_symlink_is_never_signature_checked(self):
        program = str(vm.SYSTEM_BASE / 'VPN' / ('helper-' + 'a' * 64))
        facts = SimpleNamespace(st_mode=stat.S_IFLNK | 0o700, st_uid=0, st_nlink=1)
        with patch.object(vm.os, 'lstat', return_value=facts), patch.object(vm, 'code_pins') as code:
            self.assertFalse(vm.helper_program_diagnostics(program, {program: ('B', {})})['regular'])
            code.assert_not_called()


if __name__ == '__main__': unittest.main()
