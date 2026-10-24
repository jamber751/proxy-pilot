"""Unprivileged checks for redacted disposable-VM launchd diagnostics."""
from pathlib import Path
import stat
import unittest
from unittest.mock import patch, Mock, call
from types import SimpleNamespace

import test_vpn_rescue_system_vm as vm


class RescueSystemDiagnosticTests(unittest.TestCase):
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
            'ProxyPilot VPN repair phase: arbitraryPrivateValue\n'
            'ProxyPilot VPN repair failure category: launchd\n'),
            ['retireRecovery', 'failure:launchd'])

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
