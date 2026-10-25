"""Unprivileged checks for redacted disposable-VM launchd diagnostics."""
from pathlib import Path
import array
import ctypes
import os
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock, call
from types import SimpleNamespace

import test_vpn_rescue_system_vm as vm


class RescueSystemDiagnosticTests(unittest.TestCase):
    def test_helper_history_preserves_exit_before_failed_job_is_removed(self):
        history = vm.HelperLaunchHistory({'/owned/helper': ('B', {})})
        history.record(0, 'state = running\npid = 123\nprogram = /owned/helper\n', 10)
        history.record(0, 'state = not running\nlast exit code = 77\nprogram = /owned/helper\n', 20)
        history.record(113, '', 30)
        result = history.snapshot()
        self.assertEqual(result['records'][1]['job']['lastExitCode'], 77)
        self.assertEqual(result['records'][1]['job']['programReleaseHint'], 'B')
        self.assertEqual(result['records'][-1]['job'], {'queryStatus': 113})

    def test_helper_history_redacts_unknown_program_and_environment_without_following_paths(self):
        history = vm.HelperLaunchHistory({})
        with patch.object(vm.os, 'lstat', side_effect=AssertionError('path followed')), \
             patch.object(vm.subprocess, 'run', side_effect=AssertionError('process launched')):
            history.record(0, 'state = running\nprogram = /private/SECRET\nenvironment = SECRET\npid = 123\n', 1)
        self.assertNotIn('SECRET', repr(history.snapshot()))
        self.assertEqual(history.snapshot()['records'][0]['job']['programReleaseHint'], 'unknown')

    def test_helper_history_deduplicates_states_but_bounds_changes_and_copies_output(self):
        history = vm.HelperLaunchHistory({})
        history.record(113, '', 1); history.record(113, '', 2)
        self.assertEqual(len(history.snapshot()['records']), 1)
        for pid in range(120): history.record(0, 'pid = ' + str(pid) + '\n', pid)
        result = history.snapshot()
        self.assertEqual(len(result['records']), history.maximum_records)
        self.assertTrue(result['truncated'])
        result['records'][-1]['job']['pid'] = 'SECRET'
        self.assertNotIn('SECRET', repr(history.snapshot()))

    def test_helper_history_refuses_host_before_thread_or_job_query(self):
        history = vm.HelperLaunchHistory({})
        with patch.object(vm, 'root_vm_enabled', return_value=False), \
             patch.object(vm.threading, 'Thread') as thread, patch.object(vm.subprocess, 'run') as query:
            with self.assertRaises(AssertionError): history.start()
        thread.assert_not_called(); query.assert_not_called()

    def test_helper_history_suppresses_over_budget_input_and_arbitrary_status(self):
        history = vm.HelperLaunchHistory({})
        history.record(0, 'SECRET' * 12000, 1)
        history.record('SECRET', 'SECRET', 'SECRET')
        result = history.snapshot()
        self.assertEqual(result['records'][0]['job'], {'queryStatus': 'overBudget'})
        self.assertNotIn('SECRET', repr(result))

    def test_installer_stops_observer_before_failure_snapshot_and_preserves_deadline(self):
        case = vm.VPNRescueSystemVMTests('test_real_installer_repairs_pending137_through139_to_c_desired_on')
        case.known_helpers = {}; case.package = Path('/synthetic/package.pkg')
        observer = Mock(); observer.stop.return_value = {'records': [{'job': {'lastExitCode': 77}}]}
        def state():
            observer.stop.assert_called_once()
            return {'helperHistory': case.helper_history}
        case.state_summary = state
        failed = SimpleNamespace(returncode=1, stdout='SECRET', stderr='SECRET')
        with patch.object(vm, 'install_log_cursor', return_value=None), \
             patch.object(vm, 'install_log_tokens', return_value=[]), \
             patch.object(vm, 'HelperLaunchHistory', return_value=observer), \
             patch.object(vm.subprocess, 'run', return_value=failed) as install:
            with self.assertRaises(AssertionError) as error: case.install()
        self.assertIn('lastExitCode', str(error.exception)); self.assertNotIn('SECRET', str(error.exception))
        self.assertEqual(install.call_args.kwargs['timeout'], 420)
        self.assertEqual(install.call_args.args[0][0], '/usr/sbin/installer')

    def test_installer_timeout_stops_and_reports_observer_without_retry_or_raw_output(self):
        case = vm.VPNRescueSystemVMTests('test_real_installer_repairs_pending137_through139_to_c_desired_on')
        case.known_helpers = {}; case.package = Path('/synthetic/package.pkg')
        observer = Mock(); observer.stop.return_value = {'records': [{'job': {'lastExitCode': 77}}]}
        timeout = subprocess.TimeoutExpired(['/usr/sbin/installer'], 420, stderr=b'SECRET')
        with patch.object(vm, 'install_log_cursor', return_value=None), \
             patch.object(vm, 'HelperLaunchHistory', return_value=observer), \
             patch.object(vm.subprocess, 'run', side_effect=timeout) as install, \
             patch('builtins.print') as output:
            with self.assertRaises(subprocess.TimeoutExpired): case.install()
        observer.stop.assert_called_once(); self.assertEqual(install.call_count, 1)
        self.assertIn('lastExitCode', repr(output.call_args_list))
        self.assertNotIn('SECRET', repr(output.call_args_list))

    def test_installed_result_only_emits_closed_phase_and_category(self):
        text = chr(10).join(['PRIVATE /path account',
                'ProxyPilot VPN installed result phase: snapshot; category: storeBusy',
                'ProxyPilot VPN installed result phase: finalSnapshot; category: timeout',
                'ProxyPilot VPN installed result phase: PRIVATE; category: store',
                'ProxyPilot VPN installed result phase: snapshot; category: SECRET',
                'ProxyPilot VPN installed result phase: snapshot; category: storeBusy trailing secret'])
        self.assertEqual(vm.installed_result_tokens(text), ['snapshot:storeBusy', 'finalSnapshot:timeout'])
        self.assertEqual(vm.installed_result_tokens(None), [])

    def test_installed_result_denial_keeps_failure_and_redacts_arbitrary_output(self):
        case = vm.VPNRescueSystemVMTests('test_z_ordinary_owner_updates_repaired_c_desired_off')
        case.state_summary = lambda: {'budget': {'desired': False}, 'installedRelease': 'D'}
        result = SimpleNamespace(returncode=77, stdout='PRIVATE', stderr=chr(10).join([
            'PRIVATE', 'ProxyPilot VPN installed result phase: snapshot; category: storeBusy']))
        with patch.object(vm.subprocess, 'run', return_value=result) as run:
            with self.assertRaises(AssertionError) as failure: case._assert_installed_result(False)
        self.assertIn('snapshot:storeBusy', str(failure.exception))
        self.assertIn('installedRelease', str(failure.exception))
        self.assertNotIn('PRIVATE', str(failure.exception))
        self.assertEqual(run.call_args.kwargs['timeout'], 15)
        self.assertEqual(run.call_args.args[0][-1], '--vpn-verify-update-result')

    def test_installed_result_success_keeps_exact_desired_outcome_without_extra_state_reads(self):
        case = vm.VPNRescueSystemVMTests('test_z_ordinary_owner_updates_repaired_c_desired_off')
        case.state_summary = Mock(side_effect=AssertionError('Unexpected diagnostic read'))
        for desired, status in ((False, 41), (True, 40)):
            with patch.object(vm.subprocess, 'run', return_value=SimpleNamespace(returncode=status, stderr='')):
                case._assert_installed_result(desired)
        case.state_summary.assert_not_called()

    def test_installed_result_timeout_keeps_state_without_raw_stderr(self):
        case = vm.VPNRescueSystemVMTests('test_z_ordinary_owner_updates_repaired_c_desired_off')
        case.state_summary = lambda: {'installedRelease': 'D'}
        timeout = subprocess.TimeoutExpired(['PRIVATE'], 15, stderr=b'PRIVATE')
        with patch.object(vm.subprocess, 'run', side_effect=timeout):
            with self.assertRaises(AssertionError) as failure: case._assert_installed_result(False)
        self.assertIn('Installed result timeout', str(failure.exception))
        self.assertIn('installedRelease', str(failure.exception))
        self.assertNotIn('PRIVATE', str(failure.exception))

    def test_successor_observation_reuses_supplied_deadline_and_fixture_owner(self):
        case = vm.VPNRescueSystemVMTests('test_z_ordinary_owner_update_completes_without_ready_receiver')
        case.fixture = {'owner': 501, 'successorPins': {'synthetic': 'pin'}}
        with tempfile.TemporaryDirectory(prefix='pp-successor-budget-') as folder:
            base = Path(folder)
            (base / 'Broker').mkdir()
            transaction = bytearray(128); transaction[10:12] = (7).to_bytes(2, 'big')
            (base / 'Broker/update-broker-transaction.bin').write_bytes(transaction)
            with patch.object(vm, 'SYSTEM_BASE', base), patch.object(vm, 'APPLICATION', base / 'synthetic-app'), \
                 patch.object(vm.time, 'monotonic', return_value=50), \
                 patch.object(vm, 'code_pins', return_value=case.fixture['successorPins']), \
                 patch.object(vm, 'ordinary_owner_command', return_value=SimpleNamespace(returncode=0, stdout='status:installed')) as status, \
                 patch.object(case, 'assert_clean_release') as clean, patch.object(case, 'state_summary', return_value={}):
                case.assert_successor_installed(False, deadline=100)
                self.assertEqual([entry.args[0] for entry in status.call_args_list], [501, 501])
                clean.assert_called_once_with(False, 142, case.fixture['successorPins'])

    def test_expired_successor_budget_is_not_restarted(self):
        case = vm.VPNRescueSystemVMTests('test_z_ordinary_owner_update_completes_without_ready_receiver')
        with patch.object(vm.time, 'monotonic', return_value=100), \
             patch.object(vm, 'code_pins') as pins, patch.object(vm, 'ordinary_owner_command') as status:
            with self.assertRaisesRegex(AssertionError, 'budget expired'):
                case.assert_successor_installed(False, deadline=99)
            pins.assert_not_called(); status.assert_not_called()

    def test_disconnected_vm_case_denies_before_inspection_or_process_launch(self):
        case = vm.VPNRescueSystemVMTests('test_z_ordinary_owner_update_completes_without_ready_receiver')
        with patch.object(vm, 'root_vm_enabled', return_value=False), \
             patch.object(vm, 'private_process_api') as inspect, patch.object(vm.subprocess, 'Popen') as launch, \
             patch.object(case, 'exercise') as repair:
            with self.assertRaises(AssertionError): case.test_z_ordinary_owner_update_completes_without_ready_receiver()
            inspect.assert_not_called(); launch.assert_not_called(); repair.assert_not_called()

    def test_private_probe_uses_guarded_fixed_protocol_without_helper_test_flags(self):
        source = (vm.ROOT / 'tests/vpn_rescue_system_probe_main.swift').read_text()
        role = source[source.index('if args.count >= 2 && args[1] == "--vm-submit-without-reply"'):]
        self.assertLess(role.index('guard ordinaryVMOwner()'), role.index('try submitWithoutReply('))
        for required in ('VPNUpdateBrokerDaemon.endpointPath',
                         'VPNUpdateBrokerProtocol.encode(try .submit(expectedFromSequence: 141))',
                         'expectControl(0x47', 'close(channel); channel = -1', 'expectControl(0x51'):
            self.assertIn(required, source)
        self.assertNotIn('VPN_UPDATE_BROKER_TRANSPORT_TESTING', source)
        self.assertNotIn('shutdown(', source)

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin public proc_info ABI')
    def test_private_proc_structures_match_installed_public_sdk(self):
        source = r'''
#include <libproc.h>
#include <sys/proc_info.h>
#include <stddef.h>
#include <stdio.h>
int main(void) {
    printf("%zu %zu %zu %zu %zu %zu %zu\n", sizeof(struct proc_fdinfo), sizeof(struct vnode_fdinfo),
        sizeof(struct proc_bsdinfo), offsetof(struct vnode_fdinfo, pvi.vi_stat.vst_dev),
        offsetof(struct vnode_fdinfo, pvi.vi_stat.vst_ino), offsetof(struct proc_bsdinfo, pbi_uid),
        offsetof(struct proc_bsdinfo, pbi_start_tvsec));
}
'''
        with tempfile.TemporaryDirectory(prefix='pp-own-proc-sdk-') as folder:
            binary = Path(folder) / 'abi-check'
            subprocess.run(['/usr/bin/clang', '-x', 'c', '-', '-o', str(binary)], input=source,
                           capture_output=True, text=True, check=True, timeout=30)
            result = subprocess.run([str(binary)], capture_output=True, text=True, check=True, timeout=5)
        self.assertEqual(list(map(int, result.stdout.split())), [ctypes.sizeof(vm.ProcFDInfo),
            ctypes.sizeof(vm.VNodeFDInfo), ctypes.sizeof(vm.ProcBSDInfo),
            vm.VNodeFDInfo.vnode.offset + vm.VNodeInfo.stat.offset + vm.VInfoStat.device.offset,
            vm.VNodeFDInfo.vnode.offset + vm.VNodeInfo.stat.offset + vm.VInfoStat.inode.offset,
            vm.ProcBSDInfo.uid.offset, vm.ProcBSDInfo.startSeconds.offset])

    @unittest.skipUnless(sys.platform == 'darwin', 'private Darwin AF_UNIX/libproc proof')
    def test_partial_frame_fd_barrier_then_closed_reply_keeps_process_alive(self):
        # Only this process, its socketpair and private temporary directory.
        # Never a host endpoint, another process, Security API or root operation.
        api = vm.private_process_api()
        self.assertEqual(vm.private_process_stamp(api, os.getpid(), os.geteuid())[0], os.getpid())
        with tempfile.TemporaryDirectory(prefix='pp-own-partial-frame-') as folder:
            directory = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            candidate = os.fstat(directory)
            client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            received_descriptors = array.array('i')
            try:
                self.assertEqual(server.family, socket.AF_UNIX)
                server.getpeername()  # before disconnect, as production auth does
                token = server.getsockopt(0, 6, 32)  # SOL_LOCAL / LOCAL_PEERTOKEN
                self.assertEqual(len(token), 32)
                values = struct.unpack('=8I', token)
                self.assertEqual((values[1], values[5]), (os.geteuid(), os.getpid()))
                uid, gid = ctypes.c_uint32(), ctypes.c_uint32()
                libc = ctypes.CDLL(None, use_errno=True)
                self.assertEqual(libc.getpeereid(server.fileno(), ctypes.byref(uid), ctypes.byref(gid)), 0)
                self.assertEqual(uid.value, os.geteuid())
                frame = struct.pack('>8sHQ', b'PPVPNB01', 1, 141)
                self.assertEqual(client.sendmsg([frame[:1]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                                              array.array('i', [directory]))]), 1)
                os.close(directory); directory = None
                self.assertFalse(vm.private_received_directory(api, os.getpid(), candidate.st_dev, candidate.st_ino))
                first, ancillary, flags, _ = server.recvmsg(len(frame), socket.CMSG_SPACE(array.array('i').itemsize))
                self.assertEqual(first, frame[:1])
                self.assertEqual(flags & socket.MSG_CTRUNC, 0)
                self.assertEqual(len(ancillary), 1)
                level, kind, data = ancillary[0]
                self.assertEqual((level, kind), (socket.SOL_SOCKET, socket.SCM_RIGHTS))
                received_descriptors.frombytes(data)
                self.assertEqual(len(received_descriptors), 1)
                self.assertTrue(vm.private_received_directory(api, os.getpid(), candidate.st_dev, candidate.st_ino))
                client.sendall(frame[1:]); client.close()
                self.assertEqual(first + server.recv(len(frame) - 1), frame)
                with self.assertRaises(BrokenPipeError): server.send(b'fixed-ready-response')
                self.assertEqual(vm.private_process_stamp(api, os.getpid(), os.geteuid())[0], os.getpid())
            finally:
                client.close(); server.close()
                if directory is not None: os.close(directory)
                for descriptor in received_descriptors: os.close(descriptor)

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
