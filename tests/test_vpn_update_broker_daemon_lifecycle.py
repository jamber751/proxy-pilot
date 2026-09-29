"""Test-only contract for the future update-broker daemon lifecycle.

The model is deliberately inert: it creates no socket, registers no launchd
job, runs no privileged process, and cannot reach the update mutation pipeline.
It fixes the authority/lifecycle decisions that a later production daemon must
implement.  The final test is an intentionally red Darwin binding until that
production entry exists.
"""
from dataclasses import dataclass
from enum import IntEnum
import json
import os
from pathlib import Path
import plistlib
import shutil
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DAEMON = ROOT / 'app/vpn-helper/VPNUpdateBrokerDaemon.swift'
LAUNCHD = ROOT / 'app/vpn-helper/VPNUpdateBrokerLaunchdJob.swift'


class Phase(IntEnum):
    IDLE = 0
    CHECKING = 1
    READY = 2
    INSTALLING = 3
    COMPLETE = 4
    FAILED = 5


@dataclass(frozen=True)
class Status:
    phase: Phase
    from_sequence: int = 0
    to_sequence: int = 0
    revision: int = 0

    def encode(self):
        # This is the complete public status vocabulary.  There is no string
        # payload in which a path, identity, diagnostic, or secret could hide.
        return (int(self.phase), self.from_sequence, self.to_sequence, self.revision)


@dataclass(frozen=True)
class Peer:
    user_id: int
    signing_identifier: str
    cdhash: str


class Refused(Exception):
    pass


class BrokerDaemonContract:
    label = 'kz.documentolog.proxypilot.vpn-update-broker'
    executable_parent = '/Library/Application Support/ProxyPilot/VPN'
    private_state_parent = '/Library/Application Support/ProxyPilot/Broker'
    endpoint_parent = '/Library/Application Support/kz.documentolog.proxypilot.vpn'
    endpoint_name = 'update-broker.sock'
    endpoint_mode = 0o666
    entry_argument = 'serve-update-broker'
    status_name = 'update-broker-status-v1'

    def __init__(self, state_directory, *, endpoint_owner=0, endpoint_parent_mode=0o755,
                 private_state_owner=0, private_state_mode=0o700, effective_user=0,
                 authorized_identifier, authorized_cdhash, mutation=None):
        if (effective_user != 0 or endpoint_owner != 0 or
                endpoint_parent_mode != 0o755):
            raise Refused('unsafePublicEndpoint')
        if private_state_owner != 0 or private_state_mode != 0o700:
            raise Refused('unsafePrivateState')
        self.state_directory = Path(state_directory)
        self.authorized_identifier = authorized_identifier
        self.authorized_cdhash = authorized_cdhash
        self.mutation = mutation
        self.running = False

    @property
    def endpoint(self):
        return f'{self.endpoint_parent}/{self.endpoint_name}'

    @classmethod
    def verified_executable(cls, digest):
        if (len(digest) != 64 or any(character not in '0123456789abcdef'
                                     for character in digest)):
            raise Refused('unverifiedExecutable')
        return f'{cls.executable_parent}/helper-{digest}'

    @classmethod
    def launchd_description(cls, verified_executable):
        prefix = cls.executable_parent + '/helper-'
        digest = verified_executable.removeprefix(prefix)
        if verified_executable != cls.verified_executable(digest):
            raise Refused('unverifiedExecutable')
        return {
            'Label': cls.label,
            'ProgramArguments': [verified_executable, cls.entry_argument],
            'RunAtLoad': True,
            'KeepAlive': True,
            'ProcessType': 'Background',
            'ThrottleInterval': 10,
        }

    @classmethod
    def validate_entry_arguments(cls, arguments, verified_executable):
        # argv[0] is the already-verified release-A helper.  No path or mode is
        # accepted from any later argument.
        expected = [verified_executable, cls.entry_argument]
        if len(arguments) != 2 or arguments != expected:
            raise Refused('invalidDaemonArguments')

    @classmethod
    def install_job_for_test(cls, plist_directory, verified_executable):
        destination = Path(plist_directory) / f'{cls.label}.plist'
        pending = destination.with_name('.' + destination.name + '.pending')
        pending.write_bytes(plistlib.dumps(cls.launchd_description(verified_executable)))
        os.chmod(pending, 0o644)
        os.replace(pending, destination)
        return destination

    @classmethod
    def remove_job_for_test(cls, plist_directory):
        destination = Path(plist_directory) / f'{cls.label}.plist'
        try:
            destination.unlink()
        except FileNotFoundError:
            pass

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def restart(self):
        self.stop()
        self.start()
        return self.status()

    def _authorize(self, peer):
        # UID is the kernel credential.  It is necessary but not sufficient:
        # the exact signed application role is pinned independently.
        if (peer.user_id == 0 or
                peer.signing_identifier != self.authorized_identifier or
                peer.cdhash != self.authorized_cdhash):
            raise Refused('unauthorizedPeer')

    def _state_file(self):
        return self.state_directory / self.status_name

    def status(self):
        path = self._state_file()
        if not path.exists():
            return Status(Phase.IDLE)
        raw = json.loads(path.read_text())
        if set(raw) != {'phase', 'from', 'to', 'revision'}:
            raise Refused('invalidDurableStatus')
        values = [raw['phase'], raw['from'], raw['to'], raw['revision']]
        if not all(type(value) is int and 0 <= value < 2**64 for value in values):
            raise Refused('invalidDurableStatus')
        try:
            phase = Phase(raw['phase'])
        except ValueError as error:
            raise Refused('invalidDurableStatus') from error
        return Status(phase, raw['from'], raw['to'], raw['revision'])

    def persist_for_test(self, status):
        self.state_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = self.state_directory / (self.status_name + '.pending')
        temporary.write_text(json.dumps({
            'phase': int(status.phase), 'from': status.from_sequence,
            'to': status.to_sequence, 'revision': status.revision,
        }, separators=(',', ':')))
        os.replace(temporary, self._state_file())

    def connection(self, peer, requests):
        if not self.running:
            raise Refused('notRunning')
        self._authorize(peer)
        if len(requests) != 1:
            raise Refused('oneRequestPerConnection')
        request = requests[0]
        if set(request) - {'operation', 'expectedFromSequence', 'descriptor'}:
            raise Refused('ambientAuthority')
        if request.get('operation') == 'status':
            if set(request) != {'operation'}:
                raise Refused('ambientAuthority')
            return self.status()
        if request.get('operation') != 'submit':
            raise Refused('unknownOperation')
        if set(request) != {'operation', 'expectedFromSequence', 'descriptor'}:
            raise Refused('ambientAuthority')
        if self.mutation is None:
            raise Refused('mutationNotConnected')
        return self.mutation(request['expectedFromSequence'], request['descriptor'])


class VPNUpdateBrokerDaemonLifecycleContractTests(unittest.TestCase):
    identifier = 'kz.documentolog.proxypilot'
    cdhash = '11' * 20
    helper_digest = 'a1' * 32

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='pp-broker-daemon-contract-')
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name) / 'state'
        self.peer = Peer(os.geteuid(), self.identifier, self.cdhash)

    def daemon(self, **values):
        options = dict(endpoint_owner=0, endpoint_parent_mode=0o755,
                       private_state_owner=0, private_state_mode=0o700,
                       effective_user=0,
                       authorized_identifier=self.identifier,
                       authorized_cdhash=self.cdhash)
        options.update(values)
        return BrokerDaemonContract(self.state, **options)

    def test_endpoint_is_one_fixed_name_in_the_existing_public_root_directory(self):
        daemon = self.daemon()
        self.assertEqual(daemon.endpoint,
                         '/Library/Application Support/kz.documentolog.proxypilot.vpn/update-broker.sock')
        self.assertEqual(daemon.endpoint_mode, 0o666)
        for options in ({'effective_user': 501}, {'endpoint_owner': 501},
                        {'endpoint_parent_mode': 0o700},
                        {'endpoint_parent_mode': 0o777}):
            with self.subTest(options=options), self.assertRaisesRegex(
                    Refused, 'unsafePublicEndpoint'):
                self.daemon(**options)

    def test_private_status_and_inbox_root_are_separate_from_public_endpoint(self):
        self.assertEqual(BrokerDaemonContract.private_state_parent,
                         '/Library/Application Support/ProxyPilot/Broker')
        self.assertNotEqual(BrokerDaemonContract.private_state_parent,
                            BrokerDaemonContract.endpoint_parent)
        self.assertFalse(BrokerDaemonContract.private_state_parent.startswith(
            BrokerDaemonContract.endpoint_parent + '/'))
        for options in ({'private_state_owner': 501},
                        {'private_state_mode': 0o755},
                        {'private_state_mode': 0o770}):
            with self.subTest(options=options), self.assertRaisesRegex(
                    Refused, 'unsafePrivateState'):
                self.daemon(**options)

    def test_launchd_job_has_fixed_identity_program_and_restart_policy(self):
        executable = BrokerDaemonContract.verified_executable(self.helper_digest)
        description = BrokerDaemonContract.launchd_description(executable)
        self.assertEqual(description['Label'], BrokerDaemonContract.label)
        self.assertEqual(description['ProgramArguments'], [
            executable, BrokerDaemonContract.entry_argument])
        self.assertEqual(executable,
                         '/Library/Application Support/ProxyPilot/VPN/helper-' + self.helper_digest)
        self.assertNotIn('vpn-update-broker', Path(executable).name)
        self.assertTrue(description['RunAtLoad'])
        self.assertIs(description['KeepAlive'], True)
        self.assertEqual(description['ThrottleInterval'], 10)
        encoded = plistlib.dumps(description)
        for forbidden in (b'${', b'--path', b'--socket', b'--command', b'--uid'):
            self.assertNotIn(forbidden, encoded)

    def test_daemon_accepts_exactly_the_release_a_executable_and_one_fixed_argument(self):
        executable = BrokerDaemonContract.verified_executable(self.helper_digest)
        BrokerDaemonContract.validate_entry_arguments(
            [executable, 'serve-update-broker'], executable)
        refused = (
            [executable],
            [executable, 'serve-update-broker', '/attacker/path'],
            ['/tmp/helper-' + self.helper_digest, 'serve-update-broker'],
            [executable, 'serve-update-broker', '--uid=0'],
        )
        for arguments in refused:
            with self.subTest(arguments=arguments), self.assertRaisesRegex(
                    Refused, 'invalidDaemonArguments'):
                BrokerDaemonContract.validate_entry_arguments(arguments, executable)
        for digest in ('', 'aa', 'G1' * 32, self.helper_digest + '00'):
            with self.subTest(digest=digest), self.assertRaisesRegex(
                    Refused, 'unverifiedExecutable'):
                BrokerDaemonContract.verified_executable(digest)

    def test_launchd_description_install_and_removal_are_atomic_and_idempotent(self):
        plists = Path(self.temporary.name) / 'LaunchDaemons'
        plists.mkdir(mode=0o755)
        executable = BrokerDaemonContract.verified_executable(self.helper_digest)
        installed = BrokerDaemonContract.install_job_for_test(plists, executable)
        self.assertEqual(plistlib.loads(installed.read_bytes()),
                         BrokerDaemonContract.launchd_description(executable))
        self.assertEqual(installed.stat().st_mode & 0o7777, 0o644)
        self.assertEqual([entry.name for entry in plists.iterdir()
                          if entry.name.startswith('.')], [])
        BrokerDaemonContract.remove_job_for_test(plists)
        BrokerDaemonContract.remove_job_for_test(plists)
        self.assertFalse(installed.exists())

    def test_lifecycle_starts_stops_and_restarts_without_losing_status(self):
        daemon = self.daemon()
        saved = Status(Phase.READY, 41, 42, 7)
        daemon.persist_for_test(saved)
        daemon.start()
        self.assertEqual(daemon.status(), saved)
        daemon.stop()
        with self.assertRaisesRegex(Refused, 'notRunning'):
            daemon.connection(self.peer, [{'operation': 'status'}])
        self.assertEqual(daemon.restart(), saved)
        self.assertEqual(daemon.connection(self.peer, [{'operation': 'status'}]), saved)
        replacement_process = self.daemon(); replacement_process.start()
        self.assertEqual(replacement_process.status(), saved)

    def test_one_connection_carries_exactly_one_request(self):
        daemon = self.daemon(); daemon.start()
        self.assertEqual(daemon.connection(self.peer, [{'operation': 'status'}]),
                         Status(Phase.IDLE))
        for requests in ([], [{'operation': 'status'}, {'operation': 'status'}]):
            with self.subTest(requests=requests), self.assertRaisesRegex(
                    Refused, 'oneRequestPerConnection'):
                daemon.connection(self.peer, requests)

    def test_peer_needs_kernel_uid_and_exact_signed_application_pin(self):
        daemon = self.daemon(); daemon.start()
        refused = [
            Peer(0, self.identifier, self.cdhash),
            Peer(os.geteuid(), 'kz.documentolog.proxypilot.other', self.cdhash),
            Peer(os.geteuid(), self.identifier, '22' * 20),
        ]
        for peer in refused:
            with self.subTest(peer=peer), self.assertRaisesRegex(Refused, 'unauthorizedPeer'):
                daemon.connection(peer, [{'operation': 'status'}])

    def test_public_endpoint_is_reachability_not_authority(self):
        calls = []
        daemon = self.daemon(mutation=lambda sequence, descriptor:
                             calls.append((sequence, descriptor)))
        daemon.start()
        # The endpoint is intentionally world-connectable; possessing its fixed
        # name or reaching its 0666 socket grants no broker operation.
        self.assertEqual(daemon.endpoint_mode, 0o666)
        attacker = Peer(os.geteuid(), 'kz.documentolog.proxypilot.other', self.cdhash)
        with self.assertRaisesRegex(Refused, 'unauthorizedPeer'):
            daemon.connection(attacker, [{
                'operation': 'submit', 'expectedFromSequence': 41, 'descriptor': 9}])
        self.assertEqual(calls, [])

    def test_requests_cannot_supply_paths_argv_or_identity(self):
        daemon = self.daemon(); daemon.start()
        for field in ('path', 'url', 'argv', 'shell', 'environment', 'uid',
                      'endpoint', 'executable', 'label'):
            with self.subTest(field=field), self.assertRaisesRegex(
                    Refused, 'ambientAuthority'):
                daemon.connection(self.peer, [{'operation': 'status', field: 'attacker'}])

    def test_restart_status_is_bounded_numeric_and_corruption_fails_closed(self):
        daemon = self.daemon(); daemon.start()
        saved = Status(Phase.INSTALLING, 41, 42, 2**64 - 1)
        daemon.persist_for_test(saved)
        encoded = daemon.restart().encode()
        self.assertEqual(len(encoded), 4)
        self.assertTrue(all(type(value) is int and 0 <= value < 2**64
                            for value in encoded))
        self.assertNotIn('/', repr(encoded))
        self._write_raw({'phase': 99, 'from': 41, 'to': 42, 'revision': 8})
        with self.assertRaisesRegex(Refused, 'invalidDurableStatus'):
            daemon.restart()

    def _write_raw(self, value):
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        (self.state / BrokerDaemonContract.status_name).write_text(json.dumps(value))

    def test_daemon_has_no_mutation_until_an_explicit_handler_is_connected(self):
        calls = []
        daemon = self.daemon(); daemon.start()
        submit = {'operation': 'submit', 'expectedFromSequence': 41, 'descriptor': 9}
        with self.assertRaisesRegex(Refused, 'mutationNotConnected'):
            daemon.connection(self.peer, [submit])
        self.assertEqual(calls, [])

        connected = self.daemon(mutation=lambda sequence, descriptor:
                                calls.append((sequence, descriptor)) or Status(
                                    Phase.CHECKING, sequence, 0, 1))
        connected.start()
        self.assertEqual(connected.connection(self.peer, [submit]),
                         Status(Phase.CHECKING, 41, 0, 1))
        self.assertEqual(calls, [(41, 9)])


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'),
                     'production binding is a macOS Swift gate')
class VPNUpdateBrokerDaemonProductionBindingTests(unittest.TestCase):
    def test_production_daemon_and_launchd_entries_exist(self):
        missing = [path for path in (DAEMON, LAUNCHD) if not path.is_file()]
        self.assertFalse(
            missing,
            'expected red test: update-broker daemon lifecycle is not implemented: '
            + ', '.join(str(path.relative_to(ROOT)) for path in missing),
        )

    def test_production_surface_preserves_the_test_only_contract(self):
        if not DAEMON.is_file() or not LAUNCHD.is_file():
            self.skipTest('covered by the explicit missing-production-entry failure')
        daemon_source = DAEMON.read_text()
        launchd_source = LAUNCHD.read_text()
        source = daemon_source + '\n' + launchd_source
        for required in (
                BrokerDaemonContract.label, BrokerDaemonContract.executable_parent,
                BrokerDaemonContract.private_state_parent,
                BrokerDaemonContract.endpoint_parent, BrokerDaemonContract.endpoint_name,
                'VPNUpdateBrokerTransport.receive', 'VPNPeerPolicy', 'KeepAlive',
                'deployment.helperFileName', 'VPNHelperArtifact.validate',
                'launch_activate_socket', 'arguments.count == 2',
                '0o666', '0o755', '0o700'):
            self.assertIn(required, source)
        for forbidden in ('CommandLine.arguments[2]', '/bin/sh', '/usr/bin/env',
                          '/Library/Application Support/ProxyPilot/VPN/vpn-update-broker'):
            self.assertNotIn(forbidden, source)
        # The broker itself never launches a process. The launchd publisher may
        # execute only fixed /bin/launchctl with its empty environment.
        self.assertNotIn('Process()', daemon_source)
        self.assertIn('private static let launchctlPath = "/bin/launchctl"', launchd_source)
        self.assertIn('process.environment = [:]', launchd_source)


if __name__ == '__main__':
    unittest.main()
