"""Ordinary-user update-broker client contract.

The model fixes the important durable-ready boundary before broker rotation.
EOF or timeout before that ACK is indeterminate and must never release a mount
or terminate app A. Newly launched app B may independently read
the bounded durable status, using a fresh one-request connection and no FD.
"""
from collections import deque
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / 'app/vpn-helper/VPNUpdateBrokerClient.swift'
FIXED_ENDPOINT = (
    '/Library/Application Support/kz.documentolog.proxypilot.vpn/'
    'update-broker.sock'
)


class State(Enum):
    ACCEPTED = 'accepted'
    CHECKING = 'checking'
    READY = 'ready'
    INSTALLING = 'installing'
    COMPLETE = 'complete'
    FAILED = 'failed'
    BUSY = 'busy'
    STALE = 'stale'


@dataclass(frozen=True)
class Status:
    state: State
    from_sequence: int
    to_sequence: int
    revision: int


class Disconnected(Exception):
    def __init__(self, *, after_send):
        super().__init__('disconnected')
        self.after_send = after_send


class DeadlineExceeded(Exception):
    pass


class MismatchedTransaction(Exception):
    pass


class SubmitOutcome(Enum):
    INDETERMINATE = 'indeterminate'


class ScriptedConnection:
    """One connection accepts exactly one request from the contract model."""

    def __init__(self, script, observations):
        self.script = script
        self.observations = observations

    def exchange(self, operation, *, descriptor=None, expected_sequence=0):
        self.observations.append((operation, descriptor, expected_sequence))
        action = self.script.popleft()
        if isinstance(action, Exception):
            raise action
        return action


class ScriptedEndpoint:
    def __init__(self, scripts):
        self.scripts = deque(deque(script) for script in scripts)
        self.requests = []

    def connect(self):
        if not self.scripts:
            raise AssertionError('unexpected connection')
        return ScriptedConnection(self.scripts.popleft(), self.requests)


class BrokerClientModel:
    def __init__(self, endpoint):
        self.endpoint = endpoint

    def submit(self, candidate_directory, expected_from_sequence, deadline):
        try:
            response = self.endpoint.connect().exchange(
                'submit', descriptor=candidate_directory,
                expected_sequence=expected_from_sequence,
            )
        except Disconnected as error:
            if not error.after_send:
                raise
            return SubmitOutcome.INDETERMINATE
        return response

    def status(self, deadline):
        if deadline <= 0:
            raise DeadlineExceeded
        return self.endpoint.connect().exchange('status')


def status(state, revision):
    return Status(state, 41, 42, revision)


class VPNUpdateBrokerClientModelTests(unittest.TestCase):
    def test_post_submit_disconnect_is_indeterminate_without_reconnecting(self):
        endpoint = ScriptedEndpoint([
            [Disconnected(after_send=True)],
        ])
        result = BrokerClientModel(endpoint).submit(73, 41, deadline=9)

        self.assertEqual(result, SubmitOutcome.INDETERMINATE)
        self.assertEqual(endpoint.requests, [('submit', 73, 41)])
        self.assertEqual(len(endpoint.scripts), 0)

    def test_disconnect_before_submit_is_sent_is_not_reported_as_ready(self):
        endpoint = ScriptedEndpoint([[Disconnected(after_send=False)]])
        with self.assertRaises(Disconnected):
            BrokerClientModel(endpoint).submit(73, 41, deadline=9)
        self.assertEqual(endpoint.requests, [('submit', 73, 41)])

        mismatch = ScriptedEndpoint([[MismatchedTransaction()]])
        with self.assertRaises(MismatchedTransaction):
            BrokerClientModel(mismatch).submit(73, 41, deadline=9)

    def test_new_app_reads_terminal_status_on_separate_descriptor_free_connection(self):
        endpoint = ScriptedEndpoint([[status(State.COMPLETE, 7)]])
        result = BrokerClientModel(endpoint).status(deadline=9)
        self.assertEqual(result, status(State.COMPLETE, 7))
        self.assertEqual(endpoint.requests, [('status', None, 0)])

        with self.assertRaises(DeadlineExceeded):
            BrokerClientModel(ScriptedEndpoint([])).status(deadline=0)


class VPNUpdateBrokerClientSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CLIENT.is_file():
            raise AssertionError(
                'VPNUpdateBrokerClient.swift must implement the client')
        cls.source = CLIENT.read_text()

    def function_source(self, name):
        start = self.source.index(f'func {name}(')
        opening = self.source.index('{', start)
        depth = 0
        for index in range(opening, len(self.source)):
            if self.source[index] == '{':
                depth += 1
            elif self.source[index] == '}':
                depth -= 1
                if depth == 0:
                    return self.source[start:index + 1]
        self.fail(f'unterminated Swift function {name}')

    def test_public_submit_surface_is_descriptor_sequence_and_deadline_only(self):
        start = self.source.index('func submit(')
        end = self.source.index(')', start)
        surface = self.source[start:end]
        for required in ('candidateDirectory: Int32',
                         'expectedFromSequence: UInt64', 'deadline: UInt64'):
            self.assertIn(required, surface)
        for forbidden in ('String', 'URL', 'Data', 'UUID', 'path', 'command',
                          'arguments', 'environment'):
            self.assertNotIn(forbidden, surface)

    def test_endpoint_is_fixed_and_submit_uses_one_rights_descriptor(self):
        self.assertIn(FIXED_ENDPOINT, self.source)
        for required in ('VPNUpdateBrokerRequest.submit', 'sendmsg', 'SCM_RIGHTS'):
            self.assertIn(required, self.source)
        self.assertNotIn('endpoint:', self.source)
        self.assertNotIn('socketPath:', self.source)

    def test_disconnect_is_indeterminate_and_never_reconnects(self):
        for required in ('decodeResponse', 'indeterminate'):
            self.assertIn(required, self.source)
        submit = self.function_source('exchangeSubmit')
        self.assertNotIn('VPNUpdateBrokerRequest.status', submit)
        self.assertNotIn('reconnect(', submit)
        # Validation must occur outside the receive/disconnect catch; otherwise
        # a valid frame for another transaction could be mislabeled as transport.
        self.assertGreater(submit.index('try validate('),
                           submit.index('catch {', submit.index('try receive(')))

    def test_new_app_status_api_is_separate_and_descriptor_free(self):
        start = self.source.index('func status(')
        end = self.source.index(')', start)
        surface = self.source[start:end]
        self.assertIn('deadline: UInt64', surface)
        self.assertNotIn('candidateDirectory', surface)
        self.assertNotIn('expectedFromSequence', surface)

        body = self.function_source('status')
        self.assertIn('VPNUpdateBrokerRequest.status', body)
        self.assertNotIn('candidateDirectory', body)
        self.assertNotIn('SCM_RIGHTS', body)

    def test_deadlines_and_interrupted_io_remain_bounded(self):
        for required in ('deadline', 'POLL', 'EINTR'):
            self.assertIn(required, self.source)

    def test_busy_and_stale_allow_an_unpublished_destination(self):
        validate = self.function_source('validate')
        self.assertIn('case .busy, .stale', validate)
        self.assertIn('response.toSequence == 0', validate)

    def test_only_durable_ready_is_a_successful_submit_response(self):
        validate = self.function_source('validate')
        self.assertIn('case .ready:', validate)
        self.assertIn('case .accepted, .checking, .installing, .complete, .failed:',
                      validate)


if __name__ == '__main__':
    unittest.main()
