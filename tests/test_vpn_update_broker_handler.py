"""Test-only contract for the future unified VPN update-broker handler.

This model has no production imports and performs no filesystem, process, or
service mutation.  It fixes the transaction semantics expected when receive,
private inbox, signed authorization, joint preparation, executor handoff, and
durable status are eventually wired together.  The final test is deliberately
red until that production binding exists.
"""
from dataclasses import dataclass, field
from enum import IntEnum
import hashlib
from pathlib import Path
import sys
from typing import List, Optional
import unittest


ROOT = Path(__file__).resolve().parents[1]
HANDLER = ROOT / "app/vpn-helper/VPNUpdateBrokerHandler.swift"


class State(IntEnum):
    ACCEPTED = 0
    CHECKING = 1
    READY = 2
    INSTALLING = 3
    COMPLETE = 4
    FAILED = 5
    BUSY = 6
    STALE = 7


@dataclass(frozen=True)
class Response:
    state: State
    from_sequence: int
    to_sequence: int
    revision: int


@dataclass(frozen=True)
class CandidateDirectory:
    """An out-of-band directory capability, not an IPC wire value."""
    descriptor: int
    contents: bytes
    from_sequence: int
    to_sequence: int
    signed_transition: bool = True

    @property
    def identity(self):
        return hashlib.sha256(self.contents).digest()


@dataclass
class DurableTransaction:
    identity: bytes
    from_sequence: int
    to_sequence: int
    status: Optional[Response] = None
    recovery_armed: bool = False
    handoff_complete: bool = False


@dataclass
class DurableBrokerState:
    """State shared by fresh handler instances after broker death/restart."""
    inbox_identity: Optional[bytes] = None
    transaction: Optional[DurableTransaction] = None
    next_revision: int = 1
    transaction_lock: bool = False
    events: List[str] = field(default_factory=list)


class Refused(Exception):
    pass


class SimulatedCrash(Exception):
    pass


class CallerGone(Exception):
    pass


class UnifiedBrokerHandlerContract:
    """Executable model of one broker-owned, restartable transaction."""

    checkpoint_names = (
        "afterInbox", "afterAcceptedStatus", "afterCheckingStatus",
        "afterAuthorization", "afterPreparation", "afterReadyStatus",
        "beforeHandoff", "afterInstallingStatus", "afterHandoff",
        "afterCompleteStatus",
    )

    def __init__(self, durable, *, crash_at=None, hook=None):
        self.durable = durable
        self.crash_at = crash_at
        self.hook = hook
        self._crashed = False
        self._held = []

    def receive(self, request, descriptors, *, reply=lambda response: response):
        # Candidate identity, UUID, path, command, and destination are absent
        # from the fixed frame.  The only candidate authority is one received FD.
        if set(request) != {"operation", "expectedFromSequence"}:
            raise Refused("ambientAuthority")
        if request["operation"] != "submit":
            raise Refused("unknownOperation")
        expected = request["expectedFromSequence"]
        if type(expected) is not int or not 0 < expected < 2**64:
            raise Refused("invalidFrame")
        if len(descriptors) != 1 or not isinstance(descriptors[0], CandidateDirectory):
            raise Refused("exactlyOneDirectoryDescriptor")

        candidate = descriptors[0]
        self.durable.events.append("receive")
        # Ownership transfers to the broker before any reply is attempted.
        self.durable.events.append("broker-owns-request")
        response = self._submit(expected, candidate)
        return reply(response)

    def _submit(self, expected, candidate):
        if self.durable.transaction_lock:
            current = self.durable.transaction
            if current is not None and current.identity == candidate.identity:
                return current.status or Response(
                    State.ACCEPTED, current.from_sequence, current.to_sequence, 0)
            return self._transient(State.BUSY, expected)

        self._acquire("broker.transaction")
        self.durable.transaction_lock = True
        try:
            if (self.durable.inbox_identity is not None and
                    self.durable.inbox_identity != candidate.identity):
                return self._transient(State.BUSY, expected)
            self._publish_inbox(candidate)
            transaction = self.durable.transaction
            if transaction is None:
                transaction = DurableTransaction(
                    candidate.identity, expected, candidate.to_sequence)
                self.durable.transaction = transaction
            elif transaction.identity != candidate.identity:
                return self._transient(State.BUSY, expected)
            elif transaction.from_sequence != expected:
                return self._transient(State.STALE, expected)

            if (transaction.status is not None and
                    transaction.status.state in (State.COMPLETE, State.FAILED)):
                return transaction.status

            self._checkpoint("afterInbox")
            self._publish(State.ACCEPTED, transaction)
            self._checkpoint("afterAcceptedStatus")
            self._publish(State.CHECKING, transaction)
            self._checkpoint("afterCheckingStatus")

            try:
                self._authorize(candidate, expected)
                self._checkpoint("afterAuthorization")
                self._prepare(transaction)
                self._checkpoint("afterPreparation")
                self._publish(State.READY, transaction)
                self._checkpoint("afterReadyStatus")
                self._checkpoint("beforeHandoff")
                self._publish(State.INSTALLING, transaction)
                self._checkpoint("afterInstallingStatus")
                self._handoff(transaction, signed_authorized=True)
                self._checkpoint("afterHandoff")
                self._publish(State.COMPLETE, transaction)
                self._checkpoint("afterCompleteStatus")
                return transaction.status
            except Refused:
                self._publish(State.FAILED, transaction)
                raise
        finally:
            self.durable.transaction_lock = False
            self._release("broker.transaction")

    def _publish_inbox(self, candidate):
        identity = candidate.identity
        if self.durable.inbox_identity is None:
            self.durable.events.append("inbox.publish")
            self.durable.inbox_identity = identity
        elif self.durable.inbox_identity != identity:
            raise Refused("busy")
        else:
            self.durable.events.append("inbox.alreadyPublished")

    def _authorize(self, candidate, expected):
        self.durable.events.append("authorize.signed")
        if (not candidate.signed_transition or
                candidate.from_sequence != expected or
                candidate.to_sequence <= expected):
            raise Refused("invalidAuthorization")

    def _prepare(self, transaction):
        self._acquire("service.lifecycle")
        try:
            self._acquire("application.namespace")
            try:
                if not transaction.recovery_armed:
                    self.durable.events.append("prepare.armRecovery")
                    transaction.recovery_armed = True
                else:
                    self.durable.events.append("prepare.alreadyArmed")
            finally:
                self._release("application.namespace")
        finally:
            self._release("service.lifecycle")

    def _handoff(self, transaction, *, signed_authorized):
        if transaction.handoff_complete:
            self.durable.events.append("handoff.alreadyComplete")
            return

        # Parent proves the protected executor while owning only the Update
        # namespace, then releases that lease before GO.  The child reacquires
        # locks in the established service -> application order.
        self._acquire("application.namespace")
        self.durable.events.append("handoff.parentProof")
        self._release("application.namespace")
        self.durable.events.append("handoff.go")
        self._acquire("service.lifecycle")
        try:
            self._acquire("application.namespace")
            try:
                if not signed_authorized or not transaction.recovery_armed:
                    raise Refused("drainBeforeAuthorization")
                self.durable.events.append("service.drain")
                self.durable.events.append("handoff.commit")
                transaction.handoff_complete = True
            finally:
                self._release("application.namespace")
        finally:
            self._release("service.lifecycle")

    def _publish(self, state, transaction):
        current = transaction.status
        if current is not None and current.state >= state:
            return
        transaction.status = Response(
            state, transaction.from_sequence, transaction.to_sequence,
            self.durable.next_revision)
        self.durable.next_revision += 1
        self.durable.events.append("status." + state.name.lower())

    def _transient(self, state, expected):
        current = self.durable.transaction
        return Response(state, expected,
                        current.to_sequence if current is not None else 0,
                        current.status.revision
                        if current is not None and current.status is not None else 0)

    def _checkpoint(self, name):
        self.durable.events.append("checkpoint." + name)
        if self.hook is not None:
            self.hook(name)
        if self.crash_at == name and not self._crashed:
            self._crashed = True
            raise SimulatedCrash(name)

    def _acquire(self, name):
        if name == "broker.transaction":
            if self._held:
                raise AssertionError("broker transaction lock must be outermost")
        elif name == "service.lifecycle":
            if "application.namespace" in self._held:
                raise AssertionError("lock inversion: application before service")
        elif name == "application.namespace":
            pass  # It may stand alone for parent executor proof.
        self._held.append(name)
        self.durable.events.append("lock+" + name)

    def _release(self, name):
        if not self._held or self._held[-1] != name:
            raise AssertionError("non-LIFO lock release")
        self._held.pop()
        self.durable.events.append("lock-" + name)


class UnifiedBrokerHandlerContractTests(unittest.TestCase):
    def setUp(self):
        self.durable = DurableBrokerState()
        self.candidate = CandidateDirectory(19, b"signed exact A-to-B candidate", 41, 42)
        self.request = {"operation": "submit", "expectedFromSequence": 41}

    def submit(self, handler=None, candidate=None, request=None, **values):
        return (handler or UnifiedBrokerHandlerContract(self.durable)).receive(
            request or self.request, [candidate or self.candidate], **values)

    def test_one_serialized_transaction_same_candidate_idempotent_other_busy(self):
        observations = []

        def concurrent(point):
            if point != "afterAcceptedStatus":
                return
            nested = UnifiedBrokerHandlerContract(self.durable)
            observations.append(self.submit(nested))
            other = CandidateDirectory(20, b"different signed candidate", 41, 43)
            observations.append(self.submit(nested, other))

        final = self.submit(UnifiedBrokerHandlerContract(
            self.durable, hook=concurrent))
        self.assertEqual(observations[0].state, State.ACCEPTED)
        self.assertEqual(observations[1].state, State.BUSY)
        self.assertEqual(final.state, State.COMPLETE)
        repeated = self.submit()
        self.assertEqual(repeated, final)
        self.assertEqual(self.durable.events.count("service.drain"), 1)

    def test_request_has_no_path_uuid_identity_or_other_ambient_authority(self):
        forbidden = ("path", "url", "uuid", "transactionID", "candidateID",
                     "destination", "argv", "command", "uid")
        for field in forbidden:
            with self.subTest(field=field), self.assertRaisesRegex(
                    Refused, "ambientAuthority"):
                self.submit(request={**self.request, field: "attacker-controlled"})
        for descriptors in ([], [self.candidate, self.candidate], ["/tmp/candidate"]):
            with self.subTest(descriptors=descriptors), self.assertRaisesRegex(
                    Refused, "exactlyOneDirectoryDescriptor"):
                UnifiedBrokerHandlerContract(self.durable).receive(
                    self.request, descriptors)

    def test_caller_death_after_receive_does_not_cancel_broker_owned_work(self):
        def dead_reply(_response):
            raise CallerGone("peer disconnected")

        with self.assertRaises(CallerGone):
            self.submit(reply=dead_reply)
        self.assertEqual(self.durable.transaction.status.state, State.COMPLETE)
        self.assertTrue(self.durable.transaction.handoff_complete)
        self.assertLess(self.durable.events.index("broker-owns-request"),
                        self.durable.events.index("prepare.armRecovery"))

    def test_status_is_durable_numeric_and_survives_fresh_handler(self):
        expected = self.submit()
        restarted = UnifiedBrokerHandlerContract(self.durable)
        actual = self.submit(restarted)
        self.assertEqual(actual, expected)
        self.assertEqual(actual, self.durable.transaction.status)
        self.assertTrue(all(type(value) is int and 0 <= value < 2**64
                            for value in (int(actual.state), actual.from_sequence,
                                          actual.to_sequence, actual.revision)))
        self.assertNotIn("/", repr(actual))

    def test_service_drain_follows_signed_authorization_and_recovery_arm(self):
        self.submit()
        events = self.durable.events
        self.assertLess(events.index("authorize.signed"),
                        events.index("prepare.armRecovery"))
        self.assertLess(events.index("prepare.armRecovery"),
                        events.index("service.drain"))

        invalid_state = DurableBrokerState()
        invalid = CandidateDirectory(21, b"unsigned", 41, 42, False)
        with self.assertRaisesRegex(Refused, "invalidAuthorization"):
            UnifiedBrokerHandlerContract(invalid_state).receive(
                self.request, [invalid])
        self.assertNotIn("service.drain", invalid_state.events)
        self.assertEqual(invalid_state.transaction.status.state, State.FAILED)

    def test_exact_lock_order_and_executor_go_boundary(self):
        self.submit()
        events = self.durable.events
        expected = [
            "lock+broker.transaction",
            "lock+service.lifecycle", "lock+application.namespace",
            "lock-application.namespace", "lock-service.lifecycle",
            "lock+application.namespace", "handoff.parentProof",
            "lock-application.namespace", "handoff.go",
            "lock+service.lifecycle", "lock+application.namespace",
            "service.drain", "lock-application.namespace",
            "lock-service.lifecycle", "lock-broker.transaction",
        ]
        actual = [event for event in events if event.startswith("lock") or event in {
            "handoff.parentProof", "handoff.go", "service.drain"}]
        self.assertEqual(actual, expected)

    def test_every_inbox_status_preparation_and_handoff_crash_is_resumable(self):
        for checkpoint in UnifiedBrokerHandlerContract.checkpoint_names:
            with self.subTest(checkpoint=checkpoint):
                durable = DurableBrokerState()
                crashing = UnifiedBrokerHandlerContract(durable, crash_at=checkpoint)
                with self.assertRaisesRegex(SimulatedCrash, checkpoint):
                    crashing.receive(self.request, [self.candidate])
                recovered = UnifiedBrokerHandlerContract(durable).receive(
                    self.request, [self.candidate])
                self.assertEqual(recovered.state, State.COMPLETE)
                self.assertTrue(durable.transaction.recovery_armed)
                self.assertTrue(durable.transaction.handoff_complete)
                self.assertEqual(durable.events.count("service.drain"), 1)
                self.assertEqual(durable.inbox_identity, self.candidate.identity)


@unittest.skipUnless(sys.platform == "darwin", "production binding is a Darwin gate")
class UnifiedBrokerHandlerProductionBindingTests(unittest.TestCase):
    def test_unified_production_handler_file_exists(self):
        self.assertTrue(
            HANDLER.is_file(),
            "unified broker handler is required: "
            "app/vpn-helper/VPNUpdateBrokerHandler.swift",
        )

    def test_production_binding_names_every_required_boundary(self):
        if not HANDLER.is_file():
            self.skipTest("covered by the explicit missing-production-handler failure")
        source = HANDLER.read_text()
        for required in (
                "VPNUpdateBrokerInbox",
                "authorizePrivateInbox", "VPNJointUpdatePreparation.prepare",
                "VPNReplacementExecutorHandoff.launchPrepared",
                "VPNUpdateBrokerStatusStore", "VPNLifecycleOwnership",
                "recovery", "rotation"):
            self.assertIn(required, source)
        for forbidden in ("UUID(uuidString:", "URL(fileURLWithPath:",
                          "CommandLine.arguments[2]", "request.path"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
