"""Focused model and source contracts for broker A-to-B rotation."""
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import unittest


ROOT = Path(__file__).resolve().parents[1]
ROTATION = ROOT / "app/vpn-helper/VPNUpdateBrokerRotation.swift"
JOINT = ROOT / "app/vpn-helper/VPNJointApplicationReplacement.swift"
RECOVERY = ROOT / "app/vpn-helper/VPNSelectedCandidateRecovery.swift"
EXECUTOR_ENTRY = ROOT / "app/vpn-helper/VPNReplacementExecutorEntry.swift"
RECOVERY_ENTRY = ROOT / "app/vpn-helper/VPNSelectedCandidateRecoveryEntry.swift"
RECOVERY_DAEMON_ENTRY = (
    ROOT / "app/vpn-helper/VPNSelectedCandidateRecoveryDaemonEntry.swift")


class InvalidTransaction(Exception):
    pass


@dataclass(frozen=True)
class Journal:
    transaction_id: str
    revision: int
    phase: str
    recovery: str
    previous_release: str
    candidate_release: str
    from_sequence: int
    to_sequence: int


@dataclass(frozen=True)
class Receipt:
    identity: bytes
    transaction_id: str
    journal_revision: int
    journal_phase: str
    from_sequence: int
    to_sequence: int
    phase: str = "handoffStarted"


@dataclass(frozen=True)
class InboxPayload:
    identity: bytes
    previous_release: str
    candidate_release: str
    transition_from: str
    transition_to: str


@dataclass(frozen=True)
class Completion:
    identity: bytes
    transaction_id: str
    journal_revision: int


class RotationContract:
    """No-I/O model: a receipt is an index, never authorization."""

    def __init__(self, receipt: Optional[Receipt], inbox: Optional[InboxPayload],
                 journal: Journal, selected_release: str):
        self.receipt = receipt
        self.inbox = inbox
        self.journal = journal
        self.selected_release = selected_release
        self.retired = False
        self.events = []

    def rotate_if_required(self):
        if self.receipt is None:
            self.events.append("legacy.noReceipt")
            return None
        receipt = self.receipt
        journal = self.journal
        inbox = self.inbox
        valid = (
            receipt.phase in {"handoffStarted", "handoffComplete", "rotatingBroker"}
            and receipt.transaction_id == journal.transaction_id
            and receipt.journal_revision == journal.revision
            and receipt.journal_phase == "completed"
            and receipt.from_sequence == journal.from_sequence
            and receipt.to_sequence == journal.to_sequence
            and journal.phase == "completed"
            and journal.recovery == "completed"
            and self.selected_release == journal.candidate_release
            and inbox is not None
            and inbox.identity == receipt.identity
            and inbox.previous_release == journal.previous_release
            and inbox.candidate_release == journal.candidate_release
            and inbox.transition_from == journal.previous_release
            and inbox.transition_to == journal.candidate_release
        )
        if not valid:
            raise InvalidTransaction("receipt/journal/inbox mismatch")
        self.events.extend(("rotation.installB", "rotation.durableComplete"))
        return Completion(receipt.identity, journal.transaction_id, journal.revision)

    def retire_journal(self):
        self.events.append("journal.retire")
        self.retired = True

    def finish(self, completion):
        if (not self.retired or self.receipt is None or
                completion.identity != self.receipt.identity or
                completion.transaction_id != self.journal.transaction_id or
                completion.journal_revision != self.journal.revision):
            raise InvalidTransaction("completion before/mismatched retirement")
        self.events.extend(("transaction.complete", "status.complete"))


class VPNUpdateBrokerRotationModelTests(unittest.TestCase):
    def setUp(self):
        self.identity = b"i" * 32
        self.journal = Journal("txn-1", 3, "completed", "completed",
                               "release-A", "release-B", 41, 42)
        self.receipt = Receipt(self.identity, "txn-1", 3, "completed", 41, 42)
        self.inbox = InboxPayload(self.identity, "release-A", "release-B",
                                  "release-A", "release-B")

    def model(self, **changes):
        values = dict(receipt=self.receipt, inbox=self.inbox,
                      journal=self.journal, selected_release="release-B")
        values.update(changes)
        return RotationContract(**values)

    def test_exact_receipt_journal_and_reopened_inbox_are_all_required(self):
        model = self.model()
        completion = model.rotate_if_required()
        self.assertEqual(completion,
                         Completion(self.identity, "txn-1", 3))
        self.assertEqual(model.events,
                         ["rotation.installB", "rotation.durableComplete"])

    def test_rotation_precedes_retirement_and_completion_follows_retirement(self):
        model = self.model()
        completion = model.rotate_if_required()
        with self.assertRaisesRegex(InvalidTransaction, "before/mismatched"):
            model.finish(completion)
        model.retire_journal()
        model.finish(completion)
        self.assertEqual(model.events, [
            "rotation.installB", "rotation.durableComplete",
            "journal.retire", "transaction.complete", "status.complete",
        ])

    def test_legacy_update_without_broker_receipt_is_a_no_op(self):
        model = self.model(receipt=None, inbox=None)
        self.assertIsNone(model.rotate_if_required())
        self.assertEqual(model.events, ["legacy.noReceipt"])

    def test_every_receipt_journal_inbox_or_selection_mismatch_fails_closed(self):
        mismatches = {
            "receipt identity": dict(inbox=InboxPayload(
                b"x" * 32, "release-A", "release-B", "release-A", "release-B")),
            "transaction": dict(receipt=Receipt(
                self.identity, "other", 3, "completed", 41, 42)),
            "journal revision": dict(receipt=Receipt(
                self.identity, "txn-1", 2, "completed", 41, 42)),
            "source sequence": dict(receipt=Receipt(
                self.identity, "txn-1", 3, "completed", 40, 42)),
            "destination sequence": dict(receipt=Receipt(
                self.identity, "txn-1", 3, "completed", 41, 43)),
            "journal phase": dict(journal=Journal(
                "txn-1", 3, "selected", "recoverCandidate",
                "release-A", "release-B", 41, 42)),
            "selected release": dict(selected_release="release-A"),
            "inbox previous": dict(inbox=InboxPayload(
                self.identity, "other-A", "release-B", "release-A", "release-B")),
            "inbox candidate": dict(inbox=InboxPayload(
                self.identity, "release-A", "other-B", "release-A", "release-B")),
            "transition edge": dict(inbox=InboxPayload(
                self.identity, "release-A", "release-B", "other-A", "release-B")),
        }
        for name, change in mismatches.items():
            with self.subTest(name=name), self.assertRaises(InvalidTransaction):
                self.model(**change).rotate_if_required()


class VPNUpdateBrokerRotationSourceTests(unittest.TestCase):
    def test_production_rotation_revalidates_exact_receipt_journal_inbox_and_selection(self):
        source = ROTATION.read_text()
        for required in (
                "transaction.identity", "recorded.transactionID == journal.transactionID",
                "transaction.fromSequence == journal.previous.release.sequence",
                "transaction.toSequence == journal.candidate.release.sequence",
                "current.transactionID == journal.transactionID",
                "current.revision == journal.revision",
                "selected.release.isSameRelease(as: journal.candidate.release)",
                "inbox.openPublished(identity: transaction.identity)",
                "VPNJointUpdatePayload.loadForBroker",
                "payload.previous.isSameRelease(as: journal.previous.release)",
                "payload.candidate.release.isSameRelease(as: journal.candidate.release)",
                "payload.transition.matchesSource(journal.previous.release)",
                "payload.transition.matchesDestination(journal.candidate.release)"):
            self.assertIn(required, source)

    def test_legacy_absent_broker_state_is_no_op_but_present_mismatch_throws(self):
        source = ROTATION.read_text()
        self.assertIn("return nil", source)
        self.assertIn("guard var transaction = try transactions.load() else { return nil }",
                      source)
        self.assertIn("throw VPNUpdateBrokerRotationError.invalidTransaction", source)
        self.assertLess(source.index("openSystemBrokerDirectory(create: false)"),
                        source.index("guard var transaction"))

    def test_rotation_and_final_status_straddle_durable_journal_retirement(self):
        joint = JOINT.read_text()
        before = joint.index("try beforeJournalRetirement(store, lease, completed)")
        retire = joint.index("try VPNSelectedCandidateRecovery.retireCompleted(", before)
        after = joint.index("try afterJournalRetirement(store, lease)", retire)
        self.assertLess(before, retire)
        self.assertLess(retire, after)

        recovery = RECOVERY.read_text()
        before = recovery.index("try beforeJournalRetirement(completed)")
        retire = recovery.index("try retireCompleted(", before)
        after = recovery.index("try afterJournalRetirement(store, lease)", retire)
        self.assertLess(before, retire)
        self.assertLess(retire, after)

        rotation = ROTATION.read_text()
        rotate = rotation.index("try job.installAndStart(")
        rotation_done = rotation.index("phase: .rotatingBroker", rotate)
        finish = rotation.index("static func finish", rotation_done)
        transaction_done = rotation.index("phase: .complete", finish)
        status_done = rotation.index("state: .complete", transaction_done)
        self.assertLess(rotate, rotation_done)
        self.assertLess(rotation_done, finish)
        self.assertLess(finish, transaction_done)
        self.assertLess(transaction_done, status_done)

    def test_normal_executor_and_both_recovery_entries_wire_both_sides(self):
        sources = {
            "executor": EXECUTOR_ENTRY.read_text(),
            "recovery": RECOVERY_ENTRY.read_text(),
            "recovery daemon": RECOVERY_DAEMON_ENTRY.read_text(),
        }
        for name, source in sources.items():
            with self.subTest(entry=name):
                before = source.index("beforeJournalRetirement:")
                rotate = source.index("VPNUpdateBrokerRotation.rotateIfRequired(", before)
                after = source.index("afterJournalRetirement:", rotate)
                finish = source.index("VPNUpdateBrokerRotation.finish(", after)
                self.assertLess(before, rotate)
                self.assertLess(rotate, after)
                self.assertLess(after, finish)


if __name__ == "__main__":
    unittest.main()
