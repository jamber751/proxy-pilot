"""Contract for the final joint-update relaunch and app-B acknowledgement.

This is deliberately a no-I/O model plus source-level acceptance contract.  It
does not teach the ordinary updater wire a path or turn Sparkle's deferred
``installHandler`` into a joint-update capability.
"""
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "app/update-worker/UpdateWorker.swift"
WIRE = ROOT / "app/update-worker/UpdateWire.swift"
SENTINEL = ROOT / "app/update-worker/JointRelaunchSentinel.swift"
STARTUP = ROOT / "app/vpn-helper/VPNJointUpdateStartupStatus.swift"
BUILD = ROOT / "app/build.sh"
FIXED_APPLICATION = "/Applications/ProxyPilot.app"


class RelaunchFailure(Exception):
    pass


class FrontendEvent(Enum):
    EOF = "eof"
    EXIT = "exit"
    MESSAGE = "message"


class JointRelaunchSentinelModel:
    """One armed worker may open one fixed application after frontend death."""

    maximum_timeout = 120

    def __init__(self):
        self.armed = False
        self.deadline = None
        self.finished = False
        self.opened = []

    def arm(self, *, joint_discovery, now, timeout, install_handler=None,
            wire=None):
        if not joint_discovery or self.armed or self.finished:
            raise RelaunchFailure("not an unused joint discovery")
        if install_handler is not None:
            raise RelaunchFailure("Sparkle install handler is forbidden")
        if not 0 < timeout <= self.maximum_timeout:
            raise RelaunchFailure("unbounded timeout")
        wire = {} if wire is None else wire
        forbidden = {"path", "url", "command", "arguments", "destination"}
        if forbidden.intersection(key.lower() for key in wire):
            raise RelaunchFailure("authority-bearing wire field")
        self.armed = True
        self.deadline = now + timeout

    def observe(self, event, *, now):
        if not self.armed or self.finished:
            return
        if now >= self.deadline:
            self.finished = True
            self.armed = False
            return
        if event not in {FrontendEvent.EOF, FrontendEvent.EXIT}:
            return
        self.finished = True
        self.armed = False
        self.opened.append(FIXED_APPLICATION)


class BrokerState(Enum):
    ACCEPTED = "accepted"
    INSTALLING = "installing"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass(frozen=True)
class BrokerStatus:
    state: BrokerState
    from_sequence: int
    to_sequence: int
    revision: int


class AppBStartupStatusModel:
    """A status frame is evidence only when it names this exact sealed B."""

    @staticmethod
    def acknowledge(status, *, sealed_sequence):
        if sealed_sequence <= 0:
            raise RelaunchFailure("invalid sealed release")
        if (status.state is not BrokerState.COMPLETE
                or status.from_sequence <= 0
                or status.from_sequence >= status.to_sequence
                or status.to_sequence != sealed_sequence
                or status.revision <= 0):
            raise RelaunchFailure("status does not name exact sealed B")
        return True


class JointRelaunchSentinelModelTests(unittest.TestCase):
    def test_only_joint_discovery_can_arm_without_a_sparkle_handler(self):
        with self.assertRaises(RelaunchFailure):
            JointRelaunchSentinelModel().arm(
                joint_discovery=False, now=1, timeout=30)
        with self.assertRaisesRegex(RelaunchFailure, "Sparkle"):
            JointRelaunchSentinelModel().arm(
                joint_discovery=True, now=1, timeout=30,
                install_handler=lambda: None)

    def test_frontend_exit_or_eof_opens_only_the_fixed_app_once(self):
        for event in (FrontendEvent.EXIT, FrontendEvent.EOF):
            with self.subTest(event=event):
                model = JointRelaunchSentinelModel()
                model.arm(joint_discovery=True, now=10, timeout=30)
                model.observe(FrontendEvent.MESSAGE, now=11)
                self.assertEqual(model.opened, [])
                model.observe(event, now=12)
                model.observe(event, now=13)
                self.assertEqual(model.opened, [FIXED_APPLICATION])

    def test_timeout_is_bounded_and_expiry_never_opens(self):
        for timeout in (0, 121, 10_000):
            with self.subTest(timeout=timeout), self.assertRaises(RelaunchFailure):
                JointRelaunchSentinelModel().arm(
                    joint_discovery=True, now=1, timeout=timeout)
        model = JointRelaunchSentinelModel()
        model.arm(joint_discovery=True, now=10, timeout=30)
        model.observe(FrontendEvent.EOF, now=40)
        self.assertEqual(model.opened, [])

    def test_wire_cannot_choose_what_or_where_to_open(self):
        for field in ("path", "URL", "command", "arguments", "destination"):
            with self.subTest(field=field), self.assertRaises(RelaunchFailure):
                JointRelaunchSentinelModel().arm(
                    joint_discovery=True, now=1, timeout=30,
                    wire={field: "attacker-controlled"})


class AppBStartupStatusModelTests(unittest.TestCase):
    def test_only_complete_exact_forward_sealed_sequence_is_accepted(self):
        status = BrokerStatus(BrokerState.COMPLETE, 41, 42, 7)
        self.assertTrue(AppBStartupStatusModel.acknowledge(
            status, sealed_sequence=42))

    def test_every_nonterminal_or_mismatched_status_fails_closed(self):
        cases = (
            BrokerStatus(BrokerState.INSTALLING, 41, 42, 7),
            BrokerStatus(BrokerState.FAILED, 41, 42, 7),
            BrokerStatus(BrokerState.COMPLETE, 41, 43, 7),
            BrokerStatus(BrokerState.COMPLETE, 42, 42, 7),
            BrokerStatus(BrokerState.COMPLETE, 0, 42, 7),
            BrokerStatus(BrokerState.COMPLETE, 41, 42, 0),
        )
        for status in cases:
            with self.subTest(status=status), self.assertRaises(RelaunchFailure):
                AppBStartupStatusModel.acknowledge(status, sealed_sequence=42)


class JointRelaunchSentinelSourceTests(unittest.TestCase):
    def test_worker_arms_sentinel_only_from_joint_discovery(self):
        self.assertTrue(SENTINEL.is_file(),
                        "implement the fixed joint relaunch sentinel")
        worker = WORKER.read_text()
        arm = worker[worker.index("case .armJointRelaunch"):]
        arm = arm[:arm.index("default:")]
        self.assertIn("guard jointDiscovery", arm)
        self.assertIn("jointRelaunch.arm()", arm)
        self.assertNotIn("installHandler", arm)

    def test_sentinel_waits_for_exit_or_eof_then_opens_one_fixed_app(self):
        self.assertTrue(SENTINEL.is_file(),
                        "implement the fixed joint relaunch sentinel")
        source = SENTINEL.read_text()
        for required in (FIXED_APPLICATION, "EOF", "deadline", "oneShot"):
            self.assertIn(required, source)
        for forbidden in ("installHandler", "applicationPath:", "url:",
                          "command:", "destination:"):
            self.assertNotIn(forbidden, source)

    def test_update_wire_carries_neither_location_nor_launch_authority(self):
        source = WIRE.read_text()
        # Comments may explain that these fields are forbidden; the serialized
        # vocabulary itself must not contain any of them.
        for forbidden in ('"path"', '"url"', '"command"', '"arguments"',
                          '"destination"', '"installHandler"'):
            self.assertNotIn(forbidden, source)

    def test_app_b_reads_status_and_matches_the_exact_sealed_sequence(self):
        self.assertTrue(STARTUP.is_file(),
                        "implement exact app-B startup status verification")
        source = STARTUP.read_text()
        for required in ("VPNUpdateBrokerClient.status", ".complete",
                         "response.toSequence == sealedRelease.sequence",
                         "response.fromSequence < response.toSequence",
                         "response.revision > 0"):
            self.assertIn(required, source)
        for forbidden in ("UserDefaults", "expectedSequence:",
                          "availableVersion", "displayVersionString"):
            self.assertNotIn(forbidden, source)

    def test_both_new_components_are_explicitly_wired_into_the_build(self):
        build = BUILD.read_text()
        self.assertIn("JointRelaunchSentinel.swift", build)
        self.assertIn("VPNJointUpdateStartupStatus", build)


if __name__ == "__main__":
    unittest.main()
