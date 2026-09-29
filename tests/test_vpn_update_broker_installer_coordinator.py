"""Minimum safety contract for VPNUpdateBrokerInstallerCoordinator.

The executable model intentionally contains no filesystem or launchd code.  It
fixes the cross-component ordering that the production coordinator must keep.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
import unittest


ROOT = Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "app/vpn-helper/VPNUpdateBrokerInstallerCoordinator.swift"


class Refused(Exception):
    pass


@dataclass
class DurableFixture:
    selected: Optional[str] = None
    broker_selected: Optional[str] = None
    events: List[str] = field(default_factory=list)
    held: List[str] = field(default_factory=list)


class CoordinatorModel:
    def __init__(self, durable):
        self.durable = durable

    def acquire(self, lease):
        if lease == "service" and self.durable.held != ["broker"]:
            raise AssertionError("global lock order must be Broker -> service")
        self.durable.held.append(lease)
        self.durable.events.append("lock+" + lease)

    def release(self, lease):
        if not self.durable.held or self.durable.held[-1] != lease:
            raise AssertionError("leases must be released in reverse order")
        self.durable.held.pop()
        self.durable.events.append("lock-" + lease)

    def install(self, exact_release, installer_result="installed"):
        self.acquire("broker")
        self.acquire("service")
        self.durable.events.append("reconcile.selected")
        selected = self.durable.selected
        self.release("service")
        self.release("broker")

        # installAndStart takes the service lifecycle lease itself. Holding the
        # outer Broker lease here would invert its nested operations/deadlock.
        self.durable.events.append("installAndStart")
        if installer_result in ("alreadyInstalled", "stale"):
            self.durable.events.append("reload.selected")
            if selected != exact_release:
                raise Refused("selected release does not exactly match retry")
            self.durable.events.append("retry.reconciled")
        elif installer_result != "installed":
            raise Refused(installer_result)
        else:
            self.durable.selected = exact_release

        self.durable.broker_selected = exact_release
        self.durable.events.append("broker.install.exactSelected")

    def uninstall(self, unexpected=False):
        self.acquire("broker")
        self.acquire("service")
        self.durable.events.append("uninstall.preflight")
        if unexpected:
            self.release("service")
            self.release("broker")
            raise Refused("unexpected content")
        self.durable.events.append("uninstall.cleanupTransactions")
        self.durable.events.append("broker.remove")
        self.durable.broker_selected = None
        self.durable.events.append("helperArtifacts.remove")
        self.durable.selected = None
        self.release("service")
        self.release("broker")


class VPNUpdateBrokerInstallerCoordinatorModelTests(unittest.TestCase):
    def test_global_lock_order_is_broker_then_service(self):
        durable = DurableFixture()
        CoordinatorModel(durable).install("release-a")
        self.assertLess(durable.events.index("lock+broker"),
                        durable.events.index("lock+service"))
        self.assertLess(durable.events.index("lock-service"),
                        durable.events.index("lock-broker"))

    def test_broker_lease_is_released_before_install_and_start(self):
        durable = DurableFixture()
        CoordinatorModel(durable).install("release-a")
        self.assertLess(durable.events.index("lock-broker"),
                        durable.events.index("installAndStart"))

    def test_already_installed_or_stale_retry_requires_exact_selected_release(self):
        for result in ("alreadyInstalled", "stale"):
            with self.subTest(result=result):
                durable = DurableFixture(selected="release-a")
                CoordinatorModel(durable).install("release-a", result)
                self.assertEqual(durable.broker_selected, "release-a")
                self.assertIn("retry.reconciled", durable.events)
                mismatch = DurableFixture(selected="release-other")
                with self.assertRaisesRegex(Refused, "exactly match"):
                    CoordinatorModel(mismatch).install("release-a", result)
                self.assertIsNone(mismatch.broker_selected)

    def test_uninstall_preflights_and_removes_broker_before_helper_artifacts(self):
        durable = DurableFixture(selected="release-a", broker_selected="release-a")
        CoordinatorModel(durable).uninstall()
        events = durable.events
        self.assertLess(events.index("uninstall.preflight"),
                        events.index("uninstall.cleanupTransactions"))
        self.assertLess(events.index("uninstall.cleanupTransactions"),
                        events.index("broker.remove"))
        self.assertLess(events.index("broker.remove"),
                        events.index("helperArtifacts.remove"))

        refused = DurableFixture(selected="release-a", broker_selected="release-a")
        with self.assertRaisesRegex(Refused, "unexpected content"):
            CoordinatorModel(refused).uninstall(unexpected=True)
        self.assertNotIn("broker.remove", refused.events)
        self.assertNotIn("helperArtifacts.remove", refused.events)


class VPNUpdateBrokerInstallerCoordinatorSourceTests(unittest.TestCase):
    def test_production_coordinator_binds_the_required_components(self):
        self.assertTrue(
            COORDINATOR.is_file(),
            "VPNUpdateBrokerInstallerCoordinator.swift is required",
        )
        source = COORDINATOR.read_text()
        for required in (
                "VPNUpdateBrokerInstallerCoordinator", "VPNUpdateBrokerLaunchdJob",
                "VPNLifecycleOwnership", "installAndStart", "loadDeployment",
                "alreadyInstalled", "stale", "uninstall"):
            self.assertIn(required, source)

    def test_source_documents_the_non_local_ordering_invariants(self):
        self.assertTrue(COORDINATOR.is_file())
        source = COORDINATOR.read_text()
        for required in (
                "Broker -> service", "release Broker lease before installAndStart",
                "exact selected", "remove broker before helper artifacts"):
            self.assertIn(required, source)


if __name__ == "__main__":
    unittest.main()
