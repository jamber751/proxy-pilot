"""Production binding for metadata -> FD -> mount -> ready -> sentinel."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "app/vpn-helper/VPNJointUpdateCoordinator.swift"
MODEL = ROOT / "app/update-worker/IsolatedUpdates.swift"
MAIN = ROOT / "app/main.swift"
WORKER = ROOT / "app/update-worker/UpdateWorker.swift"
WIRE = ROOT / "app/update-worker/UpdateWire.swift"


class VPNJointUpdateCoordinatorTests(unittest.TestCase):
    def test_descriptor_only_security_order(self):
        source = COORDINATOR.read_text()
        order = [
            "VPNCompanionMetadataFetcher.start",
            "VPNCompanionDownloader.start",
            "VPNJointArtifactMount.open",
            "VPNUpdateBrokerClient.submit",
            "response.state == .ready",
            "mount = nil; downloaded = nil",
            "finish(.success(()))",
        ]
        positions = [source.index(value) for value in order]
        self.assertEqual(positions, sorted(positions))
        public = source[source.index("init(releaseID:"):
                        source.index("func start()")]
        for forbidden in ("URL", "path", "Data", "command", "destination"):
            self.assertNotIn(forbidden, public)

    def test_indeterminate_never_arms_or_finishes_successfully(self):
        source = COORDINATOR.read_text()
        branch = source[source.index("case .indeterminate:"):]
        branch = branch[:branch.index("} catch")]
        self.assertIn("retainIndeterminateMount()", branch)
        self.assertNotIn("finish(.success", branch)
        retention = source[source.index("private func retainIndeterminateMount"):
                           source.index("private func report")]
        self.assertIn(".now() + 120", retention)
        self.assertIn("VPNJointUpdateCoordinatorError.indeterminate", retention)

    def test_signed_appcast_technical_version_is_bounded_ui_state_only(self):
        worker = WORKER.read_text()
        wire = WIRE.read_text()
        self.assertIn("item.signingValidationStatus == .succeeded", worker)
        self.assertIn("jointReleaseID = item.versionString", worker)
        self.assertIn("canonicalVersion", wire)
        for forbidden in ('"artifactURL"', '"sha256"', '"fromSequence"',
                          '"toSequence"', '"path"'):
            self.assertNotIn(forbidden, wire)

    def test_ui_runs_joint_flow_then_arms_before_quiesce_and_exit(self):
        model = MODEL.read_text()
        check = model[model.index("func check()"):
                      model.index("var checkTitle")]
        self.assertIn("if jointUpdateAvailable { startJointUpdate(); return }", check)
        self.assertLess(check.index("startJointUpdate"), check.index("channel?.send(.check)"))
        main = MAIN.read_text()
        flow = main[main.index("updates.onJointReady"):]
        flow = flow[:flow.index("updates.checkJointUpdateCompletion")]
        arm = flow.index("armJointRelaunch")
        quiesce = flow.index("prepareForUpdate", arm)
        terminate = flow.index("NSApp.terminate", quiesce)
        self.assertLess(arm, quiesce)
        self.assertLess(quiesce, terminate)

    def test_build_includes_every_coordinator_transport_component(self):
        build = (ROOT / "app/build.sh").read_text()
        for name in ("VPNCompanionMetadataFetcher", "VPNCompanionStaging",
                     "VPNCompanionDownloader", "VPNJointUpdateCoordinator"):
            self.assertIn(name, build)


if __name__ == "__main__":
    unittest.main()
