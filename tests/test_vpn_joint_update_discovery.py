"""VPN-present update checks are discovery-only and never invoke Sparkle install."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "app/update-worker/UpdateWorker.swift"
WIRE = ROOT / "app/update-worker/UpdateWire.swift"
FRONTEND = ROOT / "app/update-worker/IsolatedUpdates.swift"


class VPNJointUpdateDiscoveryTests(unittest.TestCase):
    def test_vpn_present_uses_information_check_not_sparkle_install(self):
        source = WORKER.read_text()
        start = source.index("case .check:")
        end = source.index("case .automatic", start)
        flow = source[start:end]
        self.assertIn("case .requiresCoordinatedUpdate", flow)
        self.assertIn("checkForUpdateInformation()", flow)
        branch = flow[flow.index("case .requiresCoordinatedUpdate"):]
        self.assertNotIn("checkForUpdates()", branch)
        self.assertNotIn("installHandler", branch)

    def test_discovery_publishes_only_bounded_display_and_technical_version(self):
        wire = WIRE.read_text()
        self.assertIn("let jointUpdate: Bool", wire)
        self.assertIn('"jointUpdate"', wire)
        self.assertIn("let jointReleaseID: String?", wire)
        for forbidden in ('"artifactURL"', '"downloadURL"', '"path"',
                          '"destination"', '"expectedSequence"', '"command"'):
            self.assertNotIn(forbidden, wire)
        worker = WORKER.read_text()
        self.assertIn("didFindValidUpdate item: SUAppcastItem", worker)
        self.assertIn("item.displayVersionString", worker)
        self.assertIn("item.versionString", worker)
        self.assertIn("item.signingValidationStatus == .succeeded", worker)
        self.assertNotIn("propertiesDictionary", worker)

    def test_frontend_exposes_joint_offer_without_vpn_authority(self):
        source = FRONTEND.read_text()
        self.assertIn("jointUpdateAvailable", source)
        self.assertIn("state.jointUpdate", source)
        self.assertNotIn("VPNUpdateBrokerClient", source)
        self.assertNotIn("VPNJointArtifactMount", source)


if __name__ == "__main__":
    unittest.main()
