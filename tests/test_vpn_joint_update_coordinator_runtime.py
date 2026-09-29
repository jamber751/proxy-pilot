"""Native test-only runtime chain for the one-click joint coordinator."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "app/vpn-helper"


@unittest.skipUnless(
    sys.platform == "darwin"
    and shutil.which("swiftc")
    and Path("/usr/bin/hdiutil").is_file(),
    "macOS Swift and hdiutil required",
)
class VPNJointUpdateCoordinatorRuntimeTests(unittest.TestCase):
    def test_fixed_transport_download_mount_and_ready_chain(self):
        with tempfile.TemporaryDirectory(
            prefix="pp-joint-coordinator-", dir="/tmp"
        ) as temporary:
            root = Path(temporary)
            payload = root / "Payload"
            payload.mkdir(mode=0o700)
            (payload / "ProxyPilot.app").mkdir(mode=0o700)
            for name in (
                "vpn-helper",
                "vpn-engine",
                "vpn-release.manifest",
                "vpn-release.sig",
                "vpn-previous-release.manifest",
                "vpn-previous-release.sig",
                "vpn-update-transition",
                "vpn-update-transition.sig",
            ):
                (payload / name).write_bytes(name.encode("ascii"))
            image = root / "joint.dmg"
            created = subprocess.run(
                [
                    "/usr/bin/hdiutil",
                    "create",
                    "-quiet",
                    "-fs",
                    "APFS",
                    "-format",
                    "UDZO",
                    "-srcfolder",
                    str(payload),
                    str(image),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(created.returncode, 0, created.stdout + created.stderr)

            binary = root / "coordinator-checks"
            sources = [
                "VPNReleaseAuthorization",
                "VPNReleaseTrust",
                "VPNCompanionMetadata",
                "VPNCompanionMetadataFetcher",
                "VPNCompanionStaging",
                "VPNCompanionDownloader",
                "VPNJointArtifactMount",
                "VPNHelperProtocol",
                "VPNEndpointDirectory",
                "VPNUpdateBrokerProtocol",
                "VPNUpdateBrokerClient",
                "VPNPeerAuthentication",
                "VPNUpdateBrokerTransport",
                "VPNJointUpdateCoordinator",
            ]
            built = subprocess.run(
                [
                    "swiftc",
                    "-parse-as-library",
                    "-D",
                    "VPN_JOINT_UPDATE_COORDINATOR_TESTING",
                    "-D",
                    "VPN_COMPANION_METADATA_FETCHER_TESTING",
                    "-D",
                    "VPN_COMPANION_DOWNLOADER_TESTING",
                    "-D",
                    "VPN_UPDATE_BROKER_TRANSPORT_TESTING",
                    "-target",
                    "arm64-apple-macosx11.0",
                    "-module-cache-path",
                    str(root / "ModuleCache"),
                    *[str(HELPER / f"{name}.swift") for name in sources],
                    str(ROOT / "tests/vpn_joint_update_coordinator_runtime_checks.swift"),
                    "-o",
                    str(binary),
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            checked = subprocess.run(
                [str(binary), str(image)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
            self.assertEqual(
                checked.stdout.strip(),
                "vpn joint update coordinator runtime checks passed",
            )

    def test_test_seams_do_not_parameterize_production_origins(self):
        coordinator = (HELPER / "VPNJointUpdateCoordinator.swift").read_text()
        client = (HELPER / "VPNUpdateBrokerClient.swift").read_text()
        build = (ROOT / "app/build.sh").read_text()

        self.assertIn("#if VPN_JOINT_UPDATE_COORDINATOR_TESTING", coordinator)
        self.assertIn("#if VPN_JOINT_UPDATE_COORDINATOR_TESTING", client)
        production_init = coordinator.index("init(releaseID:")
        production_surface = coordinator[production_init:coordinator.index(
            ") {", production_init
        )]
        for forbidden in ("URL", "path", "socket", "configuration"):
            self.assertNotIn(forbidden, production_surface)
        self.assertIn(
            'https://github.com/jamber751/proxy-pilot/releases/download/v',
            (HELPER / "VPNCompanionMetadataFetcher.swift").read_text(),
        )
        self.assertIn(
            '/Library/Application Support/kz.documentolog.proxypilot.vpn/'
            'update-broker.sock',
            client,
        )
        self.assertNotIn("VPN_JOINT_UPDATE_COORDINATOR_TESTING", build)


if __name__ == "__main__":
    unittest.main()
