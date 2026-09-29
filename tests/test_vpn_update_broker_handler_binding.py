"""Swift sequencing contract and source binding for the unified broker handler."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HANDLER = ROOT / "app/vpn-helper/VPNUpdateBrokerHandler.swift"
DAEMON = ROOT / "app/vpn-helper/VPNUpdateBrokerDaemon.swift"
FIXTURE = ROOT / "tests/vpn_update_broker_handler_checks.swift"


class VPNUpdateBrokerHandlerSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = FIXTURE.read_text()

    def test_request_authority_is_sequence_only_and_candidate_is_a_descriptor(self):
        start = self.fixture.index("struct HandlerRequest")
        end = self.fixture.index("\n}", start)
        request = self.fixture[start:end]
        self.assertIn("expectedFromSequence: UInt64", request)
        self.assertNotIn("String", request)
        self.assertNotIn("UUID", request)
        self.assertNotIn("path", request.lower())
        self.assertIn("candidateDirectory: Int32", self.fixture)

    def test_fixture_covers_ordering_retry_rejection_crashes_and_handoff_gates(self):
        for required in (
                "receive.descriptor", "inbox.publish",
                "authorize.signed.privateInbox", "prepare.joint",
                "recovery.arm", "broker.rotation.ready", "handoff.executor",
                "invalidSignature", "protectedMutationCount", "drainCount",
                "differentSigned", "injectedCrash", "afterHandoff"):
            self.assertIn(required, self.fixture)

    def test_production_handler_has_the_narrow_descriptor_api(self):
        self.assertTrue(HANDLER.is_file(), "VPNUpdateBrokerHandler.swift is required")
        source = HANDLER.read_text()
        for required in (
                "final class VPNUpdateBrokerHandler",
                "serviceDirectory: Int32", "privateDirectory: Int32",
                "authority: VPNReleaseAuthority", "VPNUpdateBrokerRequest",
                "candidateDirectory: Int32", "VPNUpdateBrokerResponse"):
            self.assertIn(required, source)
        for forbidden in (
                "request.path", "request.url", "request.uuid",
                "UUID(uuidString:", "URL(fileURLWithPath:"):
            self.assertNotIn(forbidden, source)

    def test_production_handler_binds_every_security_boundary(self):
        self.assertTrue(HANDLER.is_file(), "VPNUpdateBrokerHandler.swift is required")
        source = HANDLER.read_text()
        for required in (
                "VPNUpdateBrokerInbox", "authorizePrivateInbox",
                "VPNJointUpdatePreparation", "VPNUpdateBrokerStatusStore",
                "VPNReplacementExecutorHandoff", "recovery", "rotation"):
            self.assertIn(required, source)

    def test_production_handler_exposes_only_a_test_checkpoint_seam(self):
        self.assertTrue(HANDLER.is_file(), "VPNUpdateBrokerHandler.swift is required")
        source = HANDLER.read_text()
        self.assertIn("#if VPN_UPDATE_BROKER_HANDLER_TESTING", source)
        self.assertIn("testSubmit", source)
        self.assertIn("checkpoint:", source)
        # These names make crash tests stable without exposing any production
        # path, identity, UUID or command injection surface.
        for point in ("afterInbox", "afterAuthorization", "afterPreparation",
                      "afterRecoveryArm", "afterBrokerRotationReady",
                      "beforeHandoff", "afterHandoff"):
            self.assertIn(f'"{point}"', source)

    def test_daemon_resumes_owned_work_before_accepting_clients(self):
        handler = HANDLER.read_text()
        daemon = DAEMON.read_text()
        self.assertIn("func resumeIfNeeded()", handler)
        for phase in (".accepted", ".authorized", ".prepared", ".handoffStarted"):
            self.assertIn(f"transaction.phase == {phase}", handler)
        resume = daemon.index("try handler.resumeIfNeeded()")
        serve = daemon.index("try serve(listener:", resume)
        self.assertLess(resume, serve)


@unittest.skipUnless(sys.platform == "darwin" and shutil.which("swiftc"),
                     "macOS Swift required")
class VPNUpdateBrokerHandlerSwiftContractTests(unittest.TestCase):
    def test_swift_sequencing_contract(self):
        with tempfile.TemporaryDirectory(prefix="pp-broker-handler-contract-") as temporary:
            binary = Path(temporary) / "handler-checks"
            compiled = subprocess.run(
                ["swiftc", "-parse-as-library",
                 "-target", "arm64-apple-macosx11.0",
                 "-module-cache-path", str(Path(temporary) / "ModuleCache"),
                 str(FIXTURE), "-o", str(binary)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            for group in ("pipeline", "retry-busy", "invalid-signed",
                          "crashes", "handoff-gates"):
                with self.subTest(group=group):
                    result = subprocess.run([str(binary), group], capture_output=True,
                                            text=True, timeout=30)
                    self.assertEqual(result.returncode, 0,
                                     result.stdout + result.stderr)
                    self.assertEqual(result.stdout.strip(), f"{group} checks passed")


if __name__ == "__main__":
    unittest.main()
