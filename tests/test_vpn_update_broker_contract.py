"""Contract for the descriptor-only privileged update broker boundary.

The Swift fixture binds to a test-only adapter while static and native checks
require the production protocol, descriptor validation, signed authorization,
and durable-state seams to remain present.
"""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/vpn_update_broker_contract_checks.swift'
PROTOCOL = ROOT / 'app/vpn-helper/VPNUpdateBrokerProtocol.swift'
BROKER = ROOT / 'app/vpn-helper/VPNUpdateBroker.swift'


class VPNUpdateBrokerContractSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = FIXTURE.read_text()

    def test_submit_surface_is_sequence_and_directory_descriptor_only(self):
        start = self.source.index('struct SubmitRequest')
        end = self.source.index('\n}', start)
        request = self.source[start:end]
        self.assertIn('expectedFromSequence: UInt64', request)
        self.assertIn('candidateDirectory: Int32', request)
        for forbidden in ('String', 'URL', '[String]', 'UUID', 'uid_t', 'Data'):
            self.assertNotIn(forbidden, request)

    def test_fixture_rejects_all_ambient_authority_fields(self):
        for field in ('path', 'url', 'argv', 'shell', 'ownerUID', 'token'):
            self.assertIn(f'"{field}"', self.source)

    def test_fixture_requires_one_descriptor_and_fixed_layout(self):
        self.assertIn('missingDirectoryDescriptor', self.source)
        self.assertIn('extraDirectoryDescriptor', self.source)
        for name in ('ProxyPilot.app', 'vpn-helper', 'vpn-engine',
                     'vpn-release.manifest', 'vpn-release.sig',
                     'vpn-previous-release.manifest', 'vpn-previous-release.sig',
                     'vpn-update-transition', 'vpn-update-transition.sig'):
            self.assertIn(f'"{name}"', self.source)
        self.assertIn('unexpectedSibling', self.source)

    def test_fixture_requires_independent_release_and_artifact_proofs(self):
        for case in ('wrongTransitionSignature', 'wrongTransitionSource',
                     'wrongTransitionDestination', 'tamperedApplication',
                     'tamperedHelper', 'tamperedEngine'):
            self.assertIn(case, self.source)

    def test_fixture_requires_stale_refusal_and_idempotency(self):
        self.assertIn('staleExpectedSequence', self.source)
        self.assertIn('alreadyAccepted', self.source)
        self.assertIn('same transaction', self.source)

    def test_status_contract_is_allowlisted_and_path_free(self):
        start = self.source.index('struct PublicStatus')
        end = self.source.index('\n}', start)
        status = self.source[start:end]
        for allowed in ('phase', 'fromSequence', 'toSequence', 'revision'):
            self.assertIn(allowed, status)
        for forbidden in ('path', 'URL', 'secret', 'token', 'transactionID', 'error'):
            self.assertNotIn(forbidden, status)


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'),
                     'macOS Swift required')
class VPNUpdateBrokerProductionBindingTests(unittest.TestCase):
    def test_real_descriptor_and_layout_boundary(self):
        with tempfile.TemporaryDirectory(prefix='pp-update-broker-dir-') as temporary:
            output = Path(temporary) / 'broker-directory'
            compiled = subprocess.run(
                ['swiftc', '-D', 'VPN_UPDATE_BROKER_TESTING',
                 '-target', 'arm64-apple-macosx11.0',
                 '-module-cache-path', str(Path(temporary) / 'ModuleCache'),
                 str(PROTOCOL), str(BROKER),
                 str(ROOT / 'tests/vpn_update_broker_directory_checks.swift'),
                 '-o', str(output)],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(output)], capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), 'broker directory checks passed')

    def test_fixed_wire_protocol_has_no_ambient_authority_payload(self):
        self.assertTrue(PROTOCOL.is_file(), 'VPNUpdateBrokerProtocol.swift is required')
        with tempfile.TemporaryDirectory(prefix='pp-update-broker-wire-') as temporary:
            output = Path(temporary) / 'broker-wire'
            compiled = subprocess.run(
                ['swiftc', '-target', 'arm64-apple-macosx11.0',
                 '-module-cache-path', str(Path(temporary) / 'ModuleCache'),
                 str(PROTOCOL),
                 str(ROOT / 'tests/vpn_update_broker_protocol_checks.swift'),
                 '-o', str(output)],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(output)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), 'broker wire checks passed')

    def test_production_broker_uses_real_authorization_and_durable_retry_state(self):
        self.assertTrue(BROKER.is_file(), 'VPNUpdateBroker.swift is required')
        production = BROKER.read_text().split('#if VPN_UPDATE_BROKER_TESTING', 1)[0]
        required_seams = (
            'VPNReleaseStore',
            'loadDeployment',
            'loadUpdateJournal',
            'VPNJointUpdatePayload.load',
            'VPNStagedApplication',
            'VPNHelperArtifact',
            'VPNEngineArtifact',
        )
        missing = [name for name in required_seams if name not in production]
        self.assertFalse(
            missing,
            'expected red test: broker still lacks real signed/durable seams: '
            + ', '.join(missing),
        )

    def test_production_broker_satisfies_contract(self):
        missing = [path for path in (PROTOCOL, BROKER) if not path.is_file()]
        self.assertFalse(
            missing,
            'expected red test: production broker entry is absent: '
            + ', '.join(str(path.relative_to(ROOT)) for path in missing),
        )

        with tempfile.TemporaryDirectory(prefix='pp-update-broker-contract-') as temporary:
            output = Path(temporary) / 'broker-contract'
            sources = [
                ROOT / 'app/vpn-helper/VPNPeerAuthentication.swift',
                ROOT / 'app/vpn-helper/VPNReleaseAuthorization.swift',
                PROTOCOL,
                BROKER,
                FIXTURE,
            ]
            compiled = subprocess.run(
                ['swiftc', '-D', 'VPN_UPDATE_BROKER_TESTING',
                 '-D', 'VPN_UPDATE_BROKER_CONTRACT_TESTING',
                 '-target', 'arm64-apple-macosx11.0',
                 '-module-cache-path', str(Path(temporary) / 'ModuleCache'),
                 *map(str, sources), '-o', str(output)],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            for group in ('ipc', 'layout', 'authorization', 'retry', 'status'):
                result = subprocess.run([str(output), group], capture_output=True,
                                        text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(result.stdout.strip(), f'{group} checks passed')


if __name__ == '__main__':
    unittest.main()
