"""Mutually authenticated, descriptor-only protected executor launch."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import test_vpn_staged_application as staged

ROOT = staged.ROOT
HELPER = staged.HELPER
ENV = staged.ENV


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNExecutorHandoffTests(unittest.TestCase):
    command = staged.VPNStagedApplicationTests.__dict__['command']
    make_app = staged.VPNStagedApplicationTests.make_app
    sign = staged.VPNStagedApplicationTests.sign
    pins = staged.VPNStagedApplicationTests.pins

    @classmethod
    def setUpClass(cls):
        staged.VPNStagedApplicationTests.setUpClass.__func__(cls)
        sources = [HELPER / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
            'VPNLifecycleOwnership.swift', 'VPNDirectoryProvisioner.swift', 'VPNStagedApplication.swift',
            'VPNReplacementExecutor.swift', 'VPNProtectedApplicationSwap.swift',
            'VPNReplacementExecutorProvisioner.swift', 'VPNReplacementExecutorHandoff.swift')]
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.build / f'handoff-{arch}'
            cls.command(['swiftc', '-D', 'VPN_EXECUTOR_HANDOFF_TESTING',
                         '-D', 'VPN_EXECUTOR_PROVISIONING_TESTING',
                         '-D', 'VPN_APPLICATION_SWAP_TESTING',
                         '-target', f'{arch}-apple-macosx11.0', *map(str, sources),
                         str(ROOT / 'tests/vpn_executor_handoff_checks.swift'), '-o', str(output)])
            slices.append(output)
        cls.handoff = cls.build / 'handoff'
        cls.command(['lipo', '-create', *map(str, slices), '-output', str(cls.handoff)])
        cls.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                     '--identifier', 'kz.documentolog.proxypilot', str(cls.handoff)])
        # make_app now embeds this exact executable, then seals the whole bundle.
        cls.universal = cls.handoff

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-handoff-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.stage = self.work / 'stage'; self.stage.mkdir(mode=0o700)
        self.app = self.stage / 'ProxyPilot.app'; self.make_app()
        self.base = self.work / 'transaction'; self.base.mkdir(mode=0o700)
        self.current = self.base / 'current'; self.stage.rename(self.current)
        (self.base / 'candidate').mkdir(mode=0o700)
        self.runner = self.current / 'ProxyPilot.app/Contents/MacOS/ProxyPilot'
        self.a = self.pins_for(self.current / 'ProxyPilot.app')

    def pins_for(self, app):
        saved = self.app
        try:
            self.app = app
            return self.pins()
        finally:
            self.app = saved

    def invoke(self, operation):
        return subprocess.run([str(self.runner), operation, str(self.base),
                               self.a['arm64'], self.a['x86_64']], env=ENV,
                              capture_output=True, text=True, timeout=90)

    def assert_rejected(self, operation, error):
        result = self.invoke(operation)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), f'rejected:{error}')

    def test_authenticated_handoff_and_canonical_request(self):
        result = self.invoke('success')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'exchanged')
        self.assertEqual((self.base / 'handoff-marker').read_text(),
                         '7BB17D0B-AE44-4B16-A9F8-C202E4A64983 1\n')

    def test_idempotent_outcome_is_returned(self):
        result = self.invoke('already')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'alreadyExchanged')

    def test_wrong_peer_is_denied_before_go(self):
        self.assert_rejected('wrong-peer', 'authenticationFailed')
        self.assertFalse((self.base / 'handoff-marker').exists())

    def test_wrong_parent_identity_is_denied_before_go(self):
        self.assert_rejected('wrong-parent', 'authenticationFailed')
        self.assertFalse((self.base / 'handoff-marker').exists())

    def test_executor_tamper_before_spawn_is_denied(self):
        self.assert_rejected('tamper-before-launch', 'invalidSignature')
        self.assertFalse((self.base / 'handoff-marker').exists())

    def test_executor_tamper_after_ready_is_denied_before_go(self):
        result = self.invoke('tamper-after-ready')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertFalse((self.base / 'handoff-marker').exists())

    def test_child_failure_after_go_is_commit_uncertain(self):
        self.assert_rejected('child-failure', 'commitUncertain')
        self.assertTrue((self.base / 'handoff-marker').is_file())

    def test_child_failure_reports_only_allowlisted_operation_stage(self):
        result = self.invoke('child-diagnostic')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'rejected:commitUncertain')
        self.assertIn('VPN replacement executor failed at candidateProof.', result.stderr)
        self.assertTrue((self.base / 'handoff-marker').is_file())

    def test_child_failure_reports_destination_recheck_stage(self):
        result = self.invoke('child-diagnostic-recheck')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'rejected:commitUncertain')
        self.assertIn(
            'VPN replacement executor failed at applicationDestinationRecheck.',
            result.stderr,
        )
        self.assertTrue((self.base / 'handoff-marker').is_file())

    def test_namespace_lock_contention_never_spawns(self):
        self.assert_rejected('busy', 'busy')
        self.assertFalse((self.base / 'executor').exists())

    def test_production_entry_requires_root(self):
        self.assert_rejected('production', 'requiresRoot')

    def test_harness_has_no_applications_or_network_path(self):
        source = (ROOT / 'tests/vpn_executor_handoff_checks.swift').read_text()
        self.assertNotIn('/Applications', source)
        self.assertNotIn('connect(', source)


if __name__ == '__main__':
    unittest.main()
