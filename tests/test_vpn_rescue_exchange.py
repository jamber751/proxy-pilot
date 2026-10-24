"""Typed live rescue identity + signed destination exchange in root VM fixtures.

No real Applications, service, journal selection or recovery daemon is touched.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import test_vpn_staged_application as staged
import test_vpn_rescue_executor as identity


@unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() == 0
                     and os.environ.get('PROXYPILOT_VM_ROOT_TESTS') == '1',
                     'explicit disposable macOS root VM fixture')
class VPNRescueExchangeRootTests(unittest.TestCase):
    root_vm_fixture = True
    command = staged.VPNStagedApplicationTests.__dict__['command']
    make_app = staged.VPNStagedApplicationTests.make_app
    sign = staged.VPNStagedApplicationTests.sign
    pins = staged.VPNStagedApplicationTests.pins

    @classmethod
    def setUpClass(cls):
        staged.VPNStagedApplicationTests.setUpClass.__func__(cls)
        sources = [staged.HELPER / name for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
            'VPNRescueAuthorization.swift', 'VPNHelperArtifact.swift', 'VPNRescueExecutor.swift',
            'VPNLifecycleOwnership.swift', 'VPNStagedApplication.swift',
            'VPNReplacementExecutor.swift', 'VPNProtectedApplicationSwap.swift',
            'VPNApplicationDestinationStage.swift', 'VPNApplicationDestinationExchange.swift')]
        sources.append(staged.ROOT / 'tests/vpn_rescue_exchange_checks.swift')
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.build / ('rescue-' + arch)
            cls.command(['swiftc', '-D', 'VPN_RESCUE_EXECUTOR_TESTING',
                         '-D', 'VPN_APPLICATION_DESTINATION_TESTING',
                         '-D', 'VPN_APPLICATION_DESTINATION_ROOT_TESTING', '-D', 'VPN_EXPLICIT_RESCUE',
                         '-target', arch + '-apple-macosx11.0', *map(str, sources), '-o', str(output)])
            slices.append(str(output))
        cls.rescue_binary = cls.build / 'rescue-exchange'
        cls.command(['lipo', '-create', *slices, '-output', str(cls.rescue_binary)])
        cls.rescue_binary.chmod(0o700)
        identity.RescueBuild.sign(cls.rescue_binary)
        cls.rescue_pins = identity.RescueBuild.pins(cls.rescue_binary)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-rescue-exchange-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        source_a = self.work / 'a'; source_a.mkdir(mode=0o700)
        self.app = source_a / 'ProxyPilot.app'; self.make_app(version='1.6.0')
        self.a = self.pins()
        source_b = self.work / 'b'; source_b.mkdir(mode=0o700)
        self.app = source_b / 'ProxyPilot.app'; self.make_app(version='1.7.0')
        self.b = self.pins()
        self.base = self.work / 'transaction'; self.base.mkdir(mode=0o700)
        for name, source in [('current', source_b), ('candidate', source_a), ('executor', source_a)]:
            target = self.base / name; target.mkdir(mode=0o700)
            shutil.copytree(source / 'ProxyPilot.app', target / 'ProxyPilot.app', symlinks=True)
        self.destination = self.work / 'Applications'; self.destination.mkdir(mode=0o700)
        shutil.copytree(source_a / 'ProxyPilot.app', self.destination / 'ProxyPilot.app', symlinks=True)
        self.stage = self.destination / '.ProxyPilot.vpn-update'; self.stage.mkdir(mode=0o700)
        shutil.copytree(source_b / 'ProxyPilot.app', self.stage / 'ProxyPilot.app', symlinks=True)
        self.rescue = self.work / 'rescue'; self.rescue.mkdir(mode=0o700)
        self.runner = self.rescue / 'vpn-rescue'
        shutil.copyfile(self.rescue_binary, self.runner); self.runner.chmod(0o700)
        self.before = self.identities()

    def identities(self):
        return tuple((folder / 'ProxyPilot.app').stat().st_ino for folder in (self.destination, self.stage))

    def test_root_owned_operation_rejects_user_owned_source_and_retained_copy(self):
        app = self.destination / 'ProxyPilot.app'
        for item in [app, *app.rglob('*')]:
            os.chown(item, 501, -1, follow_symlinks=False)
        refused = self.invoke()
        self.assertEqual(refused.returncode, 77, refused.stdout + refused.stderr)
        self.assertEqual(self.identities(), self.before)
        for item in [app, *app.rglob('*')]:
            os.chown(item, 0, -1, follow_symlinks=False)
        self.assertEqual(self.invoke().returncode, 0)
        retained = self.stage / 'ProxyPilot.app'
        for item in [retained, *retained.rglob('*')]:
            os.chown(item, 501, -1, follow_symlinks=False)
        refused = self.invoke()
        self.assertEqual(refused.returncode, 77, refused.stdout + refused.stderr)
        self.assertEqual(self.identities(), self.before[::-1])

    def invoke(self, operation='exchange', runner=None):
        return subprocess.run([str(runner or self.runner), operation, str(self.base),
                               str(self.destination), str(self.rescue), str(self.rescue_binary),
                               self.rescue_pins['arm64'], self.rescue_pins['x86_64'],
                               self.a['arm64'], self.a['x86_64'], self.b['arm64'], self.b['x86_64']],
                              env=staged.ENV, capture_output=True, text=True, timeout=60)

    def test_exact_edge_swaps_and_retries_without_inverse(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'exchanged:auth=1')
        self.assertEqual(self.identities(), self.before[::-1])
        retry = self.invoke()
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertEqual(retry.stdout.strip(), 'alreadyExchanged:auth=1')
        self.assertEqual(self.identities(), self.before[::-1])
        for folder in (self.destination, self.stage):
            self.assertEqual((folder / 'ProxyPilot.app').stat().st_uid, 0)

    def test_wrong_edge_refused_before_authorization(self):
        result = self.invoke('wrong-edge')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'rejected:invalidTransition:auth=0')
        self.assertEqual(self.identities(), self.before)

    def test_static_copy_cannot_be_used_as_live_rescue(self):
        result = self.invoke(runner=self.rescue_binary)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn('wrongProcess:auth=0', result.stdout)
        self.assertEqual(self.identities(), self.before)

    def test_ordinary_executor_role_still_rejects_rescue(self):
        result = self.invoke('ordinary-role')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn('auth=0', result.stdout)
        self.assertEqual(self.identities(), self.before)

    def test_authorization_refusal_preserves_destination(self):
        result = self.invoke('authorization-failure')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'rejected:denied:auth=1')
        self.assertEqual(self.identities(), self.before)

    def test_before_exchange_interruption_preserves_destination(self):
        result = self.invoke('before-exchange-failure')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn('interrupted:auth=0', result.stdout)
        self.assertEqual(self.identities(), self.before)

    def test_after_exchange_interruption_is_forward_recoverable(self):
        result = self.invoke('after-exchange-failure')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'rejected:commitUncertain:auth=1')
        self.assertEqual(self.identities(), self.before[::-1])
        retry = self.invoke()
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertEqual(retry.stdout.strip(), 'alreadyExchanged:auth=1')
        self.assertEqual(self.identities(), self.before[::-1])

    def test_mutated_installed_app_is_not_exchanged(self):
        result = self.invoke('mutate-installed')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn('auth=1', result.stdout)
        self.assertEqual(self.identities(), self.before)

    def test_frozen_executor_revalidated_after_authorization(self):
        result = self.invoke('mutate-frozen-executor')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn('auth=1', result.stdout)
        self.assertEqual(self.identities(), self.before)


if __name__ == '__main__':
    unittest.main()
