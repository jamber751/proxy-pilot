"""Atomic A/B exchange in a disposable Applications analogue."""
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
class VPNApplicationDestinationExchangeTests(unittest.TestCase):
    command = staged.VPNStagedApplicationTests.__dict__['command']
    make_app = staged.VPNStagedApplicationTests.make_app
    sign = staged.VPNStagedApplicationTests.sign
    pins = staged.VPNStagedApplicationTests.pins

    @classmethod
    def setUpClass(cls):
        staged.VPNStagedApplicationTests.setUpClass.__func__(cls)
        cls.checker = cls.build / 'destination-exchange'
        cls.command(['swiftc', '-D', 'VPN_APPLICATION_DESTINATION_TESTING',
                     *[str(HELPER / name) for name in (
                         'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
                         'VPNLifecycleOwnership.swift', 'VPNStagedApplication.swift',
                         'VPNReplacementExecutor.swift', 'VPNProtectedApplicationSwap.swift',
                         'VPNApplicationDestinationStage.swift',
                         'VPNApplicationDestinationExchange.swift')],
                     str(ROOT / 'tests/vpn_application_destination_exchange_checks.swift'),
                     '-o', str(cls.checker)])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-app-exchange-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        a_parent = self.work / 'a'; a_parent.mkdir(mode=0o700)
        self.app = a_parent / 'ProxyPilot.app'; self.make_app(version='1.6.0')
        self.a_pins = self.pins()
        b_parent = self.work / 'b'; b_parent.mkdir(mode=0o700)
        self.app = b_parent / 'ProxyPilot.app'; self.make_app(version='1.7.0')
        self.b_pins = self.pins()

        self.base = self.work / 'transaction'; self.base.mkdir(mode=0o700)
        self.current = self.base / 'current'; self.current.mkdir(mode=0o700)
        shutil.copytree(b_parent / 'ProxyPilot.app', self.current / 'ProxyPilot.app', symlinks=True)
        self.candidate = self.base / 'candidate'; self.candidate.mkdir(mode=0o700)
        shutil.copytree(a_parent / 'ProxyPilot.app', self.candidate / 'ProxyPilot.app', symlinks=True)

        self.destination = self.work / 'Applications'; self.destination.mkdir(mode=0o700)
        shutil.copytree(a_parent / 'ProxyPilot.app', self.destination / 'ProxyPilot.app', symlinks=True)
        self.stage = self.destination / '.ProxyPilot.vpn-update'; self.stage.mkdir(mode=0o700)
        shutil.copytree(b_parent / 'ProxyPilot.app', self.stage / 'ProxyPilot.app', symlinks=True)
        (self.destination / 'Other.app').mkdir()
        (self.destination / 'Other.app/sentinel').write_text('untouched')
        self.initial = self.identities()

    def identities(self):
        return ((self.destination / 'ProxyPilot.app').stat().st_ino,
                (self.stage / 'ProxyPilot.app').stat().st_ino)

    def invoke(self, operation='exchange'):
        return subprocess.run([str(self.checker), operation, str(self.base),
                               str(self.destination), self.a_pins['arm64'],
                               self.a_pins['x86_64'], self.b_pins['arm64'],
                               self.b_pins['x86_64']],
                              env=ENV, capture_output=True, text=True, timeout=90)

    def assert_rejected(self, operation, error):
        result = self.invoke(operation)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), f'rejected:{error}')

    def test_exchange_and_idempotent_retry(self):
        first = self.invoke()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(first.stdout.strip(), 'exchanged')
        self.assertEqual(self.identities(), self.initial[::-1])
        self.assertEqual((self.destination / 'Other.app/sentinel').read_text(), 'untouched')
        retry = self.invoke()
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertEqual(retry.stdout.strip(), 'alreadyExchanged')
        self.assertEqual(self.identities(), self.initial[::-1])

    def test_authorization_failure_has_no_namespace_effect(self):
        self.assert_rejected('authorization-failure', 'failure')
        self.assertEqual(self.identities(), self.initial)

    def test_stage_mutation_before_exchange_has_no_namespace_effect(self):
        result = self.invoke('mutate-stage')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(self.identities(), self.initial)

    def test_installed_mutation_before_exchange_has_no_namespace_effect(self):
        result = self.invoke('mutate-installed')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(self.identities(), self.initial)

    def test_post_exchange_failure_is_uncertain_and_retry_is_forward(self):
        self.assert_rejected('after-exchange-failure', 'commitUncertain')
        self.assertEqual(self.identities(), self.initial[::-1])
        retry = self.invoke()
        self.assertEqual(retry.returncode, 0, retry.stdout + retry.stderr)
        self.assertEqual(retry.stdout.strip(), 'alreadyExchanged')

    def test_lock_root_and_layout_guards(self):
        self.assert_rejected('busy', 'busy')
        self.assert_rejected('production', 'requiresRoot')
        shutil.rmtree(self.stage)
        self.assert_rejected('exchange', 'unsafeStorage')

    def test_harness_never_targets_real_applications(self):
        source = (ROOT / 'tests/vpn_application_destination_exchange_checks.swift').read_text()
        self.assertNotIn('/Applications', source)


if __name__ == '__main__':
    unittest.main()
