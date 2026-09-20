"""Exact B staging below a mutable destination parent; never replaces an app."""
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
class VPNApplicationDestinationStageTests(unittest.TestCase):
    command = staged.VPNStagedApplicationTests.__dict__['command']
    make_app = staged.VPNStagedApplicationTests.make_app
    sign = staged.VPNStagedApplicationTests.sign
    pins = staged.VPNStagedApplicationTests.pins

    @classmethod
    def setUpClass(cls):
        staged.VPNStagedApplicationTests.setUpClass.__func__(cls)
        cls.checker = cls.build / 'destination-stage'
        cls.command(['swiftc', '-D', 'VPN_APPLICATION_DESTINATION_TESTING',
                     *[str(HELPER / name) for name in (
                         'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
                         'VPNLifecycleOwnership.swift', 'VPNStagedApplication.swift',
                         'VPNApplicationDestinationStage.swift')],
                     str(ROOT / 'tests/vpn_application_destination_stage_checks.swift'),
                     '-o', str(cls.checker)])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-destination-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        source = self.work / 'source'; source.mkdir(mode=0o700)
        self.app = source / 'ProxyPilot.app'; self.make_app()
        self.base = self.work / 'transaction'; self.base.mkdir(mode=0o700)
        self.current = self.base / 'current'; source.rename(self.current)
        self.destination = self.work / 'Applications'; self.destination.mkdir(mode=0o700)
        self.installed = self.destination / 'ProxyPilot.app'; self.installed.mkdir()
        (self.installed / 'sentinel').write_text('untouched')
        self.a = self.pins_for(self.current / 'ProxyPilot.app')

    def pins_for(self, app):
        saved = self.app
        try:
            self.app = app
            return self.pins()
        finally:
            self.app = saved

    def invoke(self, operation='prepare'):
        return subprocess.run([str(self.checker), operation, str(self.base),
                               str(self.destination), self.a['arm64'], self.a['x86_64']],
                              env=ENV, capture_output=True, text=True, timeout=90)

    def assert_rejected(self, operation, error):
        result = self.invoke(operation)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), f'rejected:{error}')

    def test_stage_and_idempotent_recheck(self):
        first = self.invoke()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(first.stdout.strip(), 'staged')
        second = self.invoke()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(second.stdout.strip(), 'alreadyStaged')
        copy = self.destination / '.ProxyPilot.vpn-update/ProxyPilot.app'
        self.assertTrue(copy.is_dir())
        self.assertNotEqual(copy.stat().st_ino,
                            (self.current / 'ProxyPilot.app').stat().st_ino)
        self.assertEqual((self.installed / 'sentinel').read_text(), 'untouched')

    def test_interruption_recovers_by_exact_recheck(self):
        self.assert_rejected('throw-after-clone', 'failure')
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'alreadyStaged')

    def test_source_or_stage_mutation_is_refused(self):
        source_resource = self.current / 'ProxyPilot.app/Contents/Resources/data.txt'
        original = source_resource.read_bytes()
        for operation in ('tamper-source', 'tamper-stage', 'extra-stage'):
            with self.subTest(operation=operation):
                if (self.destination / '.ProxyPilot.vpn-update').exists():
                    shutil.rmtree(self.destination / '.ProxyPilot.vpn-update')
                result = self.invoke(operation)
                self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
                source_resource.write_bytes(original)
                self.assertEqual((self.installed / 'sentinel').read_text(), 'untouched')

    def test_hostile_existing_fixed_name_is_refused(self):
        target = self.destination / '.ProxyPilot.vpn-update'
        target.write_text('foreign')
        self.assert_rejected('prepare', 'unsafeDestination')
        target.unlink(); os.symlink('/tmp', target)
        self.assert_rejected('prepare', 'unsafeDestination')

    def test_mutated_published_stage_is_not_repaired(self):
        self.assertEqual(self.invoke().returncode, 0)
        resource = self.destination / '.ProxyPilot.vpn-update/ProxyPilot.app/Contents/Resources/data.txt'
        resource.write_text('changed')
        self.assert_rejected('prepare', 'invalidSignature')

    def test_destination_contract_lock_and_root_guard(self):
        os.chmod(self.destination, 0o770)
        self.assert_rejected('prepare', 'unsafeDestination')
        os.chmod(self.destination, 0o700)
        self.assert_rejected('busy', 'busy')
        self.assert_rejected('production', 'requiresRoot')

    def test_harness_never_mentions_real_applications_or_installs(self):
        source = (ROOT / 'tests/vpn_application_destination_stage_checks.swift').read_text()
        self.assertNotIn('/Applications', source)
        self.assertNotIn('rename', source)


if __name__ == '__main__':
    unittest.main()
