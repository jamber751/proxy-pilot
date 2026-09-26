"""Descriptor-bound inspection of an installed candidate analogue."""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import test_vpn_staged_application as staged

ROOT = staged.ROOT
HELPER = staged.HELPER
ENV = staged.ENV


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNInstalledApplicationTests(unittest.TestCase):
    command = staged.VPNStagedApplicationTests.__dict__['command']
    make_app = staged.VPNStagedApplicationTests.make_app
    sign = staged.VPNStagedApplicationTests.sign
    pins = staged.VPNStagedApplicationTests.pins

    @classmethod
    def setUpClass(cls):
        staged.VPNStagedApplicationTests.setUpClass.__func__(cls)
        cls.checker = cls.build / 'installed-application'
        cls.command(['swiftc', '-D', 'VPN_APPLICATION_DESTINATION_TESTING',
                     str(HELPER / 'VPNPeerAuthentication.swift'),
                     str(HELPER / 'VPNReleaseAuthorization.swift'),
                     str(HELPER / 'VPNStagedApplication.swift'),
                     str(HELPER / 'VPNInstalledApplication.swift'),
                     str(ROOT / 'tests/vpn_installed_application_checks.swift'),
                     '-o', str(cls.checker)])

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-installed-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.app = self.work / 'ProxyPilot.app'
        self.make_app(version='1.7.0')
        self.release_pins = self.pins()

    def invoke(self, operation):
        return subprocess.run([str(self.checker), operation, str(self.work),
                               self.release_pins['arm64'], self.release_pins['x86_64']],
                              env=ENV, capture_output=True, text=True, timeout=60)

    def assert_rejected(self, operation, error):
        result = self.invoke(operation)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn(error, result.stdout)

    def test_exact_installed_executable_path_is_bound(self):
        result = self.invoke('inspect')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = (self.app / 'Contents/MacOS/ProxyPilot').resolve()
        self.assertEqual(result.stdout.strip(), f'path:{expected}')

    def test_content_change_invalidates_receipt(self):
        self.assert_rejected('mutate', 'invalidSignature')

    def test_name_change_invalidates_receipt(self):
        self.assert_rejected('replace', 'unsafeStorage')

    def test_unrelated_process_and_production_nonroot_are_refused(self):
        self.assert_rejected('self', 'wrongProcess')
        self.assert_rejected('production', 'requiresRoot')


if __name__ == '__main__':
    unittest.main()
