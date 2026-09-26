"""One-shot mutual authentication for exact installed candidate B."""
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
class VPNInstalledCandidateHandoffTests(unittest.TestCase):
    command = staged.VPNStagedApplicationTests.__dict__['command']
    make_app = staged.VPNStagedApplicationTests.make_app
    sign = staged.VPNStagedApplicationTests.sign
    pins = staged.VPNStagedApplicationTests.pins

    @classmethod
    def setUpClass(cls):
        staged.VPNStagedApplicationTests.setUpClass.__func__(cls)
        sources = [str(HELPER / name) for name in (
            'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
            'VPNHelperProtocol.swift', 'VPNStagedApplication.swift',
            'VPNInstalledApplication.swift', 'VPNInstalledCandidateHandoff.swift')]
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.build / f'candidate-handoff-{arch}'
            cls.command(['swiftc', '-D', 'VPN_APPLICATION_DESTINATION_TESTING',
                         '-D', 'VPN_INSTALLED_CANDIDATE_HANDOFF_TESTING',
                         '-D', 'VPN_EXECUTOR_HANDOFF_TESTING',
                         '-target', f'{arch}-apple-macosx11.0', *sources,
                         str(ROOT / 'tests/vpn_installed_candidate_handoff_checks.swift'),
                         '-o', str(output)])
            slices.append(str(output))
        cls.fixture = cls.build / 'candidate-handoff'
        cls.command(['lipo', '-create', *slices, '-output', str(cls.fixture)])
        cls.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill',
                     '--identifier', 'kz.documentolog.proxypilot', str(cls.fixture)])
        cls.universal = cls.fixture

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-candidate-handoff-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.app = self.work / 'ProxyPilot.app'
        self.make_app(version='1.7.0')
        self.release_pins = self.pins()

    def invoke(self, operation):
        runner = self.app / 'Contents/MacOS/ProxyPilot'
        return subprocess.run([str(runner), operation, str(self.work),
                               self.release_pins['arm64'], self.release_pins['x86_64']],
                              env=ENV, capture_output=True, text=True, timeout=30)

    def test_exact_installed_candidate_completes_mutual_handoff(self):
        result = self.invoke('success')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'ready:4')

    def test_context_change_terminates_child_without_success(self):
        result = self.invoke('context-change')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'rejected:changed')


if __name__ == '__main__':
    unittest.main()
