"""Unprivileged synthetic child authentication; never contacts system services."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest
import test_vpn_staged_application as staged

@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc') and os.geteuid() != 0,
                     'unprivileged macOS fixture required')
class VPNInstalledUpdateResultTests(unittest.TestCase):
    command = staged.VPNStagedApplicationTests.__dict__['command']
    make_app = staged.VPNStagedApplicationTests.make_app
    sign = staged.VPNStagedApplicationTests.sign
    pins = staged.VPNStagedApplicationTests.pins

    @classmethod
    def setUpClass(cls):
        staged.VPNStagedApplicationTests.setUpClass.__func__(cls)
        names = ('VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNReleaseTrust.swift',
                 'VPNHelperArtifact.swift', 'VPNReleaseStore.swift', 'VPNHelperProtocol.swift',
                 'VPNHelperReadiness.swift', 'VPNLifecycleOwnership.swift', 'VPNEndpointDirectory.swift',
                 'VPNActivationBudget.swift', 'VPNActivationCoordinator.swift', 'VPNLaunchdRuntime.swift',
                 'VPNStagedApplication.swift', 'VPNInstalledApplication.swift', 'VPNDirectoryProvisioner.swift',
                 'VPNInstalledUpdateResultEntry.swift', 'VPNRescueInstalledResultVerifier.swift')
        cls.driver = cls.build / 'result-checks'
        cls.command(['swiftc', '-D', 'VPN_INSTALLED_UPDATE_RESULT_TESTING', '-D', 'VPN_APPLICATION_DESTINATION_TESTING',
                     *map(str, (staged.HELPER / name for name in names)),
                     str(staged.ROOT / 'tests/vpn_installed_update_result_checks.swift'), '-o', str(cls.driver)])

    def setUp(self):
        staged.VPNStagedApplicationTests.setUp(self)
        self.app.rename(self.stage / 'old.app')
        shutil.rmtree(self.stage / 'old.app')
        self.marker = self.work / 'child-executed'
        code = 41 if self._testMethodName in ('test_authenticated_child_remained_off', 'test_off_result_cannot_prove_on') else 40
        if self._testMethodName == 'test_generic_success_exit_is_not_a_proof': code = 0
        source = self.work / 'child.c'
        source.write_text('#include <stdio.h>\n#include <unistd.h>\nint main(void) { FILE *f=fopen(' +
                          json.dumps(str(self.marker)) + ', "w"); if(f) {fputs("executed",f);fclose(f);}' +
                          ('sleep(5);' if self._testMethodName == 'test_child_deadline_kills_and_reaps' else '') +
                          'return ' + str(code) + ';}\n')
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = self.work / ('child-' + arch)
            self.command(['clang', '-target', arch + '-apple-macosx11.0', str(source), '-o', str(output)])
            slices.append(str(output))
        universal = self.work / 'child-universal'
        self.command(['lipo', '-create', *slices, '-output', str(universal)])
        old_universal = self.universal
        self.universal = universal
        try: self.make_app(version='1.7.0')
        finally: self.universal = old_universal
        self.code_pins = self.pins()

    def invoke(self, operation='observe', desired='on', failures=0, deadline=3000):
        return subprocess.run([str(self.driver), operation, str(self.stage), self.code_pins['arm64'],
                               self.code_pins['x86_64'], desired, str(failures), str(deadline)],
                              env=staged.ENV, capture_output=True, text=True, timeout=10)

    def test_authenticated_child_ready(self):
        result = self.invoke(); self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'helperReady'); self.assertTrue(self.marker.exists())
    def test_authenticated_child_remained_off(self):
        result = self.invoke(desired='off'); self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'remainedOff')
    def test_off_result_cannot_prove_on(self): self.assertEqual(self.invoke().returncode, 77)
    def test_on_result_cannot_prove_off(self): self.assertEqual(self.invoke(desired='off').returncode, 77)
    def test_generic_success_exit_is_not_a_proof(self): self.assertEqual(self.invoke().returncode, 77)
    def test_failed_budget_cannot_claim_ready(self): self.assertEqual(self.invoke(failures=1).returncode, 77)
    def test_denial_before_resume_executes_no_child_code(self):
        result = self.invoke('deny-before-resume'); self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn('changed', result.stdout); self.assertFalse(self.marker.exists())
    def test_installed_change_before_resume_executes_no_child_code(self):
        result = self.invoke('mutate-before-resume'); self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertFalse(self.marker.exists())
    def test_expired_deadline_executes_no_child_code(self):
        self.assertEqual(self.invoke(deadline=0).returncode, 77); self.assertFalse(self.marker.exists())
    def test_child_deadline_kills_and_reaps(self):
        started = time.monotonic(); result = self.invoke(deadline=300)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn('deadlineExceeded', result.stdout); self.assertLess(time.monotonic() - started, 3)
    def test_root_only_entries_refuse_before_system_reads(self):
        result = subprocess.run([str(self.driver), 'guards'], env=staged.ENV, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'guarded')

if __name__ == '__main__': unittest.main()
