"""Live dual-role rescue exchanges only disposable protected app slots.

No Applications destination, service, journal or host launchd job is touched.
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
class VPNRescueProtectedSwapRootTests(unittest.TestCase):
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
            'VPNRescueAuthorization.swift', 'VPNRescuePreparationAuthorization.swift',
            'VPNHelperArtifact.swift', 'VPNRescueExecutor.swift',
            'VPNRescuePreparationExecutor.swift', 'VPNLifecycleOwnership.swift',
            'VPNStagedApplication.swift', 'VPNReplacementExecutor.swift',
            'VPNProtectedApplicationSwap.swift')]
        sources.append(staged.ROOT / 'tests/vpn_rescue_protected_swap_checks.swift')
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = cls.build / ('rescue-' + arch)
            cls.command(['swiftc', '-D', 'VPN_RESCUE_EXECUTOR_TESTING',
                         '-D', 'VPN_RESCUE_PREPARATION', '-D', 'VPN_APPLICATION_SWAP_TESTING',
                         '-D', 'VPN_APPLICATION_SWAP_ROOT_TESTING',
                         '-target', arch + '-apple-macosx11.0', *map(str, sources), '-o', str(output)])
            slices.append(str(output))
        cls.rescue_binary = cls.build / 'rescue-protected-swap'
        cls.command(['lipo', '-create', *slices, '-output', str(cls.rescue_binary)])
        cls.rescue_binary.chmod(0o700)
        identity.RescueBuild.sign(cls.rescue_binary)
        cls.rescue_pins = identity.RescueBuild.pins(cls.rescue_binary)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pp-rescue-protected-swap-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        source_a = self.work / 'a'; source_a.mkdir(mode=0o700)
        self.app = source_a / 'ProxyPilot.app'; self.make_app(version='1.6.0')
        self.a = self.pins()
        source_b = self.work / 'b'; source_b.mkdir(mode=0o700)
        self.app = source_b / 'ProxyPilot.app'; self.make_app(version='1.7.0')
        self.b = self.pins()
        self.base = self.work / 'transaction'; self.base.mkdir(mode=0o700)
        for name, source in [('current', source_a), ('candidate', source_b), ('executor', source_a)]:
            target = self.base / name; target.mkdir(mode=0o700)
            shutil.copytree(source / 'ProxyPilot.app', target / 'ProxyPilot.app', symlinks=True)
        # The shared driver accepts a destination descriptor but never uses it.
        self.destination = self.work / 'unused-destination'; self.destination.mkdir(mode=0o700)
        self.rescue = self.work / 'rescue'; self.rescue.mkdir(mode=0o700)
        self.runner = self.rescue / 'vpn-rescue'
        shutil.copyfile(self.rescue_binary, self.runner); self.runner.chmod(0o700)
        self.before = self.identities()
        self.executor_inode = (self.base / 'executor/ProxyPilot.app').stat().st_ino

    def identities(self):
        return tuple((self.base / name / 'ProxyPilot.app').stat().st_ino
                     for name in ('current', 'candidate'))

    def invoke(self, operation='exchange', runner=None):
        return subprocess.run([str(runner or self.runner), operation, str(self.base),
                               str(self.destination), str(self.rescue), str(self.rescue_binary),
                               self.rescue_pins['arm64'], self.rescue_pins['x86_64'],
                               self.a['arm64'], self.a['x86_64'], self.b['arm64'], self.b['x86_64']],
                              env=staged.ENV, capture_output=True, text=True, timeout=60)

    def refused(self, operation='exchange', callbacks=0, runner=None):
        result = self.invoke(operation, runner)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertTrue(result.stdout.strip().endswith(':auth=' + str(callbacks)), result.stdout)
        self.assertEqual(self.identities(), self.before)
        return result

    def test_exact_dual_role_swaps_and_retries_forward_only(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'exchanged:auth=1')
        self.assertEqual(self.identities(), self.before[::-1])
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'alreadyExchanged:auth=1')
        self.assertEqual(self.identities(), self.before[::-1])
        self.assertEqual((self.base / 'executor/ProxyPilot.app').stat().st_ino, self.executor_inode)
        for name in ('current', 'candidate', 'executor'):
            app = self.base / name / 'ProxyPilot.app'
            self.assertTrue(all(p.lstat().st_uid == 0 for p in (app, *app.rglob('*'))))
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_finish_edge_must_match_actual_swap(self): self.refused('wrong-edge')
    def test_start_edge_must_match_finish_edge(self): self.refused('wrong-start-edge')
    def test_copied_binary_is_not_live_rescue(self): self.refused(runner=self.rescue_binary)
    def test_ordinary_role_still_refuses_rescue(self): self.refused('ordinary-role')
    def test_callback_failure_has_no_swap(self): self.refused('authorization-failure', callbacks=1)
    def test_before_exchange_interruption_has_no_callback(self): self.refused('before-exchange-failure')

    def test_after_exchange_interruption_retries_without_inverse(self):
        result = self.invoke('after-exchange-failure')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'rejected:commitUncertain:auth=1')
        self.assertEqual(self.identities(), self.before[::-1])
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), 'alreadyExchanged:auth=1')
        self.assertEqual(self.identities(), self.before[::-1])

    def test_source_mutation_after_callback_refused(self): self.refused('mutate-source', callbacks=1)
    def test_candidate_mutation_after_callback_refused(self): self.refused('mutate-candidate', callbacks=1)
    def test_retained_executor_mutation_after_callback_refused(self):
        self.refused('mutate-frozen-executor', callbacks=1)
    def test_live_proof_revalidated_after_callback(self): self.refused('mutate-live', callbacks=1)

    def test_invalid_staged_signature_has_no_callback(self):
        (self.base / 'candidate/ProxyPilot.app/Contents/Resources/data.txt').write_text('changed')
        self.refused()

    def test_user_owned_source_or_retained_executor_has_no_callback(self):
        for name in ('current', 'executor'):
            with self.subTest(slot=name):
                app = self.base / name / 'ProxyPilot.app'
                entries = (app, *app.rglob('*'))
                for entry in entries: os.chown(entry, 501, -1, follow_symlinks=False)
                try: self.refused()
                finally:
                    for entry in entries: os.chown(entry, 0, -1, follow_symlinks=False)


if __name__ == '__main__': unittest.main()
