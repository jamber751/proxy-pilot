"""Atomic exchange of disposable application copies; never an Applications install."""
import os
import fcntl
from pathlib import Path
import shutil
import subprocess
import unittest

from test_vpn_staged_application import VPNStagedApplicationTests, ROOT, HELPER, ENV


class VPNApplicationSwapTests(VPNStagedApplicationTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.swap_checker = cls.build / 'swap-checks'
        sanitize = ['-sanitize=address'] if os.environ.get('PP_SWAP_ASAN') == '1' else []
        cls.command(['swiftc', *sanitize, '-D', 'VPN_APPLICATION_SWAP_TESTING',
                     *[str(HELPER / name) for name in ('VPNPeerAuthentication.swift',
                       'VPNReleaseAuthorization.swift', 'VPNLifecycleOwnership.swift',
                       'VPNStagedApplication.swift', 'VPNReplacementExecutor.swift', 'VPNProtectedApplicationSwap.swift')],
                     str(ROOT / 'tests/vpn_application_swap_checks.swift'), '-o', str(cls.swap_checker)])

    def setUp(self):
        super().setUp()
        self.base = self.work / 'exchange'; self.base.mkdir(mode=0o700)
        self.a = self.pins()
        self.current = self.base / 'current'
        self.stage.rename(self.current)
        self.stage = self.base / 'candidate'; self.stage.mkdir(mode=0o700)
        self.app = self.stage / 'ProxyPilot.app'
        self.make_app(version='1.7.0')
        self.b = self.pins()
        self.initial = self.identities()

    def identities(self):
        return tuple((self.base / name / 'ProxyPilot.app').stat().st_ino for name in ('current', 'candidate'))

    def run_swap(self, operation='exchange', expected='exchanged', pins=None, executable=None):
        b = pins or self.b
        result = subprocess.run([str(executable or self.swap_checker), operation, str(self.base),
                                 self.a['arm64'], self.a['x86_64'], b['arm64'], b['x86_64']],
                                env=ENV, capture_output=True, text=True, timeout=60)
        if operation == 'crash-after':
            self.assertEqual(result.returncode, 91, result.stderr)
        else:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), expected, result.stderr)
        self.assertNotIn('AddressSanitizer', result.stderr)

    def test_atomic_exchange_and_idempotent_new_process(self):
        self.run_swap()
        self.assertEqual(self.identities(), self.initial[::-1])
        self.run_swap(expected='alreadyExchanged')
        self.assertEqual(self.identities(), self.initial[::-1])

    def test_post_exchange_failure_and_process_crash_recover_forward(self):
        for operation in ('throw-after', 'throw-sync', 'crash-after'):
            with self.subTest(operation=operation):
                if self.identities() != self.initial:
                    # Reset only the fixture via fresh test setup, never inverse-swap production.
                    self.setUp()
                self.run_swap(operation, expected='rejected:commitUncertain')
                self.assertEqual(self.identities(), self.initial[::-1])
                self.run_swap(expected='alreadyExchanged')
                self.assertEqual(self.identities(), self.initial[::-1])

    def test_pre_exchange_failure_and_lost_lease_do_not_swap(self):
        self.run_swap('throw-before', 'rejected:failure')
        self.assertEqual(self.identities(), self.initial)
        self.run_swap('lose-lock', 'rejected:lost')
        self.assertEqual(self.identities(), self.initial)
        self.run_swap()

    def test_failed_post_exchange_validation_never_rolls_back(self):
        self.run_swap('tamper-after', 'rejected:commitUncertain')
        self.assertEqual(self.identities(), self.initial[::-1])
        self.run_swap(expected='rejected:invalidLayout')
        self.assertEqual(self.identities(), self.initial[::-1])

    def test_recheck_rejects_modified_candidate_and_base_permissions(self):
        self.run_swap('tamper-before', 'rejected:invalidSignature')
        self.assertEqual(self.identities(), self.initial)
        self.setUp()
        self.run_swap('unsafe-base', 'rejected:unsafeStorage')
        self.assertEqual(self.identities(), self.initial)

    def test_busy_namespace_and_production_root_guard(self):
        self.run_swap('busy', 'rejected:busy')
        self.run_swap('production', 'rejected:requiresRoot')
        self.assertEqual(self.identities(), self.initial)

    def test_other_process_holding_namespace_lock(self):
        lock = os.open(self.base / 'lifecycle.lock', os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.run_swap(expected='rejected:busy')
            self.assertEqual(self.identities(), self.initial)
        finally:
            os.close(lock)
        self.run_swap()

    def test_concurrent_requests_never_reverse_exchange(self):
        args = [str(self.swap_checker), 'exchange', str(self.base), self.a['arm64'],
                self.a['x86_64'], self.b['arm64'], self.b['x86_64']]
        processes = [subprocess.Popen(args, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True) for _ in range(2)]
        try:
            outputs = []
            diagnostics = []
            for process in processes:
                out, err = process.communicate(timeout=60)
                self.assertEqual(process.returncode, 0, err)
                self.assertNotIn('AddressSanitizer', err)
                outputs.append(out.strip())
                diagnostics.append(err)
            self.assertEqual(outputs.count('exchanged'), 1)
            self.assertTrue(set(outputs) <= {'exchanged', 'alreadyExchanged', 'rejected:busy'}, (outputs, diagnostics))
            self.assertEqual(self.identities(), self.initial[::-1])
            self.run_swap(expected='alreadyExchanged')
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill(); process.communicate(timeout=10)

    def test_executor_inside_slot_or_hardlinked_is_refused(self):
        inside = self.current / 'ProxyPilot.app/Contents/Resources/Runner'
        shutil.copyfile(self.swap_checker, inside); inside.chmod(0o755)
        self.run_swap(expected='rejected:unsafeExecutor', executable=inside)
        outside = self.work / 'linked-runner'
        os.link(inside, outside)
        self.run_swap(expected='rejected:unsafeExecutor', executable=outside)
        self.assertEqual(self.identities(), self.initial)

    def test_wrong_edge_and_indistinguishable_artifacts(self):
        self.run_swap('wrong-edge', 'rejected:invalidTransition')
        self.run_swap('identical', 'rejected:invalidTransition', pins=self.a)
        self.run_swap('exchange', 'rejected:invalidTransition', pins=self.a)
        self.assertEqual(self.identities(), self.initial)

    def test_duplicate_corrupt_and_missing_layouts(self):
        shutil.rmtree(self.app)
        shutil.copytree(self.current / 'ProxyPilot.app', self.app, symlinks=True)
        self.run_swap(expected='rejected:invalidLayout')
        self.setUp()
        (self.app / 'Contents/Resources/data.txt').write_text('changed')
        self.run_swap(expected='rejected:invalidLayout')
        shutil.rmtree(self.app)
        self.run_swap(expected='rejected:invalidLayout')

    def test_unsafe_or_redirected_slot_and_extra_content(self):
        os.chmod(self.stage, 0o755)
        self.run_swap(expected='rejected:unsafeStorage')
        os.chmod(self.stage, 0o700)
        (self.stage / 'extra').write_text('keep')
        self.run_swap(expected='rejected:invalidLayout')
        self.assertEqual((self.stage / 'extra').read_text(), 'keep')
        self.stage.rename(self.base / 'elsewhere')
        self.stage.symlink_to(self.base / 'elsewhere', target_is_directory=True)
        self.run_swap(expected='rejected:unsafeStorage')


def load_tests(loader, tests, pattern):
    # Reuse signed bundle fixture helpers, not its separate validation test suite.
    return unittest.TestSuite(VPNApplicationSwapTests(name) for name in
                              loader.getTestCaseNames(VPNApplicationSwapTests)
                              if name in VPNApplicationSwapTests.__dict__)


if __name__ == '__main__': unittest.main()
