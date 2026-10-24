"""Host-safe compilation and guard tests; never executes system acceptance.

Actual acceptance lives in vpn-dns-session.yml and has no skip/pass fallback.
This suite only runs the pure path or the fail-closed entrypoint with at least
one required gate absent. No SystemConfiguration API is reached locally.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).with_name('vpn_dns_session_vm_checks.swift')


class DNSDynamicStoreVMGuards(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-dns-session-compile-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        subprocess.run(['/usr/bin/swiftc', '-parse-as-library', str(SOURCE),
                        '-framework', 'SystemConfiguration', '-o', str(cls.binary)],
                       check=True, capture_output=True, text=True, timeout=120)

    def invoke(self, arguments, environment):
        return subprocess.run([str(self.binary), *arguments], env=environment,
                              capture_output=True, text=True, timeout=10)

    def test_pure_guard_and_namespace_truth_table(self):
        result = self.invoke(['--pure-checks'], {})
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout, 'PASS pure-root-ci-opt-in-and-exact-namespace-guards\n')

    def test_local_invocation_denied_before_any_system_api(self):
        for arguments in (['--acceptance'], ['--child', 'State:/Network/Service/fixture/DNS'], []):
            for environment in ({}, {'GITHUB_ACTIONS': 'true'},
                                {'PROXYPILOT_VM_DNS_SESSION_TESTS': '1'}):
                with self.subTest(arguments=arguments, environment=environment):
                    result = self.invoke(arguments, environment)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, 'FAIL guardDenied\n')
                    self.assertEqual(result.stderr, '')

    def test_ordinary_user_cannot_opt_in(self):
        # Root callers still test the ordinary-user condition in the pure truth
        # table, but must never enter the live path with every gate satisfied.
        if os.getuid() == 0 or os.geteuid() == 0:
            return
        result = self.invoke(['--acceptance'], {
            'GITHUB_ACTIONS': 'true', 'PROXYPILOT_VM_DNS_SESSION_TESTS': '1'})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, 'FAIL guardDenied\n')
        self.assertEqual(result.stderr, '')


if __name__ == '__main__':
    unittest.main()
