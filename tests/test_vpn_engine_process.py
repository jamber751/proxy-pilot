"""Supervised OpenVPN child boundary; uses a deterministic fake child only."""
from pathlib import Path
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNEngineProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-engine-process-build-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = Path(cls.temp.name) / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        sources = [ROOT / 'app/vpn-helper/VPNProfileVault.swift',
                   ROOT / 'app/vpn-helper/VPNEngineProcess.swift',
                   ROOT / 'app/vpn-helper/VPNEngineSupervisor.swift',
                   ROOT / 'tests/vpn_engine_process_checks.swift']
        result = subprocess.run([
            'swiftc', '-D', 'VPN_ENGINE_PROCESS_TESTING',
            '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(cls.binary)
        ], capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, name, word):
        with tempfile.TemporaryDirectory(prefix='pp-engine-process-', dir='/tmp') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), name, folder], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(word, result.stdout)

    def test_fixed_argv_empty_environment_fd_hygiene_and_exit(self):
        self.run_case('exit', 'passed')

    def test_graceful_termination_and_reaping(self):
        self.run_case('term', 'passed')

    def test_bounded_wait_does_not_claim_a_terminal_state(self):
        self.run_case('timeout', 'passed')

    def test_deadline_escalates_to_kill_and_reaps(self):
        self.run_case('kill', 'passed')

    def test_helper_eof_kills_and_reaps_ignored_term_engine(self):
        with tempfile.TemporaryDirectory(prefix='pp-engine-eof-', dir='/tmp') as folder:
            os.chmod(folder, 0o700)
            result = subprocess.run([str(self.binary), 'eof-controller', folder],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            pids = [int((Path(folder) / name).read_text())
                    for name in ('engine.pid', 'supervisor.pid')]
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                alive = []
                for pid in pids:
                    try:
                        os.kill(pid, 0)
                        alive.append(pid)
                    except ProcessLookupError:
                        pass
                if not alive:
                    break
                time.sleep(0.02)
            else:
                self.fail(f'processes survived helper EOF: {alive}')

    def test_rejects_unsafe_profile_before_engine_validation(self):
        self.run_case('profile', 'rejected')

    def test_validation_failure_never_spawns(self):
        self.run_case('validation', 'rejected')

    def test_source_has_no_shell_or_connected_claim(self):
        source = ''.join((ROOT / path).read_text() for path in (
            'app/vpn-helper/VPNEngineProcess.swift',
            'app/vpn-helper/VPNEngineSupervisor.swift'))
        self.assertNotIn('/bin/sh', source)
        self.assertNotIn('system(', source)
        self.assertNotIn('case connected', source)
        self.assertIn('POSIX_SPAWN_CLOEXEC_DEFAULT', source)
        self.assertIn('--route-noexec', source)
        self.assertNotIn('--ifconfig-noexec', source)
        for required in ('--route-noexec', '--route-nopull', '--script-security',
                         '--auth-nocache', '--management-hold'):
            self.assertIn(required, source)


if __name__ == '__main__':
    unittest.main()
