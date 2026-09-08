"""Production idle daemon lifecycle in disposable per-user launchd services."""
import json
import os
from pathlib import Path
import socket
import subprocess
import time

import test_vpn_installer as installer


class VPNDaemonTests(installer.VPNInstallerTests):
    # Re-run all installer acceptance cases against the real daemon lifecycle,
    # not the old thin listener fixture; only its entry boundary is substituted.
    service_components = installer.COMPONENTS + ['VPNHelperListener.swift', 'VPNHelperRuntime.swift',
                                               'VPNHelperDaemon.swift', 'VPNReleaseTrust.swift']
    service_main = installer.ROOT / 'tests/vpn_daemon_main.swift'
    service_flags = ['-D', 'VPN_DAEMON_TESTING', '-D', 'VPN_HELPER_READINESS_TESTING']

    def install_ready(self):
        self.assertEqual(self.run_installer().stdout.strip(), 'ready:10')

    def bootstrap(self):
        self.command(['/bin/launchctl', 'bootstrap', self.domain, str(self.plists / f'{self.label}.plist')])

    def wait_ready(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = self.run_installer('probe')
            if result.returncode == 0: return result.stdout.strip()
            time.sleep(0.05)
        self.fail(result.stdout + result.stderr)

    def wait_refused(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = self.command(['/bin/launchctl', 'print', f'{self.domain}/{self.label}'])
            if 'last exit code = 77' in result.stdout: return
            time.sleep(0.05)
        self.fail(result.stdout)

    def budget(self, desired, failures):
        data = json.dumps(dict(schema=1, desired=desired, failures=failures), sort_keys=True, separators=(',', ':'))
        (self.storage / 'activation.json').write_text(data)
        return data

    def test_boot_recovers_a_dead_owned_socket(self):
        self.install_ready(); self.boot_out()
        endpoint = self.storage / 'helper.sock'
        self.assertTrue(endpoint.is_socket())
        self.bootstrap()
        self.assertEqual(self.wait_ready(), 'ready:10')
        self.assertTrue(endpoint.is_socket())

    def test_a_second_daemon_cannot_take_over_the_live_one(self):
        self.install_ready()
        before = self.running_snapshot()
        result = subprocess.run([str(self.work / 'server'), 'serve', str(self.storage)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertEqual(self.running_snapshot(), before)
        self.assertEqual(self.run_installer('probe').stdout.strip(), 'ready:10')

    def test_boot_honors_manual_off_but_explicit_recovery_still_works(self):
        self.install_ready(); self.boot_out()
        expected = self.budget(False, 0)
        self.bootstrap(); self.wait_refused()
        self.assertEqual((self.storage / 'activation.json').read_text(), expected)
        result = self.run_installer('update', sequence=11, expected=10)
        self.assertEqual(result.stdout.strip(), 'ready:11', result.stdout + result.stderr)

    def test_boot_honors_the_exhausted_failure_budget(self):
        self.install_ready(); self.boot_out()
        expected = self.budget(True, 3)
        self.bootstrap(); self.wait_refused()
        self.assertEqual((self.storage / 'activation.json').read_text(), expected)

    def test_boot_does_not_delete_a_foreign_file(self):
        self.install_ready(); self.boot_out()
        endpoint = self.storage / 'helper.sock'
        endpoint.unlink(); endpoint.write_text('keep')
        self.bootstrap(); self.wait_refused()
        self.assertEqual(endpoint.read_text(), 'keep')

    def test_boot_does_not_take_over_another_live_listener(self):
        self.install_ready(); self.boot_out()
        endpoint = self.storage / 'helper.sock'
        endpoint.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(endpoint)); os.chmod(endpoint, 0o600); listener.listen(1)
            original = endpoint.stat().st_ino
            self.bootstrap(); self.wait_refused()
            self.assertEqual(endpoint.stat().st_ino, original)

    def test_real_daemon_entry_rejects_an_unprivileged_process(self):
        result = subprocess.run([str(self.work / 'server'), 'system'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 77)
        self.assertEqual(result.stdout.strip(), 'rejected:requiresRoot')
