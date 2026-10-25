"""Production transport lifetime against finite fake queues; no native sockets."""
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_vpn_route_sequence import SOURCES

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class RouteTransportEpochTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-route-epoch-', dir='/tmp')
        cls.addClassCleanup(cls.temp.cleanup)
        folder = Path(cls.temp.name)
        inputs = []
        for relative in [*SOURCES[:-1], 'tests/vpn_route_transport_epoch_checks.swift']:
            destination = folder / Path(relative).name
            destination.write_bytes((ROOT / relative).read_bytes())
            inputs.append(str(destination))
        cls.binary = folder / 'checks'
        arch = 'arm64' if platform.machine() == 'arm64' else 'x86_64'
        result = subprocess.run(['/usr/bin/swiftc', '-target', arch + '-apple-macosx11.0',
                                 *inputs, '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_case(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'PASS route-transport-epoch\n')

    def test_idle_broadcast_queue_cannot_drop_the_next_reply(self): self.run_case('idle-full')
    def test_broadcast_between_requests_cannot_drop_the_next_reply(self): self.run_case('between-full')
    def test_failed_new_socket_does_not_issue_a_write_or_leak_previous_socket(self): self.run_case('open-failure')
    def test_failed_write_is_not_retried_and_all_owned_sockets_close(self): self.run_case('write-failure')
    def test_each_request_has_one_owned_socket_and_all_close_once(self): self.run_case('lifetime')
    def test_original_deadline_and_receive_bound_are_forwarded(self): self.run_case('deadline')
    def test_initial_open_failure_creates_no_socket(self): self.run_case('initial-failure')


if __name__ == '__main__': unittest.main()
