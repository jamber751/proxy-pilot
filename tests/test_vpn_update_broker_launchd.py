"""Real broker launchd lifecycle in a disposable per-user domain.

This is intentionally unprivileged: it proves plist publication, exact
content-addressed executable selection, socket activation, restart, and removal.
It never touches the system domain or production endpoint.
"""
import hashlib
import os
from pathlib import Path
import plistlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'app/vpn-helper'
SOURCES = [HELPER / name for name in (
    'VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift',
    'VPNHelperArtifact.swift', 'VPNReleaseStore.swift',
    'VPNUpdateBrokerLaunchdJob.swift',
)] + [ROOT / 'tests/vpn_update_broker_launchd_checks.swift']


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'),
                     'macOS Swift required')
class VPNUpdateBrokerLaunchdTests(unittest.TestCase):
    @classmethod
    def command(cls, arguments, timeout=180):
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise AssertionError(' '.join(map(str, arguments)) + '\n'
                                 + result.stdout + result.stderr)
        return result

    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise unittest.SkipTest('Never register the fixture as root')
        cls.domain = f'gui/{os.geteuid()}'
        if subprocess.run(['/bin/launchctl', 'print', cls.domain], capture_output=True,
                          timeout=60).returncode:
            raise unittest.SkipTest('no reachable per-user GUI launchd domain')
        cls.temporary = tempfile.TemporaryDirectory(prefix='pp-broker-launchd-build-', dir='/tmp')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.build = Path(cls.temporary.name)
        slices = []
        for architecture in ('arm64', 'x86_64'):
            output = cls.build / f'fixture-{architecture}'
            cls.command([
                'swiftc', '-O', '-D', 'VPN_UPDATE_BROKER_LAUNCHD_TESTING',
                '-D', 'VPN_HELPER_READINESS_TESTING',
                '-target', f'{architecture}-apple-macosx11.0',
                *map(str, SOURCES), '-o', str(output),
            ])
            slices.append(str(output))
        cls.binary = cls.build / 'fixture'
        cls.command(['lipo', '-create', *slices, '-output', str(cls.binary)])
        cls.binary.chmod(0o700)
        cls.command([
            'codesign', '--force', '--sign', '-', '--identifier',
            'kz.documentolog.proxypilot.vpn-helper', '--options',
            'runtime,hard,kill', str(cls.binary),
        ])
        cls.hashes = {}
        for architecture in ('arm64', 'x86_64'):
            result = cls.command([
                'codesign', '-d', '--verbose=4', '--arch', architecture,
                str(cls.binary),
            ])
            cls.hashes[architecture] = re.search(
                r'^CDHash=([a-f0-9]{40})$', result.stderr, re.M).group(1)

        # The production surface must compile with no test configurability.
        for architecture in ('arm64', 'x86_64'):
            cls.command([
                'swiftc', '-parse-as-library', '-emit-library',
                '-target', f'{architecture}-apple-macosx11.0',
                *map(str, SOURCES[:-1]),
                '-o', str(cls.build / f'production-{architecture}.dylib'),
            ])

    def setUp(self):
        self.temporary_case = tempfile.TemporaryDirectory(prefix='pp-broker-launchd-', dir='/tmp')
        self.addCleanup(self.temporary_case.cleanup)
        self.base = Path(self.temporary_case.name)
        self.storage = self.base / 'store'
        self.storage.mkdir(mode=0o700)
        self.plists = self.base / 'plists'
        self.plists.mkdir(mode=0o755)
        self.endpoint = self.base / 'update-broker.sock'
        self.label = 'kz.documentolog.proxypilot.vpn-update-broker.test-' + uuid.uuid4().hex
        self.plist = self.plists / f'{self.label}.plist'
        self.addCleanup(self.force_bootout)
        artifact = self.binary.read_bytes()
        digest = hashlib.sha256(artifact).hexdigest()
        fields = {
            'format': 1,
            'product': 'kz.documentolog.proxypilot',
            'sequence': 41,
            'version': '1.6.0',
            'protocol': 1,
            'app-arm64': self.hashes['arm64'],
            'app-x86_64': self.hashes['x86_64'],
            'helper-arm64': self.hashes['arm64'],
            'helper-x86_64': self.hashes['x86_64'],
            'helper-sha256': digest,
            'helper-bytes': len(artifact),
        }
        self.helper_name = 'helper-' + digest
        self.manifest = self.base / 'manifest'
        self.manifest.write_text(''.join(f'{key}={value}\n' for key, value in fields.items()))
        result = self.run_fixture('seed', self.manifest, self.binary)
        self.assertEqual(result.stdout.strip(), 'seeded', result.stdout + result.stderr)

    def run_fixture(self, action, *extra, timeout=60):
        return subprocess.run([
            str(self.binary), action, str(self.storage), str(self.plists),
            str(self.endpoint), self.label, *map(str, extra),
        ], capture_output=True, text=True, timeout=timeout)

    def force_bootout(self):
        subprocess.run(
            ['/bin/launchctl', 'bootout', f'{self.domain}/{self.label}'],
            capture_output=True, timeout=60)

    def loaded_pid(self):
        result = subprocess.run(
            ['/bin/launchctl', 'print', f'{self.domain}/{self.label}'],
            capture_output=True, text=True, timeout=60)
        match = re.search(r'^\s*pid = (\d+)$', result.stdout, re.M)
        return int(match.group(1)) if match else None

    def wait_for(self, predicate, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.05)
        self.fail('timed out waiting for launchd state')

    def request(self):
        def attempt():
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(1)
            try:
                client.connect(str(self.endpoint))
                return client.recv(64)
            except (FileNotFoundError, ConnectionRefusedError, socket.timeout):
                return None
            finally:
                client.close()
        return self.wait_for(attempt)

    def test_socket_activation_restart_and_exact_plist(self):
        result = self.run_fixture('install')
        self.assertEqual(result.stdout.strip(), 'installed', result.stdout + result.stderr)
        # installAndStart must not return on plist/bootstrap acceptance alone.
        # Its success is a receipt for a live peer authenticated against the
        # exact selected helper pins.
        self.assertIsNotNone(self.loaded_pid())
        self.assertEqual(self.request(), b'broker-ready')
        description = plistlib.loads(self.plist.read_bytes())
        self.assertEqual(description, {
            'Label': self.label,
            'ProgramArguments': [str(self.storage.resolve() / self.helper_name),
                                 'serve-update-broker'],
            'RunAtLoad': True,
            'KeepAlive': True,
            'ProcessType': 'Background',
            'ThrottleInterval': 10,
            'Sockets': {'Broker': {
                'SockPathName': str(self.endpoint),
                'SockPathMode': 0o666,
            }},
        })
        self.assertEqual(self.plist.stat().st_mode & 0o7777, 0o644)
        self.assertEqual(self.endpoint.stat().st_mode & 0o7777, 0o666)
        self.assertEqual([entry.name for entry in self.plists.iterdir()
                          if entry.name.startswith('.')], [])

        first = self.wait_for(self.loaded_pid)
        os.kill(first, 9)
        second = self.wait_for(lambda: (pid := self.loaded_pid()) and pid != first and pid)
        self.assertNotEqual(first, second)
        self.assertEqual(self.request(), b'broker-ready')

    def test_remove_is_exact_and_idempotent(self):
        sibling = self.plists / 'unrelated.plist'
        sibling.write_text('leave me')
        self.assertEqual(self.run_fixture('install').returncode, 0)
        for _ in range(2):
            result = self.run_fixture('remove')
            self.assertEqual(result.stdout.strip(), 'removed', result.stdout + result.stderr)
        self.assertFalse(self.plist.exists())
        self.assertTrue(sibling.exists())
        self.assertFalse(self.endpoint.exists())
        self.assertIsNone(self.loaded_pid())

    def test_changed_selected_helper_is_refused_before_bootstrap(self):
        helper = self.storage / self.helper_name
        helper.write_bytes(helper.read_bytes() + b'tampered')
        helper.chmod(0o700)
        result = self.run_fixture('install')
        self.assertEqual(result.returncode, 77, result.stdout + result.stderr)
        self.assertIn('rejected:', result.stdout)
        self.assertFalse(self.plist.exists())
        self.assertIsNone(self.loaded_pid())

    def test_system_entry_refuses_unprivileged_fixture(self):
        result = self.run_fixture('system')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('requiresRoot', result.stdout)


if __name__ == '__main__':
    unittest.main()
