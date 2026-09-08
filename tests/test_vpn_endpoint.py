"""Protected public IPC directory, only disposable sockets; no root/system writes."""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise unittest.SkipTest('No elevated endpoint tests')
        cls.build = tempfile.TemporaryDirectory(prefix='pp-ep-build-', dir='/tmp')
        cls.addClassCleanup(cls.build.cleanup)
        cls.binary = Path(cls.build.name) / 'check'
        slices = []
        for arch in ('arm64', 'x86_64'):
            output = Path(cls.build.name) / arch
            subprocess.run(['swiftc', '-target', f'{arch}-apple-macosx11.0',
                            str(ROOT / 'app/vpn-helper/VPNHelperProtocol.swift'),
                            str(ROOT / 'app/vpn-helper/VPNEndpointDirectory.swift'),
                            str(ROOT / 'tests/vpn_endpoint_checks.swift'), '-o', str(output)],
                           check=True, capture_output=True, timeout=90)
            slices.append(str(output))
        subprocess.run(['lipo', '-create', *slices, '-output', str(cls.binary)], check=True, capture_output=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pp-e-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.directory = self.base / 'kz.documentolog.proxypilot.vpn'
        self.endpoint = self.directory / 'helper.sock'

    def run_check(self, mode):
        return subprocess.run([str(self.binary), mode, str(self.base)], capture_output=True, text=True, timeout=5)

    def create(self):
        result = self.run_check('create')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.directory.stat().st_mode & 0o7777, 0o755)

    def listener(self):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(str(self.endpoint))
        self.endpoint.chmod(0o666)
        server.listen(1)
        return server

    def test_directory_has_no_private_payload_and_can_be_reopened(self):
        self.create()
        self.assertEqual(list(self.directory.iterdir()), [])
        self.assertEqual(self.run_check('read').returncode, 0)
        self.assertEqual(self.run_check('create').returncode, 0)

    def test_read_never_provisions(self):
        self.assertEqual(self.run_check('read').returncode, 77)
        self.assertFalse(self.directory.exists())

    def test_root_guard_does_not_create_system_directory(self):
        result = self.run_check('root-guard')
        self.assertEqual(result.stdout.strip(), 'rejected:requiresRoot')

    def test_shared_writable_parent_is_rejected(self):
        self.base.chmod(0o777)
        self.assertEqual(self.run_check('create').returncode, 77)
        self.assertFalse(self.directory.exists())

    def test_existing_wrong_permissions_are_not_repaired(self):
        self.directory.mkdir(mode=0o700)
        self.assertEqual(self.run_check('create').returncode, 77)
        self.assertEqual(self.directory.stat().st_mode & 0o7777, 0o700)

    def test_symlink_directory_is_not_followed(self):
        target = self.base / 'other'
        target.mkdir(mode=0o755)
        self.directory.symlink_to(target)
        self.assertEqual(self.run_check('create').returncode, 77)
        self.assertEqual(list(target.iterdir()), [])

    def test_acl_directory_is_rejected(self):
        self.create()
        subprocess.run(['chmod', '+a', 'everyone allow read', str(self.directory)], check=True, capture_output=True)
        self.assertEqual(self.run_check('read').returncode, 77)

    def test_connect_is_nonblocking_and_close_on_exec(self):
        self.create()
        self.listener()
        self.assertEqual(self.run_check('connect').stdout.strip(), 'connected nonblocking cloexec')

    def test_expired_connect_does_not_return_a_descriptor(self):
        self.create()
        self.listener()
        self.assertIn('rejected:timeout', self.run_check('expired').stdout)

    def test_missing_or_regular_file_endpoint_is_rejected(self):
        self.create()
        self.assertEqual(self.run_check('connect').returncode, 77)
        self.endpoint.write_bytes(b'not a socket')
        self.assertEqual(self.run_check('connect').returncode, 77)

    def test_socket_symlink_is_rejected(self):
        self.create()
        target = self.directory / 'other.sock'
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(str(target))
        target.chmod(0o666)
        server.listen(1)
        self.endpoint.symlink_to(target)
        self.assertEqual(self.run_check('connect').returncode, 77)

    def test_wrong_socket_permissions_are_rejected(self):
        self.create()
        self.listener()
        self.endpoint.chmod(0o600)
        self.assertEqual(self.run_check('connect').returncode, 77)
