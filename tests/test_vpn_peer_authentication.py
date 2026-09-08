"""Exercise the real kernel audit-token/signature gate with separate processes.

Only disposable AF_UNIX sockets and ad-hoc test executables; never installs a
service, escalates privileges, reads a VPN profile or changes networking.
"""
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
IDENTIFIER = 'kz.documentolog.proxypilot.peer-test'


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNPeerAuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix='pp-peer-', dir='/tmp')
        cls.addClassCleanup(cls.build.cleanup)
        cls.directory = Path(cls.build.name)
        sources = [ROOT / 'app/vpn-helper/VPNPeerAuthentication.swift',
                   ROOT / 'app/vpn-helper/VPNReleaseAuthorization.swift', ROOT / 'tests/vpn_peer_checks.swift']
        binaries = []
        for arch in ('arm64', 'x86_64'):
            binary = cls.directory / arch
            cls.command(['swiftc', '-target', f'{arch}-apple-macosx11.0',
                         *map(str, sources), '-o', str(binary)])
            binaries.append(str(binary))
        cls.verifier = cls.directory / 'verifier'
        cls.command(['lipo', '-create', *binaries, '-output', str(cls.verifier)])
        cls.command(['codesign', '--force', '--sign', '-', '--identifier', IDENTIFIER,
                     '--options', 'runtime,hard,kill', str(cls.verifier)])
        cls.clients = {}
        cls.hashes = {}
        for name, options, identifier, entitlements in [
            ('allowed', 'runtime,hard,kill', IDENTIFIER, None),
            ('same-name-other-build', 'runtime,hard,kill,restrict', IDENTIFIER, None),
            ('other-identifier', 'runtime,hard,kill', IDENTIFIER + '.other', None),
            ('unhardened', None, IDENTIFIER, None),
            ('runtime-exception', 'runtime,hard,kill', IDENTIFIER,
             {'com.apple.security.cs.disable-library-validation': True}),
            ('debuggable', 'runtime,hard,kill', IDENTIFIER, {'com.apple.security.get-task-allow': True}),
            ('release-app', 'runtime,hard,kill', 'kz.documentolog.proxypilot', None),
        ]:
            path = cls.directory / name
            shutil.copyfile(cls.verifier, path)
            path.chmod(0o700)
            # Strip inherited options before signing the deliberately weak fixture.
            cls.command(['codesign', '--remove-signature', str(path)])
            args = ['codesign', '--force', '--sign', '-', '--identifier', identifier]
            if options:
                args += ['--options', options]
            if entitlements:
                entitlement_file = cls.directory / (name + '.plist')
                with entitlement_file.open('wb') as stream:
                    plistlib.dump(entitlements, stream)
                args += ['--entitlements', str(entitlement_file)]
            cls.command([*args, str(path)])
            cls.command(['codesign', '--verify', '--strict', str(path)])
            output = cls.command(['codesign', '-d', '--verbose=4', '--arch', platform.machine(), str(path)])
            match = re.search(r'^CDHash=([a-f0-9]{40})$', output.stderr, re.M)
            if not match:
                raise AssertionError('fixture has no CDHash')
            cls.clients[name] = path
            cls.hashes[name] = match.group(1)

    @staticmethod
    def command(args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stderr)
        return result

    def verify(self, descriptor, *, hashes=None, identifier=IDENTIFIER, user_id=None, signed_release=False, installer=False):
        return subprocess.run(
            [str(self.verifier), 'verify-installer' if installer else ('verify-release' if signed_release else 'verify'), str(descriptor),
             str(os.geteuid() if user_id is None else user_id), identifier,
             self.hashes['allowed'] if hashes is None else hashes],
            pass_fds=(descriptor,) if descriptor >= 0 else (), capture_output=True,
            text=True, timeout=10)

    def with_client(self, name, check):
        with tempfile.TemporaryDirectory(prefix='pp-peer-', dir='/tmp') as directory:
            address = str(Path(directory) / 'peer.sock')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.settimeout(5)
                listener.bind(address)
                listener.listen(1)
                process = subprocess.Popen([str(self.clients[name]), 'client', address],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    with listener.accept()[0] as connection:
                        connection.settimeout(5)
                        self.assertEqual(connection.recv(1), b'\x01')
                        check(connection, process)
                finally:
                    if process.poll() is None:
                        process.terminate()
                    process.communicate(timeout=5)

    def assert_decision(self, name, expected, **policy):
        def check(connection, process):
            result = self.verify(connection.fileno(), **policy)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(), 'allowed' if expected == 0 else 'denied')
        self.with_client(name, check)

    def test_exact_hardened_build_allowed_on_reconnect(self):
        for _ in range(3):
            self.assert_decision('allowed', 0)

    def test_same_identifier_does_not_authorize_other_build(self):
        self.assertNotEqual(self.hashes['allowed'], self.hashes['same-name-other-build'])
        self.assert_decision('same-name-other-build', 77)

    def test_wrong_identifier_rejected_even_with_matching_pin(self):
        self.assert_decision('other-identifier', 77, hashes=self.hashes['other-identifier'])

    def test_wrong_account_rejected(self):
        self.assert_decision('allowed', 77, user_id=os.geteuid() + 1)

    def test_installer_role_requires_root_even_for_the_pinned_app(self):
        self.assert_decision('release-app', 77, hashes=self.hashes['release-app'], installer=True)

    def test_unhardened_pinned_binary_rejected(self):
        self.assert_decision('unhardened', 77, hashes=self.hashes['unhardened'])

    def test_runtime_exception_rejected_even_with_matching_pin(self):
        self.assert_decision('runtime-exception', 77, hashes=self.hashes['runtime-exception'])

    def test_debuggable_binary_rejected_even_with_matching_pin(self):
        self.assert_decision('debuggable', 77, hashes=self.hashes['debuggable'])

    def test_explicit_rotation_allowlist(self):
        pins = self.hashes['allowed'] + ',' + self.hashes['same-name-other-build']
        self.assert_decision('allowed', 0, hashes=pins)
        self.assert_decision('same-name-other-build', 0, hashes=pins)
        # Once removed from trusted policy, the old build fails the next request.
        self.assert_decision('allowed', 77, hashes=self.hashes['same-name-other-build'])

    def test_rechecks_policy_on_existing_connection(self):
        def check(connection, process):
            self.assertEqual(self.verify(connection.fileno()).returncode, 0)
            self.assertEqual(self.verify(connection.fileno(), hashes='00' * 20).returncode, 77)
        self.with_client('allowed', check)

    def test_terminated_peer_is_not_authorized(self):
        def check(connection, process):
            process.terminate()
            process.wait(timeout=5)
            self.assertEqual(self.verify(connection.fileno()).returncode, 77)
        self.with_client('allowed', check)

    def test_signed_release_drives_real_peer_authentication(self):
        self.assert_decision('release-app', 0, hashes=self.hashes['release-app'], signed_release=True)
        self.assert_decision('release-app', 77, hashes=self.hashes['allowed'], signed_release=True)
        self.assert_decision('allowed', 77, hashes=self.hashes['allowed'], signed_release=True)

    def test_non_socket_and_invalid_descriptor_rejected(self):
        self.assertEqual(self.verify(-1).returncode, 77)
        with open(os.devnull, 'rb') as stream:
            self.assertEqual(self.verify(stream.fileno()).returncode, 77)

    def test_unconnected_and_non_unix_socket_rejected(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            self.assertEqual(self.verify(connection.fileno()).returncode, 77)
        # No bind/connect: deliberately not a usable local authenticated stream.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            self.assertEqual(self.verify(connection.fileno()).returncode, 77)

    def test_invalid_policy_fails_closed(self):
        for policy in ({'hashes': ''}, {'hashes': '00'}, {'identifier': ''},
                       {'identifier': 'fake or identifier'}, {'user_id': 0},
                       {'hashes': ','.join(f'{n:040x}' for n in range(17))}):
            with self.subTest(policy=policy):
                result = self.verify(-1, **policy)
                self.assertEqual(result.returncode, 64)
                self.assertEqual(result.stdout.strip(), 'invalid-policy')
