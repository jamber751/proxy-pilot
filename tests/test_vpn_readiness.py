"""Real signed unprivileged peers; production root rule is never bypassed in shipping code."""
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
IDENTIFIER = 'kz.documentolog.proxypilot.vpn-helper'


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class VPNReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() == 0:
            raise unittest.SkipTest('Never run the inert fixtures as root')
        cls.build = tempfile.TemporaryDirectory(prefix='pp-ready-', dir='/tmp')
        cls.addClassCleanup(cls.build.cleanup)
        cls.work = Path(cls.build.name)
        sources = [ROOT / 'app/vpn-helper' / name for name in
                   ('VPNPeerAuthentication.swift', 'VPNReleaseAuthorization.swift', 'VPNHelperProtocol.swift',
                    'VPNHelperReadiness.swift', 'VPNHelperSession.swift')]
        sources.append(ROOT / 'tests/vpn_readiness_checks.swift')
        for flavor in ('test', 'production'):
            slices = []
            for arch in ('arm64', 'x86_64'):
                output = cls.work / f'{flavor}-{arch}'
                flags = ['-D', 'VPN_HELPER_READINESS_TESTING'] if flavor == 'test' else []
                cls.command(['swiftc', *flags, '-target', f'{arch}-apple-macosx11.0', *map(str, sources), '-o', str(output)])
                slices.append(str(output))
            output = cls.work / flavor
            cls.command(['lipo', '-create', *slices, '-output', str(output)])
            cls.command(['codesign', '--force', '--sign', '-', '--options', 'runtime,hard,kill', str(output)])
        cls.servers, cls.pins = {}, {}
        for name, identifier, options, entitlements in [
            ('allowed', IDENTIFIER, 'runtime,hard,kill', None),
            ('other-id', IDENTIFIER + '.other', 'runtime,hard,kill', None),
            ('other-build', IDENTIFIER, 'runtime,hard,kill,restrict', None),
            ('weak', IDENTIFIER, None, None),
            ('debuggable', IDENTIFIER, 'runtime,hard,kill', {'com.apple.security.get-task-allow': True}),
        ]:
            output = cls.work / name
            shutil.copyfile(cls.work / 'production', output)
            output.chmod(0o700)
            cls.command(['codesign', '--remove-signature', str(output)])
            args = ['codesign', '--force', '--sign', '-', '--identifier', identifier]
            if options:
                args += ['--options', options]
            if entitlements:
                path = cls.work / (name + '.plist')
                path.write_bytes(plistlib.dumps(entitlements))
                args += ['--entitlements', str(path)]
            cls.command([*args, str(output)])
            result = cls.command(['codesign', '-d', '--verbose=4', '--arch', platform.machine(), str(output)])
            cls.pins[name] = re.search(r'^CDHash=([a-f0-9]{40})$', result.stderr, re.M).group(1)
            cls.servers[name] = output

    @staticmethod
    def command(args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        return result

    def probe(self, mode='valid', server='allowed', pin=None, timeout=1500, production=False, unreadable=False):
        with tempfile.TemporaryDirectory(prefix='pp-ready-', dir='/tmp') as directory:
            address = str(Path(directory) / 's')
            process = subprocess.Popen([str(self.servers[server]), 'serve', address, mode],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                self.assertEqual(process.stdout.readline().strip(), 'listening')
                if unreadable:
                    # Reproduce root-private executable access without root:
                    # keep the signed process alive but deny opening its file.
                    self.servers[server].chmod(0)
                    with self.assertRaises(PermissionError):
                        self.servers[server].read_bytes()
                started = time.monotonic()
                result = subprocess.run([str(self.work / ('production' if production else 'test')), 'probe',
                                         address, pin or self.pins[server], str(timeout)],
                                        capture_output=True, text=True, timeout=8)
                self.assertLess(time.monotonic() - started, 4)
                self.assertIn('closed', result.stdout, result.stdout + result.stderr)
                return result
            finally:
                if unreadable:
                    self.servers[server].chmod(0o700)
                if process.poll() is None:
                    process.terminate()
                process.communicate(timeout=5)

    def test_authenticated_fresh_response(self):
        for _ in range(3):
            result = self.probe()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('ready:10', result.stdout)

    def test_fragmented_response(self):
        self.assertEqual(self.probe('fragmented').returncode, 0)

    def test_kernel_identity_works_without_reading_the_helper_file(self):
        result = self.probe(unreadable=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('ready:10', result.stdout)

    def test_unreadable_helper_still_requires_exact_pin_and_hardening(self):
        for server in ('other-build', 'weak', 'debuggable'):
            with self.subTest(server=server):
                pin = self.pins['allowed'] if server == 'other-build' else self.pins[server]
                self.assertIn('rejected:denied', self.probe(server=server, pin=pin, unreadable=True).stdout)

    def test_production_rejects_nonroot_even_with_correct_signature(self):
        self.assertIn('rejected:denied', self.probe(production=True).stdout)

    def test_wrong_identifier_even_with_matching_pin(self):
        self.assertIn('rejected:denied', self.probe(server='other-id').stdout)

    def test_other_build_same_identifier(self):
        self.assertIn('rejected:denied', self.probe(server='other-build', pin=self.pins['allowed']).stdout)

    def test_weak_or_debuggable_even_with_matching_pin(self):
        for server in ('weak', 'debuggable'):
            with self.subTest(server=server):
                self.assertIn('rejected:denied', self.probe(server=server).stdout)

    def test_wrong_version_sequence_nonce_or_magic(self):
        for mode in ('protocol', 'sequence', 'nonce', 'magic', 'replay'):
            with self.subTest(mode=mode):
                self.assertIn('rejected:invalidResponse', self.probe(mode).stdout)

    def test_silent_server_times_out(self):
        self.assertIn('rejected:timeout', self.probe('silent', timeout=150).stdout)

    def test_partial_bytes_do_not_reset_deadline(self):
        self.assertIn('rejected:timeout', self.probe('trickle', timeout=150).stdout)

    def test_truncated_or_empty_response(self):
        for mode in ('short', 'eof'):
            self.assertIn('rejected:transport', self.probe(mode).stdout)

    def test_invalid_timeout_consumes_descriptor(self):
        for timeout in (0, -1, 5001):
            self.assertIn('rejected:invalidTimeout', self.probe(timeout=timeout).stdout)

    def test_unavailable_endpoint(self):
        result = subprocess.run([str(self.work / 'test'), 'probe', str(self.work / 'absent'),
                                 self.pins['allowed'], '100'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 77)
        self.assertIn('rejected:transport closed', result.stdout)
