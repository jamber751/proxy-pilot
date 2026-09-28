"""Red, disposable SCM_RIGHTS contract for the future update-broker transport."""
import array
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/vpn_update_broker_transport_server.swift'
PROTOCOL = ROOT / 'app/vpn-helper/VPNUpdateBrokerProtocol.swift'
TRANSPORT = ROOT / 'app/vpn-helper/VPNUpdateBrokerTransport.swift'
REQUEST = struct.Struct('>8sHQ')
RESPONSE = struct.Struct('>8sHQQQ')


class VPNUpdateBrokerTransportSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = FIXTURE.read_text()

    def test_adapter_surface_is_descriptor_relative(self):
        start = cls_start = self.source.index('enum VPNUpdateBrokerTransportFixture')
        surface = self.source[cls_start:]
        self.assertIn('takingSocket:', surface)
        self.assertIn('inTrustedDirectory:', surface)
        self.assertNotIn('URL', surface)
        self.assertNotIn('endpointPath', surface)
        self.assertNotIn('sourceUserID:', surface)
        self.assertEqual(start, cls_start)

    def test_fixture_demands_kernel_live_peer_credentials(self):
        for value in ('peerUserID', 'sourceUserID', 'credentialSource',
                      'kernelPeerCredential', 'LOCAL_PEERCRED', 'SO_PEERCRED'):
            self.assertIn(value, self.source)
        self.assertNotIn('claimedUserID', self.source)

    def test_fixture_checks_descriptor_lifetime_and_single_request(self):
        for value in ('descriptorWasCloexec', 'descriptorWasClosed',
                      'requestsHandled', 'one request per connection'):
            self.assertIn(value, self.source)

    def test_fixture_checks_fixed_private_endpoint(self):
        for value in ('update-broker.sock', 'endpointMode', '0o600',
                      'endpointInsideTrustedParent'):
            self.assertIn(value, self.source)

    def test_fixture_status_is_fixed_numeric_only(self):
        self.assertIn('VPNUpdateBrokerResponse', self.source)
        for forbidden in ('errorDescription', 'secret', 'profile', 'privateKey'):
            self.assertNotIn(forbidden, self.source)


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'),
                     'macOS Swift required')
class VPNUpdateBrokerTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TRANSPORT.is_file():
            raise AssertionError(
                'expected red test: app/vpn-helper/VPNUpdateBrokerTransport.swift is absent')
        cls.temporary = tempfile.TemporaryDirectory(prefix='pp-broker-transport-build-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.binary = Path(cls.temporary.name) / 'transport-server'
        compiled = subprocess.run(
            ['swiftc', '-D', 'VPN_UPDATE_BROKER_TRANSPORT_TESTING',
             '-target', 'arm64-apple-macosx11.0',
             '-module-cache-path', str(Path(cls.temporary.name) / 'ModuleCache'),
             str(ROOT / 'app/vpn-helper/VPNPeerAuthentication.swift'),
             str(ROOT / 'app/vpn-helper/VPNHelperProtocol.swift'),
             str(PROTOCOL), str(TRANSPORT), str(FIXTURE), '-o', str(cls.binary)],
            capture_output=True, text=True, timeout=120,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    def setUp(self):
        # AF_UNIX paths are capped at 104 bytes on macOS. Keep the live
        # endpoint fixture below that limit even when TMPDIR itself is long.
        self.temp = tempfile.TemporaryDirectory(prefix='ppbt-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'candidate'
        self.source.mkdir(mode=0o700)
        self.directory_fd = os.open(self.source, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.directory_fd)

    @staticmethod
    def frame(operation, sequence=0):
        return REQUEST.pack(b'PPVPNB01', operation, sequence)

    def exchange(self, frame=b'', descriptor_groups=(), mode='serve', close=False):
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(client.close)
        process = subprocess.Popen(
            [str(self.binary), mode, str(server.fileno())],
            pass_fds=(server.fileno(),), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        server.close()
        if frame:
            ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                          array.array('i', group)) for group in descriptor_groups]
            client.sendmsg([frame], ancillary)
        if close:
            client.shutdown(socket.SHUT_WR)
        client.settimeout(1)
        try:
            response = client.recv(4096)
        except socket.timeout:
            response = b''
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0, stderr)
        return response, json.loads(stdout)

    def assert_refused_and_consumed(self, frame, descriptor_groups=(), reason=None,
                                    mode='serve'):
        response, observed = self.exchange(frame, descriptor_groups, mode=mode)
        self.assertEqual(response, b'')
        self.assertEqual(observed['result'], 'refused')
        if reason is not None:
            self.assertEqual(observed['reason'], reason)
        self.assertTrue(observed['descriptorWasClosed'])
        return observed

    def test_submit_requires_exactly_one_directory_descriptor(self):
        response, observed = self.exchange(
            self.frame(1, 41), ((self.directory_fd,),))
        self.assertEqual(len(response), RESPONSE.size)
        self.assertEqual(observed['result'], 'accepted')
        self.assertEqual(observed['requestsHandled'], 1)
        self.assertEqual(observed['peerUserID'], os.geteuid())
        self.assertEqual(observed['sourceUserID'], os.geteuid())
        self.assertEqual(observed['credentialSource'], 'kernelPeerCredential')
        self.assertTrue(observed['descriptorWasCloexec'])
        self.assertTrue(observed['descriptorWasClosed'])

        self.assert_refused_and_consumed(self.frame(1, 41), reason='missingDescriptor')
        duplicate = os.dup(self.directory_fd)
        self.addCleanup(os.close, duplicate)
        self.assert_refused_and_consumed(
            self.frame(1, 41), ((self.directory_fd, duplicate),), 'extraDescriptor')

        regular = self.root / 'regular'; regular.write_bytes(b'x')
        regular_fd = os.open(regular, os.O_RDONLY)
        self.addCleanup(os.close, regular_fd)
        self.assert_refused_and_consumed(
            self.frame(1, 41), ((regular_fd,),), 'notDirectory')

        denied = self.assert_refused_and_consumed(
            self.frame(1, 41), ((self.directory_fd,),), 'unauthorizedPeer', mode='deny')
        self.assertEqual(denied['peerUserID'], os.geteuid())

    def test_status_requires_zero_descriptors(self):
        response, observed = self.exchange(self.frame(2))
        self.assertEqual(len(response), RESPONSE.size)
        self.assertEqual(observed['result'], 'accepted')
        self.assertEqual(observed['requestsHandled'], 1)
        self.assert_refused_and_consumed(
            self.frame(2), ((self.directory_fd,),), 'unexpectedDescriptor')

    def test_malformed_frames_and_extra_ancillary_are_refused(self):
        valid = self.frame(1, 41)
        for malformed in (valid[:-1], valid + b'x', self.frame(0x7fff, 41)):
            with self.subTest(length=len(malformed)):
                self.assert_refused_and_consumed(
                    malformed, ((self.directory_fd,),), 'invalidFrame')
        # A source UID appended by IPC is only an overlong malformed frame.
        self.assert_refused_and_consumed(
            valid + struct.pack('>Q', os.geteuid()),
            ((self.directory_fd,),), 'invalidFrame')

        # Darwin rejects two SCM_RIGHTS control groups in one sendmsg with
        # EINVAL. Multiple descriptors in the accepted group are exercised by
        # test_submit_requires_exactly_one_directory_descriptor; the Swift
        # parser still independently rejects multiple ancillary groups.

    def test_control_truncation_is_refused_and_every_received_fd_closed(self):
        descriptors = [os.dup(self.directory_fd) for _ in range(32)]
        for descriptor in descriptors:
            self.addCleanup(os.close, descriptor)
        observed = self.assert_refused_and_consumed(
            self.frame(1, 41), (tuple(descriptors),), 'controlTruncated')
        self.assertTrue(observed['messageControlTruncated'])

    def test_eof_timeout_and_one_request_per_connection(self):
        _, eof = self.exchange(close=True)
        self.assertEqual(eof['result'], 'eof')
        self.assertEqual(eof['requestsHandled'], 0)
        self.assertTrue(eof['descriptorWasClosed'])

        _, timeout = self.exchange()
        self.assertEqual(timeout['result'], 'timeout')
        self.assertEqual(timeout['requestsHandled'], 0)
        self.assertTrue(timeout['descriptorWasClosed'])

        response, observed = self.exchange(self.frame(2) + self.frame(2))
        self.assertEqual(response, b'')
        self.assertEqual(observed['result'], 'refused')
        self.assertEqual(observed['reason'], 'invalidFrame')
        self.assertEqual(observed['requestsHandled'], 0)  # one request per connection

    def test_response_is_bounded_numeric_and_contains_no_text_payload(self):
        response, _ = self.exchange(self.frame(2))
        self.assertEqual(len(response), RESPONSE.size)
        magic, state, from_sequence, to_sequence, revision = RESPONSE.unpack(response)
        self.assertEqual(magic, b'PPVPNR01')
        self.assertIn(state, range(8))
        self.assertGreaterEqual(from_sequence, 0)
        self.assertGreaterEqual(to_sequence, 0)
        self.assertGreaterEqual(revision, 0)
        for text in (b'/', b'error', b'path', b'secret', b'profile', b'key'):
            self.assertNotIn(text, response.lower())

    def test_endpoint_is_fixed_private_and_descriptor_relative(self):
        parent = self.root / 'endpoint'; parent.mkdir(mode=0o700)
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, parent_fd)
        process = subprocess.run(
            [str(self.binary), 'endpoint', str(parent_fd)],
            pass_fds=(parent_fd,), capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        observed = json.loads(process.stdout)
        self.assertEqual(observed['endpointName'], 'update-broker.sock')
        self.assertEqual(observed['endpointMode'], 0o600)
        self.assertTrue(observed['endpointInsideTrustedParent'])
        self.assertFalse(observed['acceptedCallerPath'])


if __name__ == '__main__':
    unittest.main()
