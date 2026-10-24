"""Compile/pure tests by default. --acceptance is DISPOSABLE GITHUB VM ONLY.

No local SC calls, getaddrinfo, bind/listen or DNS packets during default tests.
Live mode owns only 127.0.0.1:53 UDP/TCP and an exact random service DNS key.
RFC 1035 wire format: https://www.rfc-editor.org/rfc/rfc1035#section-4
.test, rather than .invalid: https://www.rfc-editor.org/rfc/rfc6761#section-6.2
Answers are documentation addresses; nothing connects to returned addresses.
"""
import ipaddress
from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

SOURCE = Path(__file__).with_name('vpn_dns_resolver_vm_checks.swift')
FLAG = 'PROXYPILOT_VM_DNS_RESOLVER_TESTS'


def allowed(uid, euid, environment):
    return uid == euid == 0 and environment.get('GITHUB_ACTIONS') == 'true' and environment.get(FLAG) == '1'


def compile_tool(folder):
    binary = folder / 'resolver-checks'
    subprocess.run(['/usr/bin/swiftc', '-parse-as-library', str(SOURCE),
                    '-framework', 'SystemConfiguration', '-o', str(binary)],
                   check=True, capture_output=True, text=True, timeout=120)
    return binary


def question(name, kind, identifier=123):
    labels = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.split('.')) + b'\0'
    return struct.pack('!HHHHHH', identifier, 0x0100, 1, 0, 0, 0) + labels + struct.pack('!HH', kind, 1)


class Responder:
    """Pure fixed-fixture DNS encoder; no sockets until separately gated live()."""
    def __init__(self, run):
        self.names = {'udp.pp-' + run + '.test': 'udp', 'tcp.pp-' + run + '.test': 'tcp'}
        self.seen = set()

    def response(self, packet, transport):
        if len(packet) < 12 or len(packet) > 4096:
            return None
        identifier, flags, qd, an, ns, _ = struct.unpack('!HHHHHH', packet[:12])
        if flags & 0xF800 or qd != 1 or an != 0 or ns != 0:
            return None
        index, labels = 12, []
        try:
            while packet[index]:
                length = packet[index]
                if not 1 <= length <= 63 or index + 1 + length >= len(packet):
                    return None
                labels.append(packet[index + 1:index + 1 + length].decode('ascii').lower())
                index += length + 1
                if index > 267:
                    return None
            index += 1
            kind, dnsclass = struct.unpack('!HH', packet[index:index + 4])
        except (IndexError, UnicodeError, struct.error):
            return None
        name = '.'.join(labels)
        if name not in self.names or dnsclass != 1 or kind not in (1, 28):
            return None
        # Only recognized exact synthetic query categories are retained.
        label = self.names[name]
        self.seen.add((label, kind, transport))
        truncated = label == 'tcp' and transport == 'udp'
        header = struct.pack('!HHHHHH', identifier, 0x8380 if truncated else 0x8180,
                             1, 0 if truncated else 1, 0, 0)
        query = packet[12:index + 4]
        if truncated:
            return header + query
        address = ipaddress.ip_address('192.0.2.53' if kind == 1 else '2001:db8::53').packed
        # TTL zero: each canary has to reach our responder; no search-list alias.
        record = b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 0, len(address)) + address
        return header + query + record

    def print_categories(self):
        # These six booleans describe only our fixed synthetic queries. Never
        # print DNS names, packet bytes, peer addresses, or host resolver state.
        categories = [('udpA', ('udp', 1, 'udp')), ('udpAAAA', ('udp', 28, 'udp')),
                      ('tcpTruncA', ('tcp', 1, 'udp')), ('tcpTruncAAAA', ('tcp', 28, 'udp')),
                      ('tcpA', ('tcp', 1, 'tcp')), ('tcpAAAA', ('tcp', 28, 'tcp'))]
        print('PACKETS ' + ' '.join(name + '=' + str(key in self.seen).lower()
                                    for name, key in categories))


def read_exact(connection, length):
    data = b''
    while len(data) < length:
        part = connection.recv(length - len(data))
        if not part:
            raise ValueError('short-frame')
        data += part
    return data


def live(binary):
    # Gate is before creation/binding/listening of any socket or child execution.
    if not allowed(os.getuid(), os.geteuid(), os.environ):
        raise RuntimeError('guardDenied')
    run = str(uuid.uuid4())
    responder = Responder(run)
    stop = threading.Event()
    errors = []
    # No SO_REUSEADDR/PORT, takeover, or killing existing listeners.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
        try:
            udp.bind(('127.0.0.1', 53))
            tcp.bind(('127.0.0.1', 53))
            tcp.listen(8)
        except OSError:
            raise RuntimeError('fixturePortOccupied') from None
        with selectors.DefaultSelector() as selector:
            selector.register(udp, selectors.EVENT_READ)
            selector.register(tcp, selectors.EVENT_READ)

            def serve():
                try:
                    while not stop.is_set():
                        for event, _ in selector.select(timeout=0.1):
                            if event.fileobj is udp:
                                packet, peer = udp.recvfrom(4096)
                                if not ipaddress.ip_address(peer[0]).is_loopback:
                                    continue
                                answer = responder.response(packet, 'udp')
                                if answer is not None:
                                    udp.sendto(answer, peer)
                            else:
                                connection, peer = tcp.accept()
                                with connection:
                                    connection.settimeout(1)
                                    if not ipaddress.ip_address(peer[0]).is_loopback:
                                        continue
                                    length = struct.unpack('!H', read_exact(connection, 2))[0]
                                    if not 12 <= length <= 4096:
                                        continue
                                    answer = responder.response(read_exact(connection, length), 'tcp')
                                    if answer is not None:
                                        connection.sendall(struct.pack('!H', len(answer)) + answer)
                except Exception:
                    errors.append('responder')

            thread = threading.Thread(target=serve)
            thread.start()
            try:
                # subprocess.run kills/waits on timeout, releasing the owner's
                # Mach session even when system getaddrinfo is stuck in a child.
                result = subprocess.run([str(binary), '--acceptance', run],
                                        capture_output=True, text=True, timeout=110)
            except subprocess.TimeoutExpired:
                raise RuntimeError('ownerTimeout') from None
            finally:
                stop.set()
                thread.join(timeout=3)
                # Also emitted on subprocess timeout, resolver failure and
                # absent fallback, before the fixed failure category is raised.
                responder.print_categories()
            if thread.is_alive() or errors:
                raise RuntimeError('responder')
            allowed_lines = {'PASS udp-A-AAAA-system-getaddrinfo', 'PASS tcp-A-AAAA-system-getaddrinfo',
                             'PASS owner-session-close-cleanup'}
            # Fixed categories only, never raw exception text, packets or state.
            if result.returncode or set(result.stdout.splitlines()) != allowed_lines:
                category = next((line for line in result.stdout.splitlines()
                                 if line in {'FAIL ' + value for value in
                                             ('guardDenied', 'arguments', 'create', 'occupied', 'read',
                                              'add', 'copy', 'resolve', 'answer', 'child', 'timeout', 'cleanup')}),
                                'FAIL resolver-child')
                raise RuntimeError(category)
            expected = {(label, kind, transport) for label, transports in
                        [('udp', ['udp']), ('tcp', ['udp', 'tcp'])]
                        for kind in (1, 28) for transport in transports}
            if not expected <= responder.seen:
                raise RuntimeError('missingExactCanaryPackets')
            for line in sorted(allowed_lines):
                print(line)
            print('PASS own-responder-exact-A-AAAA-UDP-and-TCP-fallback-packets')
    print('PASS owned-loopback-sockets-closed')


class ResolverPureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp-resolver-pure-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.binary = compile_tool(Path(cls.temp.name))

    def test_swift_pure_and_denials(self):
        result = subprocess.run([str(self.binary), '--pure-checks'], env={}, capture_output=True, text=True, timeout=10)
        self.assertEqual((result.returncode, result.stdout), (0, 'PASS pure-guards\n'))
        for env in ({}, {'GITHUB_ACTIONS': 'true'}, {FLAG: '1'}):
            for args in (['--acceptance', str(uuid.uuid4())], ['--resolve', str(uuid.uuid4()), 'udp', '4']):
                result = subprocess.run([str(self.binary), *args], env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (1, 'FAIL guardDenied\n', ''))
        if os.getuid() != 0 and os.geteuid() != 0:
            result = subprocess.run([str(self.binary), '--acceptance', str(uuid.uuid4())],
                                    env={'GITHUB_ACTIONS': 'true', FLAG: '1'}, capture_output=True, text=True, timeout=10)
            self.assertEqual((result.returncode, result.stdout), (1, 'FAIL guardDenied\n'))

    def test_python_gate_truth_table(self):
        env = {'GITHUB_ACTIONS': 'true', FLAG: '1'}
        self.assertTrue(allowed(0, 0, env))
        for ids in [(501, 501), (501, 0), (0, 501)]:
            self.assertFalse(allowed(*ids, env))
        for missing in ({}, {'GITHUB_ACTIONS': 'true'}, {FLAG: '1'}):
            self.assertFalse(allowed(0, 0, missing))

    def test_python_live_denial_precedes_socket_creation(self):
        with patch.dict(os.environ, {}, clear=True), patch('socket.socket') as create:
            with self.assertRaisesRegex(RuntimeError, '^guardDenied$'):
                live(None)
            create.assert_not_called()

    def test_fixed_wire_answers_and_truncation_without_sockets(self):
        run = str(uuid.uuid4())
        responder = Responder(run)
        for kind, address in [(1, '192.0.2.53'), (28, '2001:db8::53')]:
            for label in ('udp', 'tcp'):
                query = question(label + '.pp-' + run + '.test', kind)
                answer = responder.response(query, 'udp')
                header = struct.unpack('!HHHHHH', answer[:12])
                self.assertEqual(header[1] & 0x0200 != 0, label == 'tcp')
                self.assertEqual(header[3], 0 if label == 'tcp' else 1)
                full = responder.response(query, 'tcp')
                self.assertEqual(struct.unpack('!HHHHHH', full[:12])[3], 1)
                self.assertTrue(full.endswith(ipaddress.ip_address(address).packed))
                self.assertIn(struct.pack('!HHI', kind, 1, 0), full)
        for packet in (b'', b'\0' * 12, question('other.test', 1),
                       question('udp.pp-' + run + '.test', 15), b'\0' * 12 + b'\xc0\x0c'):
            self.assertIsNone(responder.response(packet, 'udp'))
        output = io.StringIO()
        with redirect_stdout(output):
            responder.print_categories()
        self.assertEqual(output.getvalue(), 'PACKETS udpA=true udpAAAA=true tcpTruncA=true '
                         'tcpTruncAAAA=true tcpA=true tcpAAAA=true\n')


if __name__ == '__main__':
    if sys.argv[1:] == ['--acceptance']:
        # Fail before even compiling when live invocation isn't authorized.
        if not allowed(os.getuid(), os.geteuid(), os.environ):
            print('FAIL guardDenied'); sys.exit(1)
        try:
            with tempfile.TemporaryDirectory(prefix='pp-resolver-vm-') as folder:
                live(compile_tool(Path(folder)))
        except Exception as error:
            categories = {'guardDenied', 'fixturePortOccupied', 'ownerTimeout', 'responder', 'missingExactCanaryPackets'}
            text = str(error)
            print(text if text.startswith('FAIL ') and text[5:] in
                  {'guardDenied', 'arguments', 'create', 'occupied', 'read', 'add', 'copy', 'resolve', 'answer', 'child', 'timeout', 'cleanup', 'resolver-child'}
                  else 'FAIL ' + (text if text in categories else 'unexpected'))
            sys.exit(1)
    else:
        unittest.main()
