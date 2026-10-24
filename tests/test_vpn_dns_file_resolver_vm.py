"""Default: compile/pure tests only, own temporary files, NO sockets/getaddrinfo.

--acceptance: explicitly opted-in disposable GitHub root VM ONLY. Creates one
random /private/etc/resolver/*.test file and exclusive loopback UDP/TCP sockets.
Apple's public port/domain/timeout syntax:
https://github.com/apple-oss-distributions/libresolv/blob/main/resolver.5
https://github.com/apple-oss-distributions/configd/blob/main/dnsinfo/dnsinfo_flatfile.c
The file binds a SUFFIX. Writer death is tested; configd death/reboot are not.
A bounded negative result with closed listeners does NOT prove no default
fallback/no leak. No packet capture or inspection of other resolver settings.
External CNAME selection, TTL expiry, exact-host isolation, utun/remote DNS
routes and fail-closed behavior remain open. No connection to returned answers.
"""
from contextlib import redirect_stdout
import io
import ipaddress
import os
from pathlib import Path
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import uuid

SOURCE = Path(__file__).with_name('vpn_dns_file_resolver_vm_checks.swift')
FLAG = 'PROXYPILOT_VM_DNS_FILE_RESOLVER_TESTS'


def allowed(uid, euid, environment):
    return uid == euid == 0 and environment.get('GITHUB_ACTIONS') == 'true' and environment.get(FLAG) == '1'


def compile_tool(folder):
    binary = folder / 'file-resolver-checks'
    subprocess.run(['/usr/bin/swiftc', '-parse-as-library', str(SOURCE), '-o', str(binary)],
                   check=True, capture_output=True, text=True, timeout=120)
    return binary


def content(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise RuntimeError('arguments')
    return ('nameserver 127.0.0.1\nport ' + str(port) + '\ntimeout 2\n').encode('ascii')


def fingerprint(directory, name, expected, uid):
    """Bounded exact fixture proof; never enumerate, follow symlinks or dump state."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size != len(expected)):
            raise RuntimeError('foreignIdentity')
        data = os.read(fd, 257)
        after = os.fstat(fd)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_mode,
                                  value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if data != expected or identity(before) != identity(after):
            raise RuntimeError('foreignIdentity')
        return identity(after)
    finally:
        os.close(fd)


def remove_owned(directory, name, expected, uid, captured):
    if fingerprint(directory, name, expected, uid) != captured:
        raise RuntimeError('foreignIdentity')
    # Root-only, non-writable fixture directory; no CAS/hostile-root claim.
    os.unlink(name, dir_fd=directory)


def remove_created_directory(parent, directory, created):
    if not created:
        return
    own = os.fstat(directory)
    current = os.stat('resolver', dir_fd=parent, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != (own.st_dev, own.st_ino):
        raise RuntimeError('foreignIdentity')
    # Never enumerate/empty it; foreign contents make rmdir fail safely.
    os.rmdir('resolver', dir_fd=parent)


def question(name, kind):
    labels = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.split('.')) + b'\0'
    return struct.pack('!HHHHHH', 123, 0x0100, 1, 0, 0, 0) + labels + struct.pack('!HH', kind, 1)


class Responder:
    def __init__(self, run):
        self.names = {phase + '-' + mode + '.pp-file-' + run + '.test': (phase, mode)
                      for phase in ('before', 'after') for mode in ('udp', 'tcp')}
        self.seen = set()

    def response(self, packet, transport):
        if not 12 <= len(packet) <= 4096:
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
        pair = self.names.get('.'.join(labels))
        if pair is None or dnsclass != 1 or kind not in (1, 28):
            return None
        phase, mode = pair
        self.seen.add((phase, mode, kind, transport))
        truncated = mode == 'tcp' and transport == 'udp'
        header = struct.pack('!HHHHHH', identifier, 0x8380 if truncated else 0x8180,
                             1, 0 if truncated else 1, 0, 0)
        query = packet[12:index + 4]
        if truncated:
            return header + query
        address = ipaddress.ip_address('192.0.2.53' if kind == 1 else '2001:db8::53').packed
        return header + query + b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 0, len(address)) + address

    def require_phase(self, phase):
        expected = {(phase, mode, kind, transport) for mode, transports in
                    [('udp', ['udp']), ('tcp', ['udp', 'tcp'])]
                    for kind in (1, 28) for transport in transports}
        if not expected <= self.seen:
            raise RuntimeError('missingPackets')

    def print_categories(self):
        categories = [('udpA', 'udp', 1, 'udp'), ('udpAAAA', 'udp', 28, 'udp'),
                      ('tcpTruncA', 'tcp', 1, 'udp'), ('tcpTruncAAAA', 'tcp', 28, 'udp'),
                      ('tcpA', 'tcp', 1, 'tcp'), ('tcpAAAA', 'tcp', 28, 'tcp')]
        for phase in ('before', 'after'):
            print('PACKETS ' + phase + ' ' + ' '.join(label + '=' + str((phase, mode, kind, transport)
                  in self.seen).lower() for label, mode, kind, transport in categories))


def read_exact(connection, length):
    result = b''
    while len(result) < length:
        part = connection.recv(length - len(result))
        if not part:
            raise RuntimeError('shortFrame')
        result += part
    return result


class Server:
    """No sockets until live() has passed all authorization guards."""
    def __init__(self, responder):
        self.responder, self.stop, self.errors = responder, threading.Event(), []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.thread = None
        try:
            # One exclusive port choice; no takeover, reuse or retries.
            self.udp.bind(('127.0.0.1', 0))
            self.port = self.udp.getsockname()[1]
            self.tcp.bind(('127.0.0.1', self.port))
            self.tcp.listen(8)
        except OSError:
            self.udp.close(); self.tcp.close()
            raise RuntimeError('portOccupied') from None

    def start(self):
        def serve():
            try:
                with selectors.DefaultSelector() as selection:
                    selection.register(self.udp, selectors.EVENT_READ)
                    selection.register(self.tcp, selectors.EVENT_READ)
                    while not self.stop.is_set():
                        for event, _ in selection.select(timeout=0.05):
                            if event.fileobj is self.udp:
                                packet, peer = self.udp.recvfrom(4096)
                                answer = self.responder.response(packet, 'udp') if peer[0] == '127.0.0.1' else None
                                if answer is not None:
                                    self.udp.sendto(answer, peer)
                            else:
                                connection, peer = self.tcp.accept()
                                with connection:
                                    connection.settimeout(1)
                                    if peer[0] != '127.0.0.1':
                                        continue
                                    length = struct.unpack('!H', read_exact(connection, 2))[0]
                                    if not 12 <= length <= 4096:
                                        continue
                                    answer = self.responder.response(read_exact(connection, length), 'tcp')
                                    if answer is not None:
                                        connection.sendall(struct.pack('!H', len(answer)) + answer)
            except Exception:
                self.errors.append('responder')
        self.thread = threading.Thread(target=serve)
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=3)
        self.udp.close(); self.tcp.close()
        if (self.thread and self.thread.is_alive()) or self.errors:
            raise RuntimeError('responder')


def resolve(binary, run, label, family):
    try:
        result = subprocess.run([str(binary), '--resolve', run, label, str(family)],
                                capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        # subprocess.run kills/waits only its own child. Not a DNS timeout claim.
        raise RuntimeError('resolveTimeout') from None
    expected = 'PASS negative\n' if label.startswith('closed') else 'PASS answer\n'
    if result.returncode or result.stdout != expected or result.stderr:
        raise RuntimeError('negative' if label.startswith('closed') else 'resolve')


def writer_marker(writer, expected):
    with selectors.DefaultSelector() as selection:
        selection.register(writer.stdout, selectors.EVENT_READ)
        if not selection.select(timeout=5) or writer.stdout.readline(64) != expected:
            raise RuntimeError('writer')


def live(binary):
    # Before socket creation, root directory open, writer dispatch or getaddrinfo.
    if not allowed(os.getuid(), os.geteuid(), os.environ):
        raise RuntimeError('guardDenied')
    run = str(uuid.uuid4())
    name = 'pp-file-' + run + '.test'
    directory = parent = None
    created_directory = False
    writer = server = captured = expected = None
    responder = Responder(run)
    try:
        parent = os.open('/private/etc', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        parent_info = os.fstat(parent)
        if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
            raise RuntimeError('directory')
        try:
            directory = os.open('resolver', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:
            os.mkdir('resolver', mode=0o755, dir_fd=parent)
            created_directory = True
            directory = os.open('resolver', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        info = os.fstat(directory)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('directory')
        # Only our exact nonce path is checked. O_EXCL in the writer is decisive.
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError('occupied')
        server = Server(responder)
        expected = content(server.port)
        server.start()
        writer = subprocess.Popen([str(binary), '--writer', run, str(server.port)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        writer_marker(writer, b'READY owned-file\n')
        captured = fingerprint(directory, name, expected, 0)
        writer.stdin.write(b'G'); writer.stdin.flush()
        writer_marker(writer, b'READY persistent\n')
        # File notifications/configd -> mDNSResponder are asynchronous. Fixed
        # initial propagation wait only; no retry/negative-cache priming.
        time.sleep(3)
        for phase in ('before', 'after'):
            for mode in ('udp', 'tcp'):
                for family in (4, 6):
                    resolve(binary, run, phase + '-' + mode, family)
            responder.require_phase(phase)
            if phase == 'before':
                if writer.poll() is not None:
                    raise RuntimeError('writer')
                writer.kill()
                if writer.wait(timeout=5) != -signal.SIGKILL:
                    raise RuntimeError('writer')
                if fingerprint(directory, name, expected, 0) != captured:
                    raise RuntimeError('foreignIdentity')
                print('PASS writer-SIGKILL-file-unchanged')
        print('PASS postkill-system-A-AAAA-UDP-TCP-exact-packets')
        server.close(); server = None
        # Fresh name avoids positive cache. A negative completion says nothing
        # about traffic to default resolvers; closed sockets cannot observe it.
        for family in (4, 6):
            resolve(binary, run, 'closed' + str(family), family)
        print('PASS closed-listener-bounded-negative-NOT-no-fallback-proof')
    finally:
        try:
            if writer:
                # Before the parent has an inode receipt, EOF asks the writer
                # to clean its own unacknowledged file. Kill only this child if
                # it fails to finish; that is an honest fixture failure.
                writer.stdin.close()
                try:
                    writer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    writer.kill(); writer.wait(timeout=5)
                    raise RuntimeError('writer') from None
                finally:
                    writer.stdout.close()
        finally:
            try:
                if server:
                    server.close()
            finally:
                responder.print_categories()
                try:
                    if captured is not None:
                        remove_owned(directory, name, expected, 0, captured)
                finally:
                    try:
                        if directory is not None:
                            try:
                                remove_created_directory(parent, directory, created_directory)
                            finally:
                                os.close(directory)
                    finally:
                        if parent is not None:
                            os.close(parent)
    print('PASS exact-owned-file-and-socket-cleanup')


class PureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(prefix='pp-file-resolver-pure-')
        cls.addClassCleanup(cls.folder.cleanup)
        cls.binary = compile_tool(Path(cls.folder.name))

    def test_swift_guards_and_documented_content(self):
        result = subprocess.run([str(self.binary), '--pure-checks'], env={}, capture_output=True, text=True, timeout=10)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, 'PASS pure-guards\n', ''))
        environments = [{}, {'GITHUB_ACTIONS':'true'}, {FLAG:'1'}]
        if os.getuid() != 0 and os.geteuid() != 0:
            environments.append({'GITHUB_ACTIONS':'true', FLAG:'1'})
        for environment in environments:
            for args in (['--writer', str(uuid.uuid4()), '12345'], ['--resolve', str(uuid.uuid4()), 'before-udp', '4']):
                result = subprocess.run([str(self.binary), *args], env=environment, capture_output=True, text=True, timeout=10)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (1, 'FAIL guardDenied\n', ''))

    def test_python_guard_precedes_all_live_apis(self):
        environment = {'GITHUB_ACTIONS':'true', FLAG:'1'}
        self.assertTrue(allowed(0, 0, environment))
        for ids in [(501,501), (0,501), (501,0)]:
            self.assertFalse(allowed(*ids, environment))
        for missing in ({}, {'GITHUB_ACTIONS':'true'}, {FLAG:'1'}):
            self.assertFalse(allowed(0, 0, missing))
        with patch.dict(os.environ, {}, clear=True), patch('os.open') as opening, patch('socket.socket') as sockets, patch('subprocess.Popen') as child:
            with self.assertRaisesRegex(RuntimeError, '^guardDenied$'):
                live(None)
            opening.assert_not_called(); sockets.assert_not_called(); child.assert_not_called()

    def test_content_has_only_public_bounded_directives(self):
        self.assertEqual(content(12345), b'nameserver 127.0.0.1\nport 12345\ntimeout 2\n')
        for port in [0, 65536, -1, True, '53']:
            with self.assertRaisesRegex(RuntimeError, '^arguments$'):
                content(port)

    def test_exact_wire_categories_and_zero_ttl(self):
        run = str(uuid.uuid4()); responder = Responder(run)
        for phase in ('before', 'after'):
            for mode in ('udp', 'tcp'):
                for kind, address in [(1, '192.0.2.53'), (28, '2001:db8::53')]:
                    query = question(phase + '-' + mode + '.pp-file-' + run + '.test', kind)
                    udp = responder.response(query, 'udp')
                    self.assertEqual(bool(struct.unpack('!HHHHHH', udp[:12])[1] & 0x0200), mode == 'tcp')
                    full = responder.response(query, 'tcp')
                    self.assertTrue(full.endswith(ipaddress.ip_address(address).packed))
                    self.assertIn(struct.pack('!HHI', kind, 1, 0), full)
            responder.require_phase(phase)
        for packet in [b'', b'\0'*12, question('foreign.test', 1), question('before-udp.pp-file-'+run+'.test', 15)]:
            self.assertIsNone(responder.response(packet, 'udp'))
        output = io.StringIO()
        with redirect_stdout(output): responder.print_categories()
        self.assertEqual(output.getvalue().count('=true'), 12)
        self.assertNotIn(run, output.getvalue())
        with self.assertRaisesRegex(RuntimeError, '^missingPackets$'):
            Responder(run).require_phase('before')

    def test_cleanup_refuses_foreign_inode_content_links_or_mode(self):
        with tempfile.TemporaryDirectory(prefix='pp-file-resolver-ownership-') as folder:
            directory = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, directory)
            name, expected = 'owned.test', content(12345)
            def create():
                fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=directory)
                os.write(fd, expected); os.close(fd)
            create()
            captured = fingerprint(directory, name, expected, os.geteuid())
            os.rename(name, 'old', src_dir_fd=directory, dst_dir_fd=directory)
            create()
            with self.assertRaisesRegex(RuntimeError, '^foreignIdentity$'):
                remove_owned(directory, name, expected, os.geteuid(), captured)
            self.assertTrue(Path(folder, name).exists())
            for change, undo in [(lambda: os.chmod(Path(folder, name), 0o644), lambda: os.chmod(Path(folder, name), 0o600)),
                                 (lambda: Path(folder, name).write_bytes(b'x'), lambda: Path(folder, name).write_bytes(expected)),
                                 (lambda: os.link(Path(folder, name), Path(folder, 'link')), lambda: Path(folder, 'link').unlink())]:
                change()
                with self.assertRaisesRegex(RuntimeError, '^foreignIdentity$'):
                    fingerprint(directory, name, expected, os.geteuid())
                undo()
            captured = fingerprint(directory, name, expected, os.geteuid())
            remove_owned(directory, name, expected, os.geteuid(), captured)
            self.assertTrue(Path(folder, 'old').exists())
            Path(folder, name).symlink_to(Path(folder, 'old'))
            with self.assertRaises(OSError): fingerprint(directory, name, expected, os.geteuid())
            self.assertTrue(Path(folder, 'old').exists())

    def test_directory_cleanup_only_owned_created_empty_identity(self):
        with tempfile.TemporaryDirectory(prefix='pp-file-resolver-directory-') as folder:
            parent = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            try:
                Path(folder, 'resolver').mkdir()
                directory = os.open('resolver', os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent)
                try:
                    remove_created_directory(parent, directory, False)
                    self.assertTrue(Path(folder, 'resolver').is_dir())
                    foreign = Path(folder, 'resolver', 'foreign')
                    foreign.write_bytes(b'owned by another fixture')
                    with self.assertRaises(OSError): remove_created_directory(parent, directory, True)
                    self.assertTrue(foreign.exists())
                    foreign.unlink()
                    os.rename('resolver', 'old', src_dir_fd=parent, dst_dir_fd=parent)
                    Path(folder, 'resolver').mkdir()
                    with self.assertRaisesRegex(RuntimeError, '^foreignIdentity$'):
                        remove_created_directory(parent, directory, True)
                    self.assertTrue(Path(folder, 'resolver').is_dir())
                finally:
                    os.close(directory)
                directory = os.open('resolver', os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent)
                try:
                    remove_created_directory(parent, directory, True)
                    self.assertFalse(Path(folder, 'resolver').exists())
                    self.assertTrue(Path(folder, 'old').is_dir())
                finally:
                    os.close(directory)
            finally:
                os.close(parent)

    def test_resolver_child_budget_and_nonpositive_category_without_resolving(self):
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, 'PASS negative\n', '')) as child:
            resolve(Path('/synthetic/tool'), str(uuid.uuid4()), 'closed4', 4)
            self.assertEqual(child.call_args.kwargs['timeout'], 20)
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired([], 20)):
            with self.assertRaisesRegex(RuntimeError, '^resolveTimeout$'):
                resolve(Path('/synthetic/tool'), str(uuid.uuid4()), 'closed6', 6)
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, 'PASS answer\n', '')):
            with self.assertRaisesRegex(RuntimeError, '^negative$'):
                resolve(Path('/synthetic/tool'), str(uuid.uuid4()), 'closed4', 4)


if __name__ == '__main__':
    if sys.argv[1:] == ['--acceptance']:
        if not allowed(os.getuid(), os.geteuid(), os.environ):
            print('FAIL guardDenied'); sys.exit(1)
        try:
            with tempfile.TemporaryDirectory(prefix='pp-file-resolver-vm-') as folder:
                live(compile_tool(Path(folder)))
        except Exception as error:
            categories = {'guardDenied', 'arguments', 'foreignIdentity', 'directory', 'occupied',
                          'portOccupied', 'writer', 'responder', 'missingPackets', 'resolveTimeout', 'resolve', 'negative'}
            category = str(error)
            print('FAIL ' + (category if category in categories else 'unexpected'))
            sys.exit(1)
    else:
        unittest.main()
