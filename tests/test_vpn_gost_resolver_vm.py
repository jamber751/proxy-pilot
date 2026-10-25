"""Default: pure/file/source/refusal tests ONLY, no sockets or GOST execution.

--acceptance: fresh opted-in ordinary-user GHA VM; unchanged hash-pinned GOST,
owned loopback endpoints and nonce .invalid names only. No DNS configuration,
interfaces, root APIs or onward target connections. This proves proxy resolver /
CIDR selection, NOT system DNS selection, DNS privacy, relay authority or VPN.
"""
from pathlib import Path
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
FLAG = 'PROXYPILOT_VM_GOST_RESOLVER_TESTS'
BINARY = 'PROXYPILOT_VM_GOST_BINARY'
VERSION = '3.2.6'
# Read-only extraction of BOTH shipped universal Mach-O slices; no dynamic pin
# adoption. Workflow independently checks official archive SHA from make-dmg.sh.
NATIVE = {
    'arm64': (33800962, 'ca290005f02c39628130efd5ca4b8671ec3aced61ab1290da53b14304855c03b'),
    'x86_64': (36646112, '6dc5b3d76283aebcc2a7de3334864efc9fd0816c6b0f6dc268a323f566043034'),
}
ARCHIVE = {
    'arm64': 'e54f6c22e81c00650adfbbb23317c74a4dca9b9b73fa28cfa150f5559cc3ff2e',
    'amd64': '0892485bd94e37b67a1f1d0d2372ed12d7dc0f1bc763d56177a0c0ee734855e6',
}
CASES = ('absent-host', 'literal', 'in-cidr', 'out-cidr', 'failure', 'empty',
         'invalid-ip', 'malformed', 'http-error', 'timeout', 'token', 'basic', 'redirect', 'unix')
PROTOCOLS = ('http', 'socks')
FAILURES = {'guardDenied', 'binaryRefused', 'configuration', 'startup', 'client',
            'request', 'decision', 'plugin', 'bounds', 'cleanup', 'unexpected'}


class Refused(Exception):
    def __init__(self, category):
        self.category = category if category in FAILURES else 'unexpected'
        super().__init__(self.category)


def require(value, category):
    if not value:
        raise Refused(category)


def allowed(uid, euid, system, environment):
    return (system == 'darwin' and uid == euid and uid >= 500
            and environment.get('GITHUB_ACTIONS') == 'true' and environment.get(FLAG) == '1')


def native_pin(machine):
    require(machine in NATIVE, 'binaryRefused')
    return NATIVE[machine]


def identity(info):
    # File observation only, not an immutable executable identity claim.
    return (info.st_dev, info.st_ino, info.st_uid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink, stat.S_IMODE(info.st_mode))


class BinaryLease:
    def __init__(self, path, descriptor, attributes):
        self.path, self.descriptor, self.attributes = path, descriptor, attributes

    def validate(self):
        require(self.descriptor >= 0, 'binaryRefused')
        try:
            require(identity(os.fstat(self.descriptor)) == self.attributes
                    and identity(self.path.lstat()) == self.attributes, 'binaryRefused')
        except OSError:
            raise Refused('binaryRefused') from None

    def close(self):
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def verify_binary(folder, path, uid, expected_size, expected_sha):
    """Own filesystem reads only; production call uses fixed native_pin()."""
    descriptor = -1
    try:
        folder, path = Path(folder), Path(path)
        require(folder.is_absolute() and path.is_absolute() and folder != path,
                'binaryRefused')
        require(folder.resolve(strict=True) == folder and path.resolve(strict=True) == path,
                'binaryRefused')
        require(path.is_relative_to(folder), 'binaryRefused')
        for directory in [folder, *list(path.parents)[:list(path.parents).index(folder)]]:
            info = directory.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid
                    and not info.st_mode & 0o022, 'binaryRefused')
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
                and info.st_size == expected_size and info.st_mode & stat.S_IXUSR
                and not info.st_mode & 0o022, 'binaryRefused')
        digest = hashlib.sha256()
        remaining = expected_size
        while remaining:
            data = os.read(descriptor, min(1024 * 1024, remaining))
            require(bool(data), 'binaryRefused')
            digest.update(data)
            remaining -= len(data)
        require(os.read(descriptor, 1) == b'' and digest.hexdigest() == expected_sha, 'binaryRefused')
        lease = BinaryLease(path, descriptor, identity(info))
        lease.validate()
        descriptor = -1
        return lease
    except (OSError, ValueError):
        raise Refused('binaryRefused') from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def decode_headers(data):
    require(len(data) <= 4096 and b'\r\n\r\n' in data, 'bounds')
    header, rest = data.split(b'\r\n\r\n', 1)
    try:
        lines = header.decode('ascii').split('\r\n')
        fields = {}
        for row in lines[1:]:
            key, value = row.split(':', 1)
            key = key.lower()
            require(key not in fields, 'request')
            fields[key] = value.strip()
        return lines[0], fields, rest
    except (ValueError, UnicodeError):
        raise Refused('request') from None


def plugin_request(data, expected_host):
    require(len(data) <= 1024, 'bounds')
    try:
        request = json.loads(data)
    except (ValueError, UnicodeError):
        raise Refused('request') from None
    require(type(request) is dict and set(request) == {'network', 'host', 'client'}, 'request')
    require(request['network'] == 'ip' and request['host'] == expected_host
            and type(request['client']) is str and len(request['client']) <= 128, 'request')
    return request


def configuration(port, upstream, resolver=None):
    require(type(port) is int and 0 < port <= 65535
            and re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', upstream), 'configuration')
    result = {
        'services': [{'name': 'owned-contract', 'addr': '127.0.0.1:' + str(port),
                      'handler': {'type': 'auto', 'chain': 'c0'}, 'listener': {'type': 'tcp'}}],
        'chains': [{'name': 'c0', 'hops': [{'name': 'h0', 'bypass': 'b0',
                    'nodes': [{'name': 'n0', 'addr': upstream, 'connector': {'type': 'http'},
                               'dialer': {'type': 'tcp'}}]}]}],
        'bypasses': [{'name': 'b0', 'matchers': ['127.0.0.2/32']}],
    }
    if resolver is not None:
        result['services'][0]['resolver'] = 'owned-plugin'
        result['resolvers'] = [{'name': 'owned-plugin', 'plugin': resolver}]
    return result


def live():
    # BEFORE binary/namespace reads, imports that expose sockets, any listener,
    # process spawn or GOST execution. No environment-driven alternate pins.
    require(allowed(os.getuid(), os.geteuid(), sys.platform, os.environ), 'guardDenied')
    size, digest = native_pin(platform.machine())
    require(bool(os.environ.get('RUNNER_TEMP')) and bool(os.environ.get(BINARY)), 'binaryRefused')
    lease = verify_binary(os.environ['RUNNER_TEMP'], os.environ[BINARY], os.getuid(), size, digest)
    try:
        run_contract(lease)
    finally:
        lease.close()


def run_contract(lease):
    # Live imports and all network operations below are unreachable in local
    # default tests. No DNS config, lookup API or external target is used.
    import base64
    import secrets
    import socket
    import threading

    def receive(connection, count, end):
        remaining = end - time.monotonic()
        require(remaining > 0, 'client')
        connection.settimeout(remaining)
        return connection.recv(count)

    def receive_header(connection, end=None):
        end = time.monotonic() + 1.0 if end is None else end
        data = bytearray()
        while b'\r\n\r\n' not in data:
            chunk = receive(connection, 512, end)
            require(bool(chunk), 'request')
            data.extend(chunk)
            require(len(data) <= 4096, 'bounds')
        return decode_headers(bytes(data))

    def exact(connection, count, end=None):
        end = time.monotonic() + 1.0 if end is None else end
        require(0 < count <= 4096, 'bounds')
        data = bytearray()
        while len(data) < count:
            chunk = receive(connection, count - len(data), end)
            require(bool(chunk), 'client')
            data.extend(chunk)
        return bytes(data)

    class Server:
        def __init__(self, address, handler):
            self.handler = handler
            self.stop = threading.Event()
            self.lock = threading.Lock()
            self.connections, self.workers, self.errors = set(), [], []
            self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.listener.bind((address, 0))
                self.listener.listen(16)
                self.listener.settimeout(0.1)
                self.port = self.listener.getsockname()[1]
                self.thread = threading.Thread(target=self.accept, daemon=True)
                self.thread.start()
            except BaseException:
                self.listener.close()
                raise

        def accept(self):
            while not self.stop.is_set():
                try:
                    connection, peer = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if not self.stop.is_set():
                        self.errors.append('accept')
                    return
                with self.lock:
                    if len(self.workers) >= 32:
                        connection.close(); self.errors.append('bounds'); return
                    self.connections.add(connection)
                worker = threading.Thread(target=self.handle, args=(connection,), daemon=True)
                self.workers.append(worker); worker.start()

        def handle(self, connection):
            try:
                connection.settimeout(1.0)
                self.handler(self, connection)
            except (OSError, Refused):
                # Closing after a deliberately timed-out plugin is expected;
                # assertions are based on captured exact requests/decisions.
                pass
            except BaseException:
                self.errors.append('handler')
            finally:
                with self.lock:
                    self.connections.discard(connection)
                connection.close()

        def close(self):
            self.stop.set(); self.listener.close()
            self.thread.join(timeout=1.0)
            with self.lock:
                connections = list(self.connections)
            for connection in connections:
                try: connection.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                connection.close()
            end = time.monotonic() + 2.0
            for worker in self.workers:
                worker.join(timeout=max(0.0, end - time.monotonic()))
            require(not self.thread.is_alive() and all(not worker.is_alive() for worker in self.workers), 'cleanup')
            require(not self.errors, 'cleanup')

    def response(connection, body, code=200, extra=None):
        headers = {'Content-Length': str(len(body)), 'Connection': 'close'}
        headers.update(extra or {})
        connection.sendall(('HTTP/1.1 ' + str(code) + ' Owned\r\n' +
                            ''.join(key + ': ' + value + '\r\n' for key, value in headers.items()) +
                            '\r\n').encode('ascii') + body)

    def case(name, protocol):
        events = {'proxy': [], 'in': 0, 'out': 0, 'plugin': [], 'redirect': []}
        lock = threading.Lock()
        marker = b'OWNED-' + secrets.token_hex(12).encode('ascii') + b'\n'
        host = secrets.token_hex(12) + '.invalid'
        servers, process, log = [], None, None
        started = False
        try:
            def target(kind):
                def handle(server, connection):
                    with lock: events[kind] += 1
                    connection.sendall(marker)
                return handle
            inside = Server('127.0.0.2', target('in')); servers.append(inside)
            outside = Server('127.0.0.3', target('out')); servers.append(outside)

            def upstream(server, connection):
                first, headers, rest = receive_header(connection)
                words = first.split(' ')
                require(len(words) == 3 and words[0] == 'CONNECT' and words[2] == 'HTTP/1.1', 'request')
                # Never resolve or connect to words[1], even on failure.
                with lock: events['proxy'].append(words[1])
                connection.sendall(b'HTTP/1.1 200 Owned\r\n\r\n' + marker)
            proxy = Server('127.0.0.1', upstream); servers.append(proxy)

            def plugin_handler(role):
                def handle(server, connection):
                    first, headers, rest = receive_header(connection)
                    require(first == ('POST /redirect HTTP/1.1' if role == 'redirect' else 'POST /resolve HTTP/1.1'), 'request')
                    require('transfer-encoding' not in headers and re.fullmatch(r'[0-9]{1,4}', headers.get('content-length', '')), 'request')
                    length = int(headers['content-length']); require(0 < length <= 1024 and len(rest) <= length, 'bounds')
                    body = rest + (exact(connection, length - len(rest)) if length > len(rest) else b'')
                    request = plugin_request(body, host)
                    with lock: events[role].append((request, headers, body))
                    if role == 'redirect':
                        response(connection, b'', 307, {'Location': 'http://127.0.0.1:' + str(plugin.port) + '/resolve'})
                        return
                    if name == 'timeout':
                        server.stop.wait(1.0)
                    if name == 'malformed': body = b'{'
                    elif name == 'failure': body = b'{"ok":false,"ips":[]}'
                    elif name == 'empty': body = b'{"ok":true,"ips":[]}'
                    elif name == 'invalid-ip': body = b'{"ok":true,"ips":["not-an-ip"]}'
                    else: body = json.dumps({'ok': True, 'ips': ['127.0.0.3' if name == 'out-cidr' else '127.0.0.2']}).encode()
                    response(connection, body, 503 if name == 'http-error' else 200)
                return handle
            plugin = Server('127.0.0.1', plugin_handler('plugin')); servers.append(plugin)
            redirect = Server('127.0.0.1', plugin_handler('redirect')); servers.append(redirect)

            # A released reservation may race; any GOST startup/bind failure
            # fails this case. Never terminate an occupant or retry the case.
            reservation = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
            finally:
                reservation.close()
            resolver = None
            if name not in ('absent-host', 'literal'):
                url = 'http://' + ('canary:synthetic@' if name == 'basic' else '') + '127.0.0.1:' + str(plugin.port) + '/resolve'
                if name == 'redirect': url = 'http://127.0.0.1:' + str(redirect.port) + '/redirect'
                if name == 'unix': url = 'unix:/owned-nonexistent-canary-socket'
                resolver = {'type': 'http', 'addr': url, 'timeout': '300ms'}
                if name == 'token': resolver['token'] = 'synthetic-ignored-canary'
            target_host = '127.0.0.2' if name == 'literal' else host
            target_port = outside.port if name == 'out-cidr' else inside.port
            target_address = target_host + ':' + str(target_port)
            with tempfile.TemporaryDirectory(prefix='gost-owned-contract-', dir=os.environ['RUNNER_TEMP']) as folder:
                folder = Path(folder); folder.chmod(0o700)
                config = folder / 'config.json'
                config.write_text(json.dumps(configuration(port, '127.0.0.1:' + str(proxy.port), resolver)))
                config.chmod(0o600)
                log = (folder / 'closed.log').open('x+b'); os.chmod(log.name, 0o600)
                lease.validate()
                process = subprocess.Popen([str(lease.path), '-C', str(config)], stdin=subprocess.DEVNULL,
                                           stdout=log, stderr=subprocess.STDOUT,
                                           env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
                lease.validate()
                end = time.monotonic() + 3.0
                while True:
                    require(process.poll() is None, 'startup')
                    try:
                        ready = socket.create_connection(('127.0.0.1', port), timeout=0.1)
                        ready.close(); started = True; break
                    except OSError:
                        require(time.monotonic() < end, 'startup')
                        time.sleep(0.02)
                require(started and process.poll() is None, 'startup')
                successful = name in ('absent-host', 'literal', 'in-cidr', 'out-cidr', 'token', 'basic', 'redirect')
                with socket.create_connection(('127.0.0.1', port), timeout=2.0) as client:
                    client.settimeout(2.0)
                    client_end = time.monotonic() + 2.0
                    if protocol == 'http':
                        client.sendall(('CONNECT ' + target_address + ' HTTP/1.1\r\nHost: ' + target_address + '\r\n\r\n').encode())
                        first, headers, rest = receive_header(client, client_end)
                        ok = re.fullmatch(r'HTTP/1\.[01] 200(?: .*)?', first) is not None
                    else:
                        client.sendall(b'\x05\x01\x00'); require(exact(client, 2, client_end) == b'\x05\x00', 'client')
                        encoded = target_host.encode('ascii')
                        address = b'\x01' + bytes((127, 0, 0, 2)) if name == 'literal' else b'\x03' + bytes([len(encoded)]) + encoded
                        client.sendall(b'\x05\x01\x00' + address + target_port.to_bytes(2, 'big'))
                        reply = exact(client, 4, client_end); require(reply[0] == 5 and reply[2] == 0, 'client')
                        sizes = {1: 4, 4: 16}
                        size = exact(client, 1, client_end)[0] if reply[3] == 3 else sizes.get(reply[3], 0)
                        require(size > 0, 'client'); exact(client, size + 2, client_end)
                        ok, rest = reply[1] == 0, b''
                    require(ok == successful, 'decision')
                    if successful:
                        payload = rest
                        while not payload.endswith(b'\n'):
                            chunk = receive(client, 128, client_end)
                            require(bool(chunk), 'client')
                            payload += chunk
                            require(len(payload) <= 128, 'bounds')
                        require(payload == marker, 'decision')
                expected_proxy = [target_address] if name == 'absent-host' else ['127.0.0.3:' + str(target_port)] if name == 'out-cidr' else []
                require(events['proxy'] == expected_proxy and events['out'] == 0, 'decision')
                require(events['in'] == (1 if name in ('literal', 'in-cidr', 'token', 'basic', 'redirect') else 0), 'decision')
                expected_plugin = 0 if name in ('literal', 'absent-host', 'unix') else 1
                require(len(events['plugin']) == expected_plugin, 'plugin')
                if name == 'token':
                    headers = events['plugin'][0][1]
                    require('authorization' not in headers and 'token' not in headers, 'plugin')
                if name == 'basic':
                    require(events['plugin'][0][1].get('authorization') == 'Basic ' + base64.b64encode(b'canary:synthetic').decode(), 'plugin')
                if name == 'redirect':
                    require(len(events['redirect']) == 1 and events['redirect'][0][2] == events['plugin'][0][2], 'plugin')
                else: require(not events['redirect'], 'plugin')
                require(process.poll() is None, 'decision')
                process.terminate()
                try: process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=2.0)
                log.flush(); require(os.fstat(log.fileno()).st_size <= 65536, 'bounds')
                if name == 'unix':
                    log.seek(0); require(b'unsupported protocol scheme "unix"' in log.read(65537).replace(b'\\"', b'"'), 'plugin')
                log.close(); log = None
                lease.validate()
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try: process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=2.0)
            if log is not None: log.close()
            for server in reversed(servers): server.close()

    for protocol in PROTOCOLS:
        for name in CASES:
            case(name, protocol)
            print('PASS gost-resolver-' + protocol + '-' + name, flush=True)
    print('PASS gost-resolver-all-28-owned-cases', flush=True)


class PureTests(unittest.TestCase):
    def test_gate_requires_all_components_and_ordinary_same_uid(self):
        full = {'GITHUB_ACTIONS': 'true', FLAG: '1'}
        self.assertTrue(allowed(501, 501, 'darwin', full))
        for uid, euid in ((0, 0), (0, 501), (501, 0), (499, 499)):
            self.assertFalse(allowed(uid, euid, 'darwin', full))
        for environment in ({}, {'GITHUB_ACTIONS': 'true'}, {FLAG: '1'}, {'GITHUB_ACTIONS': '1', FLAG: '1'}):
            self.assertFalse(allowed(501, 501, 'darwin', environment))
        self.assertFalse(allowed(501, 501, 'linux', full))

    def test_denied_gate_never_reads_binary_or_calls_live_network_or_popen(self):
        with patch.dict(os.environ, {}, clear=True), patch(__name__ + '.verify_binary') as binary, patch(__name__ + '.run_contract') as network, patch('subprocess.Popen') as child:
            with self.assertRaisesRegex(Refused, '^guardDenied$'): live()
        binary.assert_not_called(); network.assert_not_called(); child.assert_not_called()

    def test_native_pins_are_fixed_and_unknown_arch_refuses(self):
        self.assertEqual(set(NATIVE), {'arm64', 'x86_64'})
        self.assertTrue(all(size > 30_000_000 and re.fullmatch('[0-9a-f]{64}', digest) for size, digest in NATIVE.values()))
        with self.assertRaises(Refused): native_pin('unknown')

    def test_workflow_archives_match_shipped_pins_before_actual_step(self):
        shipped = (ROOT / 'make-dmg.sh').read_text()
        workflow = (ROOT / '.github/workflows/vpn-gost-resolver.yml').read_text()
        self.assertIn('GOST_VERSION="' + VERSION + '"', shipped)
        for architecture, digest in ARCHIVE.items():
            self.assertIn('GOST_SHA256_' + architecture + '="' + digest + '"', shipped)
            self.assertIn('expected=' + digest, workflow)
        self.assertIn('/v' + VERSION + '/gost_' + VERSION + '_darwin_${arch}.tar.gz', workflow)
        self.assertLess(workflow.index('test "$actual" = "$expected"'), workflow.index('--acceptance'))
        self.assertIn('tar -xzf "$work/release.tar.gz" -C "$work" gost', workflow)
        self.assertIn(BINARY + ': ${{ runner.temp }}/gost-resolver-contract/gost', workflow)

    def test_config_keeps_numeric_upstream_and_exact_single_cidr(self):
        config = configuration(1234, '127.0.0.1:2345')
        self.assertNotIn('resolver', config['services'][0])
        self.assertNotIn('resolvers', config)
        self.assertEqual(config['bypasses'][0]['matchers'], ['127.0.0.2/32'])
        plugin = {'type': 'http', 'addr': 'http://127.0.0.1:3456/resolve', 'timeout': '300ms'}
        self.assertEqual(configuration(1234, '127.0.0.1:2345', plugin)['resolvers'][0]['plugin'], plugin)
        for bad in ('example.invalid:2345', '203.0.113.1:2345', '127.0.0.2:2345'):
            with self.assertRaises(Refused): configuration(1234, bad)

    def test_plugin_schema_bounded_and_no_opaque_or_authority_fields(self):
        payload = b'{"network":"ip","host":"nonce.invalid","client":""}'
        self.assertEqual(plugin_request(payload, 'nonce.invalid')['network'], 'ip')
        for data in (payload, payload.replace(b'"ip"', b'"tcp"'), payload+b'X', b'[]', b'X'*1025):
            if data == payload:
                with self.assertRaises(Refused): plugin_request(data, 'different.invalid')
            else:
                with self.assertRaises(Refused): plugin_request(data, 'nonce.invalid')
        changed = json.loads(payload); changed['token'] = 'opaque'
        with self.assertRaises(Refused): plugin_request(json.dumps(changed).encode(), 'nonce.invalid')

    def test_header_bounds_duplicate_fields_and_redacted_errors(self):
        self.assertEqual(decode_headers(b'POST /resolve HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}')[1], {'content-length': '2'})
        for data in (b'X'*4097, b'bad', b'X\r\nA: 1\r\nA: 2\r\n\r\n', b'X\r\nmalformed\r\n\r\n'):
            with self.assertRaises(Refused): decode_headers(data)
        self.assertEqual(str(Refused('/private/path secret')), 'unexpected')

    def test_owned_file_hash_and_identity_cannot_adopt_replacement(self):
        with tempfile.TemporaryDirectory(prefix='gost-file-pure-') as folder:
            root = Path(folder).resolve(); root.chmod(0o700)
            path = root/'fixture'; payload = b'SYNTHETIC NOT EXECUTABLE'; path.write_bytes(payload); path.chmod(0o700)
            digest = hashlib.sha256(payload).hexdigest()
            lease = verify_binary(root, path, os.geteuid(), len(payload), digest)
            try:
                lease.validate()
                replacement = root/'replacement'; replacement.write_bytes(payload); replacement.chmod(0o700)
                replacement.replace(path)
                with self.assertRaises(Refused): lease.validate()
            finally: lease.close()
            for expected_size, expected_digest in ((len(payload)+1, digest), (len(payload), '0'*64)):
                with self.assertRaises(Refused): verify_binary(root, path, os.geteuid(), expected_size, expected_digest)
            hardlink = root/'linked'; os.link(path, hardlink)
            with self.assertRaises(Refused): verify_binary(root, path, os.geteuid(), len(payload), digest)
            hardlink.unlink()
            alias = root/'alias'; alias.symlink_to(path)
            with self.assertRaises(Refused): verify_binary(root, alias, os.geteuid(), len(payload), digest)
            path.chmod(0o777)
            with self.assertRaises(Refused): verify_binary(root, path, os.geteuid(), len(payload), digest)

    def test_source_has_no_onward_resolution_or_privileged_mutator(self):
        source = Path(__file__).read_text()
        live_part = source.split('def run_contract(lease):', 1)[1].split('class PureTests', 1)[0]
        for forbidden in ('getaddrinfo', 'gethostby', 'socket.AF_UNIX', 'os.killpg', 'scutil', 'networksetup', '/etc/resolver', 'sudo'):
            self.assertNotIn(forbidden, live_part)
        self.assertNotIn('vendor/', live_part)
        self.assertIn("Server('127.0.0.2'", live_part)
        self.assertIn("Server('127.0.0.3'", live_part)


if __name__ == '__main__':
    if sys.argv[1:] == ['--acceptance']:
        try:
            live()
        except BaseException as error:
            print('FAIL ' + (error.category if isinstance(error, Refused) else 'unexpected'), flush=True)
            raise SystemExit(1)
    else:
        unittest.main()
