"""Default tests never open sockets or run GOST/Node. Opted-in GHA VM only:
stock pinned GOST -> private Unix gRPC fake -> owned loopback echoes/proxy.
No OS DNS selection, corporate resolution, VPN or production adapter is proved.
"""
from pathlib import Path
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import test_vpn_gost_resolver_vm as base

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/vpn_gost_grpc_resolver_fixture.cjs'
CASES = ('in-cidr', 'out-cidr', 'failure', 'empty', 'invalid-ip', 'wrong-token', 'false-with-ip')


def live():
    base.require(base.allowed(os.getuid(), os.geteuid(), sys.platform, os.environ), 'guardDenied')
    size, digest = base.native_pin(platform.machine())
    base.require(bool(os.environ.get('RUNNER_TEMP')) and bool(os.environ.get(base.BINARY)), 'binaryRefused')
    lease = base.verify_binary(os.environ['RUNNER_TEMP'], os.environ[base.BINARY], os.getuid(), size, digest)
    try: run_contract(lease)
    finally: lease.close()


def resolver(path, wrong=False):
    base.require(path.is_absolute() and path.name == 'resolver.sock' and len(os.fsencode(path)) < 100, 'configuration')
    return {'type': 'grpc', 'addr': 'unix://' + str(path),
            'token': 'wrong-synthetic-token' if wrong else 'owned-synthetic-token'}


def run_contract(lease):
    base.require(base.allowed(os.getuid(), os.geteuid(), sys.platform, os.environ), 'guardDenied')
    import secrets
    import select
    import socket
    import socketserver
    import threading
    node = shutil.which('node'); base.require(node is not None, 'configuration')

    def exact(conn, size):
        result = b''
        while len(result) < size:
            chunk = conn.recv(size - len(result)); base.require(bool(chunk), 'client'); result += chunk
        return result

    def stop(process):
        if process is not None and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=2)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=2)

    def case(mode, protocol):
        host = secrets.token_hex(12) + '.invalid'
        probe = ('PROBE-' + secrets.token_hex(12)).encode()
        marker = ('OWNED-' + secrets.token_hex(12) + '\n').encode()
        observed = {'in': 0, 'out': 0, 'proxy': [], 'errors': []}
        lock = threading.Lock(); servers = []; children = []

        def server(address, kind):
            class Handler(socketserver.BaseRequestHandler):
                def handle(self):
                    try:
                        self.request.settimeout(1)
                        if kind == 'proxy':
                            data = b''
                            while b'\r\n\r\n' not in data:
                                chunk = self.request.recv(512); base.require(bool(chunk), 'request')
                                data += chunk; base.require(len(data) <= 4096, 'bounds')
                            first, _, rest = base.decode_headers(data)
                            words = first.split(' ')
                            base.require(len(words) == 3 and words[0] == 'CONNECT' and words[2] == 'HTTP/1.1' and not rest, 'request')
                            with lock: observed['proxy'].append(words[1])
                            # Never resolve/connect to CONNECT's target.
                            self.request.sendall(b'HTTP/1.1 200 Owned\r\n\r\n')
                        else:
                            with lock: observed[kind] += 1
                        base.require(exact(self.request, len(probe)) == probe, 'request')
                        self.request.sendall(marker)
                    except (OSError, base.Refused):
                        with lock: observed['errors'].append(kind)
            class TCP(socketserver.ThreadingTCPServer):
                address_family = socket.AF_INET6 if address == '::1' else socket.AF_INET
                daemon_threads = False
                allow_reuse_address = False
            base.require(address in ('127.0.0.1', '::1'), 'configuration')
            instance = TCP((address, 0), Handler)
            thread = threading.Thread(target=lambda: instance.serve_forever(poll_interval=0.05), daemon=True)
            thread.start(); servers.append((instance, thread)); return instance.server_address[1]

        try:
            inside = server('127.0.0.1', 'in'); outside = server('::1', 'out'); upstream = server('127.0.0.1', 'proxy')
            target_port = outside if mode == 'out-cidr' else inside
            with tempfile.TemporaryDirectory(prefix='pp-rpc-', dir=os.environ['RUNNER_TEMP']) as folder:
                folder = Path(folder); folder.chmod(0o700)
                config = folder / 'fixture.json'; config.write_text(json.dumps({'mode': mode, 'host': host})); config.chmod(0o600)
                node_log = (folder / 'node.log').open('x+b'); os.chmod(node_log.name, 0o600)
                gost_log = (folder / 'gost.log').open('x+b'); os.chmod(gost_log.name, 0o600)
                try:
                    environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'GITHUB_ACTIONS': 'true',
                        base.FLAG: '1', 'RUNNER_TEMP': os.environ['RUNNER_TEMP']}
                    rpc = subprocess.Popen([node, str(FIXTURE), str(config)], stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=node_log, env=environment); children.append(rpc)
                    ready = select.select([rpc.stdout], [], [], 3)[0]
                    base.require(bool(ready) and os.read(rpc.stdout.fileno(), 64) == b'READY\n' and rpc.poll() is None, 'startup')
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
                        reservation.bind(('127.0.0.1', 0)); port = reservation.getsockname()[1]
                    # A released port may race: fail, never evict an occupant/retry.
                    gost_config = folder / 'gost.json'
                    gost_config.write_text(json.dumps(base.configuration(port, '127.0.0.1:' + str(upstream),
                        resolver(folder / 'resolver.sock', mode == 'wrong-token')))); gost_config.chmod(0o600)
                    lease.validate()
                    gost = subprocess.Popen([str(lease.path), '-C', str(gost_config)], stdin=subprocess.DEVNULL,
                        stdout=gost_log, stderr=subprocess.STDOUT, env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
                    children.append(gost); lease.validate()
                    end = time.monotonic() + 3
                    while True:
                        base.require(gost.poll() is None and rpc.poll() is None, 'startup')
                        try:
                            connection = socket.create_connection(('127.0.0.1', port), timeout=0.1); connection.close(); break
                        except OSError:
                            base.require(time.monotonic() < end, 'startup'); time.sleep(0.02)
                    success = mode in ('in-cidr', 'out-cidr', 'false-with-ip')
                    with socket.create_connection(('127.0.0.1', port), timeout=2) as client:
                        client.settimeout(2)
                        if protocol == 'http':
                            target = host + ':' + str(target_port)
                            client.sendall(('CONNECT ' + target + ' HTTP/1.1\r\nHost: ' + target + '\r\n\r\n').encode())
                            data = b''
                            while b'\r\n\r\n' not in data:
                                chunk = client.recv(512); base.require(bool(chunk), 'client'); data += chunk; base.require(len(data) <= 4096, 'bounds')
                            first, _, payload = base.decode_headers(data); ok = first.startswith('HTTP/1.1 200 ') or first.startswith('HTTP/1.0 200 ')
                        else:
                            client.sendall(b'\x05\x01\x00'); base.require(exact(client, 2) == b'\x05\x00', 'client')
                            raw = host.encode(); client.sendall(b'\x05\x01\x00\x03' + bytes([len(raw)]) + raw + target_port.to_bytes(2, 'big'))
                            response = exact(client, 4); base.require(response[0] == 5 and response[2] == 0, 'client')
                            size = exact(client, 1)[0] if response[3] == 3 else {1: 4, 4: 16}.get(response[3], 0)
                            base.require(size > 0, 'client'); exact(client, size + 2); ok, payload = response[1] == 0, b''
                        base.require(ok == success, 'decision')
                        if success:
                            client.sendall(probe)
                            while not payload.endswith(b'\n'):
                                chunk = client.recv(128); base.require(bool(chunk), 'client'); payload += chunk; base.require(len(payload) <= 128, 'bounds')
                            base.require(payload == marker, 'decision')
                    base.require(observed['proxy'] == (['[::1]:' + str(outside)] if mode == 'out-cidr' else []), 'decision')
                    base.require(observed['in'] == (1 if mode in ('in-cidr', 'false-with-ip') else 0) and observed['out'] == 0 and not observed['errors'], 'decision')
                    rows = (folder / 'events.jsonl').read_text().splitlines()
                    base.require(len(rows) == 1 and json.loads(rows[0]) == {'valid': True, 'token': mode != 'wrong-token'}, 'plugin')
                    base.require(gost.poll() is None and rpc.poll() is None, 'decision')
                finally:
                    for child in reversed(children): stop(child)
                    log_sizes = []
                    for stream in (node_log, gost_log):
                        stream.flush(); log_sizes.append(os.fstat(stream.fileno()).st_size); stream.close()
                    if children and children[0].stdout: children[0].stdout.close()
                    base.require(all(size <= 65536 for size in log_sizes), 'bounds')
                lease.validate()
        finally:
            for child in reversed(children): stop(child)
            for instance, thread in reversed(servers):
                instance.shutdown(); instance.server_close(); thread.join(timeout=1)
                base.require(not thread.is_alive(), 'cleanup')

    for protocol in ('http', 'socks'):
        for mode in CASES:
            case(mode, protocol)
            print('PASS gost-grpc-unix-' + protocol + '-' + mode, flush=True)
    print('PASS gost-grpc-unix-all-14-owned-cases', flush=True)


class PureTests(unittest.TestCase):
    def test_host_refused_before_binary_or_process_or_live_imports(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(base, 'verify_binary') as binary, \
             patch(__name__ + '.run_contract') as network, patch('subprocess.Popen') as spawn:
            with self.assertRaisesRegex(base.Refused, '^guardDenied$'): live()
        binary.assert_not_called(); network.assert_not_called(); spawn.assert_not_called()

    def test_uds_config_is_absolute_bounded_and_uses_explicit_grpc(self):
        config = resolver(Path('/private/tmp/owned/resolver.sock'))
        self.assertEqual(config['addr'], 'unix:///private/tmp/owned/resolver.sock')
        self.assertEqual(config['type'], 'grpc')
        for path in (Path('relative/resolver.sock'), Path('/private/tmp/other'), Path('/' + 'a' * 100 + '/resolver.sock')):
            with self.assertRaises(base.Refused): resolver(path)

    def test_existing_shipped_pins_and_closed_mode_set_are_retained(self):
        self.assertEqual(base.VERSION, '3.2.6'); self.assertEqual(len(CASES), 7)
        self.assertIn('false-with-ip', CASES)
        self.assertNotIn('getaddrinfo', FIXTURE.read_text())


if __name__ == '__main__':
    if sys.argv[1:] == ['--acceptance']:
        try: live()
        except base.Refused as error: print('FAIL gost-grpc-unix category=' + error.category, flush=True); raise SystemExit(1)
        except Exception: print('FAIL gost-grpc-unix category=unexpected', flush=True); raise SystemExit(1)
    else: unittest.main()
