"""Real GOST integration tests; all traffic stays on loopback."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ipaddress
import shutil
import os
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from test_power import function

GOST = os.environ.get('PROXYPILOT_TEST_GOST') or shutil.which('gost')
VPN_TARGET = os.environ.get('PROXYPILOT_TEST_VPN_TARGET')


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'proxypilot-protocol-ok')

    def log_message(self, *_):
        pass


@unittest.skipUnless(GOST and shutil.which('curl'), 'GOST and curl required')
class LocalProtocolTests(unittest.TestCase):
    def port(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]

    def start(self, args, port):
        process = subprocess.Popen([GOST, *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop, process)
        for _ in range(100):
            self.assertIsNone(process.poll(), 'GOST exited before listening')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                    return process
            except OSError:
                time.sleep(0.03)
        self.fail('GOST did not start')

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    def check_mode(self, mode, bypass=False, overlay=False):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        upstream = None
        upstream_port = self.port()
        if mode != 'direct':
            scheme = 'socks5' if mode == 'socks' else 'http'
            upstream = self.start(['-L', f'{scheme}://127.0.0.1:{upstream_port}'], upstream_port)
        bridge_port = self.port()
        with tempfile.TemporaryDirectory(prefix='proxypilot-protocol-') as directory:
            # Generate using production code. A bypassed target must remain
            # reachable even if the otherwise configured upstream is stopped.
            script = f'''emulate -L zsh
CFG_DIR='{directory}'
BRIDGE_PORT={bridge_port}
SOCKS_UPSTREAM=127.0.0.1:{upstream_port}
HTTP_UPSTREAM=127.0.0.1:{upstream_port}
NO_PROXY_LIST={'127.0.0.1' if bypass and not overlay else "''"}
PP_VPN_BYPASS={'127.0.0.1' if overlay else "''"}
gost_nameservers() {{ print 1.1.1.1; }}
{function('effective_bridge_bypass')}
{function('write_gost_config')}
write_gost_config {mode}
'''
            result = subprocess.run(['/bin/zsh', '-f', '-c', script], capture_output=True, text=True, check=True)
            config = Path(result.stdout.strip())
            self.assertIn(f'addr: 127.0.0.1:{bridge_port}', config.read_text())
            self.assertIn('type: auto', config.read_text())
            bridge = self.start(['-C', str(config)], bridge_port)
            url = f'http://127.0.0.1:{server.server_port}/'
            for scheme in ('http', 'socks5h'):
                with self.subTest(upstream=mode, client=scheme):
                    response = subprocess.run(['curl', '-sS', '--max-time', '3', '--noproxy', '',
                                               '--proxy', f'{scheme}://127.0.0.1:{bridge_port}', url],
                                              capture_output=True, text=True)
                    self.assertEqual(response.returncode, 0, response.stderr)
                    self.assertEqual(response.stdout, 'proxypilot-protocol-ok')
            if upstream:
                self.stop(upstream)
                for scheme in ('http', 'socks5h'):
                    with self.subTest(upstream=mode, client=scheme, bypass=bypass,
                                      upstream_stopped=True):
                        response = subprocess.run([
                            'curl', '-fsS', '--max-time', '3', '--noproxy', '',
                            '--proxy', f'{scheme}://127.0.0.1:{bridge_port}', url],
                            capture_output=True, text=True)
                        if bypass:
                            self.assertEqual(response.returncode, 0, response.stderr)
                            self.assertEqual(response.stdout, 'proxypilot-protocol-ok')
                        else:
                            self.assertNotEqual(response.returncode, 0,
                                                'Upstream was bypassed unexpectedly')
            self.stop(bridge)

    def test_direct(self):
        self.check_mode('direct')

    def test_socks_upstream(self):
        self.check_mode('socks')

    def test_http_upstream(self):
        self.check_mode('http')

    def test_socks_upstream_bypass_survives_upstream_stop(self):
        self.check_mode('socks', bypass=True)

    def test_http_upstream_bypass_survives_upstream_stop(self):
        self.check_mode('http', bypass=True)

    def test_vpn_overlay_bypasses_http_without_changing_user_list(self):
        self.check_mode('http', bypass=True, overlay=True)

    def test_vpn_overlay_bypasses_socks_without_changing_user_list(self):
        self.check_mode('socks', bypass=True, overlay=True)

    @unittest.skipUnless(VPN_TARGET, 'Explicit VPN acceptance target required')
    def test_opt_in_vpn_resource_with_unavailable_upstreams(self):
        # Explicit opt-in only: never discovers private resources or reads a
        # profile. HEAD does not follow redirects or submit credentials.
        target = str(ipaddress.IPv4Address(VPN_TARGET))
        route = subprocess.run(['route', '-n', 'get', target],
                               capture_output=True, text=True, timeout=5)
        self.assertEqual(route.returncode, 0, 'VPN route lookup failed')
        self.assertRegex(route.stdout, r'interface:\s+utun[0-9]+')

        def status(proxy=None):
            args = ['curl', '-sS', '--head', '--connect-timeout', '2',
                    '--max-time', '5', '-o', os.devnull, '-w', '%{http_code}']
            args += ['--noproxy', '', '--proxy', proxy] if proxy else ['--noproxy', '*']
            response = subprocess.run([*args, f'http://{target}/'],
                                      capture_output=True, text=True, timeout=8)
            self.assertEqual(response.returncode, 0, 'VPN HTTP probe failed')
            return response.stdout

        expected = status()
        self.assertTrue(expected.isdigit() and 200 <= int(expected) < 400,
                        'Acceptance target must answer successful HTTP or redirect')
        # Hold a bound, non-listening upstream port so no unrelated service
        # can occupy it. Any successful request must bypass that upstream.
        with socket.socket() as unavailable, tempfile.TemporaryDirectory(
                prefix='proxypilot-vpn-protocol-') as directory:
            unavailable.bind(('127.0.0.1', 0))
            upstream_port = unavailable.getsockname()[1]
            for mode in ('direct', 'socks', 'http'):
                bridge_port = self.port()
                script = f'''emulate -L zsh
CFG_DIR='{directory}'
BRIDGE_PORT={bridge_port}
SOCKS_UPSTREAM=127.0.0.1:{upstream_port}
HTTP_UPSTREAM=127.0.0.1:{upstream_port}
NO_PROXY_LIST={target}
gost_nameservers() {{ print 1.1.1.1; }}
{function('effective_bridge_bypass')}
{function('write_gost_config')}
write_gost_config {mode}
'''
                config = subprocess.run(['/bin/zsh', '-f', '-c', script],
                                        capture_output=True, text=True, check=True,
                                        timeout=5).stdout.strip()
                bridge = self.start(['-C', config], bridge_port)
                try:
                    for scheme in ('http', 'socks5h'):
                        with self.subTest(mode=mode, client=scheme):
                            self.assertEqual(status(f'{scheme}://127.0.0.1:{bridge_port}'),
                                             expected)
                finally:
                    self.stop(bridge)
        after = subprocess.run(['route', '-n', 'get', target],
                               capture_output=True, text=True, timeout=5)
        self.assertEqual(after.returncode, 0)
        self.assertRegex(after.stdout, r'interface:\s+utun[0-9]+')
