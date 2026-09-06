"""Real GOST integration tests; all traffic stays on loopback."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
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

    def check_mode(self, mode):
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
            # Generate the config using the exact production function. Clear
            # bypass so even this loopback destination must use the upstream.
            script = f'''emulate -L zsh
CFG_DIR='{directory}'
BRIDGE_PORT={bridge_port}
SOCKS_UPSTREAM=127.0.0.1:{upstream_port}
HTTP_UPSTREAM=127.0.0.1:{upstream_port}
NO_PROXY_LIST=''
gost_nameservers() {{ print 1.1.1.1; }}
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
                response = subprocess.run(['curl', '-sS', '--max-time', '3', '--noproxy', '',
                                           '--proxy', f'socks5h://127.0.0.1:{bridge_port}', url],
                                          capture_output=True, text=True)
                self.assertNotEqual(response.returncode, 0, 'Upstream was bypassed unexpectedly')
            self.stop(bridge)

    def test_direct(self):
        self.check_mode('direct')

    def test_socks_upstream(self):
        self.check_mode('socks')

    def test_http_upstream(self):
        self.check_mode('http')
