"""Compile real model logic and validate split-address forms, without networking."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class ProxyFormTests(unittest.TestCase):
    def test_form_validation_and_edit_prefill(self):
        source = (Path(__file__).resolve().parents[1] / 'app/main.swift').read_text()
        model = source.split('\nstruct PowerStyle:', 1)[0]
        checks = '''
let model = ProxyModel(preview: true)
precondition(model.formEndpoint == nil)
model.proxyHost = " 192.168.1.2 "
model.proxyPort = "1080"
precondition(model.formEndpoint == "socks5://192.168.1.2:1080")
model.proxyScheme = "http"
precondition(model.formEndpoint == "http://192.168.1.2:1080")
for port in ["", "0", "65536", "-1", "1x", "１２"] {
    model.proxyPort = port
    precondition(model.formEndpoint == nil)
}
model.proxyPort = "3128"
for host in ["localhost", "127.0.0.1", "0.0.0.0", "http://proxy", "user@proxy", "proxy/path"] {
    model.proxyHost = host
    precondition(model.formEndpoint == nil)
}
model.state = ProxyState(configured: true, enabled: false, running: "direct", system_proxy: false,
                         has_socks: true, has_http: true, socks_endpoint: "socks.example:1080", http_endpoint: "http.example:3128")
model.openProxy("http")
precondition(model.proxyHost == "http.example" && model.proxyPort == "3128")
precondition(model.proxyScheme == "http" && model.replacesProxy)
model.openProxy()
precondition(model.proxyHost.isEmpty && model.proxyPort.isEmpty)
precondition(model.state?.http_endpoint == "http.example:3128")
print("form checks passed")
'''
        with tempfile.TemporaryDirectory(prefix='proxypilot-form-') as directory:
            swift = Path(directory) / 'main.swift'
            swift.write_text(model + checks)
            binary = Path(directory) / 'form-test'
            built = subprocess.run(['swiftc', str(swift), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('form checks passed', result.stdout)
