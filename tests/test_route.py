"""Compile the actual Swift state model, without launching the app or networking."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which('swiftc'), 'Swift compiler required')
class RouteTests(unittest.TestCase):
    def test_actual_route_and_incomplete_states(self):
        source = (Path(__file__).resolve().parents[1] / 'app/main.swift').read_text()
        model = source.split('struct ProxyState: Decodable {', 1)[1].split('\nstruct CommandResult', 1)[0]
        checks = '''
func check(_ running: String, _ enabled: Bool, _ system: Bool, _ owns: Bool, _ expected: String) {
    let state = ProxyState(configured: true, enabled: enabled, running: running,
                           system_proxy: system, owns_system_proxy: owns)
    precondition(state.route == expected, "Unexpected route for \\(running)")
}
check("socks", true, true, true, "SOCKS5")
check("http", true, true, true, "HTTP")
check("direct", true, true, true, "Напрямую")
check("direct", false, false, false, "Напрямую")
check("none", false, false, false, "Напрямую")
check("socks", true, false, true, "Не определён")
check("none", true, true, true, "Не определён")
check("future", true, true, true, "Не определён")
check("http", false, false, true, "Не определён")
print("9 route cases passed")
'''
        with tempfile.TemporaryDirectory(prefix='proxypilot-route-') as directory:
            swift = Path(directory) / 'main.swift'
            swift.write_text('import Foundation\nstruct ProxyState: Decodable {' + model + checks)
            binary = Path(directory) / 'route-test'
            built = subprocess.run(['swiftc', str(swift), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('9 route cases passed', result.stdout)
