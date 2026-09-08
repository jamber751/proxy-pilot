"""Production ProxyModel update preparation, with the entire CLI replaced.

No real CLI path, subprocess, proxy preference or network access is available
to the fixture. A delayed inert command exercises actual queue ordering.
"""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FAKE_CLI = '''
enum CLI {
    private static let lock = NSLock()
    private static var route = "socks"
    private static var finished = 0
    static var finishedRoutes: Int { lock.lock(); defer { lock.unlock() }; return finished }
    static func state() -> ProxyState? {
        lock.lock(); defer { lock.unlock() }
        return ProxyState(configured: true, enabled: true, running: route, system_proxy: true, selected: route,
                          has_socks: true, has_http: true, socks_endpoint: "192.0.2.47:1080", http_endpoint: "192.0.2.48:3128")
    }
    static func run(_ args: [String]) -> CommandResult {
        if args.first == "route", args.count == 2, ["socks", "http"].contains(args[1]) {
            Thread.sleep(forTimeInterval: 0.2)
            lock.lock(); route = args[1]; finished += 1; lock.unlock()
        } else { precondition(args == ["ensure"], "Unexpected fixture command") }
        return CommandResult(output: "", code: 0)
    }
}
'''


def inert_proxy_model_source():
    source = (ROOT / 'app/main.swift').read_text().split('\nstruct PowerStyle:', 1)[0]
    prefix, remainder = source.split('\nenum CLI {', 1)
    _, model = remainder.split('\nfinal class ProxyModel:', 1)
    safe = prefix + FAKE_CLI + '\nfinal class ProxyModel:' + model
    if 'Process()' in safe or 'NSHomeDirectory()' in safe or 'static var path:' in safe:
        raise AssertionError('Real CLI was not completely removed')
    return safe


@unittest.skipUnless(sys.platform == 'darwin' and shutil.which('swiftc'), 'macOS Swift required')
class UpdateQuiescenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='proxypilot-quiescence-')
        cls.addClassCleanup(cls.temp.cleanup)
        work = Path(cls.temp.name)
        model_file = work / 'ProxyModel.swift'
        model_file.write_text(inert_proxy_model_source())
        slices = []
        for arch in ('arm64', 'x86_64'):
            binary = work / arch
            result = subprocess.run(['swiftc', '-parse-as-library', '-target', f'{arch}-apple-macosx11.0',
                                     str(model_file), str(ROOT / 'tests/update_quiescence_checks.swift'), '-o', str(binary)],
                                    capture_output=True, text=True, timeout=90)
            if result.returncode: raise AssertionError(result.stderr)
            slices.append(str(binary))
        cls.binary = work / 'checks'
        subprocess.run(['lipo', '-create', *slices, '-output', str(cls.binary)], check=True, capture_output=True)

    def check(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('PASS ' + mode, result.stdout)

    def test_waits_for_in_flight_command_without_disabling_proxy(self): self.check('wait')
    def test_cancel_drops_late_completion_and_unfreezes_controls(self): self.check('cancel')
    def test_new_preparation_after_cancel_does_not_complete_old_one(self): self.check('replace-after-cancel')
    def test_only_latest_preparation_completes(self): self.check('replace')
