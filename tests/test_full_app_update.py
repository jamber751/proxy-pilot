"""Opt-in full App + production CLI functions + real loopback GOST + Sparkle.

PROXYPILOT_TEST_FULL_APP=1 PROXYPILOT_TEST_GOST=/absolute/path/to/gost python3 -m unittest discover -s tests -p test_full_app_update.py -v

Never launches the installed app/full CLI or uses real system proxy settings.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import plistlib
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import unittest

import test_isolated_update_install as install
from test_power import function

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests/isolated-update-install'
GOST = os.environ.get('PROXYPILOT_TEST_GOST')
FUNCTIONS = ('load_config', 'need_config', 'need_gost', 'tcp_open', 'saved_mode', 'is_enabled',
             'probe_cached', 'upstream_dead', 'effective_mode', 'running_mode', 'stop_bridge',
             'write_gost_config', 'cmd_ensure', 'cmd_switch', 'cmd_enable', 'cmd_route',
             'cmd_disable', 'build_bypass', 'system_points_here', 'cmd_system', 'json_string', 'cmd_app_state')


def boundary_script():
    source = (FIXTURES / 'BridgeBoundary.zsh').read_text()
    source += '\n' + '\n'.join(function(name) for name in FUNCTIONS)
    source += '\n' + function('start_bridge').replace('start_bridge()', 'production_start_bridge()', 1)
    source += '''
start_bridge() {
    production_start_bridge "$@"
    local result=$?
    print "start:$PP_VERSION:$1:$(bridge_pid):$result" >> "$CFG_DIR/starts"
    return "$result"
}
load_config
[[ "$GOST" == "$fixture_root/engine/gost" && "$BRIDGE_PORT" == <1024-65535> ]] || exit 64
[[ "$SOCKS_UPSTREAM" == 127.0.0.1:<1024-65535> && "$HTTP_UPSTREAM" == 127.0.0.1:<1024-65535> ]] || exit 64
print "$PP_VERSION:$*" >> "$CFG_DIR/commands"
case "${1:-}" in
    (app-state) cmd_app_state ;;
    (ensure) cmd_ensure ;;
    (route) [[ "${2:-}" == (socks|http|direct) && $# == 2 ]] || exit 64; cmd_route "$2" ;;
    (disable) [[ $# == 1 ]] || exit 64; cmd_disable ;;
    (fixture-start-direct) [[ $# == 1 ]] || exit 64; start_bridge direct ;;
    (*) exit 64 ;;
esac
'''
    # All OS operations are functions above; no full CLI dispatcher/startup.
    for forbidden in ('NSHomeDirectory', '$HOME', '${HOME', '/usr/sbin/networksetup', '/usr/sbin/scutil', 'launchctl', 'sudo ', 'pgrep', 'pkill'):
        if forbidden in source: raise AssertionError('Unsafe test boundary: ' + forbidden)
    return source


class EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'full-app-loopback-ok')
    def log_message(self, *_): pass


class LoopbackEnvironment:
    @staticmethod
    def port():
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]

    def __init__(self, work, initial):
        self.work = work
        self.engine = work / 'engine/gost'
        self.engine.parent.mkdir()
        shutil.copy2(GOST, self.engine)
        self.processes = []
        self.server = None
        self.handoff_checked = False
        self.handoff_pid = None
        try:
            self.socks, self.http, self.bridge = self.port(), self.port(), self.port()
            for scheme, port in [('socks5', self.socks), ('http', self.http)]:
                child = subprocess.Popen([str(self.engine), '-L', f'{scheme}://127.0.0.1:{port}'],
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'})
                self.processes.append(child)
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline:
                    if child.poll() is not None: raise AssertionError('Loopback upstream exited')
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=0.1): break
                    except OSError: time.sleep(0.03)
                else: raise AssertionError('Loopback upstream did not listen')
            self.server = ThreadingHTTPServer(('127.0.0.1', 0), EchoHandler)
            threading.Thread(target=self.server.serve_forever, daemon=True).start()
            state = work / 'state'; state.mkdir()
            (work / 'full-app-fixture').touch()
            self.config = f'BRIDGE_PORT={self.bridge}\nSOCKS_UPSTREAM=127.0.0.1:{self.socks}\nHTTP_UPSTREAM=127.0.0.1:{self.http}\nNO_PROXY_LIST=""\n'
            (state / 'config').write_text(self.config)
            (state / 'mode').write_text('socks\n')
            for name in ('enabled', 'system-web', 'system-secureweb'):
                (state / name).write_text('on\n' if initial == 'on' else 'off\n')
        except BaseException:
            self.close(); raise

    def bridge_pids(self):
        commands = {f'{self.engine} -C {self.work}/state/gost-{mode}.yaml' for mode in ('socks', 'http', 'direct')}
        result = subprocess.run(['ps', '-axo', 'pid=,command='], capture_output=True, text=True, check=True)
        return [int(row.split(None, 1)[0]) for row in result.stdout.splitlines()
                if len(row.split(None, 1)) == 2 and row.split(None, 1)[1] in commands]

    def check_traffic(self):
        for scheme in ('http', 'socks5h'):
            result = subprocess.run(['/usr/bin/curl', '-sS', '--max-time', '2', '--noproxy', '',
                                     '--proxy', f'{scheme}://127.0.0.1:{self.bridge}', f'http://127.0.0.1:{self.server.server_port}/'],
                                    env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}, capture_output=True, text=True, timeout=4)
            if result.returncode or result.stdout != 'full-app-loopback-ok':
                raise AssertionError(f'{scheme} bridge failed: {result.stderr}')

    def close(self):
        # The app deliberately leaves its listener alive for existing clients.
        # Teardown may stop only these exact fixture GOST processes.
        for pid in self.bridge_pids():
            try: os.kill(pid, signal.SIGTERM)
            except ProcessLookupError: pass
        deadline = time.monotonic() + 3
        while self.bridge_pids() and time.monotonic() < deadline: time.sleep(0.05)
        for pid in self.bridge_pids():
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
        for child in self.processes:
            if child.poll() is None: child.terminate()
            try: child.wait(timeout=3)
            except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=3)
        if self.server is not None: self.server.shutdown(); self.server.server_close()
        if self.bridge_pids(): raise AssertionError('Fixture bridge did not stop')


@unittest.skipUnless(sys.platform == 'darwin' and os.environ.get('PROXYPILOT_TEST_FULL_APP') == '1' and GOST,
                     'opt-in complete app with loopback GOST')
class FullAppUpdateTests(install.IsolatedInstallFixture, unittest.TestCase):
    full_app = True
    initial_state = 'on'

    @classmethod
    def setUpClass(cls):
        # These cases assert a real status-item popover, not only updater IPC.
        # A locked desktop invalidates its event lifecycle. Report the missing acceptance
        # prerequisite explicitly; never count the scenarios as passed or relax
        # their assertions/timeouts to conceal it. No attempt to unlock macOS.
        check = subprocess.run(['/usr/bin/swift', '-e', '''
import CoreGraphics
import Foundation
guard let state = CGSessionCopyCurrentDictionary() as? [String: Any],
      (state["kCGSSessionOnConsoleKey"] as? NSNumber)?.boolValue == true,
      (state["CGSSessionScreenIsLocked"] as? NSNumber)?.boolValue != true else { exit(78) }
'''], capture_output=True, text=True, timeout=60)
        if check.returncode == 78:
            raise unittest.SkipTest('Full popover acceptance requires an unlocked console desktop')
        if check.returncode:
            raise AssertionError('Could not check interactive desktop: ' + check.stderr)
        super().setUpClass()

    @classmethod
    def frontend_sources(cls, build, proxy_model):
        source = (ROOT / 'app/main.swift').read_text()
        begin = source.index('    static var path: String? {', source.index('\nenum CLI {'))
        end = source.index('    static func run(', begin)
        source = source[:begin] + '''    static var path: String? {
        Bundle.main.resourceURL?.appendingPathComponent("bin/proxypilot").path
    }
''' + source[end:]
        replacements = {
            'var environment = ProcessInfo.processInfo.environment\n        environment["TERM"] = "dumb"\n        process.environment = environment': 'process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TERM": "dumb"]',
            'private let updates = UpdateModel()': 'private let updates = UpdateModel()\n    private var fullAppLifecycle: FullAppLifecycle?',
            'updates.start(preview: model.preview)': 'updates.start(preview: model.preview)\n        fullAppLifecycle = FullAppLifecycle(model: model, updates: updates, popover: popover)',
            'self.model.prepareForUpdate(completion)': '''record("prepare")
            self.model.prepareForUpdate {
                record("commands-drained state-preserved")
                // Test-only observation window before acknowledging the real handoff.
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5, execute: completion)
            }''',
            'let app = NSApplication.shared': 'validateFullAppFixture()\nlet app = NSApplication.shared',
            'if model.preview { Text("ТЕСТ")': 'if true { Text("ТЕСТ")',
            'model.preview ? "hammer.circle.fill" : "circle.hexagongrid.fill"': '"hammer.circle.fill"',
            'window.title = model.preview ? "ProxyPilot — тестовый макет" : "ProxyPilot"': 'window.title = "ProxyPilot — LOOPBACK TEST"',
            'popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)': 'popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)\n        record("popover-shown=\\(popover.isShown)")',
        }
        for needle, replacement in replacements.items():
            if source.count(needle) != 1: raise AssertionError('Full app observation boundary changed: ' + needle)
            source = source.replace(needle, replacement)
        if any(forbidden in source for forbidden in ('NSHomeDirectory()', '/opt/homebrew/', '.local/bin/')):
            raise AssertionError('Real CLI fallback remains in full app fixture')
        main = build / 'main.swift'; main.write_text(source)
        return ['-D', 'ISOLATED_UPDATER', str(main), str(FIXTURES / 'FullAppLifecycle.swift'),
                *[str(ROOT / 'app' / file) for file in ('Controls.swift', 'Updates.swift', 'VPNConfiguration.swift', 'VPNProfileImporter.swift', 'VPNStore.swift')],
                str(ROOT / 'app/update-worker/IsolatedUpdates.swift')]

    def prepare_environment(self, work, mode):
        self.loopback = LoopbackEnvironment(work, self.initial_state)
        return self.loopback

    def configure_bundle(self, app, work, mode):
        info_path = app / 'Contents/Info.plist'
        info = plistlib.loads(info_path.read_bytes())
        info.update(TestInitialState=self.initial_state, TestSOCKS=f'127.0.0.1:{self.loopback.socks}', TestHTTP=f'127.0.0.1:{self.loopback.http}')
        info_path.write_bytes(plistlib.dumps(info))
        cli = app / 'Contents/Resources/bin/proxypilot'; cli.parent.mkdir(parents=True)
        cli.write_text(boundary_script()); cli.chmod(0o700)
        print(f'FULL APP TEST: {app}', flush=True)
        if self.initial_state == 'off-running':
            self.run_command([str(cli), 'fixture-start-direct'])

    @staticmethod
    def matching_processes(work, identifier):
        # App/worker must exit naturally; persistent test engines are verified
        # separately then stopped explicitly by LoopbackEnvironment.close().
        return [(pid, command) for pid, command in install.IsolatedInstallFixture.matching_processes(work, identifier)
                if not command.startswith(str(work / 'engine/gost') + ' ')]

    def observe_running(self, work, events):
        if 'commands-drained state-preserved' in events and not self.loopback.handoff_checked:
            if self.initial_state != 'off-stopped':
                self.loopback.check_traffic()
                pids = self.loopback.bridge_pids()
                self.assertEqual(len(pids), 1)
                self.loopback.handoff_pid = pids[0]
            else: self.assertEqual(self.loopback.bridge_pids(), [])
            self.loopback.handoff_checked = True

    def verify_environment(self, app, work, mode, events):
        state = work / 'state'
        self.assertEqual((state / 'config').read_text(), self.loopback.config)
        expected_mode = 'http' if mode == 'cancel-offer' else 'socks'
        expected_power = 'off' if mode == 'quit' or self.initial_state != 'on' else 'on'
        self.assertEqual((state / 'mode').read_text().strip(), expected_mode)
        for name in ('enabled', 'system-web', 'system-secureweb'):
            self.assertEqual((state / name).read_text().strip(), expected_power, f'{name}\n{events}\n{(state / "commands").read_text()}')
        starts = (state / 'starts').read_text().splitlines() if (state / 'starts').exists() else []
        if self.initial_state == 'off-stopped':
            self.assertEqual(starts, []); self.assertEqual(self.loopback.bridge_pids(), [])
        else:
            self.loopback.check_traffic()
            self.assertEqual(len(starts), 2, starts)
            self.assertTrue(all(line.endswith(':0') for line in starts), starts)
            self.assertEqual(len(self.loopback.bridge_pids()), 1)
            final_route = 'http' if mode == 'cancel-offer' else 'direct' if expected_power == 'off' else 'socks'
            self.assertIn(f':{final_route}:', starts[-1])
        if mode == 'install':
            self.assertTrue(self.loopback.handoff_checked)
            self.assertFalse((state / 'system-writes').exists(), 'Startup/update wrote system settings')
            self.assertIn('popover-closed', events)
            if self.initial_state != 'off-stopped':
                self.assertTrue(starts[0].startswith('start:1.0.0:') and starts[1].startswith('start:2.0.0:'), starts)
                self.assertNotEqual(self.loopback.handoff_pid, self.loopback.bridge_pids()[0])
        if mode == 'cancel-offer': self.assertIn('controls-restored', events)
        if mode == 'quit': self.assertIn('1.0.0:disable', (state / 'commands').read_text())

    def test_update_enabled_preserves_real_bridge_and_settings(self): self.scenario('install')
    def test_update_disabled_does_not_start_stopped_bridge(self):
        self.initial_state = 'off-stopped'; self.scenario('install')
    def test_update_disabled_preserves_existing_direct_bridge(self):
        self.initial_state = 'off-running'; self.scenario('install')
    def test_cancel_restores_route_controls_without_installing(self): self.scenario('cancel-offer')
    def test_quit_disables_only_fake_system_proxy_and_keeps_direct_listener(self): self.scenario('quit')
