"""Managed CLI migration with private configs and owned loopback-only fake GOST.

Never invokes the installed CLI, helper, system proxy tools, or an upstream.
The C fixture is an inert TCP listener, not an alternative production engine.
"""
from pathlib import Path
import os
import re
import shlex
import socket
import subprocess
import tempfile
import time
import unittest

import test_power as power

ROOT = Path(__file__).resolve().parents[1]


def extract(source, name):
    start = re.search(r'^' + re.escape(name) + r'\(\) \{.*$', source, re.M)
    end = re.search(r'^\}', source[start.end():], re.M)
    return source[start.start():start.end() + end.end()]


@unittest.skipIf(os.geteuid() == 0, 'Disposable ordinary-user processes only')
class ManagedBridgeNamespaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='pp managed engine [literal] ')
        cls.engine = Path(cls.temp.name) / 'gost'
        source = cls.engine.with_suffix('.c')
        source.write_text(r'''
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 3 || strcmp(argv[1], "-C")) return 64;
  FILE *f = fopen(argv[2], "r"); if (!f) return 65;
  char line[4096]; int port = 0;
  while (fgets(line,sizeof(line),f)) {
    char *p = strstr(line,"addr: 127.0.0.1:");
    if (p) { port = atoi(p + strlen("addr: 127.0.0.1:")); break; }
  }
  fclose(f); if (port < 1024 || port > 65535) return 66;
  int fd = socket(AF_INET, SOCK_STREAM, 0), yes = 1;
  setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));
  struct sockaddr_in addr = {0}; addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); addr.sin_port = htons(port);
  if (bind(fd,(void*)&addr,sizeof(addr)) || listen(fd,8)) return 67;
  for (;;) { int c = accept(fd,0,0); if (c >= 0) close(c); }
}
''')
        subprocess.run(['/usr/bin/cc', str(source), '-o', str(cls.engine)],
                       check=True, capture_output=True, timeout=30)
        cls.old = subprocess.run(['git', 'show', '0518754:bin/proxypilot'], cwd=ROOT,
                                 check=True, capture_output=True, text=True).stdout

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix='pp managed [literal] ')
        self.root = Path(self.tempdir.name)
        self.cfg = self.root / 'config-dir'
        self.cfg.mkdir()
        self.runtime = self.cfg / 'managed-bridge-v2'
        self.runtime.mkdir()
        self.resources = self.root / 'Contents/Resources'
        (self.resources / 'bin').mkdir(parents=True)
        self.engine = self.root / 'engine dir/gost'
        self.engine.parent.mkdir()
        self.engine.write_bytes(type(self).engine.read_bytes())
        self.engine.chmod(0o700)
        self.children = []
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            self.port = listener.getsockname()[1]
        (self.cfg / 'config').write_text('HTTP_UPSTREAM=proxy.invalid:3128\n')
        (self.cfg / 'mode').write_text('http\n')
        (self.cfg / 'enabled').write_text('on\n')

    def tearDown(self):
        # Only exact processes started by this test or discovered by its own
        # private pathname. Never enumerate/terminate a machine-wide GOST.
        result = self.run_script('print -r -- "$(managed_bridge_processes managed)"', check=False)
        for pid in result.stdout.splitlines():
            if pid.isdecimal():
                subprocess.run(['/bin/kill', pid], capture_output=True)
        for child in self.children:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
        self.tempdir.cleanup()

    def run_script(self, body, names=(), check=True):
        base = ['bridge_process_text_matches', 'bridge_process_image_matches',
                'bridge_ledger_metadata', 'bridge_process_ledger_matches', 'record_managed_bridge',
                'managed_bridge_processes', 'bridge_pid', 'running_mode',
                'validate_managed_bridge_processes', 'stop_bridge']
        functions = '\n'.join(power.function(n) for n in dict.fromkeys(base + list(names)))
        script = f'''emulate -L zsh
set -u
CFG_DIR={shlex.quote(str(self.cfg))}
BRIDGE_DIR="$CFG_DIR/managed-bridge-v2"
CFG="$CFG_DIR/config"
MODE_FILE="$CFG_DIR/mode"
ENABLED_FILE="$CFG_DIR/enabled"
PP_SELF={shlex.quote(str(self.resources / 'bin/proxypilot'))}
HOME={shlex.quote(str(self.root))}
GOST={shlex.quote(str(self.engine))}
PP_MANAGED_BRIDGE=1
PP_VERSION=1.5.1
BRIDGE_PORT={self.port}
LOG="$BRIDGE_DIR/log"
SOCKS_UPSTREAM=proxy.invalid:1080
HTTP_UPSTREAM=proxy.invalid:3128
NO_PROXY_LIST=localhost,127.0.0.1
PP_VPN_STATE='v1|9|4|198.51.100.9'
PP_VPN_BYPASS=198.51.100.9
OFFICE_GATEWAYS=''
warn() {{ print -ru2 -- "$*"; }}
ok() {{ print -r -- "$*"; }}
die() {{ print -ru2 -- "$*"; exit 1; }}
need_gost() {{ return 0; }}
load_config() {{ return 0; }}
gateway() {{ print same; }}
gost_nameservers() {{ print 192.0.2.53; }}
effective_mode() {{ print http; }}
tcp_open() {{ /usr/bin/nc -z -w 1 "$1" "$2" </dev/null >/dev/null 2>&1; }}
{functions}
{body}
'''
        result = subprocess.run(['/bin/zsh', '-f', '-c', script], capture_output=True,
                                text=True, timeout=20)
        if check:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def launch(self, path, executable=None):
        path.write_text(f'addr: 127.0.0.1:{self.port}\n')
        child = subprocess.Popen([str(self.engine), '-C', str(path)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, executable=executable)
        self.children.append(child)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            self.assertIsNone(child.poll())
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=.1):
                    return child
            except OSError:
                time.sleep(.02)
        self.fail('Own loopback fixture did not listen')

    def test_vpn_bundle_build_seals_both_protocol_and_runtime_capabilities(self):
        build = (ROOT / 'app/build.sh').read_text()
        installer = next(block.split('\nfi', 1)[0] for block in build.split(
            'if [[ "$VPN_INSTALLER" == 1 ]]; then')[1:] if 'vpn-bridge-v2' in block.split('\nfi', 1)[0])
        self.assertIn('"$APP/Contents/Resources/vpn-bridge-v1"', installer)
        self.assertIn('"$APP/Contents/Resources/vpn-bridge-v2"', installer)
        self.assertLess(build.index('vpn-bridge-v2'), build.index('codesign '))

    def test_capability_selects_stable_runtime_and_log_not_vpn_state(self):
        selector = power.function('select_bridge_runtime').replace(
            '/Applications/ProxyPilot.app/Contents/Resources',
            str(self.root / 'Installed.app/Contents/Resources'))
        for marker, expected in [(None, '0'), ('vpn-bridge-v1', '0'), ('vpn-bridge-v2', '1')]:
            if marker:
                (self.resources / marker).touch()
            result = self.run_script(selector + '\nselect_bridge_runtime\nprint "$PP_MANAGED_BRIDGE|$BRIDGE_DIR|$LOG"')
            self.assertTrue(result.stdout.startswith(expected + '|'))
            if expected == '1':
                self.assertIn('/managed-bridge-v2|', result.stdout)
                self.assertIn('proxypilot-managed-v2.log', result.stdout)
        (self.resources / 'vpn-bridge-v2').unlink()
        installed = self.root / 'Installed.app/Contents/Resources'
        installed.mkdir(parents=True)
        (installed / 'vpn-bridge-v2').touch()
        result = self.run_script(selector + '\nselect_bridge_runtime\nprint $PP_MANAGED_BRIDGE')
        self.assertEqual(result.stdout.strip(), '1')

    def test_real_old_writer_and_stop_cannot_overwrite_or_discover_managed_bridge(self):
        # Frozen pgrep treats CFG_DIR as a regex: use a plain path here, then
        # positively prove it can still find/stop a genuine legacy process.
        plain = tempfile.TemporaryDirectory(prefix='pp-old-namespace-')
        self.addCleanup(plain.cleanup)
        self.cfg = Path(plain.name) / 'cfg'
        self.cfg.mkdir()
        self.runtime = self.cfg / 'managed-bridge-v2'
        self.runtime.mkdir()
        child = self.launch(self.runtime / 'route-http.yaml')
        names = ['effective_bridge_bypass', 'write_gost_config']
        self.run_script('write_gost_config http', names)
        before = (self.runtime / 'route-http.yaml').read_bytes()
        old_functions = '\n'.join(extract(self.old, n) for n in
                                  ['write_gost_config', 'bridge_pid', 'stop_bridge'])
        result = self.run_script(old_functions + '''
mode=http
write_gost_config http
print "oldpid=$(bridge_pid)"
stop_bridge
''')
        self.assertIn('oldpid=\n', result.stdout)
        self.assertEqual((self.runtime / 'route-http.yaml').read_bytes(), before)
        self.assertNotIn(b'198.51.100.9', (self.cfg / 'gost-http.yaml').read_bytes())
        self.assertIsNone(child.poll())
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            self.port = listener.getsockname()[1]
        legacy = self.launch(self.cfg / 'gost-http.yaml')
        result = self.run_script(old_functions + f'''
[[ "$(bridge_pid)" == {legacy.pid} ]] || exit 9
stop_bridge
''')
        legacy.wait(timeout=3)
        self.assertIsNone(child.poll())

    def test_same_uid_legacy_listener_migrates_and_second_ensure_is_noop(self):
        old = self.launch(self.cfg / 'gost-http.yaml')
        result = self.run_script('''cmd_ensure || exit 1
first=$(bridge_pid)
[[ -n "$first" && "$(running_mode)" == http ]] || exit 2
cmd_ensure || exit 3
[[ "$(bridge_pid)" == "$first" ]] || exit 4
print migrated
''', ['need_config', 'is_enabled', 'effective_bridge_bypass', 'write_gost_config',
      'start_bridge', 'cmd_ensure'])
        self.assertIn('migrated', result.stdout)
        old.wait(timeout=3)
        self.assertEqual((self.cfg / 'enabled').read_text(), 'on\n')
        self.assertEqual((self.cfg / 'mode').read_text(), 'http\n')
        self.assertIn('198.51.100.9', (self.runtime / 'route-http.yaml').read_text())
        self.assertEqual((self.runtime / 'bridge-vpn').read_text(), 'v1|9|4|198.51.100.9\n')

    def test_off_legacy_migrates_to_direct_then_stop_does_not_resurrect(self):
        old = self.launch(self.cfg / 'gost-socks.yaml')
        (self.cfg / 'enabled').write_text('off\n')
        self.run_script('''cmd_ensure || exit 1
[[ "$(running_mode)" == direct ]] || exit 2
stop_bridge || exit 3
cmd_ensure || exit 4
[[ -z "$(bridge_pid)" ]] || exit 5
''', ['need_config', 'is_enabled', 'effective_bridge_bypass', 'write_gost_config',
      'start_bridge', 'cmd_ensure'])
        old.wait(timeout=3)
        self.assertEqual((self.cfg / 'enabled').read_text(), 'off\n')
        self.assertEqual((self.cfg / 'mode').read_text(), 'http\n')

    def test_foreign_argument_or_namespace_never_killed_or_adopted(self):
        child = self.launch(self.root / 'unrelated.yaml')
        result = self.run_script('''stop_bridge
print "stop=$?"
start_bridge http
print "start=$?"
''', ['effective_bridge_bypass', 'write_gost_config', 'start_bridge'])
        self.assertIn('stop=1', result.stdout)
        self.assertIn('start=1', result.stdout)
        self.assertFalse((self.runtime / 'route-http.yaml').exists())
        self.assertIsNone(child.poll())

    def test_changed_overlay_restarts_managed_only_and_preserves_settings(self):
        self.run_script('''cmd_ensure || exit 1
first=$(bridge_pid)
PP_VPN_STATE='v1|9|5|203.0.113.9'
PP_VPN_BYPASS=203.0.113.9
cmd_ensure || exit 2
[[ "$(bridge_pid)" != "$first" ]] || exit 3
''', ['need_config', 'is_enabled', 'effective_bridge_bypass', 'write_gost_config',
      'start_bridge', 'cmd_ensure'])
        config = (self.runtime / 'route-http.yaml').read_text()
        self.assertIn('203.0.113.9', config)
        self.assertNotIn('198.51.100.9', config)
        self.assertEqual((self.cfg / 'enabled').read_text(), 'on\n')

    def test_live_snapshot_failure_preserves_old_listener_and_intent(self):
        old = self.launch(self.cfg / 'gost-http.yaml')
        result = self.run_script('''
load_bridge_vpn() { return 1; }
prepare_bridge_writer ensure || exit 69
cmd_ensure
''', ['prepare_bridge_writer', 'is_enabled'], check=False)
        self.assertEqual(result.returncode, 69, result.stderr)
        self.assertIsNone(old.poll())
        self.assertEqual((self.cfg / 'enabled').read_text(), 'on\n')
        self.assertEqual((self.cfg / 'mode').read_text(), 'http\n')
        self.assertFalse((self.runtime / 'route-http.yaml').exists())

    def test_off_route_only_changes_preference_without_snapshot_or_start(self):
        (self.cfg / 'enabled').write_text('off\n')
        self.run_script('''
load_bridge_vpn() { print UNEXPECTED; return 1; }
tcp_open() { print UNEXPECTED; return 1; }
cmd_enable() { print UNEXPECTED; return 1; }
prepare_bridge_writer route socks || exit 1
cmd_route socks || exit 2
''', ['prepare_bridge_writer', 'need_config', 'saved_mode', 'is_enabled', 'cmd_route'])
        self.assertEqual((self.cfg / 'mode').read_text(), 'socks\n')
        self.assertEqual((self.cfg / 'enabled').read_text(), 'off\n')
        self.assertEqual(list(self.runtime.iterdir()), [])

    def test_config_symlink_refused_without_writing_foreign_target(self):
        foreign = self.root / 'foreign.yaml'
        foreign.write_text('unchanged')
        (self.runtime / 'route-http.yaml').symlink_to(foreign)
        result = self.run_script('write_gost_config http',
                                 ['effective_bridge_bypass', 'write_gost_config'], check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(foreign.read_text(), 'unchanged')

    def test_discovery_requires_same_uid_exact_executable_and_complete_arguments(self):
        command = f'{self.engine} -C {self.runtime}/route-http.yaml'
        rows = [f'{os.geteuid()+1} 111 {command}',
                f'{os.geteuid()} 112 {command} --extra',
                f'{os.geteuid()} 113 /unrelated/gost -C {self.runtime}/route-http.yaml',
                f'{os.geteuid()} 114 {command}']
        mock = 'bridge_process_image_matches() { return 0; }\nps() { print -r -- ' + shlex.quote('\n'.join(rows)) + '; }\n'
        result = self.run_script(mock + 'managed_bridge_processes managed')
        self.assertEqual(result.stdout.strip(), '114')

    def test_ambiguous_processes_refused_before_settings_change(self):
        rows = '\n'.join(f'{os.geteuid()} {pid} {self.engine} -C {self.runtime}/route-{mode}.yaml'
                         for pid, mode in [(111, 'http'), (112, 'socks')])
        mock = 'bridge_process_image_matches() { return 0; }\nps() { print -r -- ' + shlex.quote(rows) + '; }\n'
        result = self.run_script(mock + 'prepare_bridge_writer route socks',
                                 ['prepare_bridge_writer'], check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.cfg / 'mode').read_text(), 'http\n')
        self.assertEqual((self.cfg / 'enabled').read_text(), 'on\n')

    def test_busy_unrelated_listener_does_not_change_switch_intent(self):
        child = self.launch(self.root / 'foreign.yaml')
        result = self.run_script('cmd_switch socks', ['need_config', 'cmd_switch'], check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.cfg / 'mode').read_text(), 'http\n')
        self.assertEqual((self.cfg / 'enabled').read_text(), 'on\n')
        self.assertIsNone(child.poll())

    def test_failed_readiness_cleans_only_own_new_process(self):
        result = self.run_script('''
tcp_open() { return 1; }
start_bridge http
print "start=$?"
[[ -z "$(bridge_pid)" ]] || exit 9
''', ['effective_bridge_bypass', 'write_gost_config', 'start_bridge'])
        self.assertIn('start=1', result.stdout)
        self.assertFalse((self.runtime / 'bridge-vpn').exists())

    def test_spoofed_argv0_with_different_native_image_is_not_adopted_or_killed(self):
        foreign = self.root / 'foreign-image'
        foreign.write_bytes(self.engine.read_bytes())
        foreign.chmod(0o700)
        child = self.launch(self.runtime / 'route-http.yaml', executable=str(foreign))
        result = self.run_script('''
[[ -z "$(bridge_pid)" ]] || exit 9
stop_bridge
print "stop=$?"
''')
        self.assertIn('stop=1', result.stdout)
        self.assertIsNone(child.poll())

    def test_missing_image_inspector_never_authorizes_process(self):
        child = self.launch(self.runtime / 'route-http.yaml')
        # Actual lsof absence/error is represented at the narrow image seam.
        result = self.run_script('''
bridge_process_image_matches() { return 1; }
[[ -z "$(bridge_pid)" ]] || exit 9
stop_bridge
print "stop=$?"
''')
        self.assertIn('stop=1', result.stdout)
        self.assertIsNone(child.poll())

    def replace_engine(self):
        replacement = self.engine.with_name('new-gost')
        replacement.write_bytes(self.engine.read_bytes())
        replacement.chmod(0o700)
        replacement.replace(self.engine)

    def test_recorded_managed_image_survives_bundle_inode_replacement(self):
        old = self.launch(self.runtime / 'route-http.yaml')
        self.run_script(f'record_managed_bridge {old.pid}')
        self.assertEqual((self.runtime / 'process').stat().st_mode & 0o777, 0o600)
        self.replace_engine()
        result = self.run_script(f'''
[[ "$(bridge_pid)" == {old.pid} ]] || exit 1
cmd_ensure || exit 2
[[ "$(running_mode)" == http && "$(bridge_pid)" != {old.pid} ]] || exit 3
''', ['need_config', 'is_enabled', 'effective_bridge_bypass', 'write_gost_config',
          'start_bridge', 'cmd_ensure'])
        old.wait(timeout=3)
        self.assertEqual((self.cfg / 'mode').read_text(), 'http\n')
        self.assertEqual((self.cfg / 'enabled').read_text(), 'on\n')
        self.assertIn('198.51.100.9', (self.runtime / 'route-http.yaml').read_text())

    def test_unrecorded_unlinked_legacy_image_is_refused_not_guessed(self):
        old = self.launch(self.cfg / 'gost-http.yaml')
        self.replace_engine()
        result = self.run_script('stop_bridge; print "stop=$?"')
        self.assertIn('stop=1', result.stdout)
        self.assertIsNone(old.poll())

    def test_wrong_birth_or_image_ledger_cannot_authorize_replaced_process(self):
        old = self.launch(self.runtime / 'route-http.yaml')
        self.run_script(f'record_managed_bridge {old.pid}')
        ledger = self.runtime / 'process'
        original = ledger.read_text()
        self.replace_engine()
        for field in ('birth', 'inode'):
            lines = original.splitlines()
            if field == 'birth':
                lines[2] += ' changed'
            else:
                lines[3] = '1 1'
            ledger.write_text('\n'.join(lines) + '\n')
            result = self.run_script('stop_bridge; print "stop=$?"')
            self.assertIn('stop=1', result.stdout)
            self.assertIsNone(old.poll())

    def test_unsafe_ledger_is_not_replayed_or_overwritten(self):
        old = self.launch(self.runtime / 'route-http.yaml')
        self.run_script(f'record_managed_bridge {old.pid}')
        ledger = self.runtime / 'process'
        saved = ledger.read_bytes()
        ledger.chmod(0o644)
        self.replace_engine()
        result = self.run_script('stop_bridge; print "stop=$?"')
        self.assertIn('stop=1', result.stdout)
        self.assertEqual(ledger.read_bytes(), saved)
        self.assertIsNone(old.poll())
        ledger.unlink()
        foreign = self.root / 'foreign-ledger'
        foreign.write_bytes(saved)
        foreign.chmod(0o600)
        ledger.symlink_to(foreign)
        result = self.run_script('stop_bridge; print "stop=$?"')
        self.assertIn('stop=1', result.stdout)
        self.assertIsNone(old.poll())
        self.assertEqual(foreign.read_bytes(), saved)
        ledger.unlink()
        os.link(foreign, ledger)
        result = self.run_script('stop_bridge; print "stop=$?"')
        self.assertIn('stop=1', result.stdout)
        self.assertIsNone(old.poll())
        self.assertEqual(foreign.read_bytes(), saved)


if __name__ == '__main__':
    unittest.main()
