"""Production CLI boundaries in disposable folders; no host proxy/helper access."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

import test_power as power


class VPNBridgeHandoffTests(unittest.TestCase):
    def test_reader_entry_precedes_gui_and_is_not_a_saved_state_reader(self):
        source = (Path(__file__).resolve().parents[1] / 'app/main.swift').read_text()
        self.assertLess(source.index('VPNBridgeBypassEntry.runIfRequested'),
                        source.index('let app = NSApplication.shared'))
        entry = (Path(__file__).resolve().parents[1] / 'app/VPNBridgeBypassEntry.swift').read_text()
        self.assertIn('VPNFrontendHelperSession.open()', entry)
        self.assertIn('session.tunnelStatus()', entry)
        for forbidden in ('VPNStore', 'state.json', 'CLI.run', 'NSApplication',
                          'error.localizedDescription'):
            self.assertNotIn(forbidden, entry)

    def load(self, wire='v1|7|3|198.51.100.7,10.20.0.0/16', code=0, marker=True,
             installed=False, previous=False):
        with tempfile.TemporaryDirectory(prefix='pp-bridge-handoff-') as folder:
            root = Path(folder)
            resources = root / 'Contents/Resources'
            binary = root / 'Contents/MacOS/ProxyPilot'
            binary.parent.mkdir(parents=True)
            (resources / 'bin').mkdir(parents=True)
            if marker:
                (resources / 'vpn-bridge-v1').touch()
            # Static fixture output only; deliberately never invokes a helper.
            binary.write_text('#!/bin/zsh\nprint -r -- ' + repr(wire) + f'\nexit {code}\n')
            binary.chmod(0o700)
            if installed:
                installed_resources = root / 'Installed.app/Contents/Resources'
                installed_resources.mkdir(parents=True)
                (installed_resources / 'vpn-bridge-v1').touch()
                installed_binary = root / 'Installed.app/Contents/MacOS/ProxyPilot'
                installed_binary.parent.mkdir()
                installed_binary.write_bytes(binary.read_bytes())
                installed_binary.chmod(0o700)
            if previous:
                (root / 'bridge-vpn').write_text('v1|6|2|203.0.113.8\n')
            loader = power.function('load_bridge_vpn').replace(
                '/Applications/ProxyPilot.app/Contents/Resources',
                str(root / 'Installed.app/Contents/Resources'))
            script = f'''emulate -L zsh
set -u
CFG_DIR='{root}'
PP_SELF='{resources}/bin/proxypilot'
PP_VPN_BYPASS=stale
PP_VPN_STATE=stale
{loader}
load_bridge_vpn
print -r -- "result=$?"
print -r -- "matchers=$PP_VPN_BYPASS"
print -r -- "state=$PP_VPN_STATE"
'''
            return subprocess.run(['/bin/zsh', '-f', '-c', script], capture_output=True,
                                  text=True, timeout=10)

    def test_exact_wire_loaded(self):
        result = self.load()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('result=0', result.stdout)
        self.assertIn('matchers=198.51.100.7,10.20.0.0/16', result.stdout)

    def test_off_is_explicit_empty_overlay(self):
        result = self.load(wire='v1|8|0|')
        self.assertIn('result=0\nmatchers=\nstate=v1|8|0|', result.stdout)

    def test_default_bundle_never_queries_frontend(self):
        result = self.load(marker=False, code=69)
        self.assertIn('result=0\nmatchers=\nstate=\n', result.stdout)

    def test_standalone_uses_fixed_installed_frontend(self):
        result = self.load(marker=False, installed=True)
        self.assertIn('result=0\nmatchers=198.51.100.7,10.20.0.0/16', result.stdout)

    def test_missing_managed_frontend_never_replays_or_erases_old_overlay(self):
        result = self.load(marker=False, previous=True)
        self.assertIn('result=1\nmatchers=\nstate=\n', result.stdout)

    def test_rejected_query_never_reuses_stale_overlay(self):
        result = self.load(code=69)
        self.assertIn('result=1\nmatchers=\nstate=\n', result.stdout)

    def test_malformed_wire_is_not_used(self):
        for wire in ('', 'v2|7|3|198.51.100.7', 'v1|7|3|*.example',
                     'v1|7|3|198.51.100.7\necho injected', 'v1|7|3|$(id)',
                     'v1|7|3|' + 'a' * 131072):
            with self.subTest(size=len(wire)):
                result = self.load(wire=wire)
                self.assertIn('result=1\nmatchers=\nstate=\n', result.stdout)

    def test_merge_is_effective_only_and_deduplicated(self):
        script = f'''emulate -L zsh
set -u
NO_PROXY_LIST='localhost,198.51.100.7,custom.example'
PP_VPN_BYPASS='198.51.100.7,203.0.113.8,2001:db8::7'
{power.function('effective_bridge_bypass')}
effective_bridge_bypass
print -r -- "$NO_PROXY_LIST"
'''
        result = subprocess.run(['/bin/zsh', '-f', '-c', script], capture_output=True,
                                text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            'localhost,198.51.100.7,custom.example,203.0.113.8,2001:db8::7',
            'localhost,198.51.100.7,custom.example'])

    def test_overlay_revision_triggers_one_restart_without_changing_choice(self):
        result = power.PowerTests().run_zsh(['is_enabled', 'cmd_ensure'], '''
print on > "$ENABLED_FILE"
print socks > "$MODE_FILE"
PP_VPN_STATE='v1|8|4|203.0.113.8'
print 'v1|7|3|198.51.100.7' > "$CFG_DIR/bridge-vpn"
print 'auto-v1:43129' > "$CFG_DIR/bridge-format"
print "$PP_VERSION" > "$CFG_DIR/bridge-version"
print same > "$CFG_DIR/bridge-gateway"
print 1.1.1.1 > "$CFG_DIR/bridge-dns"
effective_mode() { print socks; }
running_mode() { print socks; }
gateway() { print same; }
gost_nameservers() { print 1.1.1.1; }
bridge_pid() { print fake; }
stop_bridge() { print stopped; }
start_bridge() { print "start:$1"; print -r -- "$PP_VPN_STATE" > "$CFG_DIR/bridge-vpn"; }
cmd_ensure
cmd_ensure
print "choice=$(< "$MODE_FILE") enabled=$(< "$ENABLED_FILE")"
''')
        self.assertEqual(result.count('start:socks'), 1)
        self.assertIn('choice=socks enabled=on', result)

    @unittest.skipIf(os.geteuid() == 0, 'Ordinary-user bridge serialization required')
    def test_writers_reload_and_read_live_only_inside_cross_process_lock(self):
        with tempfile.TemporaryDirectory(prefix='pp-bridge-writers-') as folder:
            root = Path(folder)
            script = f'''emulate -L zsh
set -u
CFG_DIR='{folder}'
{power.function('prepare_bridge_writer')}
warn() {{ print -ru2 -- "$*"; }}
load_config() {{ print "reload" >> "$CFG_DIR/events"; }}
load_bridge_vpn() {{ print "live" >> "$CFG_DIR/events"; }}
is_enabled() {{ return 0; }}
prepare_bridge_writer ensure || exit 1
print begin >> "$CFG_DIR/events"
sleep 0.1
print end >> "$CFG_DIR/events"
'''
            children = [subprocess.Popen(['/bin/zsh', '-f', '-c', script],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         text=True) for _ in range(3)]
            for child in children:
                out, err = child.communicate(timeout=8)
                self.assertEqual(child.returncode, 0, out + err)
            self.assertEqual((root / 'events').read_text().splitlines(),
                             ['reload', 'live', 'begin', 'end'] * 3)

    @unittest.skipIf(os.geteuid() == 0, 'Ordinary-user bridge serialization required')
    def test_disable_and_stop_remain_available_without_helper(self):
        for command in ('disable', 'stop'):
            with tempfile.TemporaryDirectory(prefix='pp-bridge-stop-') as folder:
                script = f'''emulate -L zsh
CFG_DIR='{folder}'
{power.function('prepare_bridge_writer')}
load_config() {{ return 0; }}
load_bridge_vpn() {{ print UNEXPECTED_QUERY; return 1; }}
prepare_bridge_writer {command}
'''
                result = subprocess.run(['/bin/zsh', '-f', '-c', script],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('UNEXPECTED_QUERY', result.stdout)

    @unittest.skipIf(os.geteuid() == 0, 'Ordinary-user bridge serialization required')
    def test_symlink_lock_rejected(self):
        with tempfile.TemporaryDirectory(prefix='pp-bridge-link-') as folder:
            root = Path(folder)
            (root / 'foreign').write_text('unchanged')
            (root / 'bridge.lock').symlink_to(root / 'foreign')
            script = f'''emulate -L zsh
CFG_DIR='{folder}'
{power.function('prepare_bridge_writer')}
prepare_bridge_writer ensure
'''
            result = subprocess.run(['/bin/zsh', '-f', '-c', script],
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((root / 'foreign').read_text(), 'unchanged')

    @unittest.skipIf(os.geteuid() == 0, 'Ordinary-user bridge serialization required')
    def test_failed_preflight_stops_before_command_mutations(self):
        with tempfile.TemporaryDirectory(prefix='pp-bridge-denied-') as folder:
            script = f'''emulate -L zsh
CFG_DIR='{folder}'
{power.function('prepare_bridge_writer')}
warn() {{ return 0; }}
load_config() {{ return 0; }}
load_bridge_vpn() {{ return 1; }}
is_enabled() {{ return 0; }}
prepare_bridge_writer ensure || exit 69
print UNEXPECTED_MUTATION
'''
            result = subprocess.run(['/bin/zsh', '-f', '-c', script],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 69, result.stderr)
            self.assertNotIn('UNEXPECTED_MUTATION', result.stdout)

    @unittest.skipIf(os.geteuid() == 0, 'Ordinary-user bridge serialization required')
    def test_off_preference_and_absent_bridge_do_not_query_vpn(self):
        for arguments in ('route socks', 'ensure', 'shellenv', 'set HTTP_UPSTREAM example:3128'):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory(
                    prefix='pp-bridge-off-') as folder:
                script = f'''emulate -L zsh
CFG_DIR='{folder}'
{power.function('prepare_bridge_writer')}
load_config() {{ return 0; }}
is_enabled() {{ return 1; }}
running_mode() {{ print none; }}
load_bridge_vpn() {{ print UNEXPECTED_QUERY; return 1; }}
prepare_bridge_writer {arguments}
'''
                result = subprocess.run(['/bin/zsh', '-f', '-c', script],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('UNEXPECTED_QUERY', result.stdout)
