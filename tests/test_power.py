"""Regression tests using production zsh functions with isolated OS boundaries.

No user config, real bridge, proxy settings or local network are touched.
Run: python3 -m unittest discover -s tests -v
"""
from pathlib import Path
import json
import re
import subprocess
import tempfile
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / 'bin/proxypilot').read_text()


def function(name):
    start = re.search(r'^' + re.escape(name) + r'\(\) \{.*$', SOURCE, re.M)
    if start.group().endswith('}'):
        return start.group()
    end = re.search(r'^\}', SOURCE[start.end():], re.M)
    return SOURCE[start.start():start.end() + end.end()]


class PowerTests(unittest.TestCase):
    def test_socks_detection_requires_no_auth(self):
        for reply, expected in [(r'\x05\x00', 0), (r'\x05\x02', 1), (r'\x05\xff', 1), (r'\x04\x00', 1)]:
            out = self.run_zsh(['is_socks5'], f'''
nc() {{ cat >/dev/null; printf '{reply}'; }}
is_socks5 proxy.example 1080
print "code=$?"
''')
            self.assertIn(f'code={expected}', out)

    def run_zsh(self, names, body):
        with tempfile.TemporaryDirectory(prefix='proxypilot-test-') as directory:
            prelude = f'''emulate -L zsh
set -u
CFG_DIR='{directory}'
CFG="$CFG_DIR/config"
MODE_FILE="$CFG_DIR/mode"
ENABLED_FILE="$CFG_DIR/enabled"
LOG="$CFG_DIR/log"
BRIDGE_PORT=43129
SOCKS_UPSTREAM=""
HTTP_UPSTREAM="old.example:3128"
OFFICE_GATEWAYS=""
NO_PROXY_LIST=localhost,127.0.0.1
NET_SERVICE=Wi-Fi
GOST=/usr/bin/true
ok() {{ print -r -- "$*"; }}
warn() {{ print -ru2 -- "$*"; }}
die() {{ print -ru2 -- "$*"; exit 1; }}
c_dim() {{ print -r -- "$*"; }}
touch "$CFG"
'''
            script = prelude + '\n'.join(function(n) for n in names) + '\n' + body
            result = subprocess.run(['/bin/zsh', '-f', '-c', script], capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return result.stdout

    def test_off_does_not_resurrect_stopped_bridge(self):
        out = self.run_zsh(['need_config', 'is_enabled', 'cmd_ensure'], '''
print off > "$ENABLED_FILE"
effective_mode() { print socks; }
running_mode() { print none; }
start_bridge() { print UNEXPECTED_START; }
cmd_ensure
print done
''')
        self.assertEqual(out.strip(), 'done')

    def test_off_converts_existing_bridge_to_direct(self):
        out = self.run_zsh(['need_config', 'is_enabled', 'cmd_ensure'], '''
print off > "$ENABLED_FILE"
effective_mode() { print socks; }
running_mode() { print socks; }
gateway() { print test; }
gost_nameservers() { print 1.1.1.1; }
bridge_pid() { print fake; }
stop_bridge() { print stopped; }
start_bridge() { print "start:$1"; }
cmd_ensure
''')
        self.assertIn('start:direct', out)

    def test_ensure_upgrades_http_only_bridge_once(self):
        out = self.run_zsh(['need_config', 'is_enabled', 'cmd_ensure'], '''
print on > "$ENABLED_FILE"
effective_mode() { print direct; }
running_mode() { print direct; }
gateway() { print same; }
gost_nameservers() { print 1.1.1.1; }
print same > "$CFG_DIR/bridge-gateway"
print 1.1.1.1 > "$CFG_DIR/bridge-dns"
bridge_pid() { print fake; }
stop_bridge() { print stopped; }
start_bridge() { print started; print "auto-v1:$BRIDGE_PORT" > "$CFG_DIR/bridge-format"; }
cmd_ensure
cmd_ensure
''')
        self.assertEqual(out.count('started'), 1)
        self.assertEqual(out.count('stopped'), 1)

    def test_off_shellenv_preserves_other_proxies(self):
        out = self.run_zsh(['is_enabled', 'cmd_shellenv'], '''
print off > "$ENABLED_FILE"
http_proxy=http://127.0.0.1:43129
https_proxy=http://other.example:8000
eval "$(cmd_shellenv)"
print "own=${http_proxy:-unset} other=$https_proxy"
''')
        self.assertIn('own=unset other=http://other.example:8000', out)

    def test_bridge_failure_rolls_back_enabled(self):
        out = self.run_zsh(['need_config', 'need_gost', 'cmd_switch', 'cmd_enable'], '''
resolve_auto() { print direct; }
stop_bridge() { return 0; }
start_bridge() { return 1; }
cmd_system() { print "system:$1" >> "$CFG_DIR/calls"; }
cmd_enable
print "code=$? enabled=$(< "$ENABLED_FILE")"
cat "$CFG_DIR/calls"
''')
        self.assertIn('code=1 enabled=off', out)
        self.assertIn('system:off', out)

    def test_system_denial_returns_failure(self):
        out = self.run_zsh(['need_config', 'system_points_here', 'cmd_system'], '''
build_bypass() { print localhost; }
system_services() { print Audit-WiFi; }
networksetup() { return 1; }
cmd_system on
print "on=$?"
cmd_system off
print "off=$?"
''')
        self.assertIn('on=1', out)
        self.assertIn('off=1', out)

    def test_off_does_not_disable_foreign_proxy(self):
        out = self.run_zsh(['system_points_here', 'cmd_system'], '''
system_services() { print Audit-WiFi; }
networksetup() {
  if [[ "$1" == -get* ]]; then print 'Enabled: Yes\nServer: other.example\nPort: 8000';
  else print 'MUTATED' >> "$CFG_DIR/mutations"; fi
}
cmd_system off
[[ ! -f "$CFG_DIR/mutations" ]] && print preserved
''')
        self.assertIn('preserved', out)

    def test_disable_failure_keeps_bridge_and_state(self):
        out = self.run_zsh(['cmd_disable'], '''
print on > "$ENABLED_FILE"
cmd_system() { return 1; }
cmd_ensure() { print UNEXPECTED_ENSURE; }
cmd_disable
print "code=$? enabled=$(< "$ENABLED_FILE")"
''')
        self.assertIn('code=1 enabled=on', out)
        self.assertNotIn('UNEXPECTED', out)

    def test_detect_reloads_config_and_preserves_profile(self):
        out = self.run_zsh(['load_config', 'cmd_set', 'cmd_detect'], '''
print 'VPN_AUTO=off\nOFFICE_IP=192.0.2.10' > "$CFG"
scutil() { if [[ "$1" == --proxy ]]; then print 'HTTPProxy : new.example\nHTTPPort : 3128'; fi; }
tcp_open() { [[ "$1" == new.example ]]; }
is_socks5() { return 1; }
gateway() { print 192.0.2.1; }
cmd_enable() { print "enable_uses=$HTTP_UPSTREAM office=$OFFICE_IP"; }
cmd_detect
''')
        self.assertIn('enable_uses=new.example:3128 office=192.0.2.10', out)

    def test_setup_rejects_invalid_and_loopback_before_network(self):
        for endpoint in ['ftp://proxy:21', 'http://proxy:0', 'http://proxy:65536', 'http://127.0.0.1:3129', 'http://user:pass@proxy:80']:
            with self.subTest(endpoint=endpoint):
                out = self.run_zsh(['cmd_setup'], f'''
tcp_open() {{ print UNEXPECTED_NETWORK; }}
(cmd_setup '{endpoint}')
print "code=$?"
''')
                self.assertIn('code=1', out)
                self.assertNotIn('UNEXPECTED', out)

    def test_partial_system_proxy_is_not_connected(self):
        out = self.run_zsh(['saved_mode', 'is_enabled', 'json_string', 'cmd_app_state'], '''
print on > "$ENABLED_FILE"
running_mode() { print socks; }
scutil() { print 'HTTPEnable : 1\nHTTPProxy : 127.0.0.1\nHTTPPort : 43129\nHTTPSEnable : 0'; }
cmd_app_state
''')
        self.assertIn('"system_proxy":false', out)
        self.assertIn('"owns_system_proxy":true', out)

    def test_json_string_escapes_config_values(self):
        out = self.run_zsh(['json_string'], r'''
json_string $'host"\\\n\t\001:3128'
''')
        self.assertEqual(json.loads(out), 'host"\\\n\t\x01:3128')

    def test_setup_preserves_other_protocol(self):
        for scheme in ('socks5', 'http'):
            out = self.run_zsh(['cmd_setup'], f'''
SOCKS_UPSTREAM=old-socks.example:1080
HTTP_UPSTREAM=old-http.example:3128
tcp_open() {{ return 0; }}
is_socks5() {{ return 0; }}
cmd_set() {{ typeset -g "$1"="$2"; }}
load_config() {{ return 0; }}
cmd_enable() {{ print "mode=$1 socks=$SOCKS_UPSTREAM http=$HTTP_UPSTREAM"; }}
cmd_setup {scheme}://new.example:9999
''')
            if scheme == 'socks5':
                self.assertIn('mode=socks socks=new.example:9999 http=old-http.example:3128', out)
            else:
                self.assertIn('mode=http socks=old-socks.example:1080 http=new.example:9999', out)

    def test_route_off_saves_without_enabling_or_probing(self):
        out = self.run_zsh(['need_config', 'saved_mode', 'is_enabled', 'cmd_route'], '''
print off > "$ENABLED_FILE"
tcp_open() { print UNEXPECTED_PROBE; return 1; }
cmd_enable() { print UNEXPECTED_ENABLE; }
cmd_route http
print "selected=$(saved_mode) enabled=$(< "$ENABLED_FILE")"
''')
        self.assertIn('selected=http enabled=off', out)
        self.assertNotIn('UNEXPECTED', out)

    def test_unavailable_route_keeps_current_connection(self):
        out = self.run_zsh(['need_config', 'saved_mode', 'is_enabled', 'cmd_route'], '''
print on > "$ENABLED_FILE"
print direct > "$MODE_FILE"
tcp_open() { return 1; }
cmd_enable() { print UNEXPECTED_ENABLE; }
cmd_route http
print "code=$? selected=$(saved_mode) enabled=$(< "$ENABLED_FILE")"
''')
        self.assertIn('code=1 selected=direct enabled=on', out)
        self.assertNotIn('UNEXPECTED', out)

    def test_route_failure_restores_previous_preference(self):
        out = self.run_zsh(['need_config', 'saved_mode', 'is_enabled', 'cmd_route'], '''
print on > "$ENABLED_FILE"
print direct > "$MODE_FILE"
tcp_open() { return 0; }
cmd_enable() { print "try:$1"; print "$1" > "$MODE_FILE"; [[ "$1" == direct ]]; }
cmd_route http
print "code=$? selected=$(saved_mode)"
''')
        self.assertIn('try:http', out)
        self.assertIn('code=1 selected=direct', out)

    def test_route_enable_uses_selected_route(self):
        out = self.run_zsh(['need_config', 'saved_mode', 'is_enabled', 'cmd_route'], '''
print off > "$ENABLED_FILE"
print http > "$MODE_FILE"
tcp_open() { return 0; }
cmd_enable() { print "enable:$1"; }
cmd_route http enable
''')
        self.assertIn('enable:http', out)

    def test_route_rejects_unconfigured_and_invalid(self):
        for mode in ('socks', 'invalid'):
            out = self.run_zsh(['need_config', 'saved_mode', 'is_enabled', 'cmd_route'], f'''
print on > "$ENABLED_FILE"
print auto > "$MODE_FILE"
cmd_enable() {{ print UNEXPECTED_ENABLE; }}
cmd_route {mode}
print "code=$? selected=$(saved_mode)"
''')
            self.assertIn('code=1 selected=auto', out)
            self.assertNotIn('UNEXPECTED', out)

    def test_system_proxy_success_is_verified(self):
        out = self.run_zsh(['need_config', 'system_points_here', 'cmd_system'], '''
build_bypass() { print localhost; }
system_services() { print Audit-WiFi; }
networksetup() {
  [[ "$1" == -get* ]] && print 'Enabled: Yes\nServer: 127.0.0.1\nPort: 43129'
  return 0
}
cmd_system on
print "code=$?"
''')
        self.assertIn('code=0', out)


if __name__ == '__main__':
    unittest.main()
