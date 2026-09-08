#!/bin/zsh -f
# Test boundary only. Selected production functions are appended by the test.
# No full CLI dispatch, user home, networksetup, scutil, launchd or VPN access.
emulate -L zsh
set -u
setopt pipe_fail
(( EUID != 0 )) || exit 64
fixture_contents="${0:A:h:h:h}"
fixture_info="$fixture_contents/Info.plist"
fixture_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$fixture_info")
[[ "$fixture_id" == kz.documentolog.proxypilot.workercheck.* ]] || exit 64
fixture_root=$(/usr/libexec/PlistBuddy -c 'Print :TestDirectory' "$fixture_info")
[[ -d "$fixture_root" && -f "$fixture_root/full-app-fixture" ]] || exit 64
PP_VERSION=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$fixture_info")
CFG_DIR="$fixture_root/state"
CFG="$CFG_DIR/config"
MODE_FILE="$CFG_DIR/mode"
ENABLED_FILE="$CFG_DIR/enabled"
LOG="$fixture_root/bridge.log"
GOST="$fixture_root/engine/gost"
BRIDGE_PORT=0
SOCKS_UPSTREAM=""
HTTP_UPSTREAM=""
NO_PROXY_LIST=""
NET_SERVICE=TestService

die() { print -ru2 -- "$*"; exit 1; }
warn() { print -ru2 -- "$*"; }
ok() { print -r -- "$*"; }
c_dim() { print -r -- "$*"; }
gateway() { print loopback-fixture; }
gost_nameservers() { print 127.0.0.1:9; }
resolve_auto() { die 'Auto detection is outside this test'; }
system_services() { print TestService; }

# Exact command equality, no regex/legacy port fallback or broad process search.
bridge_pid() {
    ps -axo pid=,command= | awk -v exe="$GOST" -v cfg="$CFG_DIR" '
      { pid=$1; $1=""; sub(/^ /, "");
        if ($0==exe" -C "cfg"/gost-socks.yaml" || $0==exe" -C "cfg"/gost-http.yaml" || $0==exe" -C "cfg"/gost-direct.yaml") print pid }'
}

# A tiny fake SystemConfiguration surface, persisted only inside the fixture.
networksetup() {
    [[ "${2:-}" == TestService ]] || die 'Unexpected network service'
    local kind flag=off
    case "$1" in
      (-getwebproxy|-getsecurewebproxy)
        kind=${${1#-get}%proxy}
        [[ -r "$CFG_DIR/system-$kind" ]] && flag=$(< "$CFG_DIR/system-$kind")
        print "Enabled: $([[ "$flag" == on ]] && print Yes || print No)\nServer: 127.0.0.1\nPort: $BRIDGE_PORT" ;;
      (-setwebproxy|-setsecurewebproxy)
        [[ "$3" == 127.0.0.1 && "$4" == "$BRIDGE_PORT" ]] || die 'Unexpected proxy endpoint'
        print -r -- "$1" >> "$CFG_DIR/system-writes" ;;
      (-setwebproxystate|-setsecurewebproxystate)
        [[ "$3" == (on|off) ]] || die 'Unexpected state'
        kind=${${1#-set}%proxystate}; print "$3" > "$CFG_DIR/system-$kind"
        print -r -- "$1:$3" >> "$CFG_DIR/system-writes" ;;
      (-setsocksfirewallproxystate) [[ "$3" == off ]] || die 'Unexpected SOCKS state' ;;
      (*) die 'Unexpected networksetup operation' ;;
    esac
}
scutil() {
    [[ "$1" == --proxy ]] || die 'Unexpected scutil operation'
    local web=0 secure=0
    [[ "$(< "$CFG_DIR/system-web")" == on ]] && web=1
    [[ "$(< "$CFG_DIR/system-secureweb")" == on ]] && secure=1
    print "HTTPEnable : $web\nHTTPPort : $BRIDGE_PORT\nHTTPProxy : 127.0.0.1\nHTTPSEnable : $secure\nHTTPSPort : $BRIDGE_PORT\nHTTPSProxy : 127.0.0.1"
}
