<div align="center">

<img src=".github/assets/logo.png" width="120" alt="ProxyPilot">

# ProxyPilot

**One local proxy address. Switchable route out.**

[![Build](https://github.com/jamber751/proxy-pilot/actions/workflows/ci.yml/badge.svg)](https://github.com/jamber751/proxy-pilot/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jamber751/proxy-pilot)](https://github.com/jamber751/proxy-pilot/releases/latest)
[![macOS](https://img.shields.io/badge/macOS-11%2B-black?logo=apple)](https://github.com/jamber751/proxy-pilot/releases/latest)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**[jamber751.github.io/proxy-pilot](https://jamber751.github.io/proxy-pilot/)**

</div>

Corporate HTTP proxies often shape traffic while a fast SOCKS5 endpoint sits on
the same network. In our office the gap was fourfold — 630 KB/s vs 2552 KB/s.

The catch: **plenty of tools don't speak SOCKS.** Claude Code (undici) says so
outright — `UnsupportedProxyProtocol`.

ProxyPilot runs an HTTP-CONNECT bridge on `127.0.0.1:3129` and routes it out
through SOCKS5, an HTTP proxy, or straight out:

```
   Claude Code ─┐                                  ┌─ SOCKS5   ⚡ fast
   curl / git  ─┼─→  127.0.0.1:3129  ──mode──→     ├─ HTTP     🐢 fallback
   browser     ─┘      (never changes)             └─ direct   ⇢ off-site
```

**Why it matters:** the address your clients use never changes, so switching
routes doesn't restart them. `auto` mode picks the route from the network —
take the laptop home and the proxy switches itself off.

“From the network” means the address and gateway of the **physical** interface,
matched against `OFFICE_GATEWAYS`. Not upstream reachability: on a VPN from home
the office proxy answers too, and routing every request through it would be a
detour through the office — office hosts already travel the tunnel by route and
skip the bridge by `NO_PROXY_LIST`. Leave `OFFICE_GATEWAYS` empty and `auto`
falls back to the old “first upstream that answers” behaviour.

## Install

Grab the DMG from [Releases](https://github.com/jamber751/proxy-pilot/releases/latest)
→ right-click **`Install.command`** → Open. It copies the app to Applications,
clears quarantine, offers Login Items and launches.

Self-contained (CLI and gost ship inside), universal, macOS 11+. No Homebrew,
no terminal.

> Ad-hoc signed, not Developer ID — the first launch needs right-click → Open.

<sub>From source: `git clone https://github.com/jamber751/proxy-pilot.git && cd proxy-pilot && ./install.sh`</sub>

## Use it

Everything lives in the menu bar icon, which shows the active route (⚡ SOCKS5 ·
🐢 HTTP · ⇢ direct). Click to switch routes, benchmark, run diagnostics or open
**Settings (⌘,)** — proxy addresses with live reachability dots, bridge port,
office gateway prefixes, all with a "Find on network" button that discovers
proxies for you. On first launch it does that automatically.

For GUI apps set the system proxy once — **System Settings → Network → Wi-Fi →
Details → Proxies** → HTTP and HTTPS to `127.0.0.1:3129`, SOCKS **off**. After
that you never touch it again; the address is constant.

<details>
<summary><b>CLI</b> — same thing from the terminal</summary>

| Command | What it does |
|---|---|
| `proxypilot detect` | find proxies on this network, write a config |
| `proxypilot bench` | compare routes: direct / http / socks5 |
| `proxypilot status` · `doctor` | current state · diagnose problems |
| `proxypilot socks` · `http` · `direct` · `auto` | switch route |
| `proxypilot set KEY VALUE` | write a config key (validated) |
| `proxypilot json` | machine-readable state |
| `proxypilot shellenv` | `eval "$(proxypilot shellenv)"` in `.zshrc` |
| `proxypilot net` · `net install` | network profile: where you are, apply it on every network change |
| `proxypilot vpn` · `vpn install FILE.ovpn` | split-tunnel from an OpenVPN profile |
| `proxypilot vpn auto on` · `vpn up` · `vpn down` | tunnel: automatic outside the office, or by hand |

Config lives in `~/.config/proxypilot/config` (`KEY=VALUE`) and is what the
Settings window edits — through `proxypilot set`, so only the CLI knows the
format.

`bench` uses one stream and a short file on purpose: it compares routes against
each other, not your bandwidth. Measure the line with fast.com.

</details>

<details>
<summary><b>Gotchas</b> — two things that cost real debugging time</summary>

**CIDR in `no_proxy` is not enough.** `curl` and `git` understand
`192.168.0.0/16`; **Node/Bun and python-requests don't** — they match an exact
hostname or a dot-suffix. Claude Code is Bun/undici, i.e. the second group. List
important local hosts explicitly:

```sh
NO_PROXY_LIST=localhost,127.0.0.1,::1,.local,192.168.0.0/16,192.168.1.4,my-server.internal
```

Also: `curl` ignores `HTTP_PROXY` for `http://` URLs (lowercase `http_proxy`
only) — `shellenv` exports both.

**`no route to host` while the network is fine.** On macOS 15+ that's the Local
Network privacy gate. The permission belongs to whichever process opens the
connection, so the bridge runs as a child of `ProxyPilot.app` and inherits it —
which is exactly why it is *not* a LaunchAgent. Check System Settings →
Privacy & Security → Local Network.

Logs: `~/Library/Logs/proxypilot.log` (bridge), `proxypilot-app.log` (app).

</details>

<details>
<summary><b>Network profile and VPN</b> — optional, off by default</summary>

The same question `auto` answers — *am I in the office?* — decides two more
things. In the office your access is often granted to a fixed IP, so a static
address is required there; in any other network that same static address from a
foreign subnet means “no internet”. And the VPN behind the office is needed
exactly the other way round: outside.

```
office     → static IP + office DNS,  tunnel down (you are already inside)
elsewhere  → DHCP,                    tunnel up
```

Both halves are independent and disabled unless configured: empty `OFFICE_IP` —
the address is left alone, `VPN_AUTO=off` — the tunnel is yours to raise by hand.

```sh
proxypilot set OFFICE_IP 192.168.8.246       # empty = don't touch the address
proxypilot set OFFICE_MASK 255.255.255.0
proxypilot set OFFICE_DNS "192.168.8.1 8.8.8.8"
sudo proxypilot net install                  # apply on every network change

proxypilot set VPN_PROFILE ~/office.ovpn
sudo proxypilot vpn install                  # build split-tunnel, install daemon
proxypilot vpn auto on                       # up outside, down in the office
```

Everything is also in Settings (⌘,) — the same keys, plus buttons for the steps
that need a password.

**Why the office test is strict.** “Can I ping the office gateway” is not enough:
from home over the VPN it answers too, and the script would set the office static
IP in your home network — cutting the machine off. The gateway must answer
*behind the physical interface*, and the address is checked alongside the gateway
because a static setup has no DHCP lease to read.

**Why split-tunnel needs explicit routes.** Servers usually push
`redirect-gateway` and push *no* routes into office subnets — so everything,
video included, detours through the office, at the routing level. `vpn install`
takes your `.ovpn`, drops the pushed default (`pull-filter ignore
"redirect-gateway"`) and adds `route` lines for the office instead — by default a
`/16` around the office network, since office hosts tend to be scattered across
neighbouring subnets. The subnet the laptop physically sits in is unaffected: its
own route is more specific than any `/16`.

The built config lives in `/usr/local/etc/proxypilot-vpn/office.conf`, mode `600`,
owned by root — it embeds your private key. `proxypilot vpn uninstall` removes it.

Changing IPv4 is root-only in macOS (`is-root` on
`system.services.systemconfiguration.network`), unlike proxy settings — hence the
LaunchDaemon and the password prompt. Logs: `/var/log/proxypilot-net.log`,
`/var/log/proxypilot-vpn.log`.

Two tunnels at once fight over routes, so a tunnel raised by another client
(OpenVPN Connect, Tunnelblick) is detected and left alone. “Another client”
means a tunnel that already carries a route into your office subnets — not any
`utun` with an address, so a permanently-up Tailscale or WireGuard link doesn't
block the office tunnel from coming up.

</details>

## How it works

`bin/proxypilot` (zsh) holds the logic; `app/main.swift` is a menu bar front end
over `proxypilot json`; the bridge itself is [gost](https://github.com/go-gost/gost).
ProxyPilot proxies nothing and stores no secrets — it picks the upstream and
keeps the bridge in the right mode.

`./make-dmg.sh` builds a release. The gost binary isn't committed (git would
keep 25 MB forever) — the script downloads the official release for both
architectures, verifies pinned SHA-256 and merges with `lipo`. CI builds every
push and attaches a DMG to every `v*` tag.

## License

MIT — see [LICENSE](LICENSE).
