### What's new in 1.4.0

- Minimal menu-bar popover anchored to the ProxyPilot icon; the large power button stays.
- Route picker: Auto, Direct, SOCKS5 and HTTP, with the actual active route shown separately.
- Saved proxy list; add or edit an IP/host and port, selecting the protocol without typing a URL.
- HTTP and SOCKS5 clients share the local loopback port, including Telegram.
- Error handling, configuration preservation and isolated regression tests.

### Install

Download the DMG below → right-click **`Install.command`** → **Open**.

The script copies the app to Applications, clears the quarantine flag, offers to
add it to Login Items and launches it. Press **Find automatically** in ProxyPilot,
or use the gear icon and **+** to enter your proxy address.

Self-contained: the CLI and `gost` ship inside the bundle — no Homebrew, no
terminal. Universal binary (Intel + Apple Silicon), macOS 11 Big Sur and newer.

> A plain double-click is blocked: the app is ad-hoc signed, not Developer ID.
> Right-click → Open is the way around it. `READ_ME_FIRST.txt` inside the image
> explains the manual path too.

### After installing

The power button applies/removes ProxyPilot's macOS HTTP/HTTPS proxy settings.
Switching routes keeps the local address unchanged. Turning off leaves an
existing local bridge forwarding directly, so terminal and Telegram clients
can continue working. This is not a kill switch or a VPN.

Telegram: choose SOCKS5, server `127.0.0.1`, port `3129`, no username/password.
The listener is local to your Mac. UDP relay and Telegram calls are not verified.

Startup checks the saved state and bridge; it does not reapply system proxy
settings that were changed outside ProxyPilot. If necessary, turn the proxy
off/on. Settings currently support one address per protocol, without proxy
authentication or IPv6. Legacy VPN/network-profile commands remain CLI-only.

Full documentation: [README](https://github.com/jamber751/proxy-pilot#readme)
