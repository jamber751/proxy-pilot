### Install

Download the DMG below → right-click **`Install.command`** → **Open**.

The script copies the app to Applications, clears the quarantine flag, offers to
add it to Login Items and launches it. On first launch ProxyPilot discovers
proxies on your network by itself and opens Settings for confirmation.

Self-contained: the CLI and `gost` ship inside the bundle — no Homebrew, no
terminal. Universal binary (Intel + Apple Silicon), macOS 11 Big Sur and newer.

> A plain double-click is blocked: the app is ad-hoc signed, not Developer ID.
> Right-click → Open is the way around it. `READ_ME_FIRST.txt` inside the image
> explains the manual path too.

### After installing

For GUI apps set the system proxy once — **System Settings → Network → Wi-Fi →
Details → Proxies** → HTTP and HTTPS to `127.0.0.1:3129`, SOCKS **off**. You
never touch it again: switching routes happens inside the bridge, so the address
your clients use stays constant.

Full documentation: [README](https://github.com/jamber751/proxy-pilot#readme)
