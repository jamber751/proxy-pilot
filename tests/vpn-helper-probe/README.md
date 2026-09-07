# VPN helper installation probe — not a VPN service

This is an isolated stage-1 experiment. It is **not included in ProxyPilot.app**, the
DMG or the release workflow. Building and running the automated tests does not
install anything or request administrator access.

The probe accepts exactly one XPC method: return wire/build versions, PID and
effective UID. It accepts no profile, password, command, executable or file path.
It cannot start OpenVPN, change routes/DNS/proxies, or read application settings.
The public diagnostic endpoint is intentionally unauthenticated. **A successful
root ping is not proof of secure authorization for production VPN operations.**
Caller authentication and operation-specific authorization remain a separate gate;
an ad-hoc bundle identifier is not an identity guarantee.

## Build and isolated tests

From the repository root:

```sh
python3 -m unittest discover -s tests -p 'test_vpn_helper_probe.py' -v
```

For packages to inspect manually, pass a new absolute directory to `build.sh`:

```sh
zsh tests/vpn-helper-probe/build.sh /tmp/proxypilot-probe-review
```

The script refuses an existing output path. It builds arm64 and x86_64 for macOS
11, ad-hoc signs the executable, and creates unsigned macOS Installer packages
with explicit macOS 11 metadata and legacy-compatible compression:

- `ProxyPilot-VPN-Probe-0.0.1.pkg` — initial installation.
- `ProxyPilot-VPN-Probe-0.0.2.pkg` — same label and wire protocol, different build.
- `Remove-ProxyPilot-VPN-Probe.pkg` — stop the probe and remove its two files.

The isolated suite tests real anonymous XPC (not registered with launchd), version
rejection, reconnection, missing-service errors, universal binaries, signatures,
package payload/ownership, and script refusal when not root. It does **not** test
system authorization, a root daemon, Installer cancellation, or live upgrades.

## Manual installation gate — explicit owner approval required

Use macOS Installer, not a hidden elevation script. Packages are unsigned and the
probe executable is ad-hoc signed; downloaded/quarantined distribution and macOS
11/Intel must be checked separately. Do not disable Gatekeeper/SIP or remove
quarantine attributes to manufacture a successful result.

Before installation, verify the following label, files and receipt are absent;
stop if they unexpectedly exist. Do not touch legacy `pro.proxypilot.vpn`.

- Service and installation receipt: `kz.documentolog.proxypilot.vpn-probe`.
- `/Library/LaunchDaemons/kz.documentolog.proxypilot.vpn-probe.plist`.
- `/Library/PrivilegedHelperTools/kz.documentolog.proxypilot.vpn-probe`.

Record each result in `docs/vpn-implementation-plan.md`:

1. Open the 0.0.1 package, cancel the administrator prompt and check no files,
   receipt or service appeared.
2. Install 0.0.1. Its postinstall checks root XPC; also run the **unprivileged**
   staged 0.0.1 binary with `--check-installed` and record the returned PID/version.
3. Repeat the client check: the PID should be unchanged. Close/reopen the client.
4. Cancel installation of 0.0.2 before authorization; check 0.0.1 still responds.
5. Install 0.0.2. Verify a new PID/build; the old client must exit 65 (mismatch),
   while the staged 0.0.2 client succeeds. Reinstall 0.0.2 and check again.
6. Install the removal package. Verify both files and the service are gone and
   `--check-installed` exits 69. Repeat removal to check idempotence.

Removal forgets the installation receipt. Standard Installer history remains;
on the tested macOS 26.1 machine, `pkgutil` reported no separate receipt for the
script-only removal package. Any Installer records are not a running service.
Removal does not recursively delete directories.

The probe deliberately does not implement failed-upgrade rollback or production
authorization. A failed package postinstall can leave the inert probe installed;
use the removal package and record the failure. Do not treat that outcome as
production update readiness. A successful local experiment on a development Mac
is not a clean-machine or release-distribution acceptance test.
