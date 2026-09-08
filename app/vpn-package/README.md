# VPN support package (acceptance candidate)

This is an opt-in, scripts-only macOS 11 package. It installs an authenticated
**idle support service** and, with format 2, stores a verified OpenVPN engine.
It never executes that engine or applies a profile, routes or DNS. It neither replaces
the app in Applications nor changes the normal release build. Do not publish it
as a working VPN feature.

## Build and sign

1. Build a fresh app with `PROXYPILOT_ISOLATED_UPDATER=1` and
   `PROXYPILOT_VPN_INSTALLER=1` using `app/build.sh`. Build the Universal helper
   using `zsh app/vpn-helper/build.sh <new-absolute-output-directory>`.
2. Run `python3 app/vpn-package/package.py prepare --app <absolute-ProxyPilot.app>
   --helper <absolute-vpn-helper> --sequence <next-sequence>
   --engine-artifact <absolute-engine-build/artifact>
   --output <new-absolute-stage-directory>`. Use the complete output of
   `app/vpn-engine/build.py`: exact source archives, current reviewed recipe,
   provenance and upstream license notices are required. Omitting the engine
   option prepares a legacy helper-only format-1 package.
3. Review the manifest. Sign `Payload/vpn-release.manifest` into the prepared
   `Payload/vpn-release.sig` using the existing `app/vpn-release-key.swift` tool
   and the existing VPN release Keychain key. Never generate/rotate a key merely
   to make a package pass. The packager does not access the Keychain.
4. Run `python3 app/vpn-package/package.py build --stage <absolute-stage-directory>
   --action install --output <new-absolute-package.pkg>`.
   Build `update` and `remove` packages the same way with distinct output paths.

No output is overwritten. `Payload` contains exactly the sealed app, helper,
manifest, signature and (for format 2) the fixed `vpn-engine` sidecar. `EngineSources`
is separate distribution material: pinned archives, recipe, provenance and license
notices. Publish that material alongside any eventual engine distribution; it is
not copied into the app seal or the privileged installation. Package creation
refuses missing/modified source archives, recipe or license notices. No user
config, profile or private key belongs in the stage.
The manifest must stay **beside**, not inside, the app whose final CDHashes it
pins. Changing or resigning that app afterwards invalidates the package.
The same signature binds both engine architecture pins, SHA-256, size and
OpenVPN/OpenSSL versions. Copying never executes the engine or supplied scripts.

## Authorization and fixed entry points

Open the package in the standard macOS Installer. Only macOS can grant its
administrative authorization. `preinstall` verifies the copied, signed materials
without system writes; `postinstall` invokes the **same pinned app executable**
with one fixed action. Environment is cleared. App/UI/proxy/updater startup is
not entered, and no paths, owner IDs or shell commands are accepted as arguments.

- `--vpn-support-verify`: validates the package, with no installed-service access.
- `--vpn-support-status`: ordinary-user, mutually authenticated status only.
- `--vpn-support-install`: root only, refuses an existing installation; the
  initial owner is the active local console user, not an environment variable.
- `--vpn-support-update`: root only, preserves the owner and enforces the current
  sequence and signed forward transition. Both binaries are staged and validated
  before the running service stops; one atomic record selects the complete set.
  Failure never becomes first install, component downgrade or silent repair.
- `--vpn-support-remove`: root only, stops the exact service and removes only
  recognized files; unexpected content aborts removal.
  Recognized content-addressed old engine versions are included in that cleanup.

The normal GUI is never allowed to run as root, including in non-candidate builds.
The separate updater cannot enroll a new VPN release through IPC.

## Acceptance boundaries

Before installing, inspect the exact targets and stop if they belong to an
existing installation:

- `/Library/Application Support/ProxyPilot/VPN`
- `/Library/Application Support/kz.documentolog.proxypilot.vpn`
- `/Library/LaunchDaemons/kz.documentolog.proxypilot.vpn-helper.plist`
- `system/kz.documentolog.proxypilot.vpn-helper`

Verify authorization cancellation leaves them absent. After an authorized
installation, use the staged app's `--vpn-support-status` as the ordinary console
user: successful package verification alone is not root-to-user IPC evidence.
Then check update, old-client rejection, recovery and removal. Failed installation
may leave the selected idle service on disk; inspect it and use the known remove
package, never recursively delete an unknown directory. Native Installer history
is not erased. A real reboot and execution on macOS 11/Intel remain distinct from
simulated per-user service restart and cross-compilation.

Automated package/payload tests use a disposable embedded public key, synthetic
helper and an app whose normal GUI/CLI bootstrap traps. An optional complete
engine build is checked/copied into all three packages, without engine execution.
They never launch Installer,
touch personal profiles or access the real release key. Daemon tests use the
production service loop with test-only per-user paths and identity policy.
