# VPN support package (acceptance candidate)

This is an opt-in, scripts-only macOS 11 package. It installs an authenticated
**idle support service** and, with format 2, stores a verified OpenVPN engine.
It never executes that engine or applies a profile, routes or DNS. The install
package does not replace the app in Applications; the separately signed joint
update package can replace the exact authorized app and helper together. Neither
path changes the normal release build. Do not publish it as a working VPN feature.

Latest status (28 September 2026): an authorized native Apple Silicon/macOS 26.1
run installed signed A119 and completed the exact signed A119 → B120 joint app/helper
update. Installed B matched both expected architecture hashes, its ordinary-user
status reported release 120, the selected helper was ready, and the recovery job
retired. This closes one clean joint-update path, not release acceptance. The fixed
remove path passed a separate authorized sequence-121 system run; crash/reboot
recovery, Intel/macOS 11 execution, and integration with the default Sparkle flow
remain open.

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
4. For an update only, add the exact signed previous release with
   `package.py prepare-update --stage <stage> --previous-manifest <old-manifest>
   --previous-signature <old-signature>`. Then use `vpn-release-key
   sign-transition <old-manifest> <old-signature> <stage>/Payload/vpn-release.manifest
   <stage>/Payload/vpn-release.sig <stage>/Payload/vpn-update-transition
   <stage>/Payload/vpn-update-transition.sig`. The tool constructs the canonical
   A→B record itself and refuses non-forward or mismatched releases.
5. Run `python3 app/vpn-package/package.py build --stage <absolute-stage-directory>
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
  sequence and signed forward transition. The legacy helper-only mutation is
  disabled because it could select helper B while application A remained
  installed. The complete joint input is staged without stopping the service;
  candidate B then mutually authenticates and hands control to protected executor
  A. A owns drain, application replacement, live-B proof, helper readiness and
  forward recovery. One authorized native A119 → B120 joint replacement passed on
  Apple Silicon/macOS 26.1. Reboot/crash recovery, Intel/macOS 11 and the default
  release updater remain unaccepted; do not publish it yet.
- `--vpn-support-remove`: root only, stops the exact service and removes only
  recognized files; unexpected content aborts removal.
  Recognized content-addressed old engine versions are included in that cleanup.
  The first B120 system removal stopped the service and removed VPN storage, then
  failed when the shared parent still contained the intentionally retained
  `ProxyPilot/Update` directory. The implementation now preserves that sibling and
  passes focused tests. The corrected sequence-121 package also passed an authorized
  system run with a root-private retained `Update` marker present: it removed the
  service, endpoint, plist and VPN directory without consuming the marker.
  `/Applications/.ProxyPilot.vpn-update` has its own authenticated transaction
  cleanup and must not be treated as part of this directory-removal proof.

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

The 28 September recovery package restored the original ProxyPilot 1.5.1 after
the joint-update run. After the later corrected sequence-121 removal passed, a
scoped cleanup archived its exact retained marker. Both runs ended with system
labels, VPN support directories and application transaction stages clean.

Automated package/payload tests use a disposable embedded public key, synthetic
helper and an app whose normal GUI/CLI bootstrap traps. An optional complete
engine build is checked/copied into all three packages, without engine execution.
They never launch Installer,
touch personal profiles or access the real release key. Daemon tests use the
production service loop with test-only per-user paths and identity policy.
