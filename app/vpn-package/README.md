# VPN support package (acceptance candidate)

This is an opt-in, scripts-only macOS 11 package. It installs an authenticated
**idle support service** and, with format 2, stores a verified OpenVPN engine.
It never executes that engine or applies a profile, routes or DNS. The install
package does not replace the app in Applications; the separately signed joint
update package can replace the exact authorized app and helper together. Neither
path changes the normal release build. Do not publish it as a working VPN feature.

Latest system status (28 September 2026): an authorized native Apple Silicon/macOS 26.1
run installed signed A119 and completed the exact signed A119 → B120 joint app/helper
update. Installed B matched both expected architecture hashes, its ordinary-user
status reported release 120, the selected helper was ready, and the recovery job
retired. This closes one clean joint-update path, not release acceptance. The fixed
remove path passed a separate authorized sequence-121 system run; crash/reboot
recovery, Intel/macOS 11 execution, and integration with the default Sparkle flow
remain open.

Latest local transport status (29 September 2026): the production release key
assembled an unpublished universal B123 companion for the signed A122 → B123
edge. Its metadata, signature, exact byte count and SHA-256 verified; the
production read-only mount boundary accepted the real DMG; and the sealed B app
inside it accepted the complete joint payload through
`--vpn-support-verify-update`. Truncated metadata, signature and artifact copies
were rejected. Before/after checks showed no change to the installed app, system
VPN/Broker directories or launchd plists. Both candidates use technical version
1.5.1, so this is pre-Broker artifact acceptance only, not Sparkle discovery or
release evidence.

## Build and sign

The preferred local assembly is `app/build-joint-release.sh <next-sequence>
<previous-manifest> <previous-signature> <engine-artifact>
<universal-gost> <new-absolute-output-directory>`. It verifies that the existing Keychain key
matches the embedded public key, performs all steps below, verifies the final
DMG against its signed metadata, and preserves the new signed release sidecars
for the next forward update. It also emits one bounded
`ProxyPilot-<version>-vpn-engine-sources.tar.gz` containing the exact reviewed
source archives, recipe, provenance and notices corresponding to the signed
engine. It never tags, uploads, installs or elevates.

1. Choose the next canonical positive release sequence, then build a fresh app
   with `PROXYPILOT_ISOLATED_UPDATER=1`, `PROXYPILOT_VPN_INSTALLER=1` and
   `PROXYPILOT_VPN_RELEASE_SEQUENCE=<next-sequence>` using `app/build.sh`.
   The same value must be passed to `package.py prepare`; the packager refuses a
   mismatch after the value has been sealed by the app signature. The joint
   builder also requires an exact arm64+x86_64 GOST input, copies it into the
   app resources and re-signs/verifies the complete bundle before its CDHashes
   enter the release manifest. Build the Universal helper
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
6. For the one-click Broker flow, build the separate read-only transport image:
   `python3 app/vpn-package/package.py build-companion --stage <stage>
   --output <new-absolute-ProxyPilot-version-vpn-joint.dmg>`. This requires the
   complete format-2 joint payload (app, helper, engine, both signed releases and
   signed transition), runs the same update verification, creates a compressed
   read-only APFS image, verifies it, and publishes it atomically without
   overwrite. Its printed SHA-256 and byte count are release metadata, not VPN
   authority; the Broker still revalidates every inner signature and code pin.
7. Create and sign the transport-only sidecar without inventing release values:
   `package.py prepare-companion-metadata --stage <stage> --companion <dmg>
   --output <new-absolute-metadata>`, then `vpn-release-key sign-companion
   <metadata> <signature>`. Finally run `vpn-release-key
   verify-companion-artifact <metadata> <signature> <public-key-file> <dmg>`.
   The canonical metadata binds version, forward A→B sequence, byte count and
   SHA-256 in a domain separate from root authorization. Its artifact name and
   HTTPS GitHub release URL are derived by the app; neither is supplied by IPC.
8. Publish the generated engine-source archive beside the companion. The builder
   verifies it in memory before completion: only the fixed `EngineSources`
   layout is accepted, upstream hashes/notices and reviewed recipe must match,
   and provenance `binarySHA256` must equal the engine SHA-256 in the signed
   release manifest. Links, traversal, duplicate/extra entries and unbounded
   archives are refused; no carried code is executed or extracted.

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
