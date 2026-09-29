# Updates (free distribution)

ProxyPilot uses Sparkle 2.9.6, pinned to the SHA-256 in its tagged upstream
`Package.swift`. No Sparkle account, paid hosting or Apple Developer subscription
is required. This does **not** make the first install Developer ID signed or
notarized: macOS Gatekeeper prompts still apply.

## User experience

- Checks once per day while the app is running; no separate background daemon.
- The main ProxyPilot process does not load Sparkle. A fixed nested updater runs
  as the same ordinary user and has no VPN/helper/root authority.
- Settings shows the installed version, **Проверить обновления**, and an opt-out
  **Проверять автоматически** checkbox.
- Scheduled discoveries add a dot to the gear and an update button in Settings;
  they do not steal focus. Explicit checks use Sparkle's standard native UI.
- No automatic downloads/installations or forced restart. The user confirms
  installation. Sparkle may request administrator authorization if the app is
  not writable by the current user.
- The update window uses compact English HTML notes from `.github/update-notes.html`.
  Full GitHub release notes and first-install instructions remain separate in
  `.github/release-notes.md`. Update both files for each release before signing.
- Configuration remains outside the bundle. The whole app, CLI and GOST update
  together. The existing GOST process stays alive while Sparkle replaces the app;
  the new CLI replaces that engine once on relaunch (`bridge-version`). The
  enabled flag, selected route and system proxy settings are not changed by the
  updater. Existing connections may briefly drop when GOST restarts.
- If VPN support is installed, or its state cannot be proven absent, an ordinary
  app-only update is refused before download. Do not remove VPN components as a
  workaround; a future jointly signed app/helper path must perform that update.
- Normal **Выйти** still disables the proxy. Update relaunch is a separate path.
- Version 1.4.0 has no updater: users must install the first updater-enabled
  version manually once. A release feed becomes live only when published.

## Signing key

The public key in `app/updater-public-key.txt` is safe to commit. The matching
private key was generated in this Mac's login Keychain with Sparkle account name
`kz.documentolog.proxypilot`. Never commit or paste the private key into chat,
logs, command-line arguments, release assets or workflow files.

Both the feed and update archive are signed with Ed25519. The app requires a
valid signed feed and verifies the archive **before extraction**. Unsigned-feed
fallback is disabled. Back up the key securely: with this ad-hoc distribution,
losing the key means manual reinstall for users; generating another key is not
a transparent rotation.

To inspect the public key (not the private key):

```sh
vendor/sparkle-2.9.6/bin/generate_keys --account kz.documentolog.proxypilot -p
```

## Local release preparation

For a release with VPN support, use the single local assembly entry so the
public DMG/ZIP and VPN companion contain the exact same ad-hoc-signed app:

```sh
zsh app/build-joint-release.sh SEQUENCE PREVIOUS_MANIFEST PREVIOUS_SIGNATURE \
  ENGINE_ARTIFACT UNIVERSAL_GOST NEW_OUTPUT_DIRECTORY
```

The sequence must match `app/vpn-release-sequence.txt`. The command uses the
existing Sparkle and VPN keys in this Mac's login Keychain, never exports either
private key, and produces exactly nine release assets. It does not tag, upload,
install or publish. `app/verify-release-candidate.sh VERSION ASSET_DIRECTORY`
rechecks that exact set using only committed public keys.

The standalone commands remain useful for non-release smoke builds:

```sh
./make-dmg.sh
zsh app/sign-update.sh
```

The signing tool requests Keychain access. Outputs:

- `dist/ProxyPilot-<version>.dmg` — first install;
- `dist/updates/ProxyPilot-<version>.zip` — self-contained update bundle;
- `dist/updates/appcast.xml` — signed feed with versioned download URL.

The joint builder additionally emits the signed VPN companion and metadata,
candidate release manifest/signature, verified corresponding engine sources,
and those three public artifacts from one exact sealed application.

The release-time verifier checks the archive signature against the public key
committed in the app, its byte count, version and GitHub URL. Sparkle's own tool
also verifies the signed feed. Do not edit a signed feed or archive afterward.

## Private keys stay local

GitHub Actions receives neither the Sparkle private key nor the independent VPN
release key. Both signatures are created locally through Keychain. The workflow
only downloads draft assets and verifies them with committed public keys. Keep a
separate secure backup of both local keys; losing either requires a fix-forward
manual migration rather than silently rotating trust.

## Publishing

Bump `PP_VERSION` and the VPN release sequence, update both English release-note
files, build and verify the nine local assets, then create and push the matching
tag when authorized. The tag workflow runs tests and creates a **draft only**; it
never uploads a separately rebuilt app and never publishes on the first run.

Upload the exact nine local files to that draft without overwrite, then manually
run the Release workflow for the same tag with phase `finalize`. Finalize requires
an unpublished draft, snapshots asset IDs/sizes/SHA-256, downloads the exact
allowlist, verifies Sparkle and VPN signatures, versions/sequences, source
correspondence, read-only joint layout, strict code signatures and byte-identical
apps across DMG/ZIP/companion. It snapshots the draft again and publishes only as
the final command if nothing changed. Any failure leaves the release as a draft.

Published signed releases are immutable; make a newer version instead of
replacing an existing package. Never overwrite a draft asset.

Feed URL: `https://github.com/jamber751/proxy-pilot/releases/latest/download/appcast.xml`.
No GitHub Pages deployment or API token is needed on users' Macs. Every release
marked Latest must contain `appcast.xml`. The initial feed serves one stable
version; before raising the minimum supported macOS version, preserve the last
compatible release in the feed and test multi-version appcasts.

## Verification before shipping

Run `python3 -m unittest discover -s tests -v`, universal bundle verification,
and `zsh app/sign-update.sh`. The real installer test is explicitly enabled with:

```sh
PROXYPILOT_TEST_INSTALLER=1 python3 -m unittest discover -s tests -p test_sparkle_install.py -v
```

It generates an ephemeral test key, updates a disposable ad-hoc `.app` from
1.0.0 to 2.0.0 over loopback, verifies the resulting bundle and confirms relaunch.
It never installs ProxyPilot into `/Applications`. The release workflow also
runs this test. The signed-feed tests run after local signing and check real
Sparkle acceptance, tamper rejection and an unavailable feed.

For a release candidate also test two disposable app versions end to end:
scheduled check, explicit check, no update, cancellation, offline feed/download,
invalid signatures, read-only installation and relaunch. Check enabled, disabled
and stopped bridges, and configured SOCKS5/HTTP routes. Do not test by replacing
the user's installed app without explicit intent to install it.

### Initial 1.5.0 local verification, 2026-09-07

- Universal arm64/x86_64 app and GOST built; deep code-signature check passed.
- DMG filesystem checksums verified; ZIP and feed signed with the Keychain key.
- Release ZIP signature checked against the public key embedded in the app.
- Real Sparkle accepted the signed feed, rejected a modified one and handled 404.
- Disposable ad-hoc app installed and relaunched successfully through Sparkle.
- Settings layout inspected in a native isolated preview with two fake proxies.
- Settings content scrolls only when its measured height exceeds the available
  space. The normal two-proxy list has no scroll container or rubber-banding;
  long errors scroll independently of the fixed update controls and footer.
  Off-screen layout regression covers seven states (configured, empty, error,
  busy, main, proxy form and routes), including the 16-point bottom inset.
- All 39 local tests passed, including embedded HTML notes and the disposable
  Sparkle installation test.
- Engine restart/state retention and update-cancellation gates covered by isolated tests.

Not yet verified: real ProxyPilot-to-ProxyPilot replacement during active user
traffic; authorization on an unwritable app; first install of a quarantined
download on a clean Mac. The GitHub-hosted pipeline subsequently published
v1.5.0 successfully using the existing encrypted signing secret. Release builds
also run the manual-update result checks against the freshly signed feed.

References: [Sparkle setup](https://sparkle-project.org/documentation/),
[gentle reminders](https://sparkle-project.org/documentation/gentle-reminders/),
[publishing](https://sparkle-project.org/documentation/publishing/).
