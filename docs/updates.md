# Updates (free distribution)

ProxyPilot uses Sparkle 2.9.6, pinned to the SHA-256 in its tagged upstream
`Package.swift`. No Sparkle account, paid hosting or Apple Developer subscription
is required. This does **not** make the first install Developer ID signed or
notarized: macOS Gatekeeper prompts still apply.

## User experience

- Checks once per day while the app is running; no separate background daemon.
- Settings shows the installed version, **Проверить обновления**, and an opt-out
  **Проверять автоматически** checkbox.
- Scheduled discoveries add a dot to the gear and an update button in Settings;
  they do not steal focus. Explicit checks use Sparkle's standard native UI.
- No automatic downloads/installations or forced restart. The user confirms
  installation. Sparkle may request administrator authorization if the app is
  not writable by the current user.
- The update window uses compact Russian HTML notes from `.github/update-notes.html`.
  Full GitHub release notes and first-install instructions remain separate in
  `.github/release-notes.md`. Update both files for each release before signing.
- Configuration remains outside the bundle. The whole app, CLI and GOST update
  together. The existing GOST process stays alive while Sparkle replaces the app;
  the new CLI replaces that engine once on relaunch (`bridge-version`). The
  enabled flag, selected route and system proxy settings are not changed by the
  updater. Existing connections may briefly drop when GOST restarts.
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

```sh
./make-dmg.sh
zsh app/sign-update.sh
```

The signing tool requests Keychain access. Outputs:

- `dist/ProxyPilot-<version>.dmg` — first install;
- `dist/updates/ProxyPilot-<version>.zip` — self-contained update bundle;
- `dist/updates/appcast.xml` — signed feed with versioned download URL.

The release-time verifier checks the archive signature against the public key
committed in the app, its byte count, version and GitHub URL. Sparkle's own tool
also verifies the signed feed. Do not edit a signed feed or archive afterward.

## One-time CI setup

Before publishing, add the existing private key to the repository's GitHub Actions
secret **SPARKLE_PRIVATE_KEY**. The implementation does not create this remote
secret or publish a release automatically.

The maintainer can export it to a temporary, permission-restricted file using
Sparkle's `generate_keys --account kz.documentolog.proxypilot -x <private-file>`.
Upload with `gh secret set SPARKLE_PRIVATE_KEY < <private-file>` in this repository,
then remove the temporary export. Keep a separate secure backup. Do not put the
key in a GitHub variable: it must be an encrypted **Actions secret**.

The workflow pipes the secret to Sparkle on stdin, never as a process argument.
Release signing fails closed when it is absent or doesn't match the embedded key.
For public repositories use standard GitHub runners and keep artifact retention
within the free storage allowance; no large paid runner is needed.

From the repository directory, the maintainer can run this once to transfer the
existing key to this repository's encrypted Actions secret. The private export
is permission-restricted and removed when the command finishes; Keychain keeps
the original. Do not share the export or command output containing a key.

```sh
(
  set -eu
  umask 077
  release_key_dir=$(mktemp -d /tmp/proxypilot-release-key.XXXXXX)
  trap 'rm -f "$release_key_dir/key"; rmdir "$release_key_dir"' EXIT
  vendor/sparkle-2.9.6/bin/generate_keys --account kz.documentolog.proxypilot -x "$release_key_dir/key"
  gh secret set SPARKLE_PRIVATE_KEY --repo jamber751/proxy-pilot < "$release_key_dir/key"
)
```

## Publishing

Bump `PP_VERSION` (also used for the increasing `CFBundleVersion`), test, then
publish a matching `vX.Y.Z` tag when authorized. The release workflow checks out
the requested tag, tests the bundle, signs it, uploads all three assets to a
draft and only then publishes it. Published signed releases are immutable; make
a newer version instead of replacing an existing package.

For the prepared 1.5.0 release, after the signing secret is configured and CI is
green, create and push the release tag from the reviewed commit on `main`:

```sh
git tag v1.5.0
git push origin v1.5.0
```

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

### Local verification, 2026-09-07

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
download on a clean Mac; the GitHub-hosted pipeline. The GitHub signing secret
and public release are intentionally not created by this local implementation.

References: [Sparkle setup](https://sparkle-project.org/documentation/),
[gentle reminders](https://sparkle-project.org/documentation/gentle-reminders/),
[publishing](https://sparkle-project.org/documentation/publishing/).
