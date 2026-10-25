# VPN release notes — unpublished draft

Internal draft for the planned VPN release. The text below describes the intended
release after acceptance, not the currently published version. Do not copy it into
the release or update feed until the checks below are complete. Version pending.

## Release text

### What's new

- **VPN in the menu bar.** Import an OpenVPN `.ovpn` file, or drag it into the VPN
  settings, then connect from the same compact window.
- **Access to the resources you choose.** Select domains, IP addresses and
  networks that should use the VPN. A domain includes all its subdomains. Your existing proxy routing remains in
  control for other traffic.
- **Clearer sign-in.** Choose certificate access, a password or a one-time code
  to match your profile. One-time codes are never saved. Passwords can optionally
  be saved in your local Keychain.
- **Your setup stays yours.** Saved proxy addresses, the selected proxy route and
  VPN resources are preserved when you update.

### Updating

Requires macOS 12 Monterey or later, on Apple Silicon or Intel.

Use the ProxyPilot installer to update the app and its VPN component together.
macOS may ask you to approve the installation. Homebrew is not required.

Connections through the local HTTP and SOCKS5 bridges may briefly reconnect when
the app restarts. If a saved password cannot be filled in, enter it manually to
continue.

## Required before publication — internal checklist

- Complete current-source genuine Keychain and installed save/fill acceptance,
  including cross-version access, manual fallback and retained cleanup
  obligations. Password integration is enabled after the earlier private and
  genuine backend proofs; those proofs do not replace final installed checks.
- Complete both-architecture Installer and ownership acceptance for the final
  sources, then build and verify the final publisher-signed joint package.
- Complete production domain/split-DNS integration, ordinary DNS and WARP policy,
  route/answer custody, sleep and process-failure behavior. Pure tests and
  prototype canaries do not prove this release-text claim.
- Verify installed import, drag-and-drop, authentication, resource changes,
  disconnect, sleep/restart/network changes, VoiceOver and supported OS versions.
- Choose the final version, review the text against the shipped behavior, and
  copy the accepted text into `.github/release-notes.md` and
  `.github/update-notes.html` before the separately authorized public release.
