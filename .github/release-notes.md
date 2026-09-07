### What's new in 1.5.1

- **Easier clicks.** Larger hit targets for Back, Add, Settings, Quit and Check for
  Updates. Proxy cards, discovery and save buttons respond across their full area.
- **Consistent feedback.** Subtle hover highlights and pressed states throughout
  the app, with matching green accents for the protocol selector and checkbox.
  Disabled controls do not highlight on hover.
- **Clearer update checks.** Check for Updates is now a visible button with a
  waiting/checking state. Manual checks bring the update UI to the foreground.
- **Unmistakable test previews.** Development previews have a separate name,
  menu-bar icon and TEST badge. Their disabled updater is explicitly labeled;
  they do not change your saved proxies or macOS proxy settings.
- **Compact layout.** The normal settings screen still fits without scrolling;
  longer error messages scroll without hiding the footer.
- **English release notes**, both here and in the in-app update window.

### Update

On **1.5.0**, open **Settings → Check for Updates**, then confirm the update.
Automatic checks remain optional;
installation and restart require your confirmation.

On **1.4.0 or earlier**, install the DMG manually once. Open the DMG and read
`READ_ME_FIRST.txt` for the installer and drag-to-Applications options. The app
is ad-hoc signed, not Developer ID signed or notarized; macOS security prompts
still apply.

Your saved proxy addresses, selected route and on/off state are preserved.
Connections through the local bridge may briefly reconnect when the app restarts.
This release does not change proxy routing or add VPN behavior.

Universal app for Apple Silicon and Intel, macOS 11 or newer. The CLI and GOST
are bundled; Homebrew is not required.

### Verification

Regression coverage includes control hit-target sizes, seven layout states,
manual update results (new version, up to date and unavailable server), signed
feed verification, local HTTP/SOCKS5 bridges and a disposable Sparkle
installation/relaunch. Tests do not replace your installed ProxyPilot.

[Full documentation](https://github.com/jamber751/proxy-pilot#readme)
