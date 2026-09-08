# Isolated updater candidate

This is an opt-in staging build, **not the release/default updater**. It keeps
Sparkle out of the app process so the same app executable can eventually meet
the VPN peer policy (`runtime,hard,kill`, no runtime exceptions/entitlements).
It does not install or authorize a VPN helper.

Build into a new disposable output directory:

```sh
candidate_dir=$(mktemp -d /tmp/proxypilot-updater-candidate.XXXXXX)
PROXYPILOT_ISOLATED_UPDATER=1 zsh app/build.sh "$candidate_dir"
```

Do not launch this production-identified bundle alongside the installed app as
a test. The automated tests build uniquely identified inert hosts instead; they
never run the proxy CLI, access a real VPN profile or install a system service.
The ordinary build and release scripts continue to use the existing updater.

## Process and trust boundaries

- The hardened frontend contains `IsolatedUpdates.swift`, `UpdateWire.swift`
  and `UpdateChannel.swift`; it does not link or load Sparkle.
- A fixed nested `Contents/Helpers/ProxyPilot Updater.app` contains Sparkle and
  owns its standard update UI, release notes, preferences and updater lifecycle.
  It runs as the same ordinary user, never root. No arbitrary executable path,
  arguments, feed override or inherited environment is accepted by the launcher.
- Sparkle's `hostBundle` and `applicationBundle` are both the enclosing app, not
  the updater bundle. The worker's own version/preferences are not the host's.
  This follows Sparkle's [external-bundle API](https://sparkle-project.org/documentation/bundles/).
- The frontend validates the nested worker's static signature before launch.
  This is an integrity check, **not** an authority to operate the root helper.
  The free/ad-hoc updater is deliberately unprivileged; its messages must never
  be forwarded to the privileged VPN channel or used as VPN consent/pins.
- The only IPC is two inherited anonymous pipes. Messages are typed, versioned,
  direction-checked and framed (4 KiB payload maximum). Queued output is limited
  to 16 KiB; partial messages and stalled output expire after 10 seconds. I/O is
  nonblocking and off the main thread. CLOEXEC, per-FD SIGPIPE protection and
  dispatch-source cancellation govern descriptor lifetime.
- Worker state updates the existing settings controls. Preview launches nothing.
  Startup/transport/process failure becomes an explicit retry; it never falls
  back to loading Sparkle in the hardened app. A retry has a fresh generation,
  so old child events cannot complete a new session.
- Update preparation uses one random token for the current session. Duplicate,
  unsolicited and stale completion messages are rejected. The callback only
  quiesces the existing **unprivileged** proxy update lifecycle. Cancellation or
  worker failure releases that preparation. A worker with an acknowledged
  install handoff can outlive frontend EOF briefly; otherwise EOF exits it.

## Verified scope

`test_update_channel.py`: framing/schema/direction, fragmented and batched input,
size rejection, timeout, slow reader, EOF, SIGPIPE and descriptor close.

`test_isolated_updates.py`: the candidate model and real Sparkle in separate
Universal/macOS 11-targeted processes. A signed loopback feed exercises current
version, new host version, network error and signature rejection, stopping at
the standard driver's presentation callback before native UI/download. Other
tests cover persisted host preferences, preview isolation, child failure/retry,
and synthetic prepare/abort/duplicate/stale handoffs. Only the current Mac
executes the binaries; building Intel/macOS 11 is not runtime acceptance there.

`test_isolated_update_install.py` adds an **opt-in real installation** test:

```sh
PROXYPILOT_TEST_ISOLATED_INSTALLER=1 python3 -m unittest discover -s tests -p test_isolated_update_install.py -v
```

Four scenarios pass with Universal test hosts: install/relaunch 1.0.0 → 2.0.0
with preferences preserved, decline before download, cancel after staging, and
reject a signature-invalid but still readable/CRC-valid ZIP. The real worker,
frontend, Sparkle downloader/verifier/installer and OS relaunch are exercised;
only the native user driver is replaced with explicit test choices. No root
prompt, system service, production key/feed or actual ProxyPilot is involved.
Each case checks old/new bundle integrity and natural subprocess cleanup before
emergency teardown. Declines/corruption must never reach frontend preparation.
The ready-stage cancellation uses Sparkle's documented `.skip` API; `.dismiss`
at that stage would defer installation until the host quits instead of canceling.

An additional manual pass on 8 September used the **unmodified standard driver**:
English embedded HTML notes rendered correctly; “Install Update” → “Ready to
Install” → “Install and Relaunch” replaced the disposable host and launched 2.0.0
with its preferences intact. No fixture processes remained. To repeat this
inspection (a visible window; finish within three minutes):

```sh
python3 tests/test_isolated_update_install.py --native-preview
```

This builds/updates only a uniquely identified `ProxyPilot Install TEST.app`.
The preview does not change settings or update the installed ProxyPilot. It
asserts a successful install/relaunch, so dismissing it instead reports a failed
preview and cleans up the fixture. Basic native UI acceptance does not establish
VoiceOver, scheduled focus behavior, or every macOS/language combination.

## Required before default/release integration

1. Migration from the current in-process updater to this bundle layout, repeated
   update cycles, and the complete app's quiescence/restart behavior. The passing
   installation test starts with an already isolated updater, not the old 1.5.1.
2. Remaining native UI cases: scheduled gentle reminders/focus, errors and
   cancellation controls. The basic manual update and notes are now verified.
3. Coordinate app replacement with the separately authorized root-helper release
   policy. Never accept a new VPN client pin merely because Sparkle installed it.
4. Package the hardened app's fixed installation mode (or introduce separately
   signed installer pins) and perform explicitly authorized cross-UID acceptance.
   Neither an installer entry point nor an OpenVPN tunnel is added here.
