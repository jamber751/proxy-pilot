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
a test. The automated tests build uniquely identified disposable hosts instead.
The small hosts use an inert CLI; the full-app fixture below runs selected CLI
functions with loopback GOST and substituted OS boundaries. Neither launches the
installed app/full CLI, accesses a real VPN profile or installs a system service.
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
  worker failure releases that preparation. `ProxyModel` also invalidates the
  preparation generation: a queued command cannot complete an old/cancelled
  handoff or freeze the controls again. A worker with an acknowledged
  install handoff can outlive frontend EOF briefly; otherwise EOF exits it.
- VPN install/update has a separate same-app identity preflight in `VPNInstaller`:
  the candidate's independent VPN signature must pin the actual running hardened
  app, before changing service policy or stopping it. This component is not yet
  wired into the app/package. A Sparkle success or worker message cannot enroll
  the new app; the worker never calls the root installer. See the helper README.

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

Six scenarios pass with Universal test hosts: install/relaunch 1.0.0 → 2.0.0
with preferences preserved, decline before download, cancel after staging, and
reject a signature-invalid but still readable/CRC-valid ZIP. The real worker,
frontend, Sparkle downloader/verifier/installer and OS relaunch are exercised;
only the native user driver is replaced with explicit test choices. No root
prompt, system service, production key/feed or actual ProxyPilot is involved.
Each case checks old/new bundle integrity and natural subprocess cleanup before
emergency teardown. Declines/corruption must never reach frontend preparation.
The ready-stage cancellation uses Sparkle's documented `.skip` API; `.dismiss`
at that stage would defer installation until the host quits instead of canceling.

The two additional cases cover migration and successive updates using test-only
versions 1.5.1 → 1.5.2 → 1.5.3 (not public release artifacts). Migration starts
with the exact `UpdateModel` source from release `0518754`, an in-process Sparkle
framework and ordinary ad-hoc signing. The historical model is checked into the
fixture with a verified SHA-256, so shallow clones do not need Git history.
Only its UI controller adapter is substituted for scripted choices. Both new
versions use the hardened frontend and isolated worker. The test verifies three
distinct host processes, transition from in-process to worker-owned Sparkle,
removal of the old framework layout, and preservation of the disabled automatic
check preference and test proxy preferences across both replacements.

Installation also calls the real `ProxyModel.prepareForUpdate` behind a delayed
inert command, verifying that preparation drains the command queue and preserves
enabled state, selected route and both endpoint strings. The **entire** CLI is
replaced at compilation, so no real CLI path/command or network operation is
available to this fixture. This is not acceptance of a live bridge or the full
app's start/stop lifecycle.

`test_update_quiescence.py` separately exercises that production model with the
same inert CLI: wait for an in-flight command, cancellation, replacement after
cancellation, and replacement of a pending preparation. These regressions caught
and now guard against a late completion re-freezing controls after cancellation.

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

1. Real system/installed-app lifecycle acceptance. The complete App now passes
   the loopback bridge scenarios below, in addition to pinned-model migration,
   repeated updates and command-queue preparation. Actual SystemConfiguration,
   installed CLI discovery/process ownership and live network transitions remain
   outside these isolated tests; the installed/released app was not launched.
2. Resolve the final cancellation boundary: the stock Ready to Install window
   has no Cancel or close action, and Escape does nothing. The scripted `.skip`
   test is an API test, not evidence of a native cancellation button. No custom
   final window is added here. Remaining system, sleep and accessibility
   acceptance is separate from the native cases below.
3. Coordinate app replacement with the separately authorized root-helper release
   policy. Never accept a new VPN client pin merely because Sparkle installed it.
4. Package the hardened app's fixed installation mode (or introduce separately
   signed installer pins) and perform explicitly authorized cross-UID acceptance.
   Neither an installer entry point nor an OpenVPN tunnel is added here.

## Additional native acceptance (8 September)

The runner now supports these explicit visible scenarios:

```sh
python3 tests/test_isolated_update_install.py --native-preview --scenario cancel-offer
python3 tests/test_isolated_update_install.py --native-preview --scenario cancel-download
python3 tests/test_isolated_update_install.py --native-preview --scenario network
python3 tests/test_isolated_update_install.py --native-preview --scenario corrupt
python3 tests/test_isolated_update_install.py --native-preview --scenario background
```

All five were passed using the actual native buttons through computer use.
Close the offer; start and Cancel the throttled download; acknowledge the network
error then close the successful retried offer; start the corrupt download then
acknowledge the signature error; or click Show update in the background test host
and choose Remind Me Later. These are manual acceptance runs, not silently added
UI automation in unittest discovery. The original `install` scenario remains
the default and requires a complete disposable installation/relaunch.

`NativeProbe.swift` only records real worker callbacks and its activation events;
it does not replace the standard driver or choose actions. The background case
invokes Sparkle's real background-check path immediately after startup, verifies
the existing model's available version/action title without presentation, zero
visible worker windows, and no worker activation before a manual check. It then
requires activation after the explicit click. This does not simulate waiting a
day for the production scheduler, and the small host window is test UI only.
An earlier assertion that the host itself must be frontmost was invalid (macOS
need not activate it); worker-wide activation observation replaced it.

The network case injects one loopback feed failure and checks that the model can
retry after the real error dialog closes. It calls `UpdateModel.check` again;
it does not exercise the full ProxyPilot settings button. Corruption remains a
valid ZIP with an invalid signature. All passing cases assert no preparation or
installation, original bundle integrity, and natural process cleanup. The native
Ready to Install cancellation attempt did not pass and was interrupted with
scoped cleanup; its missing control is also explicit in the
[pinned Sparkle source](https://github.com/sparkle-project/Sparkle/blob/2.9.6/Sparkle/SPUStandardUserDriver.m#L477).

## Full App and loopback bridge acceptance (8 September)

```sh
PROXYPILOT_TEST_FULL_APP=1 PROXYPILOT_TEST_GOST=/absolute/path/to/gost python3 -m unittest discover -s tests -p test_full_app_update.py -v
```

Five scenarios pass using the complete production `App`, `ProxyModel`,
`PilotView`, isolated updater and real Sparkle replacement/relaunch:

- Enabled: 1.0.0 → 2.0.0 keeps both proxy endpoints, selected route, enabled
  state and listener port. Both local HTTP and SOCKS5 requests succeed during
  preparation and after relaunch; the new version replaces the old engine once.
- Disabled/stopped: startup and update do not resurrect a stopped bridge.
- Disabled/running: the existing direct listener remains available, with one
  engine replacement after update and no system-proxy activation.
- Cancel the offer: no installation; selecting HTTP through the real model
  succeeds afterward, and both local protocols still carry requests.
- Normal Quit: the real quit/disable flow turns off only the fake system proxy,
  while the listener remains in direct mode for existing clients.

`BridgeBoundary.zsh` supplies a unique private state directory, exact fixture-only
process matching, and fake `networksetup`/`scutil` functions. Selected production
CLI functions (config, ensure, route, start/stop, disable, state, GOST config) are
appended without changes to their logic. There is no production CLI dispatcher,
user-home fallback, network discovery, launchd or VPN command. Real GOST listeners,
HTTP/SOCKS5 upstreams, signed feed and echo server bind only to 127.0.0.1. All
requests stay on loopback; no corporate resource, key or installed app is used.

The test compiles a visibly marked, uniquely identified bundle. App observations
and scripted update choices are test-only. A 1.5-second observation interval
before acknowledging preparation allows actual traffic through the old bridge;
the relaunched App runs beyond its real five-second refresh timer to catch
repeated restarts. App/worker cleanup must be natural; teardown stops only the
exact fixture GOST processes after verifying the intentionally retained listener.
This does not prove uninterrupted existing TCP sessions across an engine restart,
native settings-button interaction, or real OS proxy configuration.

These tests caught a production startup race: a menu-bar button can already have
a window whose height is still zero, and presenting its popover silently fails.
The App now briefly waits for a usable anchor. Closing or showing updater UI
cancels a pending request; a newer request supersedes the previous one. Four
`test_popover_startup.py` regressions exercise the actual methods with inert
window boundaries, including the bounded timeout. Both ordinary and isolated
Universal builds pass strict signature verification. Execution was on the current
Apple Silicon Mac, not Intel/macOS 11 runtime acceptance. The isolated updater
remains opt-in; no public release or default build-mode change is made here.

The combined regression run with both installer opt-ins enabled completed 300
tests in 358.739 seconds: 299 passed, one legacy opt-in Sparkle installation test
skipped. Nine release-key tests were deliberately excluded to avoid Keychain
access. The earlier manual native UI runs are separate from that count.
