# Isolated updater

This is the release/default updater. It keeps
Sparkle out of the app process so the same app executable can eventually meet
the VPN peer policy (`runtime,hard,kill`, no runtime exceptions/entitlements).
It does not install or authorize a VPN helper.

Latest joint-update status (28 September 2026): the separately authorized VPN
package successfully replaced signed A119 with signed B120, selected helper B,
proved readiness and retired its recovery job on Apple Silicon/macOS 26.1. This
was a direct native package acceptance run, not Sparkle integration. Publication
remains blocked on a safe one-click joint-update handoff, early reboot/crash
recovery and Intel/macOS 11 runtime acceptance. The corrected
removal path passed a separate authorized sequence-121 system run.

Build into a new disposable output directory:

```sh
candidate_dir=$(mktemp -d /tmp/proxypilot-updater-candidate.XXXXXX)
zsh app/build.sh "$candidate_dir"
```

Do not launch this production-identified bundle alongside the installed app as
a test. The automated tests build uniquely identified disposable hosts instead.
The small hosts use an inert CLI; the full-app fixture below runs selected CLI
functions with loopback GOST and substituted OS boundaries. Neither launches the
installed app/full CLI, accesses a real VPN profile or installs a system service.
The ordinary build and release scripts use this updater. An explicit
`PROXYPILOT_ISOLATED_UPDATER=0` remains only for legacy test/development
comparison and must not be used for release packaging.

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
  app, before changing service policy or stopping it. The opt-in fixed installer
  entry and separately authorized support packages have passed system acceptance;
  they are not coordinated with Sparkle app replacement. A Sparkle success or
  worker message cannot enroll the new app; the worker never calls the root
  installer. See the helper README.

## Early VPN update veto (12 September)

An ordinary app-only update can strand an installed VPN helper with pins for the
previous app. Until joint replacement is implemented, the default worker uses
Sparkle's supported `shouldProceedWithUpdate` delegate to refuse a selected update
**before its offer or download** when a VPN installation marker is present or
inspection cannot establish absence. This guard is part of the default build.

`VPNUpdateAdmission` only opens the fixed `/Library/Application Support` and
`/Library/LaunchDaemons` directories and checks the three fixed private/public
installation and launch-plist names without following their symlinks. It does not
enter private storage, read profiles, contact the helper, change permissions,
repair/remove components, or request administration. A partial, stale or dangling
marker is not treated as absence; an unreadable or malformed parent is an error.
The existing Sparkle error path explains why checking stopped and permits retry.
Each selected update gets a fresh inspection; no allow decision is cached.

This is a conservative compatibility check, **not an atomic update protocol or
security authorization**. Installing a helper after this early check, or resuming
an already staged update, is not protected by this veto. The default updater
therefore refuses app-only replacement while VPN support is installed until late
installation, restart and failure recovery are coordinated with the independently
signed root policy. Do not remove a live VPN installation to work around this guard.

Verified with 10 disposable filesystem tests and 3 actual Sparkle integration
tests (all passed on this Mac):

```sh
python3 -m unittest discover -s tests -p test_vpn_update_admission.py -v
PROXYPILOT_TEST_ISOLATED_INSTALLER=1 python3 -m unittest discover -s tests -p test_vpn_update_install.py -v
```

Present and unknown state both refuse before ZIP download or proxy preparation,
preserve the old app/preferences and leave the fixture untouched. Retry after
removing only a disposable test marker installs/relaunches the test app 1.0.0 →
2.0.0, proving the previous decision is not reused. Integration fixtures substitute
only the probe's base directories and use ephemeral signing keys, signed loopback
feeds and scripted user-driver choices; they never inspect real VPN storage or
update the installed app. Both architecture slices target macOS 11; runtime
acceptance on Intel/macOS 11 remains separate.

Native acceptance on 13 September: the present-component error rendered its
description and recovery text in the unmodified Sparkle alert. Clicking **Cancel
Update** returned the host to idle without download/preparation; the old signed
app/preferences and marker were unchanged and no fixture processes remained.
An earlier attempt timed out while computer control was unavailable; it was not
counted as a pass. The unknown-state alert still needs visual acceptance: computer
control stalled again and that fixture timed out and cleaned up. Its automated
error/no-download test passed, but does not establish native presentation.

Repeat one visible scenario at a time, acknowledging the alert within three
minutes (only disposable apps; no real VPN state):

```sh
python3 tests/test_vpn_update_install.py --native-preview --scenario present
python3 tests/test_vpn_update_install.py --native-preview --scenario unknown
```

The 12 September broader regression selected 443 tests: **439 passed, 4 skipped,
0 failures** (886.969 seconds), including all five full-App/loopback cases and
the existing installers/updaters. Four opt-in real OpenVPN artifact/package tests
were skipped because their earlier temporary artifact was no longer available;
11 separate Keychain tests were intentionally excluded. Both the default app and
the isolated-updater/VPN-installer candidate built Universal and passed strict
deep signature verification. Neither production-identified build was launched.
After adding the native preview runner, all three automated VPN-update scenarios
passed again on 13 September (111.946 seconds) with the final fixture sources.
An intermediate compile was discarded because the fixture was edited while the
compiler was reading it; it ran zero tests and was not counted as a passing run.

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
3. Integrate the proven, separately authorized joint package transaction with
   Sparkle without weakening the root-helper release policy. The native signed
   A119 → B120 package path passed once, but the early veto is still the only
   protection in the opt-in Sparkle worker. Late-stage races plus crash/reboot
   recovery remain release blockers. Never accept a new VPN client pin merely
   because Sparkle installed it.
4. Preserve the accepted removal boundary. The first B120 removal failed on the
   non-empty shared parent containing the intentionally retained updater directory.
   The corrected sequence-121 remove package then passed with a root-private
   `Update` marker present: service, endpoint, plist and VPN directory disappeared,
   while the marker remained for separate cleanup. No OpenVPN tunnel was started.

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
window boundaries, including the bounded timeout. Both legacy and isolated
Universal builds pass strict signature verification. Execution was on the current
Apple Silicon Mac, not Intel/macOS 11 runtime acceptance. The isolated updater
became the default on 28 September; publication still requires the joint-update
and remaining runtime gates above.

The combined regression run with both installer opt-ins enabled completed 300
tests in 358.739 seconds: 299 passed, one legacy opt-in Sparkle installation test
skipped. Nine release-key tests were deliberately excluded to avoid Keychain
access. The earlier manual native UI runs are separate from that count.
