# VPN helper security boundary

Latest status (28 September 2026): in addition to the earlier standalone system
acceptance, an authorized Apple Silicon/macOS 26.1 run installed signed A119 and
completed the exact signed A119 → B120 joint application/helper update. Installed
B matched its expected hashes, reported release 120 through the user status entry,
the selected helper was ready, and the recovery job retired. The first B120 removal
then exposed a shared-parent cleanup bug after the service and VPN directory had
already been removed: the intentionally retained `ProxyPilot/Update` sibling made
the parent `rmdir` fail with `ENOTEMPTY`. The fix preserves that sibling and passes
focused tests, but the corrected removal package has not yet been rerun as root.
A scoped recovery package restored the original 1.5.1 app, archived retained
evidence, and left system labels/directories/stages clean. No VPN networking was
enabled. See `../update-worker/README.md`. Earlier sections below retain the
chronological history; current acceptance and open gates are tracked in
`docs/vpn-implementation-plan.md`.

Format 2 is now supported by the common verifier, protected store, package loader,
installer and daemon startup. Both component files must validate together;
missing engine data cannot become a helper-only deployment. Tests cover atomic
selection, update/retry, corruption and removal. System acceptance of format 2
completed on 8 September (install 4, retry 4, app-pin rotation 4 → 5 and removal).
The `VPN_ENGINE_DELIVERY_TESTING` factory is now only a test
convenience, with the same parser/rules as production. No engine is executed.
See `docs/vpn-engine-delivery.md` for the current evidence and remaining gates.

## Directed joint-update authorization (13 September, verification only)

`VPNReleaseAuthority.verifyUpdateTransition` checks a separate Ed25519 signature
over one exact forward release transition. This is a foundation for the joint
app/helper coordinator, not a new installer command or an enabled update path.
The same embedded release authority signs/verifies both endpoint manifests and
the transition, with a distinct signature domain:
`kz.documentolog.proxypilot/vpn-update-transition/v1` followed by one NUL byte.

The bounded (512-byte maximum), UTF-8, LF-terminated payload has exactly six
ordered fields: `format=1`, `product=kz.documentolog.proxypilot`, `from-sequence`,
`from-sha256`, `to-sequence`, `to-sha256`. Digests cover exact canonical manifest
payload bytes, not filenames, archives, signature representations or only app
hashes. The candidate is independently verified with `previous:` and all existing
version/protocol/engine rollback rules; the transition must strictly advance its
sequence. A signed malformed or mismatched record is still rejected.

The immutable result exposes only endpoint sequence numbers and exact source/
destination matching. It does not expose a combined peer policy, acquire a lease,
write a journal, change the release floor, authenticate an installer process or
prove readiness. Existing same-app/root authorization checks are unchanged.
The old release must eventually be loaded from protected storage and rechecked
under lifecycle ownership immediately before use. A saved result or worker event
cannot replace that check. Identical A→B proof verification may be repeated while
A remains selected, but B→B is not a new transition; durable retry after selection
and crash recovery still need a journal. First install and key rotation are not
authorized by this contract. No signing key, package or root service is changed.

Focused disposable verification:

```sh
python3 -m unittest discover -s tests -p test_vpn_update_transition.py -v
```

## Durable joint-update journal (disk layer; no production update entry)

`VPNReleaseStore` now records a single exact signed A→B transaction in protected
`update.json`, using the existing descriptor-relative I/O, private permissions,
nonblocking store lock, canonical encoding and file/parent-directory syncs.
Both endpoint manifests/signatures and the separate transition signature are
reverified on every journal load; the owner and both sets of staged artifacts
must still match protected storage. The journal contains no profile or secrets.

The graph is `prepared → replacementPending → selected → completed`, with only
`prepared → cancelled` allowing cancellation. Expected UUID/revision checks reject
stale callers; they are correlation, not authority. The selected release remains
A during preparation. Before app replacement, the trusted future coordinator
must record `replacementPending`. `selectUpdateCandidate` changes the selector
to B before recording `selected`: if the process dies between these writes,
`replacementPending` + exact B classifies as forward recovery, never rollback.
Impossible phase/selector combinations and corrupt journals fail closed.

Terminal records remain until explicit retirement and a directory sync. Ordinary
deployment preparation/commit, bootstrap and legacy policy mutations are blocked
by any journal, even a terminal or corrupt one; old in-memory preparation tokens
cannot bypass this. The journal API does not prune artifacts. A failed sync after
rename/unlink is an uncertain commit requiring reload, not a promise of no change.
Process-crash tests are not evidence of physical power-loss/filesystem behavior.

These are internal disk operations, not an installer command. A future coordinator
must authenticate the source app, hold lifecycle ownership, confirm drain, verify
the actual installed destination app before selecting B, and establish readiness
or an explicit desired-off result before completion. Neither a journal phase nor
a Sparkle callback proves any of those facts. `loadDeployment` remains read-only
selection; `loadUpdateJournal` gives recovery classification, not a ready receipt.
The ordinary runtime path is guarded separately; no journal-aware activation is
enabled. Installer removal does not silently discard an interrupted transaction.

Detailed recovery matrix and test evidence: `docs/vpn-update-journal-review.md`.

`VPNInstaller.prepareJointUpdate` now supplies the first trusted integration
boundary: open existing storage, hold lifecycle ownership, authenticate the live
current A app against A's pins, recheck the lease, then prepare the exact signed
transition. A candidate-only process or updater cannot prepare it. This leaves
A's PID, selected release and activation budget unchanged. There is no production
CLI/Sparkle entry or actual application replacement/selection/completion path yet.
See `docs/vpn-update-preparation.md` and `docs/vpn-update-runtime-gates.md` for
the per-user process tests and remaining integration boundaries.

`VPNInstaller.managePreparedJointUpdate` adds source-A-only actions under a fresh
lifecycle lease: confirm service drain before recording `replacementPending`,
cancel while still `prepared`, and explicitly retire only `cancelled + A`.
Every action reauthenticates the current A process and checks the journal's exact
UUID/revision/phase. Invalid requests never construct the runtime. Cancel and
retirement do not stop/start a service or change activation intent. If drain
succeeds but journal advancement fails, A may remain stopped and prepared;
cancellation still does not automatically restart it.

The returned snapshot is not ongoing drain proof: the lease has been released.
The actual future replacer must reacquire lifecycle ownership and repeat the
state/drain checks immediately before changing app bytes. No action here
authorizes completed/B retirement or skips the installed-B verification gate.
See `docs/vpn-replacement-boundary-review.md` for tests and
`docs/vpn-installed-app-verification.md` for the next trust boundary.

`VPNPeerAuthentication.swift` is an isolated, fail-closed **process identity
gate** for a connector or the current installer, not a daemon, command dispatcher,
installer entry point or ready VPN feature. It is
intentionally absent from `app/build.sh` and from all installation packages.
The older inert installation probe has no real-operation authorization and must
not acquire privileged operations merely by adding this file.

## What is implemented

- Accept only a connected local UNIX stream descriptor and the configured
  non-root account's kernel-reported credentials.
- Obtain `LOCAL_PEERTOKEN` from that descriptor, not a PID/identity claimed in a
  request. Resolve its dynamic code through `kSecGuestAttributeAudit`.
- Validate the running signature, match both the identifier and an explicit
  set of Code Directory hashes. The identifier alone is not trust, particularly
  with an ad-hoc signature.
- Require hardened runtime, hard/kill enforcement, valid dynamic status, no
  debugging and no entitlements (including runtime exceptions).
- Reject malformed/empty policies, failed security queries, dead peers and
  unexpected descriptor types. No fallback to PID, executable path or name.
- Revalidate for every operation. No successful-authentication cache.
- Preflight the current install/update process using `SecCodeCopySelf`, real and
  effective UID, and that same dynamic signature/hardening gate. This never
  substitutes for system installation authorization or helper-side checks.

`VPNPeerPolicy` is a local trusted input, **not Codable or a network payload**.
Only a future installer-controlled root-owned policy may supply production pins
and the owner UID. Do not load them from app preferences, let an IPC client enroll
itself, or hash whatever currently exists at a user-writable application path.
An update must explicitly authorize new architecture-specific hashes; it must
not silently accept every later binary with the same identifier.

## Initial security gates (historical; current status above)

1. Production bootstrap and pin activation. The release verifier authenticates
   descriptions; the descriptor-relative store below persists and rechecks them.
   Provisioning, atomic selection, cross-process ownership, the launchd adapter
   and the installation sequence that composes them all exist below and are
   tested unprivileged, but never through a real root installation in the system
   domain. None of these components bootstraps or rotates the trusted release
   key, which production must embed in the helper and installer.
2. Production frontend compatibility: today's ad-hoc app loads Sparkle and does
   not meet this gate's hardening policy. Do not silently disable validation,
   change signing models or raise the macOS floor to get a passing result.
   A separate relay is not sufficient unless its own callers are authenticated.
   An isolated test now demonstrates a different approach: keep the frontend
   hardened and move Sparkle to an **unprivileged updater worker**. The worker
   must never be a proxy for privileged VPN commands. An opt-in candidate now
   wires the app's update model/preferences to a bounded worker channel; see
   `../update-worker/README.md`. The ordinary build remains unchanged. Actual
   disposable installation/relaunch, native-window scenarios and full-App
   loopback lifecycle tests now pass (with the documented native cancellation
   limit). System acceptance and release-policy/package integration remain open.
3. The helper-to-client identity/readiness gate below is now integrated on both
   ends, with the endpoint created privately under the protected directory and
   close-on-exec descriptors, but only between unprivileged processes.
   Protect descriptor lifetime against concurrent close/reuse. This gate
   identifies the original connector, not recipients of a passed descriptor.
   A production transport must explicitly account for descriptor inheritance,
   exec and per-message identity; a stream alone does not provide those guarantees.
4. Bound framing, timeouts, connection count and payload size; exact protocol
   versions and typed operations; repeat profile/resource validation in the
   privileged process. Never accept arbitrary shell commands, file paths or
   OpenVPN arguments. Bind state-changing operations to the owner and revision.
5. Production helper activation and failed-start recovery, plus system-level tests.
   The disk-selection transaction below does not stop/start a service, drain VPN
   operations or validate a running candidate. No routing/DNS/subprocess launch
   is implemented in these components. Cross-process lifecycle ownership and the
   launchd adapter now exist and are tested with a real per-user launchd service,
   but the system domain, root installation authorization and restart policy are
   untested, and the helper that would serve production requests does not exist.

## Verification

```sh
python3 -m unittest discover -s tests -p test_vpn_peer_authentication.py -v
```

The harness builds both architectures with a macOS 11 deployment target, signs
disposable universal fixtures ad-hoc and launches **separate actual processes**.
The verifier receives an accepted descriptor; the kernel retains the connecting
process's credentials and audit token. No synthetic audit tokens are used.
All connections use local AF_UNIX sockets in disposable directories; a separate
unconnected AF_INET socket tests rejection of an incorrect descriptor type. There is no
installation, admin prompt, corporate traffic or use of a real VPN profile.

The test-only `verify` CLI accepts pins explicitly to exercise different policy
decisions. It must never be shipped as a daemon or used to provision trust.
Passing this suite on Apple Silicon does not establish runtime compatibility
on Intel or macOS 11, nor prove a production app/helper channel is secure.

## Signed release authorization (isolated, verification only)

`VPNReleaseAuthorization.swift` verifies Ed25519 signatures with CryptoKit over
`kz.documentolog.proxypilot/vpn-release-authorization/v1` + a NUL byte + the exact
manifest bytes. An archive/feed signature cannot be reused for this purpose.
The verifier receives a **trusted** public key and an embedded minimum sequence;
neither may originate from a client's enrollment request. The release private
key is not needed by the verifier. No production key, signing pipeline or
installer is wired to this code yet.

The maximum 4096-byte manifest has precisely these ordered LF-terminated lines:
`format`, `product`, `sequence`, `version`, `protocol`, `app-arm64`, `app-x86_64`,
`helper-arm64`, `helper-x86_64`, `helper-sha256`, `helper-bytes`, each `key=value`.
Format/protocol are currently `1`; product is `kz.documentolog.proxypilot`.
Sequence is a positive decimal integer no larger than Int64.max. Version is
three canonical nonnegative decimal components, compared numerically. Hashes
are lowercase hex (20-byte CDHashes, 32-byte artifact SHA-256). The helper must
be nonempty and no larger than 32 MiB. Unknown, repeated, missing or reordered
fields, CRLF, numeric overflow, extra bytes and unsupported protocol fail closed.
There are no executable paths, shell commands, URLs or arbitrary launch arguments.

Only successful verification creates `VerifiedVPNRelease`. It can derive the
frontend's peer policy and compare the exact universal helper artifact bytes.
It does not validate the artifact's executable hardening/CDHashes, stage or
execute it. Those checks still belong in a protected installer transaction.

Given the previously verified release, it rejects an older sequence/version,
another authority, and different payloads reusing the same sequence. Identical
retries are idempotent. This verifier alone is **not durable anti-rollback**;
`VPNReleaseStore` now implements persistence, signature revalidation and locked
check+commit, but production must provision its root-owned directory and
coordinate it with helper activation/recovery.
Missing/corrupt installed state must not be treated as `previous: nil`; that is
only for an explicitly authorized first installation. Selecting the installation
owner, trust bootstrap, public-key rotation and runtime artifact activation remain
unfinished. The store retains the explicitly provided owner but does not
authenticate that first-install choice. Do not let a caller enroll its own hash.

```sh
python3 -m unittest discover -s tests -p test_vpn_release_authorization.py -v
python3 -m unittest discover -s tests -p test_vpn_updater_isolation.py -v
```

Release tests use ephemeral in-memory keys and synthetic inert artifact bytes.
The peer suite also exercises the chain from a signed release description to
authentication of an actual separate process (correct pin, wrong pin and wrong
identifier). Fixture signing is test-only, not production trust provisioning.

`tests/vpn-updater-isolation/` builds a disposable universal frontend with
ad-hoc `runtime,hard,kill` signing, no entitlements and no Sparkle linkage. An
ad-hoc nested unprivileged worker loads Sparkle, sets the enclosing bundle as
both `hostBundle` and `applicationBundle`, and uses only the information-check
API. The real framework accepts the existing signed feed over loopback, rejects
tampering and completes when the feed is missing. The worker's own version is
999.0.0, confirming the check targets the enclosing host rather than the worker.
No update is downloaded/installed; production UI and files remain unchanged.
The blocking test pipe is not a production transport implementation.

## Persisted policy (isolated storage component)

`VPNReleaseStore.swift` receives a trusted **open directory descriptor**, never
a client-supplied path. It duplicates the descriptor close-on-exec, requires the
directory owner to equal its effective UID and permissions 0700, and rejects
extended ACL entries. Production must run this in the root helper against a
fixed root-owned directory with protected ancestors; it must not reuse the
unprivileged app's VPN data directory. Directory provisioning now has a fixed-path
primitive described below; installation and IPC wiring are still absent. Tests
run as the current user with isolated 0700 directories.

Each operation takes a nonblocking cross-process lock and uses descriptor-relative
access with no symlink following. Record/marker/lock must be singly linked regular
0600 files owned by the store's UID, without ACL entries. Bounded canonical JSON
stores the signed manifest, signature and installation owner together; each load
re-verifies the signature. Updates preserve the owner and compare the expected
sequence against freshly read state, so an outdated writer cannot overwrite a
newer accepted release. Identical descriptions are idempotent even when presented
with a different valid signature.

An explicit first-install operation persists `initialized` before `release.json`.
Missing, corrupt, oversized, noncanonical or incorrectly signed state is an error,
not an empty store. Existing marker/record prevents reinitialization. Interrupted
first installation fails closed and needs a future authorized recovery flow;
there is no automatic reset or factory-pin fallback. The lock may exist in an
otherwise fresh directory and does not by itself indicate successful bootstrap.

Replacement uses a private exclusive temporary file, file fsync, atomic rename
and directory fsync. A failure after rename reports `commitUncertain`, never
promises that old state is unchanged. Caller must reload/reconcile. A process
crash can leave a private `.release-*.tmp` file; readers ignore it. Automated
orphan cleanup is not implemented. Crash hooks exist only behind the test compiler
flag `VPN_RELEASE_STORE_TESTING`, absent from normal compilation.

```sh
python3 -m unittest discover -s tests -p test_vpn_release_store.py -v
```

Separate processes test initialization/restart, persisted rejection of older
releases, retry/stale/conflicting writes, invalid signatures, corruption/deletion,
locks, symlinks/hard links/FIFOs, modes/ACLs, and forced exits before/after rename
and during first installation. These are **process-crash tests, not physical
power-loss tests**. The deterministic fixture signing seed is intentionally
public and used only by the disposable test executable, never by production.

This persists authorization, **not helper installation or VPN connection state**.
Do not call `accept` merely on download: a reviewed activation transaction must
coordinate policy advancement with the new helper, including recovery. It does
not defend against root deliberately replacing the complete directory with an
older valid snapshot, and cannot replace authenticated key bootstrap or binary
validation. Working application and installation packages still do not include
this component.

## Protected installation directory

`VPNDirectoryProvisioner.openSystemDirectory(create:)` checks for UID 0 before
opening anything. It walks `/` → `Library` → `Application Support` using separate
no-follow directory opens, checks root ownership, a local filesystem, non-writable
group/other permissions and absence of ACL entries, then opens/creates only
`ProxyPilot/VPN` with 0700 permissions. Existing incompatible directories are
rejected, never chowned/chmodded or cleared. A caller owns the returned close-on-exec
descriptor and may pass it to the store. There is no user-provided system path.

The internal descriptor-relative primitive is tested under a private temporary
base owned by the test UID. Production must only enter through the root-gated
system function after installation authorization. Tests explicitly refuse to
exercise the production function when elevated. Its successful full `/Library`
walk still needs live acceptance, especially on machines with existing ACLs or
earlier installations. The current run created no system directory.

## Atomic on-disk binary/policy selection (schema 2)

`bootstrapDeployment`, `commitDeployment` and `loadDeployment` bind a signed
release description to a content-addressed executable, `helper-<SHA256>`:

1. Verify the release signature, owner/sequence and exact candidate bytes.
2. Create a private 0700 temporary executable. `VPNHelperArtifact` checks the
   universal format, exactly arm64/x86_64 slices, executable file type, each
   architecture's expected CDHash and helper identifier, valid native signatures,
   hardened runtime/hard/kill flags and absence of entitlements. Checks explicitly
   cover all architectures and disable network access (no notarization claim).
3. Sync and publish the verified executable under its derived basename. Recheck
   an already staged file too; never overwrite corrupt/linked candidates silently.
4. Atomically replace one schema-2 `release.json` record. That record selects both
   the policy and the exact executable. Keep the old executable; do not remove it
   during this transaction. Re-read/verify the selected file on every load.

The accepted universal form is FAT32 with two ordinary arm64/x86_64 slices, matching
the current build; thin, extra-architecture and malformed files fail closed. The
protected local directory must not be concurrently writable by untrusted parties:
Apple's static signature API is path-based. The validator cross-checks the opened
file's device/inode against the resolved path but does not defend against root
deliberately modifying it during validation.

Policy-only schema-1 methods cannot update schema-2 deployments. Schema 1 is not
silently migrated to schema 2. A crash after publishing the candidate but before
the selector leaves the old pair selected; retry rechecks/reuses the candidate.
A crash after replacing the selector leaves the new complete pair selected.
Corrupt/missing selected code fails closed, not an automatic fallback to an old
binary. Old/unselected artifacts and private crash leftovers are retained; bounded
cleanup and installation recovery still require a lifecycle design.

`VPNAuthorizedDeployment` means **verified on disk**, not running, healthy or VPN
connected. Do not wire `commitDeployment` directly to an unauthenticated download
request. A runtime coordinator still needs quiescence, authenticated candidate
startup/health checks, commit ordering, restart recovery and a deliberate policy
for failed startup without undoing the accepted security floor. This is not a
completed launchd update/rollback implementation.

```sh
python3 -m unittest discover -s tests -p test_vpn_directory.py -v
python3 -m unittest discover -s tests -p test_vpn_deployment.py -v
```

Seven directory tests and nineteen deployment tests use disposable local files,
real universal ad-hoc signatures and separate coordinator processes. They cover
both architecture pins/signatures (including a weak or differently identified
Intel slice), malformed code, modes/ACLs/links, corruption, stale/repeated writes,
and forced process exits around candidate/selector replacement. The C helper
fixtures are inert and **never executed**. These tests neither register a service
nor establish power-loss durability or successful root installation.

## Authenticated helper readiness

`VerifiedVPNRelease.helperPolicy()` derives helper pins only from the verified
manifest and fixes the peer UID to **root** and identifier to
`kz.documentolog.proxypilot.vpn-helper`. The frontend policy still rejects UID 0;
the two roles do not share a caller-selectable UID exception. Both use the same
kernel audit-token, dynamic code-signature and hardening checks.

`VPNHelperReadiness.probe` consumes an exclusively owned connected local stream
descriptor, marks it close-on-exec, suppresses SIGPIPE and validates the peer
before sending and after receiving. A fixed 56-byte request/response contains an
8-byte kind/version marker, unsigned big-endian protocol and release sequence,
and a fresh 32-byte system-random challenge. Only an exact readiness response is
accepted. The socket is closed on success and failure; no authorization cache or
subsequent privileged command is attached to this probe connection.

Nonblocking I/O and poll use one monotonic deadline (default two seconds, local
maximum five), shared across partial reads/writes. Partial bytes cannot extend it.
EOF, wrong kind/protocol/sequence/challenge and unavailable peers fail closed.
Native Security calls are synchronous and not cancellable by this I/O deadline;
they are checked against it on completion. Do not run this on the UI thread or
claim a hard wall-clock bound for the Security subsystem.

The returned opaque `VPNHelperReady` is **point-in-time service readiness**, not
a live session handle, persisted health, proof of installed routes or VPN
connectivity. A future production responder must check its locally loaded policy
and actual idle initialization before replying, not blindly echo the challenge.
No production responder is implemented here. Socket provisioning, safe server
ownership across fork/exec/fd transfer, client authorization and the actual
command protocol still need transport integration/review.

Twelve tests use separate real signed unprivileged processes, including the
server/listener side of the peer check. A narrowly scoped
`VPN_HELPER_READINESS_TESTING` build flag substitutes only the fixture's UID;
it is absent from normal builds. Tests compile both forms for arm64/x86_64 and
verify that the **normal build rejects even the correctly pinned non-root
server**. Positive root-server authentication and Intel/macOS 11 execution have
not been tested. No elevated fixture or real VPN profile is used.

## Cross-process lifecycle ownership

`VPNLifecycleOwnership` is the supervisor gate the coordinator was missing: one
process at a time may stop or start the fixed service. It opens `lifecycle.lock`
relative to the protected directory descriptor (no path, `O_NOFOLLOW`), requires a
private `0700` directory and a `0600`, single-link, owner-matching regular file
with no ACL entries, then takes an exclusive non-blocking `flock`. The kernel
releases that lock when the owning process exits, including a crash, so a dead
supervisor cannot keep the service unmanageable.

Holding a descriptor is not ownership: `check()` reruns the file checks and proves
the directory still names the exact file we hold. A renamed, replaced or unlinked
lock fails closed, because a second supervisor can lock the new file and start
managing the same service. The coordinator rechecks the lease before the stop,
before the commit, before the start and before returning readiness. If it is lost
after a start, the failure is reported **without** stop/cleanup: stopping there
could stop a service the new owner already manages. A lease is not permission to
run a release, not proof that a helper is running and not a disk transaction lock.

Fourteen tests run separate real processes against disposable directories: a second
process is refused while a lease is held, a killed owner releases it without any
cleanup, a second lease inside the same process is refused, and rename/unlink/
release are all detected by the owner. Symlinked, group-readable, hard-linked and
ACL-carrying locks, shared directories and ACL-carrying directories are rejected.
Four activation tests cover ownership taken by another process and lost before the
stop, after the stop and after the start. Unprivileged exclusion is not proof of
root ownership under launchd.

```sh
python3 -m unittest discover -s tests -p test_vpn_lifecycle.py -v
```

## Helper-side transport and readiness answer

`VPNHelperListener` authenticates a peer before reading the fixed 56-byte
readiness challenge. The non-root owner must match the application's signed
release pins and may then use the bounded typed protocol. The root installation
role must match the same exact hardened app build, not just UID 0; it receives
readiness only and never enters the command dispatcher. Packaging must execute
that pinned build in installation mode. A different installer executable would
need explicit separate signed pins; no identifier-only or root-only exception
exists. Production app hardening/updater separation and packaging are still open.

Root binds in a separate fixed IPC directory (below), not the 0700 profile vault.
The older private 0600 endpoint is retained only for unprivileged test harnesses.
Every reply revalidates the peer. Rejection costs one bounded connection, but
this is not a proof of immunity to sustained local connection flooding.
The listener **never** unlinks an existing
socket: a stale endpoint means the supervisor did not confirm the previous stop,
and quietly stealing it would hide that. The reply is bound to the release: a
challenge naming another protocol version or sequence is refused, and the receipt
is only sent when the helper's own readiness state says yes at that instant, so a
merely running process cannot answer for a helper that is not ready.

Ten tests run the production listener and the readiness probe as separate signed
processes: an authenticated client receives a receipt, sequential clients are each
served, another identity is refused, a client outside the release's pins is
refused, a not-ready helper answers nothing, a challenge for another release is
refused, the endpoint is private to its owner, an existing endpoint is never
stolen, a shared directory is refused, and a silent client does not block the next
one. The launchd suite now starts this same listener as its service, so those 11
tests exercise the real helper side, the real adapter and mutual authentication.

Bounded framing, per-request typed operations and privileged work itself remain
unimplemented — there are no operations to dispatch yet.

```sh
python3 -m unittest discover -s tests -p test_vpn_helper_listener.py -v
```

## Authorized installation sequence

`VPNInstaller` is the one place the pieces are composed, in a fixed order:
authenticate the signed candidate and the current app process, provision the
protected directory, take the lifecycle lease, re-verify against stored policy,
publish the policy/binary transaction, and only then activate through launchd.
The lease precedes every selection or activation so an installation cannot race
a running supervisor into stopping or starting the service behind its back. It is
not an IPC entry point, an updater or a user command: the caller must already
hold the user's system installation authorization, and the trusted release key
must be embedded in this code, never read from storage or the network.

`install` refuses when a policy already exists — an existing installation is
changed by `update`, never re-bootstrapped over — and `update` never creates the
directory, so an absent one answers "not installed" while an unsafe one still
surfaces as unsafe and is never silently reprovisioned. Storage errors stay
themselves: a damaged installation is not reported as an absent one, and neither
is repaired by an update. Both production entries refuse unless running as root.

### Same-app install/update preflight (8 September)

Before provisioning or opening the installation, both production entries verify
the candidate's independent VPN release signature and check their **own live code**
against its installer policy: real/effective UID 0, fixed app identifier, exact
signed app pin, runtime/hard/kill, valid non-debugged status and no entitlements.
The self-check reuses the peer gate; it cannot trust a bundle path, version string,
worker event or claimed hash. A matching hash with the updater's identifier still
fails. No new permission or enrollment message was added to the updater channel.

Previously, an old/unlisted installer could select the new policy and replace
the service, only to fail the helper's readiness authentication afterward. It now
fails before filesystem provisioning, policy/budget changes or service shutdown.
The preliminary verifier's `previous: nil` checks signature/identity only: it
does not declare a fresh installation or reset the security floor. The existing
store still checks owner, expected revision and monotonic release selection under
its lock, and the helper still authenticates the installer after activation.

Five new self-identity tests and five installation regressions pass. The latter
use two differently signed app builds and a hardened updater-identified executable
with an ephemeral release authority. They reject an unlisted first installer,
leave the old service PID and stored files unchanged on rejected replacement,
deny the updater even with signed matching pins, accept the explicitly pinned
new app, reject the old app afterward, and preserve revision checks. The two
targeted suites total **39 passing tests** (20 identity, 19 installation).

These are non-root tests in a private directory and unique user launchd domain.
Only the test entry substitutes the current user's client policy for the root
installer policy; it still enforces exact app identity and hardening. Production
entries also compile without test seams for arm64/x86_64, target macOS 11.
Successful cross-UID/root authorization, a packaged same-app installer mode,
signed release sidecar delivery and actual VPN update recovery remain untested.
The shipping app/build and release workflow are unchanged; no real key is used.

The final regression with both isolated-update installer opt-ins enabled completed
310 tests in 367.193 seconds: 309 passed and one legacy Sparkle install test was
skipped. Nine release-key tests were excluded to avoid Keychain access; native UI
acceptance was not repeated in this run.

Eight tests run the whole sequence unprivileged, with a disposable base directory
standing in for `/Library/Application Support` and the user's own launchd domain
for the system domain: an installation provisions `0700` directories, publishes
the policy and starts a service that answers the readiness challenge; a second
installation is refused and leaves the running service alone; an unsigned release
installs nothing and starts nothing; an update replaces the installed release; an
update without an installation is refused; a held lifecycle lease blocks a
concurrent installation; a shared application directory is refused; and the
production entry refuses without root.

`uninstall` is the reverse, and it decides what it may remove **before** it stops
anything: an unexpected file aborts the removal instead of leaving a stopped
service and a half-removed installation. It then stops the service, takes the
launchd description away and removes exactly the names this component creates —
by exact name or the content-addressed helper pattern — with the lifecycle lock
last, because removing it ends our exclusive ownership. The two application
directories are removed only when already empty and still passing their checks;
nothing is recursive or forced. Six more tests cover the full removal, an
uninstall without an installation, foreign files aborting it with the service
still running, a held lease blocking it, and the two boot cases.

While the service description exists, launchd starts the helper at every boot
without asking the coordinator — that is how the helper returns after a restart,
and it is why the uninstall has to take the description away. The tests cover
both halves: after a stop the description survives and loading it starts the
service again; after an uninstall there is nothing left to load.

Trusted key embedding and rotation, and the updater integration, are still
missing. Nothing here has been run as root or in the system domain.

## Typed request protocol (1.5c, first half)

`VPNHelperProtocol` is the whole vocabulary the privileged helper understands:
fixed frames, fixed sizes, no strings, no paths, no shell. A request is magic,
a 16-bit operation, the 64-bit release revision the client believes it is talking
to, and a length-prefixed payload; an answer is magic, a status and a payload.
Adding an operation is a deliberate change in that file, never something a client
can request or a payload can imply. Today the list holds exactly one operation,
`status`, which answers with the running release's sequence and protocol version.

The limits are part of the format: at most 1 MiB per payload (matching the
profile importer), at most eight
requests per connection, a deadline per request (re-authenticating a peer costs
real time) and a separate cap on the whole conversation, so a slow or idle client
cannot hold the single-threaded helper for the sum of every deadline. Oversized
or malformed frames end the connection on the header, without reading the body.
A request naming another revision is refused rather than answered, so a helper
that was replaced mid-conversation never applies an operation meant for another
build. Both ends re-authenticate around every request: no cached authorization,
no ambient authority. When the budget is spent, the helper waits briefly for the
peer to hang up instead of resetting the connection over its last answer.

`VPNHelperSession` is the client end: it performs the readiness handshake, then
spends the same bounded budget on that connection, and closes on any refusal or
transport error rather than retrying on a connection whose identity it could not
confirm again. Both ends share one deadline-bounded framing implementation.

Nine tests drive the protocol against the real listener: `status` answers the
running release, several requests share one authenticated connection, a client's
budget is spent after eight, the helper stops answering after its own budget, an
unknown operation is refused, a request for another revision is refused, an
unexpected payload is refused, an oversized frame ends the connection quickly
rather than after a deadline, and a malformed frame ends it too.

`storeProfile` is the first operation that changes anything. The helper does not
trust the client's import: it inspects the bytes again with the **same importer
the application uses**, and keeps only the importer's normalized, hardened output
in `profile.ovpn` (`0600`) inside the protected directory. `VPNProfileVault`
writes it atomically — temporary file, `fsync`, rename, `fsync` — so a refusal or
an interrupted write leaves the previously stored profile exactly as it was, and
never a truncated one. A profile larger than the frame limit never leaves the
client. Storing a profile still connects nothing: no routes, no DNS, no OpenVPN.

Five more tests cover it: a valid profile is re-validated and kept in normalized
form, the helper refuses what its own importer rejects even when a client
accepted it, a rejected profile leaves the stored one untouched, an empty payload
is refused, and an oversized profile is never sent. A mutation that stores the
client's bytes unchecked fails three of them.

## Release trust and the signing key

`VPNReleaseTrust` is the one place the helper and installer learn whom to trust,
and the key is compiled in on purpose: reading it from storage, preferences or
the network would let whoever controls that source authorize root code. Only the
public half is in the repository (`app/vpn-release-public-key.txt`, mirrored by
the constant). An empty constant fails closed — a build with no trusted key
authorizes nothing at all, which is what a test asserts by compiling one.

`app/vpn-release-key.swift` keeps the private key the way Sparkle's key is kept:
in the Keychain, never on disk, never in argv, never printed. `generate` writes
the public half and refuses to overwrite an existing key unless `--force` is
given, because rotating invalidates every earlier release. `sign` produces a
detached signature over the same domain-separated bytes the helper verifies, so
a signature over an archive or an appcast can never authorize root code. For an
update, `sign-transition` first verifies both detached release signatures, requires
a strict forward release, constructs the canonical A→B record itself and signs it
under the separate transition domain; callers never hand-author the digest record.
`verify` and `verify-transition` run the helper's own verifiers — format, protocol,
sequence, pinned hashes and the exact edge, not just signature bytes. `--keychain`
points every operation at another keychain file, which is how the tests stay off
the developer's login keychain entirely.

Thirteen tests generate, sign, verify and reject inside a disposable keychain they
create and delete: the public half is published while the secret never appears in
output, a changed release description fails verification, another key cannot sign
for this one, an existing key is never replaced silently while rotation stays
possible, signing without a key refuses, an altered or non-forward update edge is
rejected without overwriting its outputs, the committed public key matches the
compiled constant, and a build without trust refuses to build an authority.

Rotation means shipping a new build with a new constant. There is no chained
rotation and no way to authorize a new key with the old one; a release signed by
an unknown key must simply fail to verify.

```sh
python3 -m unittest discover -s tests -p test_vpn_release_key.py -v
```

## Manual off and a durable attempt budget

`VPNActivationBudget` answers one question — may we try to start the helper
again? — from durable state next to the release policy. Two rules: the owner's
decision to turn the VPN off outranks every automatic attempt, and repeated
failures stop automatic retries instead of looping. It authorizes nothing on its
own: it cannot start, stop or select anything, and it is not VPN state.

An attempt is charged **before** it happens, so a process that dies mid-attempt
has still spent it and a crash loop cannot restart the helper forever. Only a
confirmed activation clears the count, and that same write records that the VPN
is meant to be on. An explicit user action is always allowed through — the budget
bounds automation, not the owner. `turnOff` persists the decision first and stops
afterwards, so a failed or interrupted stop still cannot be undone by automation.
A missing record is a first run; a damaged one is refused rather than repaired
into a fresh budget, which would be the easiest way to defeat both rules. The
coordinator charges the attempt only once a request is worth starting a service
for, so an invalid signature or a stale revision never spends one.

Ten activation tests cover a cleared budget after success, an invalid request
spending nothing, automatic attempts stopping after three failures, an explicit
attempt surviving an exhausted budget and clearing it, a crashed attempt still
being charged, manual off outranking automation, the owner turning the VPN back
on, manual off persisting when the stop fails, a damaged record refused and a
group-readable record refused. Mutation runs confirm that dropping either rule,
or charging after the attempt, fails those tests.

## launchd service adapter (production activation mechanics)

### IPC versus private storage (8 September correction)

`VPNEndpointDirectory` keeps the public endpoint at the fixed canonical path
`/Library/Application Support/kz.documentolog.proxypilot.vpn/helper.sock`. Its directory is
root-owned 0755 and contains only a root-owned 0666 socket. Permission to connect
does not grant permission to send commands: kernel UID, signed CDHash, identifier,
runtime hardening and per-request checks remain mandatory. Other users/builds
are rejected before their challenge/payload is read. The protected policy,
executable and profile directory stays 0700 and its records stay 0600.

The fixed no-follow parent walk verifies ownership, local filesystem, modes and
absence of ACL entries. Only root can create the IPC directory; an application
uses the read-only `connectSystem` entry and authenticates the resulting socket
through `VPNHelperSession`. The connector checks the socket's type, owner and
permissions, returns close-on-exec/nonblocking descriptors, and shares the
caller's monotonic deadline. It is not yet called by the app UI. Directory and
socket creation occur during authorized setup/helper startup, not a UI preview.

The root launchd runtime uses the separate endpoint for connection and cleanup;
uninstall removes the endpoint directory only when empty. Existing unexpected
directories/files are not repaired or recursively removed. Tests use disposable
directories and ordinary UIDs: root-to-user traversal and positive root
installation authentication still require authorized live acceptance.

On this Mac `/private/var/run` is group-writable, so it is deliberately not used;
the chosen `/Library/Application Support` ancestors were inspected read-only.
The endpoint directory is persistent: a crash/reboot can leave a stale socket.
The existing coordinator's confirmed stop removes it, but unattended boot-time
recovery still needs integration. The listener does not silently steal a socket.

The readiness-only installation role is exercised through an isolated compile
flag in listener tests; normal builds cannot substitute the owner for root.
A separate test verifies the normal installer policy rejects a correctly pinned
non-root app. No production trust key is read/rotated by these tests. The 1 MiB
profile boundary is tested end-to-end, including files above the previous 64 KiB
limit and refusal before sending/allocating an oversized frame.

`VPNLaunchdRuntime` is the `VPNActivationRuntime` the coordinator was missing:
launchd is the only thing that starts, supervises and stops the fixed service.
The domain, label, plist location, socket name and argument vector are fixed in
code — nothing here accepts a path, PID, command or argument from IPC. The
executable is the content-addressed file the store verified for that deployment,
rechecked as a private single-link regular file before its path reaches launchd.
`system()` refuses unless it runs as root and uses `system/` with the fixed
`/Library/LaunchDaemons` description; a narrow `VPN_LAUNCHD_TESTING` seam adds a
per-user-domain constructor that is absent from normal builds.

`stopAndDrain` boots the label out (treating "not loaded" as success), then
**confirms**: launchd no longer knows the label, nothing answers the socket, and
the leftover endpoint is removed — but only when it is really a socket owned by
us, never a substituted regular file or symlink. An unconfirmed stop is an error,
so the coordinator cannot start a second instance on top of a live one.
`startIdleAndConnect` refuses to start while a socket still exists, writes the
service description atomically (`0644`, private temporary file, `fsync`, rename,
`fsync`), bootstraps it and waits for the endpoint until the caller's deadline,
returning a connected close-on-exec descriptor. Every `launchctl` run is direct
execution with no shell, no inherited environment and a deadline that kills it.

Eleven tests drive the real adapter through the real coordinator against real
launchd, in the current user's own GUI domain under a disposable label (never the
system domain, never `/Library/LaunchDaemons`), and boot the label out afterwards.
They cover a started service authenticated by the readiness challenge, a stop that
confirms the label is gone and the helper PID no longer exists, socket removal,
idempotent stop, a second update replacing a running service with a new process,
recovery restarting the selected release, a service that never listens failing
inside the deadline and being unloaded, a foreign file on the socket name halting
activation, the private atomic description and the root-only production entry.

The started service is the production listener above, wrapped in a thin fixture
main: it binds the socket, answers the challenge and does nothing else. This
proves the activation mechanics, not a root daemon install: the system domain,
the installation authorization, KeepAlive/restart policy, manual-off precedence
and a durable attempt budget are still open.

```sh
python3 -m unittest discover -s tests -p test_vpn_launchd.py -v
```

## Single-owner activation coordinator

`VPNActivationCoordinator` composes staged storage with authenticated readiness.
It accepts only a trusted local `VPNActivationRuntime` adapter, not paths,
commands, PIDs or process handles supplied through IPC. The launchd adapter above
is the production implementation; the isolated fixture adapter still drives the
failure-injection tests as the current non-root user. Neither exercises routing or
DNS cleanup, because no component performs routing or DNS.

An update makes one attempt, in this order:

1. `prepareDeployment` verifies and stages the candidate without advancing the
   selected release or interrupting the old service. Invalid/stale requests stop
   here. An opaque prepared value is not permission to start that file.
2. Ask the runtime to drain operations, release owned resources and confirm its
   old process has exited. Failed/late confirmation prevents commit and launch.
3. `commitPreparedDeployment` re-reads the owner/current signed release under
   the storage lock, rejects stale preparation, rechecks the staged executable
   and atomically selects it. A failed or uncertain commit does not launch either
   version; recovery must reload authenticated state.
4. Start only the selected **idle** helper, with no profile, routes or DNS
   applied. Authenticate its readiness response against that exact release.
5. Recheck disk selection before returning readiness. If launch, readiness or
   selection validation fails, ask the adapter to stop/drain the possibly started
   process. Report the failure phase and whether cleanup was confirmed.

`recoverSelected` is an explicit single attempt: stop the supervisor-owned
instance, revalidate the current disk selection and start/check only that version.
A process crash before commit leaves the previous selection; after commit only
the new security floor is eligible. There is no automatic downgrade after a
failed start, no retry loop, no fallback from corrupt/missing selected files and
no automatic reinitialization. A compatible repair release must advance the
signed sequence; authorized repair/recovery UI is still pending. An identical
update may explicitly restart the selected version once, without changing policy.

The instance gate rejects concurrent/reentrant calls inside one process. Exclusion
between processes now comes from the lifecycle lease described below, which the
coordinator requires and rechecks. The storage lock still protects each disk
transaction, and selection checks detect intervening writers. A durable attempt
budget, cancellation/manual-off handling, authenticated command transport, launchd
wiring and startup recovery integration remain unfinished. The adapter's deadlines
are a contract checked after return, not preemption of a blocking adapter.

Eighteen activation tests combine real signed Universal files, the protected
store, separate inert processes and authenticated readiness. They cover invalid
preparation, stop/start/cleanup failures, candidate tampering, changed selection,
reentry, idempotent updates, rollback rejection, corrupt state and forced exits
around commit followed by a fresh recovery process. Normal code also compiles
without the test flags for both architectures. These tests are not real root
service installation, power-loss, launchd recovery or working VPN acceptance.

```sh
python3 -m unittest discover -s tests -p test_vpn_readiness.py -v
python3 -m unittest discover -s tests -p test_vpn_activation.py -v
```

## References

- macOS public SDK: `sys/un.h` (`LOCAL_PEERTOKEN`), Security `SecCode.h`
  (`kSecGuestAttributeAudit`, `SecCodeCheckValidity`, signing-information semantics)
  and `CSCommon.h` (signature/status flags).
- [Apple: dynamic code lookup](https://developer.apple.com/documentation/security/seccodecopyguestwithattributes(_:_:_:_:)).
- [Apple DTS: hardened runtime and library validation](https://developer.apple.com/forums/thread/802437).
- [Sparkle maintainer: ad-hoc signing and library validation](https://github.com/sparkle-project/Sparkle/discussions/2466).
- [Sparkle: updating another bundle from a separate process](https://sparkle-project.org/documentation/bundles/).
- [Apple: CryptoKit Ed25519 verification](https://developer.apple.com/documentation/cryptokit/curve25519/signing/publickey).
- Apple libc sources: [ACL descriptor lookup](https://github.com/apple-oss-distributions/Libc/blob/main/posix1e/acl_file.c)
  and [absent ACL property semantics](https://github.com/apple-oss-distributions/Libc/blob/main/gen/filesec.c).
- [Apple: validating all slices and limits of static code validation](https://developer.apple.com/documentation/security/secstaticcodecheckvalidity(_:_:_:)).
