# Review: joint-update replacement boundary

## Narrow next implementation

Implement only two installer-owned operations next: `beginJointReplacement` and
`cancelJointUpdate`. Do not replace the application, select B, or start either
helper in this step.

`beginJointReplacement` should accept an expected transaction UUID and revision,
not candidate bytes or an arbitrary phase. Its production entry point remains a
root-only, already system-authorized installer operation. In this exact order it
should:

1. open the existing protected installation and acquire the lifecycle lease;
2. construct the release store and load the journal, requiring exact
   `prepared`, UUID, revision, selector A, and protected owner;
3. authenticate the current live process against A's installer policy (the
   same live-code check used by `prepareJointUpdate`), then recheck the lease;
4. call the fixed launchd runtime's `stopAndDrain` with a bounded deadline;
5. recheck the lifecycle lease and reload the journal/selector with the same
   UUID, revision, phase and exact A endpoint;
6. call `markUpdateReplacementPending`, then return only its revalidated
   snapshot.

The installer wrapper, rather than `VPNReleaseStore`, owns this sequence. The
store method is intentionally disk-only and cannot prove authentication, drain,
or lifecycle ownership. Keep the lease through the entire call; the short store
lock must not span launchd work.

The returned snapshot is state for display/recovery, not a transferable proof
that the service remains drained. `beginJointReplacement` releases its lifecycle
lease on return, so a later replacer must reacquire the lease, revalidate the
exact journal and selector, and call `stopAndDrain` again immediately before it
touches application bytes. No later operation may consume the earlier drain as
fresh evidence. When replacement exists, the stronger integration should keep
one lease across that final drain, replacement, B proof and selection (for
example inside one trusted executor closure), rather than exporting a lease or
"drained" token.

An API shape such as the following keeps authority and evidence narrow:

```swift
static func beginJointReplacement(
    authority: VPNReleaseAuthority,
    transactionID: UUID,
    expectedRevision: UInt64
) throws -> VPNUpdateJournalSnapshot

static func cancelJointUpdate(
    authority: VPNReleaseAuthority,
    transactionID: UUID,
    expectedRevision: UInt64
) throws -> VPNUpdateJournalSnapshot
```

The test-only forms may additionally accept the trusted base and runtime test
parameters. Do not expose a generic phase-transition method or accept a runtime,
directory descriptor, signing policy, app path, or claimed identity from IPC.

## Crash and failure semantics

Stopping A's helper precedes the journal advance because `replacementPending` is durable
authorization to continue forward even after a crash; it must never be written
while that helper might still be running. The authenticated A installer process
itself must remain alive to write the phase. Drain success is
positive evidence only within the held lifecycle lease. Recheck ownership before
the journal write.

A crash or error after drain but before the journal advance leaves
`prepared + selector A`, possibly with A stopped. This is safe and deliberately
ambiguous with respect to liveness: recovery may authenticate A and repeat begin,
or may cancel. It must not infer that replacement was authorized, select B, or
silently start A. A failed/uncertain journal write is reconciled by reloading:
`prepared` permits retry/cancel; `replacementPending` is forward-only.

A crash after the durable advance leaves `replacementPending + selector A`.
Cancellation is now forbidden even if no app bytes changed. Recovery must resume
toward B. A stop timeout, unconfirmed cleanup, lost lease, authentication error,
or journal/selector mismatch must leave the phase `prepared` and must not invoke
the phase transition. If drain may have partly occurred, report that cleanup is
unconfirmed rather than attempting replacement.

Idempotency is observational, not a phase skip. A repeated begin against an
already `replacementPending` record may return the freshly validated same
snapshot only if the API explicitly defines this retry behavior and verifies
the exact UUID and resulting revision; otherwise it should return a conflict.
It must never drain based only on UUID before loading and validating the journal.

## Cancellation and manual off

`cancelJointUpdate` should acquire the lifecycle lease, load and require exact
`prepared + selector A`, authenticate the current live A installer, recheck the
lease and journal, then call `cancelUpdateJournal`. It does not need to drain and
must not restart A. Whether A should run is activation intent, not cancellation
state; a later ordinary action may run only after explicit retirement of the
cancelled record.

Manual off remains available while any journal exists, including corrupt data.
It must first durably record desired-off through the existing activation budget
and then perform only the fail-safe drain under lifecycle ownership. It does not
cancel, advance, select, retire, or repair the journal. If stop fails, desired-off
still prevents automation from reconnecting. Once `replacementPending` is
durable, a UI "cancel" can cancel waiting only; it cannot call the journal
cancellation API or restore A.

## Installed B proof before selection

Do not add `selectUpdateCandidate` integration until the coordinator can prove
the installed application is exact B. Existence, version metadata, a Sparkle
callback, and a path-based check of `/Applications/ProxyPilot.app` are not durable
authority. A bundle whose files can be changed by the invoking user is not a
protected observation, and `SecStaticCodeCreateWithPath` alone has a path/replace
race.

The later B gate should combine two independently obtained facts while holding
the lifecycle lease:

1. **Protected installed bundle:** open the fixed installation hierarchy without
   following symlinks; require a local filesystem, expected owners, no ACLs,
   single-link regular executable, and no group/user-writable bundle components;
   bind pre/post descriptor metadata while strictly validating the sealed bundle,
   identifier, hardening/entitlements and B's signed per-architecture code hashes.
   If the installed bundle cannot satisfy this protection model, copy/verify it
   into a root-private staging location before replacement and make the
   privileged replacer produce an authenticated, descriptor-bound result. A
   user-writable final bundle is a blocker, not a reason to trust its path.
2. **Live B process:** launch the fixed executable only from that protected,
   freshly verified object and authenticate the resulting process incarnation
   using a kernel audit token/connected Unix socket against B's exact policy.
   Never accept a PID, path, bundle version, receipt text, or caller-provided
   audit token. Revalidate the protected installed object after live proof so an
   observed process cannot bless subsequently swapped bytes.

Only after replacement, both B checks, another confirmed drain, lease recheck,
and a fresh `replacementPending + selector A` reload may the coordinator call
`selectUpdateCandidate`. Selection must then be reloaded as exact B before the
journal can advance to `selected`. No A/B union peer policy and no rollback edge
should be introduced.

## Safe implementation order

1. Add and test the A-authorized begin boundary, including drain failure, lease
   loss, journal races, stopped-before-write crash, uncertain journal commit and
   retry classification.
2. Add and test A-authorized prepared-only cancellation and its non-restart
   behavior; preserve the existing journal-aware manual-off path separately.
3. Specify and implement a privileged application replacer whose inputs and
   results are descriptor-bound and independently authenticated.
4. Implement protected installed-B inspection plus live B process proof.
5. Integrate B selection, then activation/readiness or protected desired-off
   completion, with fresh selection and lifecycle checks at every boundary.
6. Exercise real root/launchd/Sparkle packaging and physical power-loss cases
   only after the isolated state-machine tests pass.

## Current blockers and non-goals

The first two operations above are executable with current primitives. Actual
replacement/selection remains blocked on a reviewed privileged replacement
mechanism and a protected installed-B verifier/live-B proof protocol. Current
helper artifact validation applies to root-private content-addressed Mach-O
files; it must not be casually reused as proof of a mutable application bundle.

Terminal retirement is not part of this narrow gate. A future installer wrapper
must authenticate the app matching the terminal selector (A for `cancelled`, B
for `completed`) and revalidate the terminal record under lifecycle ownership;
adding an unauthenticated convenience wrapper now would unnecessarily widen the
store method's reach.

This review does not authorize root execution, network or Keychain access,
Sparkle changes, app replacement, selector mutation, production IPC exposure, or
automatic terminal-journal retirement.

## Implemented boundary review and test evidence

The subsequently implemented `VPNInstaller.managePreparedJointUpdate` boundary
was reviewed against this ordering. It acquires lifecycle ownership before
loading state, requires the expected UUID/revision and source-consistent phase,
authenticates live A, and constructs the runtime only after those checks. Begin
drains and rechecks its deadline and lease before the store transition. Cancel
and cancelled-only retirement never construct a runtime or start a service.
Retirement deliberately supports only `cancelled + A`; completed/B retirement
remains behind the future B identity gate. No actionable production defect was
found in this boundary.

Seven focused disposable tests were added to the existing installer harness.
They cover a real per-user launchd drain with selector and activation budget
unchanged; prepared cancellation and retirement with the same live A PID;
pending-phase refusal of cancellation, repeated begin, and retirement; source-B
and updater identity denial; stale UUID/revision and held-lease rejection before
runtime construction; injected stop failure and post-stop lease loss without a
phase advance; missing and canonical-permission corrupt journals reaching the
installer wrapper; and a real stop followed by failure before journal advance,
after which cancellation/retirement leave A stopped and the budget unchanged.

Targeted result on 13 September 2026: **7 tests passed in 31.652 seconds**. The
tests used only a disposable private directory, test signing authority, local
Unix sockets, and the current user's launchd domain. They used no root, system
launchd domain, real VPN, network, Keychain, Sparkle, or installed application
replacement.

Root integration acceptance: **80 tests passed in 108.537 seconds** (35 installer
cases plus 45 against the production idle-daemon implementation in disposable
per-user launchd fixtures). This includes the seven new cases on both service
implementations and the earlier install/update/removal/identity/engine checks.
The candidate app compiled for arm64 and x86_64 and passed strict deep signature
verification; it was not launched or installed. No actual B application
replacement or physical power-loss acceptance is claimed.
