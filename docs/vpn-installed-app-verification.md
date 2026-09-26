# Installed-app verification: next integration boundary

Date: 2026-09-13. This is a read-only investigation and implementation constraint,
not evidence that application replacement or B activation is implemented.

## Observed installation

The current `/Applications/ProxyPilot.app`, its Contents/MacOS directories and
main executable are owned by the logged-in user, with owner write permission.
`/Applications` is root-owned but writable by the admin group. No permissions,
ownership, installed files or system settings were changed during inspection.

This is a normal drag-and-drop installation, not an error to repair by silently
changing `/Applications` permissions. A fixed pathname, version string or valid
signature check at one instant cannot establish that the same bundle bytes
remain installed at the later privileged selection step.

The local Apple SDK's `Security.framework/Headers/SecStaticCode.h` explicitly
limits static validation to code that is not being concurrently modified and
to the period while it remains unmodified. Its all-architectures, strict and
nested-code flags validate different aspects of the signed bundle, but do not
turn a writable filesystem namespace into a protected one.

## Required contract before selecting B

- Stage and verify complete B bundle content in storage inaccessible to
  untrusted writers, including both architectures, its signed resource seal and
  nested updater/framework code. Check identifier, hardening and entitlements;
  do not reuse the helper's bare Mach-O check as full bundle validation.
- Retain exact per-architecture app pins from the signed release rather than
  relying on a version label. Implemented on 13 September: the release model
  retains the explicit architecture mapping; dynamic peer authentication still
  consumes the same set of values. This alone proves no installed object.
- Define a bounded, privileged replacement operation with descriptor-bound
  inputs and an exact destination. Recheck lifecycle ownership, journal and drain
  immediately before modifying the application. Never treat a previously
  returned `replacementPending` snapshot as a still-held lease.
- Define how the replacement executor survives replacing the frontend bundle
  containing its own executable. Do not assume the running A process will remain
  a valid executor after its signed bundle changes, or promote the unprivileged
  Sparkle worker to root authority.
- Bind installed-object verification and live B process authentication to the
  same exact candidate and transaction. A correctly signed B launched from a
  download directory alone does not prove `/Applications` contains B. Likewise,
  a successful static check alone does not prove a trusted B process is running.
- Establish explicit handling of the writable destination namespace. A root-
  protected staging copy proves that copy, not installation at a mutable path.
  A pre/post path check must not be described as permanent immutability. Do not
  broadly change ownership/permissions or introduce a new versioned installation
  layout without designing and testing its migration and uninstall behavior.
- Only then select B and run journal-aware readiness (or preserve deliberate
  desired-off). Never fall back to A once the durable selector advanced to B.

## What the current increment does

The A-authorized begin/cancel/cancelled-retirement methods implement only the
pre-replacement boundary. Beginning confirms drain and records the forward-only
phase under one lifecycle lease. Cancellation/retirement do not start a service.

`VPNStagedApplication` adds a read-only observation of the fixed `ProxyPilot.app`
child of a private local staging-directory descriptor. It checks the physical
tree and safe internal framework links, fixed bundle metadata, both exact
architecture pins, strict nested resource/code seals, hardening and entitlements,
then repeats the tree observation. Revalidation repeats the whole inspection.
The caller must establish protected ancestry and exclusive staging/lifecycle
ownership; this API does not provide those or accept paths from IPC. It is
compiled only into the opt-in installer candidate and has no production caller.

This result is deliberately not an installed-app proof, a live-process proof,
a retained lease, or authorization to replace/select/launch anything. It must
not be serialized into a durable receipt. Runtime acceptance and limitations
are recorded in `vpn-staged-app-review.md`.

Actual app replacement, installed-B inspection, live-B proof and journal-aware
activation are still absent from production entry points. This document prevents
those missing guarantees from being inferred from the completed earlier layers.

## Protected exchange primitive (next increment)

`VPNProtectedApplicationSwap` now implements and tests an internal atomic
`RENAME_SWAP` between fixed `current/ProxyPilot.app` and
`candidate/ProxyPilot.app` children under one already-protected private base.
These are staging/test slots, not a migration of the user's installation layout.
Both signed artifacts and their exact signed transition are verified under a
namespace lease. Only A/B exchanges; only B/A is accepted as an idempotent retry.
Indistinguishable app pins (including helper-only updates) require a different
future path and are refused. Parent syncing, inode inversion and full post-swap
inspection follow the rename. Post-rename failure is uncertain, never rollback.

It deliberately refuses a mutable Applications parent and self-replacement.
Executor-path/inode exclusion is a safety check, not live authentication.
The real installer must still establish an independent authenticated executor,
hold the real service lifecycle lease, recheck the exact journal and drain, and
solve mutable-destination installation/live-B proof before selecting B. No
production entry point calls the swap, and no service or selector is changed by
it. Acceptance details: `vpn-application-swap-tests.md`.

## Journal and drain integration (protected copies only)

`VPNJointApplicationReplacement` now supplies the real service lease, fresh
pending-journal checks, exact live-A authentication and drain callback for the
protected-copy primitive. The callback runs after copy validation, before
rename, and on exact B/A retry; trees are revalidated after draining. The verified
transition is retained in the journal snapshot without changing its disk format.
No selector/journal/budget/desired-state write or service start is performed.

This closes the internal sequencing gap for protected copies, not the independent
executor or writable Applications destination boundary above. There remains no
production entry point or installed/live-B proof. Details and test scope:
`vpn-joint-replacement-review.md`, `vpn-joint-replacement-tests.md`.

## Protected executor binding

Production protected-copy exchange now requires the running A to match the
fixed `executor/ProxyPilot.app` under the same private transaction base.
The separate directory, entire exact-A bundle and fixed main executable are
descriptor-bound and revalidated under the app namespace lease before/after
drain and exchange. Same-signature A launched elsewhere is insufficient.
Dynamic A authentication remains in the coordinator; executor files are never
part of the exchange. Details: `vpn-executor-review.md`, `vpn-executor-tests.md`.

Provisioning/launch/recovery of this executor is still missing. This strengthens
the internal copy boundary, not the writable Applications installation contract
or installed/live-B proof. The existing user installation is unchanged.

## Descriptor-bound installed B receipt

`VPNInstalledApplication` now opens only literal `/Applications` in production,
performs the full installed-bundle verification for exact B, and retains open
descriptors for the destination, bundle, and main executable. Before returning
the executable path or accepting a process PID it rebinds the fixed installed
name, rechecks the complete signed tree, and compares the executable device and
inode. The receipt is deliberately short-lived because Applications remains a
mutable namespace.

Four isolated tests cover the exact executable path, resource mutation, bundle
name replacement, an unrelated live process, and the production root guard.
They pass in a private Applications analogue. This proves the launch source
identity but does not yet launch or authenticate candidate B; selector B remains
forbidden until that live handshake is implemented.

## Live installed B handshake

`VPNInstalledCandidateHandoff` now launches only the executable path returned by
the descriptor-bound installed-B receipt. It passes one fixed inherited Unix
socket, an empty environment, and one exact hidden argument. B validates its own
candidate policy and the connected previous-A policy loaded from the protected
journal; A validates B's audit-token identity and binds its PID back to the
retained installed executable inode. Both sides revalidate identity and journal
context around a bounded ready/go/ack/finish exchange. `SO_NOSIGPIPE` prevents a
dying child from terminating A.

The hidden B entry accepts no path, UID, release, or operation from argv. It
requires root and reloads exact `replacementPending / inspectApplication` state
on every context check. The production joint installer invokes this proof after
the Applications exchange while still holding service lifecycle ownership.
The parent now performs the single journal selector commit only after B has
acknowledged readiness and while the same authenticated PID/socket/inode binding
is still live. It validates exact `selected / recoverCandidate` state before
sending the finish byte; B independently reloads that selected state before a
clean exit. Failures after the commit are uncertain and recover only forward.
The handshake itself still has no disk-write authority: the caller supplies the
one commit closure while retaining the service lifecycle lease.

The isolated two-process handshake passes success, mid-flight context-change,
commit failure and post-commit selected-context failure tests (3 test groups);
the journal/disk suite remains 9/9 and the arm64/x86_64 package suite
passes all 10 required cases (3 optional external-engine cases skipped). The
joint disposable fixture cannot reproduce distinct production A/B journal
policies from the fixed system store, so its test branch stops at installed-B
proof; production composition is compiled while the cross-release handshake is
covered at the protocol boundary. Helper B readiness and journal completion are
implemented by the separate boundary below.

## Selected helper readiness and completion

`VPNSelectedCandidateFinalizer` now handles the post-selector boundary under the
same service lifecycle lease. It reloads exact selected B and the protected
activation budget. If the durable intent is off, it does not restart the helper
and records an explicit completed/off outcome. If intent is on, it charges one
bounded automatic attempt, starts only selected helper B in idle mode, validates
its signed readiness challenge, rechecks selection and lease, and clears the
failure budget only after readiness.

Only then does it advance `selected → completed` and revalidate the completed
journal. A start/readiness failure attempts stop-and-drain and leaves the journal
selected for forward retry. Once completion may have been written, errors are
`commitUncertain` and the ready helper is not torn down based on a guess. No VPN
profile, route, or DNS setting is applied by this boundary.

The joint suite now passes 11/11 scenarios, including desired-off completion
without a helper start and desired-on start failure with cleanup while remaining
selected. Authenticated helper start/readiness behavior is also covered by the
existing activation suite; the production arm64/x86_64 package composition
passes all required package cases.

## Forward recovery and terminal journal retirement

`VPNSelectedCandidateRecoveryEntry` is the fixed root-only entry for a crash
after selector B has committed. It accepts no paths, transaction identifiers,
releases or desired state from argv. It reloads the protected journal, accepts
only exact `selected / recoverCandidate` or `completed / completed`, validates
the running process against candidate B's policy, and binds that process to the
literal installed B executable before obtaining lifecycle ownership.

For `selected`, recovery repeats the normal finalizer. For `completed`, where an
in-memory readiness receipt cannot survive a crash, it positively reconciles
the durable intent: off drains the helper; on charges a bounded automatic
attempt, restarts exact helper B in idle mode and requires its signed readiness.
Only after the selected deployment and observable on/off outcome are confirmed
does recovery retire the terminal journal. Failure never selects A or removes
the journal based on an assumption.

The joint suite now passes 17/17 scenarios. It covers forward recovery from both
late phases, terminal retirement, refusal of an earlier journal before runtime
effects, and start failures that preserve the appropriate retry phase. The
production package suite passes all 10 required cases; 3 optional external
engine-artifact cases remain skipped. Automatic discovery/launch of this entry
and cleanup of retained A, executor and staging artifacts remain separate
boundaries; this entry alone does not claim unattended recovery.

## Recovery-only helper startup

The real helper previously rejected every update journal at startup, which made
the selected-candidate finalizer's readiness probe impossible in production.
The helper now distinguishes an exact late journal from all other update state.
It may start only when `selected / recoverCandidate` or `completed / completed`
names the same selected owner and release that the helper authenticates.

While that late journal exists, the listener permits only the separately pinned
root installer readiness role. The owner's app is refused before receiving a
readiness response and cannot enter status/profile operations. Booting this
recovery-only helper neither charges nor clears the automatic activation budget,
and it releases any short boot lifecycle lease so installed B can acquire the
coordinator lease. Once the terminal journal is retired, the same selected
helper may serve the owner normally. Earlier, corrupt or mismatched journals
still fail before endpoint creation.

The listener/daemon suite passes 76 scenarios, including a real disposable
launchd transition from selected recovery-only service through completed and
terminal retirement. The existing behavior of an already-running operational
helper is preserved while a newly prepared journal awaits the coordinator's
explicit drain.

The ordinary no-crash path now uses the same exact terminal-retirement primitive
immediately after its in-memory readiness (or desired-off) receipt and completed
journal check. Consequently a successful update does not leave the helper in
recovery-only mode. The recovery entry retains the same primitive for a later
forward retry; neither path can retire a non-completed or differently selected
transaction.
