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
