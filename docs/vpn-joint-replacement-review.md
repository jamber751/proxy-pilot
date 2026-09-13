# Journal-authorized protected-copy exchange

Date: 2026-09-13. Scope: internal opt-in installer component; not an
Applications installation, publication, or live VPN acceptance.

## Boundary

`VPNJointApplicationReplacement.exchangePreparedCopies` opens the existing,
fixed service directory and retains its real lifecycle lease throughout the
operation. It accepts only the exact transaction UUID/revision in
`replacementPending` with exact A still selected (`inspectApplication`). It
authenticates the current process to A, not merely root or an updater identity.
The signed transition comes from the freshly verified journal snapshot; the
caller cannot supply a different edge. The journal wire format is unchanged.

After verifying both protected application copies, the swap calls a mandatory
production authorization callback. This rechecks the journal, ownership and
live A identity, lazily constructs the runtime, checks again, drains with a
20-second monotonic deadline, then checks again. Invalid copies never construct
the runtime or stop the service. Both application trees and namespace ownership
are checked again after the callback, before the atomic rename. Exact B/A retry
also requires authorization and drain; it never exchanges back.

Lock order is service lifecycle, then distinct application namespace. A base
that aliases the service directory is rejected. Locks cover independent
namespaces and are not substitutes for one another. The final coordinator check
occurs while service ownership is retained; a failure after swap success is
`commitUncertain`, never an inverse rename.

Independent review caught a retry-specific error classification: once exact
B/A has been observed, even authorization/drain failure must remain
`commitUncertain`. The entire already-exchanged callback/check/sync path is now
inside that boundary; failures before an A/B rename retain their precise errors.

## Deliberately unchanged

- No selector, journal phase/revision, activation budget or desired-on/off write.
- No service start, readiness claim, installed-app receipt or live-B proof.
- No CLI, IPC, Sparkle or production UI entry calls this component.
- No real Applications mutation, installation-layout migration or permission fix.
- Protected ancestry and a stable authenticated A executor outside the two
  slots remain trusted-caller prerequisites. Executor exclusion is not a
  replacement for the missing independent production executor design.
- If draining succeeds but replacement fails, A may remain stopped with the
  pending journal intact. No silent restart or fallback is performed.

Tests use test-only nonroot entry points, signed disposable bundles and an
inert recording runtime. That proves sequencing and refusal behavior, not a
root install or launchd stop. See `vpn-joint-replacement-tests.md` for evidence.

Root regression checks after the retry fix: protected swap 12/12 (8.111 s),
lifecycle ownership 15/15 (2.213 s). Journal regression after retaining the
verified edge: 6/6 (60.789 s). The final isolated Universal candidate at
`/tmp/proxypilot-joint-final.fkxJtl/candidate/ProxyPilot.app` passed strict,
deep, all-architecture signature verification; staged inspection including a
protected copy of that candidate passed 14/14 (5.951 s), with no skipped cases.
The candidate was never launched or installed. No production network, profile,
Keychain, system service, push or release operation was performed.

## Remaining next boundary

Design the independently authenticated executor and writable Applications
destination contract, then installed/live-B verification and journal-aware
activation. Do not select B just because protected copies exchanged.
