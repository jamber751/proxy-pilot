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
  relying on a version label. The current release model retains the app pin set
  for dynamic peer authentication; static bundle verification needs the explicit
  architecture mapping as well.
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
Actual app replacement, installed-B inspection, live-B proof and journal-aware
activation are still absent from production entry points. This document prevents
those missing guarantees from being inferred from the completed earlier layers.
