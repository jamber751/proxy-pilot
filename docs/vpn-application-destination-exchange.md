# Applications destination exchange

Date: 2026-09-26. Scope: atomically install exact candidate B while retaining
the previous installed A for forward recovery. This boundary does not launch B,
advance the selector, activate VPN, or delete either application copy.

## Implemented boundary

`VPNApplicationDestinationExchange` requires real and effective root in
production and opens literal `/Applications` itself. It accepts no destination
path or bundle name from IPC, argv, updater metadata, or user settings. The only
accepted layouts are:

- before: exact installed A plus exact staged B;
- after: exact installed B plus exact retained A.

The operation holds the application namespace lease, binds the fixed protected
transaction slots and `.ProxyPilot.vpn-update` by descriptor and inode, and
revalidates the signed transition, protected copies, authenticated executor A,
installed copy and staged copy immediately before mutation. Installed bundles
may be owned by the original console user; the hidden destination stage and
newly installed B remain root-owned. Every node must have the expected owner,
safe permissions, no ACL, a valid resource seal and the pinned Universal code
identity.

Installation is one same-filesystem `RENAME_SWAP` between the two fixed
`ProxyPilot.app` names. The operation never removes or recursively replaces a
bundle. Once the exchange may have occurred, any later error is
`commitUncertain`; there is no automatic inverse exchange. A retry recognizes
only the complete B/A layout, reauthorizes it and returns forward success after
full revalidation and synchronization.

This primitive deliberately leaves selector advancement and process launch out
of scope. Its authorization callback is the integration boundary where the
journal-aware coordinator must prove that replacement remains pending and that
the old service is still drained. A later boundary must authenticate a live B
launched from the installed B inode before publishing selector B.

## Verification status

Seven isolated runtime scenarios cover successful exchange and retry,
authorization failure, installed/staged mutation, lock contention, unsafe or
missing layout, production root enforcement, post-exchange uncertainty and
forward recovery. The staged-application suite (15 cases, one optional real-app
case skipped) and destination-staging suite (7 cases) also pass after the
installed-owner policy was added. Test destinations are private temporary
Applications analogues; no test names or mutates the real installed bundle.

Next: connect this primitive to the protected journal while retaining the
replacement/drain authority across the final mutation, then prove exact
installed B plus a live authenticated B process before changing the selector.

## Journal-aware composition

`VPNJointApplicationReplacement.installPreparedApplication` now keeps the
service lifecycle lease and the same journal snapshot contract across the
protected-copy exchange, destination staging, and destination exchange. The
runtime adapter is created lazily only after both protected bundles validate;
the old service is drained once per attempt. Every later mutation authorization
rechecks the exact transaction UUID, revision, A/B releases, phase, recovery
mode, executor identity, and lifecycle lease.

The production hidden executor now enters this complete disk-install path. If
the destination is still A and the fixed private stage is absent, exact B is
staged from the protected current slot and then exchanged. A retry with exact
installed B and retained A skips restaging and moves forward. Any error after
the protected-copy exchange is reported as uncertain because reversing either
namespace would be unsafe. The journal remains `replacementPending`, revision
1, and selector A throughout this boundary.

The expanded journal suite passes 9/9 scenarios, including full disk install,
idempotent retry, one drain per attempt, unchanged unrelated Applications
siblings, stale journal rejection, wrong live process, executor mutation, lock
contention, and post-exchange uncertainty. The complete arm64/x86_64 package
suite passes 10 required cases; 3 cases requiring an optional external complete
engine artifact are skipped.
