# Applications destination staging

Date: 2026-09-21. Scope: prepare an exact candidate B beside the installed app
without replacing, launching or selecting it.

## Implemented boundary

`VPNApplicationDestinationStage` accepts only the protected application
transaction descriptor and a verified B release. Production requires real and
effective root and opens the literal `/Applications` directory itself; no path,
bundle name or destination is accepted from IPC, argv, updater metadata or user
settings.

The operation holds the application namespace lease, validates the exact B in
the protected `current` slot, and creates the fixed private
`.ProxyPilot.vpn-update` directory under the destination with one atomic
same-filesystem `clonefileat`. There is deliberately no recursive-copy or
cross-filesystem fallback. The cloned directory must be owner-only `0700`, stay
bound to the same name and inode, contain exactly one `ProxyPilot.app`, and pass
the full Universal bundle, nested-code, resource-seal, hardening and entitlement
checks.

Before returning, every represented file and directory is synchronized, the
source and copy are fully revalidated under the same lease, and the destination
parent is synchronized. Production repeatedly re-opens `/Applications` and
compares its device/inode to the held descriptor. A pre-existing exact stage is
revalidated and synchronized for forward recovery. Foreign, damaged or
unexpected content is refused and never automatically deleted or repaired.

The existing `/Applications/ProxyPilot.app` name is never opened, renamed or
removed by this increment. The mutable parent means a returned result is not a
durable receipt; the later exchange must re-bind and revalidate the stage at its
own mutation boundary.

## Verification status

Production and test compositions typecheck with warnings treated as errors for
arm64 and x86_64. Seven isolated runtime scenarios are implemented for staging,
idempotent recovery, source/copy mutation, hostile fixed names, damaged recovery,
destination permissions, lock contention and the production non-root guard.

After the host restart, a freshly linked smoke binary ran normally and all seven
destination scenarios passed in **6.322 seconds**. No test touched the real
Applications bundle or any system/network setting.

Next: implement the atomic exchange with the installed A name, preserve
forward-recovery evidence and bind exact installed B to a live authenticated B
process before selector B can advance.
