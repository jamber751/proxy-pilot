# Protected executor provisioning

Date: 2026-09-20. Scope: creation of a protected A copy only. This is not an
Applications install, process launch, VPN activation, selector change or release.

## Implemented boundary

`VPNReplacementExecutorProvisioner` creates the fixed `executor` directory from
the already verified `current` A slot under one application-namespace lease.
Production requires real and effective root before any operation. Its API is
descriptor-relative and accepts no path, bundle name, command or executable
from IPC or user settings.

The source `current` directory contains exactly one complete
`ProxyPilot.app`. A same-filesystem `clonefileat` creates the entire directory
hierarchy under the fixed `.executor.preparing` name. The operation is atomic;
unsupported cloning or a cross-filesystem request fails closed without a copy
fallback. Symbolic links inside the already validated bundle remain link objects.

Before publication the implementation:

- validates exact signed A in both source and clone;
- flushes every physical regular file and directory represented by the exact
  observation, then repeats full validation;
- invokes the test checkpoint, rechecks namespace ownership and revalidates
  source and clone immediately at the publication boundary;
- atomically renames `.executor.preparing` to `executor`, syncs the base and
  validates the published exact A again.

The flush is an ordered namespace/data publication boundary, not a claim about
physical power-loss durability. Filesystems without atomic cloning are refused;
there is intentionally no recursive userspace copy fallback.

## Recovery behavior

- Exact published A returns `alreadyPrepared` after fresh validation.
- Exact `.executor.preparing` left by interruption is validated, synchronized
  and published forward as `recoveredPrepared`.
- Published and preparing names present together, symlinks, wrong types,
  damaged bundles and stale source observations fail closed.
- Failure after the publication rename is `commitUncertain`; the exact copy is
  never deleted or replaced automatically. A retry inspects it and returns
  `alreadyPrepared`.

This increment deliberately does not remove a damaged or obsolete tree. Safe
cleanup belongs after the journal reaches a state that no longer needs A for
forward recovery. Recursive deletion while a replacement may still be running
would make recovery weaker.

## Evidence and remaining work

The focused disposable suite passes 7/7 scenarios, including interruption
after clone and before publish, post-publish uncertainty, hostile fixed names,
lock contention, source/copy mutation and the production non-root guard.
Fixtures are ad-hoc signed Universal app bundles in private `/tmp` directories;
the real app, system service, profiles and network are untouched.

Final normal run: **7/7 in 7.174 seconds**. AddressSanitizer repeated the full
suite: **7/7 in 8.622 seconds**, with no skips or sanitizer findings. An added
acceptance case places an unexpected sibling beside source/copy at the last
boundary; exclusive-slot validation refuses publication.

Existing journal/drain/swap integration passed **8/8 in 32.753 seconds**.
The final isolated Universal candidate at
`/tmp/proxypilot-provision-final2.dAs6cr/candidate/ProxyPilot.app` passed strict,
deep, all-architecture signature validation (arm64 and x86_64). Static staged
inspection of its protected copy passed **14/14 in 7.480 seconds**, with no
skips. The candidate was not launched or installed; no push/release occurred.

Next: a mutually authenticated fixed-mode handoff that launches this exact
executor without user paths or arbitrary arguments. After that, implement the
writable Applications destination and installed/live-B proof before selector B.
