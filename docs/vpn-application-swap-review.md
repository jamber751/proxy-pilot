# Protected application swap review

## Actionable finding

The initial helper-only transition guard treated a changed release version as
sufficient to establish application-swap direction. Swap direction must instead
come from the signed application artifacts themselves: at least one of the exact
arm64 or x86_64 app hashes must differ. Otherwise two releases with identical
app pins but different `release.version` values pass the early transition guard.
Their bundle checks will ordinarily fail later because signed `Info.plist`
versions differ, but that is an indirect layout failure rather than rejection of
the unsupported helper-only edge. Remove version inequality from the permitting
condition and require differing signed app pins.

## Confirmed boundaries

Apart from that finding, the implementation follows the reviewed primitive:

- it requires one verified exact A-to-B transition and different releases;
- it acquires and repeatedly rechecks a descriptor-bound namespace lease;
- fixed `current` and `candidate` slot descriptors are private, local,
  root-owned, no-ACL, distinct, on the base filesystem, and rebound to their
  fixed names on every check;
- each slot contains exactly one physical child named `ProxyPilot.app`;
- the executor path is converted to a directory descriptor and its ancestry is
  compared by device/inode against both slots, rather than using a lexical
  prefix test;
- exact A/B is the sole exchange state and exact B/A is the sole idempotent
  recovery state; missing, corrupt, duplicate, foreign, and ambiguous pairs fail
  closed;
- both applications receive full staged-bundle validation, with retained
  observations revalidated immediately before the atomic exchange;
- `renameatx_np(RENAME_SWAP)` has no multi-rename fallback;
- after rename, parent syncing, namespace/lease/executor rechecks, child identity
  inversion, and fresh exact B/A validation are required;
- every failure after successful rename is `commitUncertain`, and there is no
  inverse swap or selector rollback;
- an already B/A retry syncs and fully revalidates without swapping back.

This remains an internal protected-namespace mutation. It does not operate on
`/Applications`, prove that B is installed or live, authenticate a running A,
drain a service, or mutate the update journal or release selector. A separately
authenticated executor outside both trees and lifecycle/journal coordination
remain integration prerequisites.

This was a read-only source audit. The production file and tests were not edited
or compiled as part of the audit.

## Corrected implementation follow-up

The implementation was reviewed again after correction. The helper-only gap is
closed: swap eligibility now requires at least one exact per-architecture app
pin to differ, and release version no longer supplies direction. The tests cover
both identical version/pins and different version with identical pins as
`invalidTransition`.

The executor exclusion now also opens the reported executable without following
a final symlink and requires a regular, single-link inode before walking its
parent ancestry by descriptor identity. This remains correctly described as an
anti-self-replacement check, not live-process authentication. Tests exercise an
executor physically inside a slot and a hard-linked outside alias.

The expanded suite covers exact inode exchange and idempotent B/A retry,
pre-exchange failures, post-exchange uncertainty, a process `_exit(91)` after
the atomic rename followed by forward recovery, lost and cross-process-held
leases, concurrent callers that never reverse the result, tampered bundles,
wrong/indistinguishable edges, duplicate/corrupt/missing layouts, slot redirects,
permissions, and extra content. The process-exit checkpoint demonstrates the
logical rename/restart window; it is not physical power-loss evidence.

No further significant source or test gap was found within this primitive's
scope. Journal-state authorization, service drain, independent executor
authentication, `/Applications` installation, installed/live B proof, and
physical power-loss acceptance deliberately remain outside it. This follow-up
was also read-only with respect to production and tests; only this review note
was updated.
