# Review: durable joint app/helper update journal

## Recommendation

Add the journal only as a protected state-machine primitive inside
`VPNReleaseStore`. It should authenticate and preserve one exact signed `A -> B`
edge and make crash state observable; it must not install an app, drive Sparkle,
stop or start a service, authenticate an IPC caller, or claim runtime health.

The proposed durable phases are minimal and sufficient:

1. `prepared`: A is still selected, B's protected helper/engine artifacts are
   staged and revalidated, and the exact A -> B transition is recorded. This is
   the only cancellable phase.
2. `replacementPending`: written and synced before authorizing the first
   irreversible app-replacement action. From here recovery is forward-only.
3. `selected`: B is durably selected. This phase is written only after reloading
   the selector and proving it is exactly B.
4. `completed`: a future trusted coordinator has positively established its
   completion condition. Selection alone must never imply completion.

The sole cancellation edge is `prepared -> cancelled`. `cancelled` and
`completed` should remain durable terminal records until an explicit retirement
operation. Retirement is part of the state machine, not opportunistic cleanup.

Use a strict graph and monotonic revision, for example revisions 1 through 4 for
the forward path and a distinct terminal cancellation revision. An API must take
the expected transaction UUID, expected revision, and intended next phase; it
must not accept an arbitrary replacement journal that can skip or reverse
phases. The UUID is useful for correlation and idempotency but is not authority.

## Journal identity and validation

Persist enough signed input to reconstruct trust after either endpoint becomes
selected:

- schema, transaction UUID, phase and monotonic revision;
- protected owner UID copied from the current store record;
- A manifest payload and signature;
- B manifest payload and signature;
- transition payload and signature binding the exact A and B payload digests.

On every load, under `release.lock`, strictly decode the envelope, independently
verify A, verify B with `previous: A`, verify the transition, compare the owner
with protected state, and revalidate the content-addressed endpoint artifacts.
Do not serialize `VerifiedVPNUpdateTransition` or trust caller-provided decoded
values. A malformed, unknown-phase, noncanonical, oversized, foreign-authority,
or internally inconsistent journal is protected-state corruption and must fail
closed.

Use the store's existing descriptor-relative I/O, root-owner checks, no-ACL
checks, `0600` journal mode, atomic temporary-file replacement, file `fsync`,
rename, and directory `fsync`. Journal creation and all phase changes must share
`release.lock` with selector operations. A rename followed by directory-sync
failure is an uncertain commit: reload and reconcile; never report that the old
phase necessarily survived.

Retirement should verify `cancelled + selector A` or `completed + selector B`,
then `unlinkat` the fixed journal name and `fsync` the directory. If that sync is
uncertain, report uncertainty and require reload. Do not treat a terminal record
as absent until durable retirement is observed.

## Recovery decision matrix

App identity below means a future root integration has positively inspected the
installed app's live/on-disk signing identity against the exact endpoint pins.
The journal itself cannot make that observation.

| Journal | Selected release | Installed app | Recovery decision |
|---|---|---|---|
| `prepared` | A | A | May resume by durably entering `replacementPending`, or cancel to `cancelled`. Do not stop A merely because the journal exists. |
| `prepared` | B | any | Invalid state. Fail closed; prepared never authorizes selecting B. |
| `prepared` | A | B/unknown | Invalid or out-of-protocol replacement. Fail closed; do not infer permission to select B. |
| `replacementPending` | A | A | The boundary was crossed even if replacement did not occur. Resume the authorized replacement toward B; do not offer cancellation or silently retire. |
| `replacementPending` | A | B | Replacement succeeded before a crash. Reverify all inputs/artifacts, select B, reload B, then record `selected`. |
| `replacementPending` | B | B | Expected selector-rename/phase-write crash window. Reload and prove exact B, then record `selected`; never roll back to A. |
| `replacementPending` | B | A/unknown | Unsafe split state. Fail closed and require authorized repair toward B; never start A under B or lower the selector. |
| `selected` | B | B | Resume candidate activation/readiness or the explicitly defined desired-off completion path. |
| `selected` | A | any | Impossible regression. Fail closed; do not replay selection implicitly. |
| `selected` | B | A/unknown | Fail closed and repair the app toward B; do not start either mismatched pair. |
| `completed` | B | B | No recovery work; explicit retirement may remove the terminal journal. |
| `cancelled` | A | A | No recovery work; explicit retirement may remove the terminal journal. |
| terminal | wrong selector/app | any | Fail closed; terminal text is not stronger than authenticated observed state. |

If installed-app identity cannot yet be inspected safely, recovery must stop at
classification. In particular, `replacementPending + A` is not sufficient by
itself to select B, and `replacementPending + B` proves only protected helper
selection, not that the app replacement succeeded.

## Cancellation and completion boundaries

Cancellation is allowed only while `prepared` and exact A remains selected. The
cancel operation writes and syncs `cancelled`; it does not merely delete the
journal. After `replacementPending` is durable, a UI cancellation may stop
waiting, but it cannot revoke the root transaction or authorize rollback. The
system must continue or later recover forward to B.

`completed` needs a deliberately narrow future definition. For a desired-on VPN,
it should require exact B app identity, B selector, B helper readiness, lifecycle
ownership, and the coordinator's normal final selection recheck. For a deliberate
desired-off state, completion may avoid starting the VPN only if the protected
manual-off intent is durably observed and exact B app/selector consistency is
still proven. Never derive completion from a Sparkle callback, selector B alone,
process launch, or a serialized readiness receipt.

## Operations blocked while a journal exists

Any journal record, including `completed`, `cancelled`, or corrupt data, blocks
normal store mutations until explicit recovery/retirement:

- bootstrap, legacy accept, normal prepare and normal deployment commit;
- creating a second journal or replacing it with a different UUID/edge;
- owner changes, first-install/reset paths, release-floor changes, and key
  rotation;
- artifact garbage collection, pruning A or B, and cleanup of state needed to
  reverify either endpoint;
- another app/helper update, downgrade, repair release, or unrelated selector
  change;
- ordinary helper start/restart, automatic recovery, profile application, and
  route/DNS mutations outside the journal-aware lifecycle path.

Read-only status may report the journal and exact selector classification. A
fail-safe stop/drain may remain available under lifecycle ownership, and a manual
off request should still be durably recordable so automation cannot reconnect;
neither operation may mutate the journal edge or selector. Normal profile
mutations should remain blocked because they can race drain/restart and blur what
state recovery is preserving.

Malformed journal data must block rather than be ignored or retired through the
normal API. Repairing protected corruption requires a separate explicit recovery
authority; absence, corruption, and cancellation are not interchangeable.

## Conflicts and invariants

- At journal creation the selected release must be exactly A, the protected
  owner must match, B must advance from A normally, the signed edge must match,
  and B artifacts must already be complete and valid.
- Same UUID plus the same revision/content may be an idempotent retry. Same UUID
  with different edge/content, a new UUID while any journal exists, stale
  revision, phase skip, reversal, or terminal rewrite is a conflict.
- Selecting B is a trusted disk-only operation: reverify the journal and A
  selector under the same lock, atomically replace `release.json`, reload exact
  B, then advance the journal. A crash between those writes is intentionally
  represented by `replacementPending + B`.
- Never implement a symmetric rollback selector. Once B is observed selected,
  the release floor is B even if app replacement/readiness failed.
- Do not create a union of A and B peer policies. The old app authenticates the
  request against A before replacement; candidate bytes/processes authenticate
  against B. The transition only authorizes the directed handoff.
- The lifecycle lease must cover future drain, replacement authorization,
  selection, activation and final checks. `release.lock` serializes short disk
  transactions only and is not a substitute for lifecycle ownership.

## Completed review checks

Reviewed `VPNReleaseStore.swift`, `VPNActivationCoordinator.swift`,
`VPNLifecycleOwnership.swift`, `VPNReleaseAuthorization.swift`, and
`docs/vpn-update-transition-review.md` on 13 September 2026.

The current store already provides the necessary descriptor-relative file
validation, nonblocking flock, canonical protected envelope, atomic rename and
file/directory sync behavior. The coordinator already treats selector commit as
an uncertain crash boundary, reloads before recovery, starts only the selected
release, probes exact-release readiness, and avoids rollback. The lifecycle
lease is correctly distinct from the store lock and detects replacement/loss.
The transition verifier binds exact payload digests and independently enforces B
advancement from A.

## Implemented primitive review and test evidence

The subsequently implemented `VPNReleaseStore` journal API was reviewed against
the model above. No actionable source defect was found. It persists both signed
endpoint manifests and the signed exact transition, owner, UUID, phase and
revision; strictly re-encodes and re-verifies them on load; validates both
content-addressed deployments; classifies only the permitted A/B selector
states; and enforces the exact forward/cancellation graph. Candidate selection
correctly tolerates the `replacementPending + B` selector-rename crash window
without adding a rollback path. Completion remains historical state rather than
a readiness receipt.

The global mutation guard checks raw journal-file presence before ordinary
bootstrap, accept, prepare, and commit paths, so malformed and terminal journals
also block. Stale prepared deployment tokens cannot bypass it. Retirement is
limited to selector-consistent terminal records and uses fixed-name unlink plus
directory sync with explicit uncertain-commit behavior. Short journal disk
transactions use the existing release lock; lifecycle ownership remains an
explicit prerequisite for future integration rather than being falsely supplied
by this store API.

New tests are in `tests/test_vpn_update_journal.py` and
`tests/vpn_update_journal_checks.swift`. They compile the real store for arm64
and x86_64, combine and ad-hoc sign the checker, and use disposable real signed
universal helper fixtures with a deterministic test-only Ed25519 authority. The
six cases cover the full lifecycle across separate processes; cancellation and
terminal retirement; stale UUID/revision, skipped phases and cancellation after
the boundary; an old prepared-token conflict; bad transition signature; blocked
ordinary deployment, metadata, bootstrap and competing-journal mutations;
canonical strict-schema, owner, endpoint/transition signature, phase/revision,
and both endpoint-artifact corruption; update-record rename checkpoints;
selector rename recovery as pending+B; retirement checkpoints; private modes,
symlinks and the cross-process lock. The semantic JSON mutation test first proves
its encoder reproduces the Swift journal bytes exactly, avoiding a false result
from canonical-encoding differences.

Targeted result on 13 September 2026: **6 tests passed in 56.910 seconds**.
Forced `_exit` checkpoints exercise process-crash boundaries and restart
classification; they do not prove physical power-loss durability. No root,
network, Keychain, launchd, service, installed-app, Sparkle, production key, or
production installer action was used. Production app-identity inspection,
authenticated current-A preparation under the lifecycle lease, drain,
replacement, readiness/desired-off completion, and system power-loss acceptance
remain future integration work.

Root final integration review added valid `selected/revision=2` and
`completed/revision=3` records against selector A, plus a valid
`prepared/revision=0` record against selector B after the forced selector crash.
These check the selector matrix, not merely malformed revision rejection.
All 6 journal tests passed again in **58.794 seconds**. The existing release
store, deployment, signed-transition and core suites passed **62 tests in
69.783 seconds** against the journal implementation.

The subsequent authenticated preparation step is now implemented and tested
separately in `docs/vpn-update-preparation.md`; installed-B identity inspection,
drain/replacement/activation integration and physical power-loss acceptance are
still pending. The internal journal methods are not exposed as CLI or IPC actions.
