# VPN update runtime gates

## Implemented

- Ordinary coordinator updates recheck `requireNoPendingUpdate()` after candidate preparation and before attempt accounting or service stop.
- Coordinator recovery checks the journal before attempt accounting and before stopping the selected service.
- Every coordinator selection check also checks the journal, including immediately before start and after authenticated readiness. A journal appearing during startup therefore prevents a ready result and triggers the existing owned-service cleanup path.
- Daemon startup checks the journal before reading the selected release and again after lifecycle acquisition immediately before attempt accounting and endpoint preparation. The second check is unconditional, including coordinator-owned startup.
- The daemon serving/readiness loop intentionally does not acquire the release-store lock or inspect `update.json`. A journal appearing beside an already-running old daemon does not itself stop that daemon.
- Explicit `turnOff()` remains independent of the journal gate: it records manual-off first and then stops.

This is a refusal boundary only. Journal-aware replacement activation and reconciliation remain future work; ordinary startup must not interpret a journal as authorization to start either release.

## Focused coverage added

- Corrupt journal blocks recovery without charging the budget, stopping, or starting.
- Corrupt journal blocks an ordinary update without charging the budget, stopping, or starting.
- Manual turn-off remains available with a corrupt journal.
- A journal introduced after process start prevents readiness and uses cleanup.
- Daemon boot with a corrupt journal preserves a zero-failure activation budget and leaves the pre-existing dead endpoint untouched.
- A journal appearing beside an already-running daemon leaves its process identity and authenticated readiness unchanged.

## Verification evidence

Command-line Swift builds require disposable module caches on this host:

`CLANG_MODULE_CACHE_PATH=/tmp/pp-clang-cache SWIFT_MODULECACHE_PATH=/tmp/pp-swift-cache`

- `python3 -m unittest tests.test_vpn_activation -v`: all 36 tests compiled and ran. The three new pre-start journal tests passed, as did 17 existing rejection/budget tests. Sixteen readiness-positive tests failed because the inert helper did not reach its Unix-socket `listening` marker in the sandbox, uniformly reported as `failure:start cleanup:true`; sandbox denial of local socket binding is the likely cause but was not proven. This includes the new late-journal test, whose hook is reached only after that marker.
- From `tests/`, `python3 -m unittest test_vpn_daemon.VPNDaemonTests.test_boot_refuses_a_corrupt_update_journal_without_spending_attempt -v`: fixture compilation completed, but setup failed at the precondition installation for the same sandboxed start failure, before the journal boot assertion ran.
- The initial activation command without disposable caches ran zero tests because the compiler attempted to write `/Users/jamber/.cache/clang/ModuleCache` and reported the installed Swift compiler/SDK patch mismatch.

No production root path, VPN operation or Keychain operation was used.

## Root integration results

- Approved disposable-socket rerun: all **36 activation tests passed in 23.263 seconds**, including late journal appearance and cleanup. The restricted-run failures above were not counted as passes.
- First full daemon run: 33/34 passed. The added live-daemon test wrongly compared the entire directory before/after intentionally adding `update.json`; root corrected it to assert the new journal separately while preserving every prior file and PID. No production fix was needed for this assertion.
- After adding the four authenticated-preparation cases, 37/38 daemon tests passed; one existing manual-off test hit `launchctl bootstrap` error 5. Three isolated repeats passed (30.971 seconds), without a production change. This transient failure is recorded, not erased.
- Final full daemon rerun: **38/38 passed in 53.596 seconds**, including manual-off, untouched stale endpoint on refused boot, continued live-A readiness, and authenticated preparation. Fixtures use disposable per-user launchd labels with cleanup, not a system/root VPN service.
- The final candidate application (isolated updater + VPN installer) built for arm64/x86_64 and passed `codesign --verify --deep --strict`. It was not launched or installed. An earlier build overlapped a source edit and is not used as final evidence.

## Pending

- Implement journal-aware activation/reconciliation separately; these guards deliberately reject it today.
