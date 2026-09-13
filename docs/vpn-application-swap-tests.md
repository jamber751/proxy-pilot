# Protected application swap acceptance tests

These tests exercise only disposable, owner-private directories under `/tmp`.
They build inert universal A/B applications, sign them with ad-hoc test
signatures, derive fixture-only authenticated releases and an exact signed A→B
edge, and call the compile-time test entry. They never write `/Applications`,
run either application, install software, contact a service, or use production
keys.

Coverage includes atomic A/B inode exchange and fresh-process idempotence;
wrong transition proof; missing, duplicate, corrupt, and stale layouts; unsafe
base mode and symlinked fixed containers; held and replaced namespace leases;
failures before exchange, after exchange, and after directory sync; process
death immediately after exchange with forward recovery; and the separation of
the unprivileged test entry from the root-only production entry. Optional
`PP_SWAP_ASAN=1` builds the checker with AddressSanitizer.

The final expanded matrix also rejects execution from inside either slot or a
hard-linked executor alias, detects post-exchange resource tampering without
rolling back, and exercises simultaneous requests and a separate process holding
the namespace lease. The checker copied inside a fixture's Resources directory
is executed only to test the exclusion guard; neither inert app's main program
is launched.

Concurrency exposed an existing first-publication issue in lifecycle ownership:
the losing `openat(O_CREAT)` returned ENOENT on this host. Test-only diagnostics
captured errno immediately and were removed after diagnosis. Opening an existing
name first, using exclusive creation only on ENOENT, and reopening only after
EEXIST fixed the observed interleaving without accepting unsafeStorage as busy.
All owner/mode/ACL/nlink/named-inode checks remain in place, and retries are bounded.
After the fix, **24/24 repeated concurrent exchanges passed in 13.892 seconds**;
the complete **12/12 AddressSanitizer suite passed in 11.937 seconds**.
The complete ordinary suite also passed **12/12 in 8.828 seconds**. Installer
regression with the revised lifecycle lock passed **36/36 in 58.152 seconds**
using explicitly approved unprivileged per-user launchd fixtures.
The idle-daemon regression also passed **46/46 in 69.833 seconds**.

Final opt-in Universal candidate:
`/tmp/proxypilot-swap-final.MXEryh/candidate/ProxyPilot.app`. Both architectures
compiled; strict, nested, all-architecture codesign verification passed. The
entire staged-app validation suite was repeated against a private copy of that
final candidate: **14/14 passed in 6.131 seconds**. The candidate itself was not
launched, installed or published.

Scope: this is an internal two-slot protected namespace primitive, not a new
installation layout. The root-only method has no CLI/IPC/Sparkle caller. It does
not authenticate a live A or B, stop a service, change the journal/selector,
install into Applications, delete the old copy, or promise physical power-loss
durability. Existing staging contents must already be durable, and their protected
ancestry and a separate authenticated executor remain caller prerequisites.
