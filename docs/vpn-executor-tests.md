# Protected replacement executor tests

The joint replacement fixture now runs the authenticated A process from the
fixed private `executor/ProxyPilot.app` slot while keeping byte-identical A and
candidate B copies in the swap slots. A complete external A bundle is retained
only to prove that matching signed identity outside the fixed executor namespace
is insufficient.

Focused cases cover successful exchange and retry while the executor directory,
bundle and executable remain unchanged; exact external-A refusal before runtime
construction; missing, symlinked and unsafe executor parents; executor resource
corruption before drain; and resource or directory replacement during drain.
Pre-exchange refusals check controlled error exit, absence or presence of factory/drain
markers at the intended boundary, unchanged swap-slot inodes, and no runtime
start call. The fixture copies only disposable fixture bundles; it never changes
installed applications or performs helper launch, launchd, VPN, profile,
network, Keychain, or root actions.

At the primitive checkpoint immediately after the atomic exchange, the fixture
also corrupts or replaces the executor namespace. Both cases must return
`commitUncertain` while retaining the exchanged B/A inode order. This is
low-level no-rollback coverage, not journal-coordinator recovery coverage.

Verification on macOS used standard unittest discovery in an approved execution
environment. All 8 test groups passed in 29.643 seconds. This validates the
disposable signed fixtures and modeled failure boundaries; it does not prove a
real installed-application replacement or live service behavior.

The integrating agent independently reran all 8 groups: **8/8 passed in
29.790 seconds**, without skips. Primitive swap regression: **12/12 passed in
8.911 seconds**. Final staged bundle checks, including a protected copy of the
new Universal candidate: **14/14 passed in 6.026 seconds**, without skips.

The final candidate at
`/tmp/proxypilot-executor-final.Uk5rbc/candidate/ProxyPilot.app` passed strict,
deep, all-architecture signature verification (arm64 and x86_64). It was not
launched or installed. No push or release was performed.
