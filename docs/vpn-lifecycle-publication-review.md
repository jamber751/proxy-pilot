# Lifecycle lock first-publication review

Concurrent first acquisition exposed a Darwin failure mode in the earlier
single `openat(O_CREAT)` path: while one process successfully published and held
`lifecycle.lock`, another simultaneous `openat` returned `ENOENT`. The losing
swap request consequently reported `VPNLifecycleOwnershipError.unsafeStorage`
rather than ordinary contention. The winning process remained the sole swap
owner; there was no evidence that lifecycle serialization was bypassed.

The targeted implementation separates lookup from publication. It first opens
the fixed existing name without creation. Only a captured `ENOENT` permits
`O_CREAT | O_EXCL`; only a captured `EEXIST` from that exclusive create permits
a bounded retry of the ordinary open. Other errors and retry exhaustion remain
`unsafeStorage`. It never unlinks, replaces, truncates, changes permissions, or
repairs an existing object. The original type, owner, mode, link-count, ACL,
flock, and final named-inode checks remain in force, and the `flock` errno is
captured immediately.

The focused regression starts eight separate processes behind a barrier against
an initially empty private directory. The winning process holds its lease until
Python has received a bounded, readiness-checked outcome from all eight
processes, eliminating scheduler timing as a route to a second sequential owner.
Each round requires exactly one owner and seven `busy` refusals, then explicitly
releases the winner, checks that the published file remains owner-held `0600`
with one link, and proves a later process can acquire it without repair. This is
repeated across 12 fresh directories.

On 13 September 2026 the complete lifecycle suite passed **15 tests in 2.277
seconds**, including all 96 synchronized first-publication contenders. The
fixture compiled the real lifecycle implementation for arm64 and x86_64 and used
only disposable private directories and unprivileged processes. No root,
launchd, service, VPN, network, Keychain, or real installation was used.

The root agent repeated the final lifecycle suite after test-process stream
cleanup: **15/15 passed in 2.016 seconds**. Integration checks using explicitly
approved disposable user-domain launchd fixtures also passed: installer
**36/36 in 58.152 seconds**, real idle-daemon suite **46/46 in 69.833 seconds**.
No root service, VPN tunnel or production installation was involved.
