# Protected executor handoff

Date: 2026-09-20. Scope: mutually authenticated launch of the already
provisioned A executor. This is not an Applications install, selector change,
VPN connection or release.

## Implemented boundary

`VPNReplacementExecutorHandoff` opens only the fixed
`executor/ProxyPilot.app/Contents/MacOS/ProxyPilot` executable held by the
protected application transaction directory. Production requires real and
effective root. Before launch the complete executor bundle is checked against
the verified A release and its open executable is bound to its device/inode.

The parent starts that exact path with one fixed internal argument and an empty
environment. `POSIX_SPAWN_CLOEXEC_DEFAULT` closes every ambient descriptor;
spawn actions expose only two fixed descriptors to the child:

- an unnamed `AF_UNIX` stream socket;
- the already-open protected application transaction directory.

No path, command, release document or arbitrary operation crosses the channel.
The request is a fixed 32-byte frame containing one protocol magic, the journal
transaction UUID and expected revision.

Both peers validate the other live process through the socket's kernel audit
token, exact signing identifier, pinned CodeDirectory hash, hardened-runtime
flags and entitlement allowlist. The parent additionally proves that the
spawned PID is executing the exact held executor inode. The socket suppresses
`SIGPIPE`; all protocol I/O and child completion are deadline-bounded.

## Authorization order

The parent holds the application-namespace lease while it:

1. validates the protected A bundle and executable;
2. spawns the fixed child;
3. completes mutual live-code authentication;
4. receives child readiness;
5. revalidates the lease, bundle and running executable.

Only then does it release the lease and send the canonical request. This lets
the child acquire the same lease inside the journal-authorized replacement
without creating a gap in which an unchecked child can mutate state. Any
failure before GO is a precise refusal. Once GO is written, a missing or failed
answer is `commitUncertain`; the parent never guesses that the exchange did not
happen and never attempts an automatic reverse swap.

## Evidence and remaining work

The disposable Universal/hardened app-bundle suite passes all 9 handoff cases
in **17.092 seconds**:
valid exchange, idempotent result, wrong peer, mutation before spawn, mutation
after readiness, post-GO child failure, namespace contention, production
non-root refusal and static isolation checks. The full run also repeats the 14
staged-application cases: **23 tests in 24.042 seconds, one optional real-build
case skipped**. Adjacent provisioning passed **7/7 in 8.138 seconds** and the
journal/drain/swap suite passed **8/8 in 36.241 seconds**.

All fixtures lived in private `/tmp` directories. No application was installed,
no system service or network setting was changed, and no push/release occurred.

Next: connect the fixed hidden child role to the protected release journal and
`VPNJointApplicationReplacement`, then build the writable Applications
destination and installed/live-B proof. Selector B remains forbidden until that
proof exists.

## Production journal composition

The fixed hidden role is now dispatched before AppKit/UI initialization by
`VPNReplacementExecutorEntry`. It is accepted only as the sole exact internal
argument and only with real/effective root. Before opening the inherited channel,
the child obtains the release authority from the compiled trust root and loads
the previous-A policy from the protected update journal. It refuses every phase
except `replacementPending / inspectApplication`.

After mutual authentication, the fixed request goes directly to
`VPNJointApplicationReplacement.exchangePreparedCopies`. That boundary reloads
the journal under service lifecycle ownership, matches transaction UUID and
revision, authenticates the child against the fresh previous-A policy, drains
the service and performs the protected swap. Thus the preliminary policy load
cannot authorize a stale request. The internal role remains absent from the
ordinary UI path; malformed or extra internal arguments fail before AppKit.

Both architecture slices of the full installer-enabled app composition compile.
Runtime package acceptance is still required after the host's ad-hoc code-signing
service recovers; an attempted AddressSanitizer live-code run instrumented the
very identity under test and subsequently left fresh ad-hoc executable launches
blocked in the macOS signing service. No product/system files were changed.

Next: implement and prove the writable Applications destination plus exact
installed/live-B verification. Selector B remains forbidden until that proof.
