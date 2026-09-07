# VPN helper security boundary (not yet integrated)

`VPNPeerAuthentication.swift` is an isolated, fail-closed **connector identity
gate**, not a daemon, command dispatcher, installer or ready VPN feature. It is
intentionally absent from `app/build.sh` and from all installation packages.
The older inert installation probe has no real-operation authorization and must
not acquire privileged operations merely by adding this file.

## What is implemented

- Accept only a connected local UNIX stream descriptor and the configured
  non-root account's kernel-reported credentials.
- Obtain `LOCAL_PEERTOKEN` from that descriptor, not a PID/identity claimed in a
  request. Resolve its dynamic code through `kSecGuestAttributeAudit`.
- Validate the running signature, match both the identifier and an explicit
  set of Code Directory hashes. The identifier alone is not trust, particularly
  with an ad-hoc signature.
- Require hardened runtime, hard/kill enforcement, valid dynamic status, no
  debugging and no entitlements (including runtime exceptions).
- Reject malformed/empty policies, failed security queries, dead peers and
  unexpected descriptor types. No fallback to PID, executable path or name.
- Revalidate for every operation. No successful-authentication cache.

`VPNPeerPolicy` is a local trusted input, **not Codable or a network payload**.
Only a future installer-controlled root-owned policy may supply production pins
and the owner UID. Do not load them from app preferences, let an IPC client enroll
itself, or hash whatever currently exists at a user-writable application path.
An update must explicitly authorize new architecture-specific hashes; it must
not silently accept every later binary with the same identifier.

## Still required before any privileged operation

1. Production bootstrap and pin activation. The release verifier authenticates
   descriptions; the descriptor-relative store below persists and rechecks them.
   Root-owned directory provisioning and coordinated binary/policy activation
   are still not implemented. Neither component bootstraps the trusted key.
2. Production frontend compatibility: today's ad-hoc app loads Sparkle and does
   not meet this gate's hardening policy. Do not silently disable validation,
   change signing models or raise the macOS floor to get a passing result.
   A separate relay is not sufficient unless its own callers are authenticated.
   An isolated test now demonstrates a different approach: keep the frontend
   hardened and move Sparkle to an **unprivileged updater worker**. The worker
   must never be a proxy for privileged VPN commands. Production migration,
   update UI/preferences, shutdown, cancellation and install/relaunch are pending.
3. Authenticate the helper to the client; provision the fixed socket securely
   under root-owned parents, with restricted permissions and close-on-exec.
   Protect descriptor lifetime against concurrent close/reuse. This gate
   identifies the original connector, not recipients of a passed descriptor.
   A production transport must explicitly account for descriptor inheritance,
   exec and per-message identity; a stream alone does not provide those guarantees.
4. Bound framing, timeouts, connection count and payload size; exact protocol
   versions and typed operations; repeat profile/resource validation in the
   privileged process. Never accept arbitrary shell commands, file paths or
   OpenVPN arguments. Bind state-changing operations to the owner and revision.
5. Atomic helper/policy upgrades and failed-update recovery, plus system-level
   tests. No routing, DNS, subprocess launch or privileged operation exists here.

## Verification

```sh
python3 -m unittest discover -s tests -p test_vpn_peer_authentication.py -v
```

The harness builds both architectures with a macOS 11 deployment target, signs
disposable universal fixtures ad-hoc and launches **separate actual processes**.
The verifier receives an accepted descriptor; the kernel retains the connecting
process's credentials and audit token. No synthetic audit tokens are used.
All connections use local AF_UNIX sockets in disposable directories; a separate
unconnected AF_INET socket tests rejection of an incorrect descriptor type. There is no
installation, admin prompt, corporate traffic or use of a real VPN profile.

The test-only `verify` CLI accepts pins explicitly to exercise different policy
decisions. It must never be shipped as a daemon or used to provision trust.
Passing this suite on Apple Silicon does not establish runtime compatibility
on Intel or macOS 11, nor prove a production app/helper channel is secure.

## Signed release authorization (isolated, verification only)

`VPNReleaseAuthorization.swift` verifies Ed25519 signatures with CryptoKit over
`kz.documentolog.proxypilot/vpn-release-authorization/v1` + a NUL byte + the exact
manifest bytes. An archive/feed signature cannot be reused for this purpose.
The verifier receives a **trusted** public key and an embedded minimum sequence;
neither may originate from a client's enrollment request. The release private
key is not needed by the verifier. No production key, signing pipeline or
installer is wired to this code yet.

The maximum 4096-byte manifest has precisely these ordered LF-terminated lines:
`format`, `product`, `sequence`, `version`, `protocol`, `app-arm64`, `app-x86_64`,
`helper-arm64`, `helper-x86_64`, `helper-sha256`, `helper-bytes`, each `key=value`.
Format/protocol are currently `1`; product is `kz.documentolog.proxypilot`.
Sequence is a positive decimal integer no larger than Int64.max. Version is
three canonical nonnegative decimal components, compared numerically. Hashes
are lowercase hex (20-byte CDHashes, 32-byte artifact SHA-256). The helper must
be nonempty and no larger than 32 MiB. Unknown, repeated, missing or reordered
fields, CRLF, numeric overflow, extra bytes and unsupported protocol fail closed.
There are no executable paths, shell commands, URLs or arbitrary launch arguments.

Only successful verification creates `VerifiedVPNRelease`. It can derive the
frontend's peer policy and compare the exact universal helper artifact bytes.
It does not validate the artifact's executable hardening/CDHashes, stage or
execute it. Those checks still belong in a protected installer transaction.

Given the previously verified release, it rejects an older sequence/version,
another authority, and different payloads reusing the same sequence. Identical
retries are idempotent. This verifier alone is **not durable anti-rollback**;
`VPNReleaseStore` now implements persistence, signature revalidation and locked
check+commit, but production must provision its root-owned directory and
coordinate it with helper activation/recovery.
Missing/corrupt installed state must not be treated as `previous: nil`; that is
only for an explicitly authorized first installation. Selecting and storing the
owner UID, trust bootstrap, public-key rotation and artifact activation remain
unfinished. Do not add a root daemon that enrolls its caller's hash automatically.

```sh
python3 -m unittest discover -s tests -p test_vpn_release_authorization.py -v
python3 -m unittest discover -s tests -p test_vpn_updater_isolation.py -v
```

Release tests use ephemeral in-memory keys and synthetic inert artifact bytes.
The peer suite also exercises the chain from a signed release description to
authentication of an actual separate process (correct pin, wrong pin and wrong
identifier). Fixture signing is test-only, not production trust provisioning.

`tests/vpn-updater-isolation/` builds a disposable universal frontend with
ad-hoc `runtime,hard,kill` signing, no entitlements and no Sparkle linkage. An
ad-hoc nested unprivileged worker loads Sparkle, sets the enclosing bundle as
both `hostBundle` and `applicationBundle`, and uses only the information-check
API. The real framework accepts the existing signed feed over loopback, rejects
tampering and completes when the feed is missing. The worker's own version is
999.0.0, confirming the check targets the enclosing host rather than the worker.
No update is downloaded/installed; production UI and files remain unchanged.
The blocking test pipe is not a production transport implementation.

## Persisted policy (isolated storage component)

`VPNReleaseStore.swift` receives a trusted **open directory descriptor**, never
a client-supplied path. It duplicates the descriptor close-on-exec, requires the
directory owner to equal its effective UID and permissions 0700, and rejects
extended ACL entries. Production must run this in the root helper against a
fixed root-owned directory with protected ancestors; it must not reuse the
unprivileged app's VPN data directory. Directory provisioning and IPC wiring are
still absent. Tests run as the current user with isolated 0700 directories.

Each operation takes a nonblocking cross-process lock and uses descriptor-relative
access with no symlink following. Record/marker/lock must be singly linked regular
0600 files owned by the store's UID, without ACL entries. Bounded canonical JSON
stores the signed manifest, signature and installation owner together; each load
re-verifies the signature. Updates preserve the owner and compare the expected
sequence against freshly read state, so an outdated writer cannot overwrite a
newer accepted release. Identical descriptions are idempotent even when presented
with a different valid signature.

An explicit first-install operation persists `initialized` before `release.json`.
Missing, corrupt, oversized, noncanonical or incorrectly signed state is an error,
not an empty store. Existing marker/record prevents reinitialization. Interrupted
first installation fails closed and needs a future authorized recovery flow;
there is no automatic reset or factory-pin fallback. The lock may exist in an
otherwise fresh directory and does not by itself indicate successful bootstrap.

Replacement uses a private exclusive temporary file, file fsync, atomic rename
and directory fsync. A failure after rename reports `commitUncertain`, never
promises that old state is unchanged. Caller must reload/reconcile. A process
crash can leave a private `.release-*.tmp` file; readers ignore it. Automated
orphan cleanup is not implemented. Crash hooks exist only behind the test compiler
flag `VPN_RELEASE_STORE_TESTING`, absent from normal compilation.

```sh
python3 -m unittest discover -s tests -p test_vpn_release_store.py -v
```

Separate processes test initialization/restart, persisted rejection of older
releases, retry/stale/conflicting writes, invalid signatures, corruption/deletion,
locks, symlinks/hard links/FIFOs, modes/ACLs, and forced exits before/after rename
and during first installation. These are **process-crash tests, not physical
power-loss tests**. The deterministic fixture signing seed is intentionally
public and used only by the disposable test executable, never by production.

This persists authorization, **not helper installation or VPN connection state**.
Do not call `accept` merely on download: a reviewed activation transaction must
coordinate policy advancement with the new helper, including recovery. It does
not defend against root deliberately replacing the complete directory with an
older valid snapshot, and cannot replace authenticated key bootstrap or binary
validation. Working application and installation packages still do not include
this component.

## References

- macOS public SDK: `sys/un.h` (`LOCAL_PEERTOKEN`), Security `SecCode.h`
  (`kSecGuestAttributeAudit`, `SecCodeCheckValidity`, signing-information semantics)
  and `CSCommon.h` (signature/status flags).
- [Apple: dynamic code lookup](https://developer.apple.com/documentation/security/seccodecopyguestwithattributes(_:_:_:_:)).
- [Apple DTS: hardened runtime and library validation](https://developer.apple.com/forums/thread/802437).
- [Sparkle maintainer: ad-hoc signing and library validation](https://github.com/sparkle-project/Sparkle/discussions/2466).
- [Sparkle: updating another bundle from a separate process](https://sparkle-project.org/documentation/bundles/).
- [Apple: CryptoKit Ed25519 verification](https://developer.apple.com/documentation/cryptokit/curve25519/signing/publickey).
- Apple libc sources: [ACL descriptor lookup](https://github.com/apple-oss-distributions/Libc/blob/main/posix1e/acl_file.c)
  and [absent ACL property semantics](https://github.com/apple-oss-distributions/Libc/blob/main/gen/filesec.c).
