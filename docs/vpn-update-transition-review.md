# Review: signed VPN update transition

## Finding

The proposed contract is a useful, narrow missing primitive, but not a complete
joint updater. Existing release verification already proves that each manifest
is authentic and that the candidate advances monotonically. A second signature
therefore adds no authenticity to either endpoint. Its value is different: it
authorizes one **directed edge** from the exact protected current release to the
exact candidate release. Future integration can use this to let an app pinned by the current manifest request
the handoff to a candidate whose manifest pins only the new app, without creating
a current+candidate peer-policy union or treating Sparkle success as VPN authority.

Keep the result as an immutable, verification-only value. It must not expose a
combined `VPNPeerPolicy`, authorize IPC/runtime commands, select a release, stop a
service, or imply that either app or helper was installed. The candidate must
still be independently accepted by `VPNReleaseAuthority.verify(previous:)`.

## Required signed bindings and checks

Use a new fixed canonical format and the implemented domain
`kz.documentolog.proxypilot/vpn-update-transition/v1\0`; never reuse the release,
Sparkle, archive, or appcast domain. The signed bytes should bind:

- fixed format and product identifier;
- `from-sequence` and SHA-256 of the exact signed **manifest payload bytes**;
- `to-sequence` and SHA-256 of the exact signed **manifest payload bytes**.

The verifier should receive already verified `from` and `to` values, compare all
four fields in constant-shape exact equality, require `to.sequence > from.sequence`,
require both releases to belong to this authority, and require the candidate to
have been produced by `verify(payload:signature:previous: from)`. Authority/key
identity may be implicit only if one `VPNReleaseAuthority` instance verifies the
two releases and transition; otherwise the transition must also bind the release
authority identities and define key rotation explicitly. Do not bind only version,
sequence, CDHashes, filenames, archive hashes, or signature bytes: those are
either incomplete or representation-dependent. Digesting the canonical manifest
payload transitively binds protocol and every app/helper/engine pin.

The parser should follow the release parser's fail-closed rules: bounded payload,
64-byte Ed25519 signature, exact ordered LF-terminated lines, lowercase 32-byte
hex digests, strict unsigned decimal encoding, no ignored/duplicate fields, and
no alternate encodings. Give the verified transition a private/fileprivate
initializer and retain endpoint release digests, sequences, and authority identity
only; do not make it `Codable` or accept it over IPC.

## Security pitfalls

- Never trust a caller-supplied `from` manifest. At eventual use, reload it from
  the root-owned store under the lifecycle/store lock and match the transition to
  that exact selected release. Checking before the lock creates a stale-state race.
- Do not let the transition bypass candidate `verify(previous:)`, rollback,
  protocol, artifact-byte, owner, or expected-revision checks. The edge signature
  cannot repair corrupt/missing protected state and is not first-install authority.
- Authenticate the process requesting the handoff against the **from** app pins;
  authenticate candidate bytes/processes against the **to** pins. A union policy,
  fallback from one side to the other, or accepting the updater worker recreates
  the confused-deputy window this design is meant to avoid.
- Do not persist/advance the release floor merely on download or transition
  verification. Crash-safe selection, service stop/start, app replacement order,
  cancellation, and recovery require the later root-owned journal/transaction.
- Define key rotation separately. Silently allowing a transition key to bridge
  different release authorities turns it into an unintended trust-root migration.

## Minimal safe code increment

Add only a pure `VPNVerifiedReleaseTransition` value and
`VPNReleaseAuthority.verifyTransition(...)`, preferably beside
`VPNReleaseAuthorization.swift`, plus isolated parser/cryptographic tests. The API
should take the exact from/to manifest payloads (or verified releases retaining
their digests), a transition payload/signature, and require callers to supply the
candidate result of strict `verify(previous:)`. Do **not** wire it into
`VPNInstaller`, Sparkle admission, the release store, launchd, or peer policy yet.
That increment makes the authorization edge reviewable without pretending the
root transaction and recovery design already exists.

## Acceptance cases

- Accept an exact signed `A -> B` where `A` is verified, `B` is separately verified
  with `previous: A`, both use the trusted authority, and `B.sequence > A.sequence`.
- Reject modified transition bytes/signature, wrong domain/key/product/format,
  noncanonical fields, malformed/uppercase/wrong-length hashes, oversized input,
  zero/equal/reversed sequences, and trailing or unknown fields.
- Reject replay of `A -> B` as `A -> C`, `X -> B`, `B -> A`, or after protected
  selection has advanced to `B`, even when every individual manifest is valid.
- Reject matching sequences with different manifest bytes and matching manifest
  digests paired with different declared sequences.
- Reject a valid edge when `B` fails ordinary release advancement (rollback,
  conflicting sequence, protocol mismatch, component downgrade, or wrong authority).
- Prove the returned value cannot derive app/helper policies and that verification
  causes no filesystem, process, launchd, Sparkle, or VPN state change.

## Unresolved boundaries before integration

The root-owned journal must still define the durable phases and recovery rules for
old app/old helper, new app/old helper, and new app/new helper states; which exact
process invokes the root entry and how the current app proves the from identity;
when VPN is drained relative to Sparkle's irreversible replacement; cancellation
semantics; preserving desired VPN state; and behavior after power loss. Decide
also whether transition and release signatures share one key (domain-separated)
or use independently provisioned keys, and specify authenticated key rotation.
None of these should be inferred by the pure transition verifier.

## Focused verifier implementation review and test result

The pure verifier was reviewed after implementation. No actionable security defect
was found in this boundary: it checks the transition signature under the dedicated
NUL-terminated domain, rejects a foreign source authority, independently runs the
candidate through `verify(previous:)`, requires a strict sequence increase, and
then compares the signed transition to one reconstructed canonical record. The
opaque result exposes only endpoint sequences and exact release matching; it does
not manufacture peer policy or mutate state.

New isolated tests use ephemeral real Ed25519 keys and format-2 manifests. They
cover the exact valid edge and opaque matching; wrong key/domain/signature,
tampering, empty/oversized records; signed malformed, reordered/duplicate/extra/CRLF,
noncanonical numeric, uppercase/wrong-length digest and alternate product/format
records; independently valid source/destination substitution, reversal, A→B
replay with B already selected, same-sequence B substitution, and A→C separation;
same-release retry; candidate signature,
sequence/version rollback, same-sequence conflict, protocol mismatch, engine
removal and engine/crypto downgrade; foreign source authority; and a verifier
using the same key with a stricter minimum sequence. The latter correctly treats
the key as authority identity while still applying its local floor to candidates.

Targeted result on 13 September 2026 after adding those literal replay and grammar
cases: **6 tests passed in 57.850 seconds**. Each
test executable was compiled independently for arm64 and x86_64 with deployment
target macOS 11 and a disposable per-architecture module cache, then combined for
execution on the current Mac. No root operation, Keychain, VPN, network, launchd,
installed application, or production signing key was used.

Before the final test-only additions above, the root integration rerun passed
all 6 transition tests and 9 core tests together in 63.084 seconds. The candidate Universal application built successfully and
passed strict signature verification. This verifies the pure authorization
primitive, not an installed joint app/helper update or recovery transaction.
