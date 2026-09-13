# Per-architecture VPN app pins

`VerifiedVPNRelease` now retains the exact signed `app-arm64` and
`app-x86_64` mapping instead of collapsing those values into an unordered set.
`appHash(forArchitecture:)` exposes only an exact known-architecture lookup and
returns `nil` for unknown architecture names.

The existing client and installer peer policies still receive the set of both
signed app hashes. This changes no live authentication or authorization
semantics; it preserves information used by the staged-app artifact validator.

Focused signed fixtures check the positive arm64/x86_64 mapping, unknown lookup,
and that deliberately swapped signed manifest fields remain swapped rather than
being normalized or inferred. No wire format, journal, runtime, installer,
Sparkle, service, Keychain, or production signing behavior is changed.

On 13 September 2026 the complete release-authorization suite passed **22 tests
in 64.351 seconds**, including the new signed mapping case. The checker was
compiled independently for arm64 and x86_64, combined into a Universal binary,
and ad-hoc signed. It used ephemeral fixture keys and inert fixture data only;
no root, network, service, Keychain, installed-app, or production-key action was
performed.

## Read-only staged application audit

`VPNStagedApplication.swift` was independently reviewed after implementation.
No actionable correctness or security finding was identified under its stated
contract: a fixed child of trusted private local root storage, with no
concurrent privileged writer and lifecycle/staging ownership held by the future
caller.

The traversal is descriptor-relative, no-follow for real objects, bounded by
depth, entry count, per-file and aggregate sizes, and rejects unexpected node
types, unsafe ownership/modes, ACLs and hard-linked regular files. Relative
symlinks are inventoried as link objects, then resolved only through the captured
in-tree namespace with escape, dangling-target, cycle and hop checks; this is
compatible with versioned framework facade links. Before/after snapshots include
parent and tree identities, metadata, timestamps and symlink targets, while the
comments correctly avoid presenting them as an atomic snapshot against root.

The fixed bundle metadata and physical universal main executable are checked
before Security.framework performs strict, all-architecture, nested-code and
restricted-symlink validation with networking disabled. Fresh per-architecture
static-code objects compare the arm64 and x86_64 CDHashes to their exact signed
manifest mappings and enforce identifier, hardened flags and empty entitlements.
The final descriptor/path rebinding and repeated tree capture detect observable
replacement around the path-based Security calls.

The result remains an opaque observation tied to an exact release; revalidation
repeats the complete inspection and compares snapshots. It proves neither
installation nor live-process identity. This audit did not edit or compile the
validator and makes no physical power-loss or adversarial-root claim.

Runtime testing subsequently found a Swift/C pointer bug in symlink reading
that this read-only audit missed. AddressSanitizer identified a stack buffer
overflow from passing the address of the Swift Array value to `readlinkat`.
The root agent changed the call to use `withUnsafeMutableBytes` element storage.
The independent review above is not a substitute for the runtime acceptance
record in `vpn-staged-app-review.md`.

Full ASan coverage including the real application and a large directory then
found a second issue missed by ordinary tests: copying the fixed-size imported
`dirent.d_name` tuple overread variable-length `readdir` records. The root agent
replaced that copy with length-checked raw-record decoding. The same old pattern
in installer removal was identified for a separate fix/regression; the first
successful ordinary run was not treated as final acceptance.
