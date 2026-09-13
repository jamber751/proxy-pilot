# Staged application verification review

This is a bounded review of the proposed protected staged `ProxyPilot.app`
validator. A successful result should mean only: **the observed staged tree
matches the authenticated release description at validation time**. It is not
evidence that this tree was installed, selected by LaunchServices, executed, or
is the live VPN client.

## Observed production bundle shape

The inspected boundary build at
`/tmp/proxypilot-boundary-build.VCaUFT/candidate/ProxyPilot.app` has 177 directory
entries, about 9 MiB allocated, and nine symlinks. The outer application is a
universal `x86_64`/`arm64` app with identifier
`kz.documentolog.proxypilot`, executable `Contents/MacOS/ProxyPilot`, and equal
`CFBundleVersion` / `CFBundleShortVersionString` values (`1.5.1` in this build).
Its signature has `hard`, `kill`, and `runtime`, and strict, deep,
all-architectures validation succeeds.

The embedded updater contains a versioned Sparkle framework. The required
symlinks are relative:

- `Versions/Current -> B`
- framework facade links such as `Sparkle`, `Resources`, `Headers`,
  `PrivateHeaders`, `Modules`, `XPCServices`, `Autoupdate`, and `Updater.app`
  point through `Versions/Current/...`.

Therefore a blanket symlink rejection cannot validate the real bundle. The
sample also carries `com.apple.provenance` extended attributes throughout;
absence of ACL entries is a distinct check and should not accidentally become
an absence-of-all-xattrs rule unless packaging is deliberately changed.

## Recommended validation contract

1. Accept a descriptor for a pre-established private local staging directory,
   not an arbitrary candidate path. Revalidate that descriptor with `fstat`:
   local filesystem, directory, expected trusted owner, link count and mode
   policy, with no ACL. Open only the literal child `ProxyPilot.app` using
   descriptor-relative operations and no-follow semantics. Reject additional
   staging-root children if the contract says the root is immutable and
   single-purpose.

2. Traverse descriptor-relative. Enumerate each directory from its held file
   descriptor; open children with `openat`, `O_NOFOLLOW`, and type-appropriate
   flags; compare the directory-entry `fstatat(..., AT_SYMLINK_NOFOLLOW)` result
   to the opened object's `fstat`. Never build trust by resolving a string path.
   Reject sockets, devices, FIFOs, and unknown types. Enforce finite depth,
   entry count, individual-file size, symlink-text length, and aggregate byte
   limits with overflow-safe arithmetic.

3. Require the trusted owner on every real object, reject group/other write
   bits, reject setuid/setgid/sticky policy violations, reject ACLs, and require
   `st_nlink == 1` for regular files. Directory link counts normally exceed one
   and must not use the file rule. Ownership of symlink inodes should be checked
   with no-follow metadata as well.

4. Permit only internal relative symlinks. Reject absolute targets, empty
   targets, NUL/oversized text, and any normalized walk that escapes the app
   root. Also require every component reached while resolving the target to be
   an already observed in-tree object; cap link hops and detect cycles. For the
   current Sparkle layout, lexical containment alone is insufficient unless
   `Versions/Current -> B` is recursively resolved. Do not traverse facade links
   during the primary enumeration (which would duplicate subtrees); validate
   their targets after the physical tree is inventoried.

5. Capture a deterministic before-stamp of every physical entry, including
   relative name, type, device/inode, owner, mode, link count, size, relevant
   timestamps/change generation where available, ACL state, and symlink bytes.
   Hold directory/file descriptors where feasible. After all path-based
   Security checks, independently repeat descriptor-relative traversal and
   require an identical stamp and the same staging-root/app identities.

6. Parse `Contents/Info.plist` from the descriptor-opened regular file with a
   strict byte limit. Require exact fixed values for bundle identifier and
   executable, require both version keys to equal `release.version`, and reject
   non-string or ambiguous values. The executable must be exactly the physical
   regular file `Contents/MacOS/ProxyPilot`, owned/mode-checked and universal;
   do not let plist-controlled paths choose another object.

7. Perform full bundle-seal validation with
   `kSecCSStrictValidate | kSecCSCheckAllArchitectures` and nested/deep checking,
   plus no-network behavior. Then create a fresh `SecStaticCode` reference for
   each architecture (`arm64`, `x86_64`) and retrieve fresh signing information.
   Require identifier `kz.documentolog.proxypilot`, that architecture's exact
   release pin, all required flags (`runtime`, `hard`, `kill`), and absent or
   empty entitlements. Keep release app pins as an architecture-keyed dictionary
   so the arm and Intel values cannot be swapped; peer policies may continue to
   consume `Set(appHashes.values)`.

## Important race and Security API caveats

`SecStaticCodeCreateWithPath*` is path-based. A private, non-writable staging
root plus before/after stamps materially narrows substitution, but does not turn
Security.framework into a descriptor-relative verifier or prove an atomic
snapshot. The API contract and comments should say this plainly. The caller
must hold whatever staging lock establishes exclusive immutability for the
whole validation interval; the validator should not infer immutability merely
from current mode bits.

Avoid reusing one `SecStaticCode` object between the seal check, per-architecture
pin checks, or retries. Fresh references reduce stale cached assessment risk,
and the final stamp catches observable mutation, but neither warrants a claim
of perfect cache bypass. Resolving `F_GETPATH` only after descriptor identity
checks is useful for calling Security.framework, yet the resulting pathname is
still untrusted unless the protected-root contract remains continuously true.

Finally, `--deep`/nested validation is necessary for this Sparkle-containing
bundle but is not a substitute for the outer application's exact per-arch pin.
Conversely, pinning only the main executable does not validate sealed resources
or nested Sparkle code. Both checks, plus stable tree observations, are required.

## Suggested opaque result

Return a value with no path, executable descriptor, or launch/install method,
for example an opaque `ValidatedStagedApplication` containing only the verified
release identity/digest needed for later comparison. Name its predicate in
terms of `matches(release:)` or `matchesObservation`, not `isInstalled`,
`isActive`, or `isRunning`.

## Isolated acceptance coverage

The companion tests build a disposable universal C application with a sealed
resource, nested signed app, and versioned framework symlinks. They cover valid
inspection and receipt revalidation; architecture-specific pins; fixed bundle
identity, executable, package type, and version; thin code and entitlements;
outer resource and nested-code tampering; unsafe parent/tree modes, ACLs, and
hardlinks; internal links versus absolute, escaping, cyclic, and dangling
links; and stale receipts after resource, bundle, or parent substitution. The
fixture is never run, installed, or signed with a production key.

The first sanitizer run found a concrete implementation defect in symlink
capture: passing `&buffer` for a Swift `[UInt8]` to `readlinkat` exposed the
array value on the stack rather than its element storage. A valid framework
symlink consequently produced a stack-buffer overflow and ordinary runs could
segfault. The implementation was corrected to call `readlinkat` inside
`withUnsafeMutableBytes`; focused AddressSanitizer coverage now passes for valid
inspection/revalidation, valid and adversarial framework links, and ACL
rejection.

The final full sanitizer run also exposed and then verified the correction of a
second variable-length-buffer defect: materializing `row.pointee.d_name` copied
the fixed 1,024-byte Swift tuple even when `readdir` had returned a shorter
`dirent` record near the end of libc's directory buffer. Name decoding now uses
the raw record offset and validated `d_reclen` / `d_namlen` bounds without
materializing that tuple. After this correction, all 14 AddressSanitizer tests
passed in 7.406 seconds, including the unchanged built candidate, 10,001-entry
limit, main-executable mode, symlink, ACL, seal, identity, and stale-receipt
cases, with no skips.

The root agent then built the final opt-in Universal candidate at
`/tmp/proxypilot-staged-verified.yJojDq/candidate/ProxyPilot.app`, including the
installer directory fix. `codesign --verify --deep --strict --all-architectures`
passed and `lipo -archs` reported x86_64 and arm64. The complete ordinary suite
was repeated against a private copy of this final build: **14/14 passed in
6.123 seconds**. The application was neither launched nor installed. An earlier
intermediate build was cancelled after the second sanitizer finding and is not
part of final acceptance. No production signing keys or user VPN data were used.
