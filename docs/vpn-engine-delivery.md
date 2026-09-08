# VPN engine delivery — build candidate, 8 September 2026

Status: implementation of plan item **1.6**, not a shipped engine. Root-service
installation acceptance is complete and that test service was removed. The engine
is built separately; enrollment in the signed privileged delivery is still open.
Nothing here connects a VPN.

## Source candidate

OpenVPN **2.7.7**, released 3 September 2026, is the current stable bug-fix release.
The previous 2.6 branch is now in old-stable support. Choose an explicit version,
never a moving `latest` download during builds. Sources:
[downloads](https://community.openvpn.net/Downloads),
[support policy](https://community.openvpn.net/Pages/Supported%20versions).

Initially downloaded and verified the official source archive and detached
signature in a disposable directory before extracting or executing build scripts:

- Archive: `https://swupdate.openvpn.org/community/releases/openvpn-2.7.7.tar.gz`
- SHA-256: `3ab8f48fd6c26d49ba2333a092433949afdb5c85c0e6a1ff265784fbc04a2463`
- Signing primary fingerprint: `F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7`
- Signing subkey: `33DA8C9EAE0EAE8C73172C10822F6DF096D04874`

GnuPG returned successful verification and `VALIDSIG` matching that primary key
in a new isolated keyring. The trust anchor was checked against
[OpenVPN's signature instructions](https://openvpn.net/community-docs/sig.html),
not inferred from the downloaded key's display name. The personal keyring was not
used. Old expired subkeys in the certificate and the empty keyring's trust warning
are not a claim that every signature from that certificate is acceptable.

## Crypto dependency verification

The official OpenSSL **3.5.8** archive was also downloaded and verified locally:

- SHA-256: `a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2`
- Primary: `B146647E45A7B33947AB226B2A2C87D161692D40`
- Signing subkey: `C46ED3F2CBEFDA1FDAADA44264ED7B1DCCE71CB2`

The detached signature returned `VALIDSIG` with that primary, independently
checked against the authoritative [OpenSSL download page](https://openssl-library.org/source/).
The computed checksum also matched the official `.sha256` file. Verification used
the same disposable keyring, not the developer's personal GPG keyring or Keychain.
Both archive hashes and primary fingerprints are pinned in
`app/vpn-engine/sources.json`; the offline builder needs no key access.

## Build constraints

- Build arm64 and x86_64 with deployment target macOS 11; combine and inspect both
  slices. Cross-compilation is not execution on Intel or macOS 11.
- Use pinned OpenSSL **3.5.8** from the **3.5 LTS** branch. Re-verify authoritative
  checksums and signing certificates when updating the source lock.
  [OpenSSL downloads](https://openssl-library.org/source/).
- Link private static crypto libraries, not a Homebrew installation or a
  user-writable runtime search path. Deliver no configurable plugin loader.
- Review and disable unnecessary build features, including compression, plugins
  and automatic DNS scripts. Keep the management interface required by our
  restricted controller. Version 2.7 has a `dns-updown-by-default` build option:
  it must not silently compete with ProxyPilot's own DNS lifecycle.
  [Pinned configure source](https://raw.githubusercontent.com/OpenVPN/openvpn/v2.7.7/configure.ac).
- Preserve exact corresponding source archives, build instructions and license
  notices in the eventual distribution. OpenVPN's GPLv2 includes specific
  OpenSSL/Apache-2.0 linking exceptions, not removal of source obligations.
  [Pinned COPYING](https://raw.githubusercontent.com/OpenVPN/openvpn/v2.7.7/COPYING).
- Test tampered downloads, build failure, architecture/minimum-OS metadata,
  dynamic dependencies, signatures and non-network crypto smoke tests before
  extending the signed helper manifest or package format for engine delivery.

## Implementation and early results

`app/vpn-engine/build.py` performs offline builds as a non-root user. It verifies
bounded archive bytes, rejects unsafe archive members before extraction, builds
both architectures with explicit compiler/SDK flags, and stages dependency
installation only under its new local output (`DESTDIR`). No Homebrew dependency,
system installation, profile or network connection is used.

The first complete Universal candidate reported OpenVPN 2.7.7/OpenSSL 3.5.8 with
macOS 11 metadata and only system dynamic libraries. It exposed absolute temporary
paths in OpenSSL's compiled metadata. The recipe now uses constant configured
paths, a fixed source epoch, deterministic archive timestamps and local staging;
two fresh builds in different directories now match exactly, including the
complete ad-hoc-signed Universal executable.

The builder carries exact source archives, its own recipe and license notices
next to the engine, for a separate corresponding-source release asset. It does
not enroll the executable into a signed VPN helper manifest. **Item 1.6 remains
unchecked until delivery integration is complete.**

## Verified local candidate

Both frozen-recipe builds completed on 8 September 2026, with Apple clang
17.0.0 (`clang-1700.4.4.1`) and the installed Command Line Tools macOS SDK.

- Complete signed Universal SHA-256, identical in both builds:
  `d0eb52a653ec35b1efa5f63a09b61d64dd1e80356e6b01cf07cfa7f49dbe367b`.
- Exact arm64/x86_64 slices; both declare macOS 11.0, carry the fixed engine
  identifier and runtime/hard/kill flags, and pass strict signature verification.
- No runtime search paths or dynamic OpenSSL/Homebrew dependencies; no temporary
  output-directory strings remain in the executable.
- Five successful upstream crypto self-tests per build: AES-128-GCM,
  AES-256-GCM, CHACHA20-POLY1305, AES-128-CBC and AES-256-CBC. These used the
  native Apple Silicon slice without network traffic or a TUN interface.
- Exact source archives, recipe, source lock and all three license notices are
  present alongside provenance/version records and the crypto-test log.
- 14 additional builder tests pass, covering hostile archives, source checksum
  mismatch, symlinks/FIFOs, size limits and preservation of existing outputs.

Local evidence directories: `/tmp/proxypilot-vpn-engine-repro-a/artifact` and
`/tmp/proxypilot-vpn-engine-repro-b/artifact`. These are temporary build artifacts,
not release downloads. Reproducibility is demonstrated only with this same
compiler/SDK. Intel/macOS 11 execution, the complete OpenSSL upstream test suite,
TLS/server compatibility, privileged enrollment and actual VPN networking remain
unverified. The earlier general regression was 362 tests (361 passed, one skip);
the 14 new builder tests were run separately, not included in that total.
