# VPN engine delivery — source preflight, 8 September 2026

Status: preparation for plan item **1.6**, not a shipped engine or completed build.
The root-service acceptance gate remains open. Nothing here connects a VPN.

## Source candidate

OpenVPN **2.7.7**, released 3 September 2026, is the current stable bug-fix release.
The previous 2.6 branch is now in old-stable support. Choose an explicit version,
never a moving `latest` download during builds. Sources:
[downloads](https://community.openvpn.net/Downloads),
[support policy](https://community.openvpn.net/Pages/Supported%20versions).

Downloaded the official source archive and detached signature into a disposable
directory, without extraction or execution:

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

## Build constraints to implement and verify

- Build arm64 and x86_64 with deployment target macOS 11; combine and inspect both
  slices. Cross-compilation is not execution on Intel or macOS 11.
- Use a pinned OpenSSL **3.5 LTS** dependency. Current candidate is **3.5.8**;
  its archive/signature have **not yet been verified locally**. Check authoritative
  checksum and signing certificate before executing its build scripts.
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

No OpenVPN executable has been built, installed, pinned into a VPN release or run
by this preflight. Item 1.6 remains unchecked.
