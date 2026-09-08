# Pinned VPN engine candidate

This builder does not install a service, enroll code, read a VPN profile, change
system settings or create a tunnel. The existing ProxyPilot release is unchanged.
The separate VPN packager now accepts this complete artifact directory, verifies
its sources/notices and binds the engine into the independently signed delivery.
The builder itself does not enroll it. Neither installation nor the idle helper
executes OpenVPN; restricted execution and live acceptance remain separate work.

## Inputs and build

`sources.json` pins OpenVPN and OpenSSL release archives. Their detached upstream
signatures were checked using published primary fingerprints before recording
these hashes; details are in `docs/vpn-engine-delivery.md`. Future source upgrades
require that review again, not merely replacing a hash after a failed download.

Download the two listed archives into an absolute source directory, then run:

```sh
python3 app/vpn-engine/build.py --sources /absolute/source-directory --output /absolute/new-output-directory
```

Run as an ordinary macOS user with Xcode Command Line Tools. No Homebrew library,
network lookup, Keychain access or administrator permission is used by the build.
The builder refuses existing outputs and verifies complete archive bytes before
executing their build scripts. Extraction accepts only bounded, non-duplicated
regular files/directories within each expected source root.

Both architecture builds use macOS 11 as their deployment target. OpenSSL is
statically linked, with dynamic engines/modules, DSO loading and automatic config
loading disabled. OpenVPN compression, plugins, PKCS#11, DCO and automatic DNS
scripts are disabled. Its management interface remains available for the future
restricted controller; arbitrary profile options are not granted by this builder.

## Output and verification

`artifact/openvpn` is a Universal ad-hoc-signed candidate with runtime/hard/kill
flags. Build completion requires the expected version strings, architecture and
minimum-OS metadata, no runtime search paths, no non-system dynamic libraries,
and five non-network crypto self-tests matching the importer's allowed ciphers.
Temporary build-directory and Homebrew strings in the executable are rejected.

`artifact` also contains version/provenance records, crypto-test output, license
notices and exact corresponding source archives with this build recipe. Publish
the source material as a separate release asset when distribution is implemented;
it need not bloat the menu-bar app bundle. No public release is created here.

Build twice into distinct new directories and compare the complete signed
executables to check byte reproducibility on the **same compiler/SDK**. A matching
checksum does not prove reproducibility across toolchains or systems. The SDK and
compiler are recorded in provenance. Only the current Mac's native slice is
executed; building Intel/macOS 11 metadata is not an Intel/macOS 11 runtime test.

OpenSSL's full unit suite and a connected client/server test are not run by this
candidate builder. Those remain separate checks; crypto self-tests do not prove
TLS login, corporate compatibility, routes, DNS, sleep/reconnect or VPN health.
