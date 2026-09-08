# VPN engine delivery — build candidate, 8 September 2026

Status: implementation of plan item **1.6**, not a shipped engine. Root-service
installation acceptance is complete and that test service was removed. The engine
is built separately; enrollment in the signed privileged delivery is still open.
Nothing here connects a VPN.

Current integration increment: format 2 is now understood by the common verifier,
protected store, installer entry and daemon startup checks. All components are
required together before activation; the former test-only parsing gate is gone.
The historical candidate results below describe the earlier boundary. Packaging
now includes the engine and separately verified source/license material; final
system acceptance for this increment is still pending.

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

## Signed delivery format: initial candidate (superseded by integration below)

The release verifier now has a **test-only** format-2 candidate. It retains the
format-1 fields in their exact order and appends six ordered fields:
`engine-version`, `engine-crypto-version`, `engine-arm64`, `engine-x86_64`,
`engine-sha256`, `engine-bytes`. Engine/crypto versions use the existing canonical
three-component version grammar; the executable is bounded to 64 MiB. The entire
payload remains bounded to 4096 bytes. No path, URL, shell command or executable
argument can be supplied by a manifest.

The existing release-signature purpose/domain is unchanged: it signs every byte,
including the format discriminator and appended fields. App/helper/engine hashes
remain separate. A format-1 release has no engine identity. Verified engine bytes
must match their length and SHA-256, and their content-addressed basename is
derived internally, not supplied by a client.

The transition checks allow format 1 → 2 only with a new sequence, permit exact
retries, reject sequence reuse with different engine data, and prevent dropping
the engine or decreasing either OpenVPN/OpenSSL version after a format-2 release.
These are pure verification rules, not durable rollback protection or successful
installation.

`VPNEngineArtifact` shares static Mach-O/signature validation with the helper:
exactly two executable slices, fixed component-specific identifier, exact CDHash
for each architecture, runtime/hard/kill protections and no entitlements. Neither
validator executes the candidate. Existing protected-file/lock and before/after
snapshot requirements still apply; a path in a writable client directory must
never be used for privileged execution.

Results: 21 release-verifier tests (eight new engine groups), 10 static-engine
tests including the actual locally built OpenVPN, 19 existing deployment tests
and 16 installation-payload tests all passed. The tests use disposable keys and
inert executable fixtures; the actual OpenVPN check was static only. Real-engine
crypto execution was separately verified by the unprivileged builder above.

**Production format 2 is intentionally unavailable.** The only enabling factory
is compiled under `VPN_ENGINE_DELIVERY_TESTING`; ordinary app/helper/key-tool
builds cannot enable it. A production-compiled payload test confirms rejection
before reading/staging a helper. The current signed packages therefore remain
format 1, with no engine. Next: atomic storage of both artifacts, package transfer,
startup revalidation and safe update/removal; only then remove this test-only gate
and perform system acceptance. No production release was signed for this format.

### Integration checklist (implemented below; system acceptance pending)

1. Extend the protected deployment transaction to stage **both** helper and
   engine, validate each complete file, sync them, then atomically select the
   single signed release record. Missing/bad engine bytes must leave the old
   record, running PID and attempt budget untouched. A prepared update must
   revalidate both files again before committing after service stop.
2. On every stored-release load/recovery, format 2 requires its engine as well
   as its helper. Format 1 remains helper-only; no automatic PATH lookup,
   download, repair, fallback to older components or unsafely mixed release.
3. Transfer the engine as a fixed-name sidecar next to the sealed application,
   covered by the release manifest. Validate the bounded protected package
   snapshot before provisioning/stopping anything. Corresponding sources and
   license notices remain part of the eventual public release distribution.
4. Update/removal must account for selected and retained content-addressed
   engine files using the existing verified ownership/lease rules. Do not add
   broad recursive deletion or allow callers to choose executable locations.
5. Exercise first install, retry, format-1 upgrade, tampering, crash points,
   damaged current state and removal in disposable user-owned stores. Then
   enable format 2 consistently in verifier/key tool/package/daemon and repeat
   authorized root/user acceptance. Installation still must not start a tunnel;
   restricted engine execution and network rollback belong to later plan work.

## Candidate-format regression (before atomic integration)

The post-change general run discovered 395 selected tests: **390 passed, five
full-App loopback tests skipped in that invocation**, no failures (392.020 s).
The five full-App tests were then run explicitly with the local GOST fixture:
**all five passed** (76.518 s). Thus all 395 distinct selected checks passed
across the two invocations, not as one skip-free run. The nine disposable-Keychain
release-key tests were excluded; this increment did not access the release key.
Both updater installer opt-ins and the actual OpenVPN static candidate were
enabled in the general run.

The ordinary, non-test idle helper also built successfully as Universal/macOS 11
and passed strict ad-hoc signature verification. Its build remains local at
`/tmp/proxypilot-vpn-candidate-build.VbBr8y/helper/vpn-helper`; it was not installed.
After testing, the system launchd label, both VPN storage/endpoint directories
and launch plist were still absent. The installed application, real profile and
system network settings were not modified. No push, tag or public release.

## Atomic deployment integration

The store verifies the complete component byte set before staging, validates both
Universal files privately, syncs them and atomically selects one signed release
record. Helper-only releases reject extra engine bytes. Engine releases reject
missing bytes; metadata-only APIs cannot persist incomplete engine deployments.
Prepared updates revalidate both files at commit, and every stored-deployment
load/start checks both again. Retained older artifacts are never fallback targets.

An interrupted staging step can leave unselected content-addressed files, but
cannot select a mixed release. Tests kill the writer between artifacts, after
engine staging and around record selection; retries retain the existing security
floor. Modified current/candidate files are not silently repaired. Update refusal
leaves the running PID, selected policy and activation budget unchanged.

The installer passes the engine through the same lifecycle transaction. Uninstall
recognizes exact content-addressed engine names in the protected component
directory and removes retained versions; unknown lookalikes abort before stopping
the service. Daemon startup rejects a missing selected engine even when an older
engine remains. No engine execution, profile application, route or DNS change.

Targeted results for this increment: 31 deployment tests, 24 installer tests,
32 daemon tests, 24 payload tests and 21 release-verifier tests passed. These are
disposable per-user stores/services, not root/system acceptance for format 2.

## Package and signing integration

The packager accepts a complete builder artifact via `--engine-artifact`. It
rechecks the source lock/recipe, exact archive hashes, license text against those
archives and the binary's provenance digest. Static architecture, minimum-OS,
dependency and signature checks run on the copied engine. Its versions/pins/hash
and size enter the same canonical signed manifest as the app and helper.

The scripts-only package carries fixed sidecars; no engine command, source script
or arbitrary staging sibling is executed. The loader checks both binaries and
passes their byte snapshots to the atomic installer. Missing/extra engines,
symlinks/hardlinks/FIFOs, changed bytes, oversized files or shared permissions are
rejected before system operations. `EngineSources` stays outside the app and
system payload as corresponding-source distribution material. Builds fail when
those archives, recipe or license notices are missing/changed.

All 13 package tests passed, including the actual OpenVPN engine in install,
update and remove packages, with successful verification through the complete
app's fixed entry. These used a disposable signing authority and never launched
Installer. All 11 signing-tool tests passed in disposable Keychains, including
format-2 signing/verification and refusal to overwrite a signature for a malformed
manifest. Existing release keys were not accessed or rotated.

## Atomic delivery regression and acceptance handoff

The general run selected 430 tests with both updater installer opt-ins, the full
App loopback fixture, and the actual OpenVPN candidate/source artifact enabled.
**426 passed and four failed** (505.231 s); the 11 disposable-Keychain signing
tests were excluded from that run and passed separately. All 425 checks outside
the five full-App scenarios passed. The full-App ordinary-quit scenario passed,
but its other four scenarios did not:

- Cancel reached worker `cancel-offer` / `dismiss`, then the host timed out.
- The three install states preserved/relaunched the fixture, but the expected
  `popover-closed` event was missing.

A read-only CoreGraphics session check confirmed `screenLocked=true` and
`onConsole=true`. A focused cancel rerun also timed out (66.851 s). These are
failed UI acceptance results under an invalid interactive-desktop prerequisite,
not proof that the product is regression-free. The test class now reports an
explicit skip before fixture setup when the desktop is locked/non-console; it
does not relax assertions or attempt to unlock macOS. That guard was verified:
zero tests ran, one class skipped. **Rerun all five scenarios after unlocking**;
the guard/skip does not replace their acceptance.

The ordinary format-2-capable app and idle helper built successfully as Universal
with the macOS 11 deployment target and passed strict native signature checks:

- `/tmp/proxypilot-vpn-format2-build.B1RT5m/app/ProxyPilot.app`
- `/tmp/proxypilot-vpn-format2-build.B1RT5m/helper/vpn-helper`

Prepared release sequence 4, app version 1.5.1, lives at
`/tmp/proxypilot-vpn-format2-acceptance.wlJ0R2/release-4`. It includes the fixed
payload plus the verified corresponding sources/licenses outside the payload.
The helper SHA-256 is
`f35150ddd388a6c17acffa4423681cfd0ca16704279cc4f40a197bbb0bb753b0`;
the OpenVPN 2.7.7 / OpenSSL 3.5.8 engine SHA-256 is
`d0eb52a653ec35b1efa5f63a09b61d64dd1e80356e6b01cf07cfa7f49dbe367b`.
**Its release signature is empty: no installable production-authority format-2
package has been built.** Temporary paths may be purged and are not release assets.

Next, with the desktop unlocked: repeat the full-App acceptance, sign the frozen
manifest with the existing authorized release key (no rotation), build/verify
the packages, and perform native Installer/root acceptance of the complete
deployment, retry/update and removal. Do not bypass Keychain or Installer
authentication. No real profile or tunnel is needed for this idle-service check.
The system helper label was still absent after testing; the installed app,
personal VPN profile, proxy preferences, routes and DNS were not modified.
No push, tag or public release was performed.

### Unlocked-desktop follow-up

The console subsequently became unlocked. The unchanged five full-App scenarios
were rerun with the real loopback GOST fixture: **all five passed in 77.097 s**.
Together with the 425 non-full-App checks, all 430 distinct selected regression
checks have now passed across runs; this is not one uninterrupted green run.
The 11 disposable-Keychain checks remain a separate passing suite.

A fresh signing tool was compiled from the production format-2 parser and current
source at `/tmp/proxypilot-vpn-format2-acceptance.wlJ0R2/vpn-release-key`. Its
`sign` operation for the frozen sequence-4 manifest completed against the
existing login-Keychain entry. No key generation, replacement or export was
requested; security dialogs were not automated. Verification against
`app/vpn-release-public-key.txt` returned `Verified sequence 4 version 1.5.1`;
the staged app also returned `VPN support package verified.`

The earlier empty-signature state is superseded. All three local packages now
built successfully, each rechecking the actual engine and corresponding sources:

- `/tmp/proxypilot-vpn-format2-acceptance.wlJ0R2/VPN-Support-4-install.pkg`
- `/tmp/proxypilot-vpn-format2-acceptance.wlJ0R2/VPN-Support-4-update.pkg`
- `/tmp/proxypilot-vpn-format2-acceptance.wlJ0R2/VPN-Support-4-remove.pkg`

At the initial handoff, native Installer was open for the exact install package at the **Install**
step (standard installation on Macintosh HD). The final installation action and
macOS administrative confirmation are handed to the user. Root installation has
not started, and the system service remains absent. After confirmation, verify
Installer success and ordinary-user `--vpn-support-status` before continuing
with retry/update and fixed-package removal. No VPN tunnel is started by this
package. The installed application in Applications is unchanged.

## Format-2 system acceptance — 8 September

The user confirmed installation. Installer's scoped log records successful
preflight, `VPN support installed.` and the success UI for release 4. The real
root helper runs from the protected content-addressed path, in `serve` idle mode.
Ordinary-user status successfully authenticates the root service and returns
`Release 4`. The private parent is root-owned 0700; the endpoint directory is
root-owned 0755 and `helper.sock` is 0666 with authenticated IPC. The private
deployment directory remains unreadable to the ordinary user; no permissions
were weakened to inspect it.

| System scenario | Evidence |
| --- | --- |
| Initial format-2 install 4 | Installer log success; root PID 84787; client 4 returns `Release 4`; previous client 3 exits 77 |
| Exact retry/update 4 | Installer success UI; PID 86421 replaces 84787; client 4 still succeeds |
| Candidate 5 before update | Client 5 exits 77; PID 86421 and client 4 remain healthy |
| Signed update 4 → 5 | Installer success UI; PID 88456; client 5 returns `Release 5`; client 4 exits 77 |
| Refusal of older package after 5 | Not run: UI control became unavailable before the package was selected |
| Complete removal | Pending; release 5 remains installed and running idle-only |

Sequence 5 changes only the app pins by adding the restrictive code-signing flag
to a separate copy of the same test app. Existing hard/kill/runtime protections
are retained. Helper/engine bytes and versions are unchanged; this is a release
policy transition with a complete engine set, not an OpenVPN-version upgrade.
The existing release key signed this local candidate; verification through the
signing tool and the staged app succeeded before package creation. The app in
Applications, private profile and system networking were not modified.

Local handoff materials:

- Stage: `/tmp/proxypilot-vpn-format2-upgrade.vspNNk/release-5`
- Update: `/tmp/proxypilot-vpn-format2-upgrade.vspNNk/VPN-Support-5-update.pkg`
- Removal: `/tmp/proxypilot-vpn-format2-upgrade.vspNNk/VPN-Support-5-remove.pkg`

After closing the successful update window, UI control of Installer began
returning `timeoutReached` for actions, observations and app reselection after a
session reset. A read-only session check reported unlocked/on-console and client
5 still succeeded. No alternative UI automation, privilege bypass, forced app
termination or manual deletion was used. Resume with the existing fixed packages:
optionally complete the root rollback-refusal check, then run the verified
sequence-5 remove package and verify absence of the helper label, all recorded
PIDs, launch plist and both directories. Do not claim removal until observed.
The remaining system acceptance work does not invalidate the earlier
isolated rollback/tamper/crash/cleanup tests, but those do not replace this check.
No push, tag or release.
