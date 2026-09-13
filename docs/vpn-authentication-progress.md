# VPN authentication metadata progress

Updated: 2026-09-13

## Implemented scope

- Added non-secret configuration metadata for three explicit modes: certificate-only, static password, and one-time-password-as-password.
- Added a saved, normalized login for the two credential modes. Certificate-only mode rejects a login.
- Added credential persistence intent (`none` or `keychain`). Only static-password mode may opt into future Keychain persistence; certificate and OTP modes reject it.
- Kept the authentication selection optional. `nil` is the migration-safe legacy/unselected state, so an existing `auth-user-pass` profile is never silently classified as static password instead of OTP.
- Kept password and OTP values out of every Codable model. No Keychain access was added.
- Added importer compatibility classification using the existing `requiresCredentials` signal. Credential profiles accept an explicit static-password or OTP mode; credential-free profiles accept certificate-only mode. The importer still cannot and does not choose between static password and OTP.
- Added store validation so an explicit mode cannot be saved with an incompatible protected profile. Legacy/unselected snapshots remain readable and valid.
- Removing or replacing a profile clears its authentication metadata, including same-filename replacement. A future credential lookup must bind consent to a specific profile instance rather than trusting its display filename.

The persisted schema version remains `1`: all additions are optional/additive, and decoding an old configuration without `authentication` yields the legacy/unselected state while retaining its profile name, resources, DNS, enablement intent, revision, and protected profile bytes.

## Tests

Focused command (all files/directories disposable):

```text
CLANG_MODULE_CACHE_PATH=/private/tmp/proxypilot-clang-cache \
SWIFT_MODULECACHE_PATH=/private/tmp/proxypilot-swift-cache \
python3 -m unittest \
  tests.test_vpn_core.VPNCoreTests.test_authentication_metadata_and_migration \
  tests.test_vpn_core.VPNCoreTests.test_configuration \
  tests.test_vpn_core.VPNCoreTests.test_import \
  tests.test_vpn_core.VPNCoreTests.test_atomic_store_and_pending_revisions -v
```

Focused result: 4 tests passed (`authentication`, `configuration`, `import`, and `store`) in 3.052 seconds. After adding the final setter guard, the authentication test passed again in 2.858 seconds and `git diff --check` was clean. The default compiler cache path was initially blocked by the workspace sandbox, so the successful runs used temporary module-cache paths shown above.

Coverage includes mode invariants, login normalization, exact metadata-only JSON keys, OTP persistence rejection, malformed/unknown decoded metadata rejection, metadata round-trip, same-name replacement clearing authentication, model and full-envelope migration without losing profile/resources, importer ambiguity, certificate/credential compatibility, profile/store round-trip, and atomic rejection of an incompatible auth change.

### Integration review

Root review added a store-level guard against replacing protected profile bytes while retaining authentication metadata through a direct store call. A display filename is not profile identity. Identical-content reimport remains allowed; different content requires clearing the selection, importing, and choosing authentication again. Tests verify rejection preserves the whole previous snapshot and that the explicit replacement/reselection path succeeds.

The broad integration run passed 149 tests in 40.814 seconds before this final store guard. After the guard, all 9 core tests and 6 signed-transition tests passed together in 63.084 seconds (15 tests, no skips). The candidate Universal app with isolated updater and VPN installer also built and passed strict signature verification. No installed app or network settings were changed.

## Deliberately untouched / pending

- No GUI or form controls.
- No Keychain reads or writes and no secret persistence.
- No password or OTP/code field in Codable storage; OTP must be supplied fresh by a future runtime flow.
- No live connection, OpenVPN invocation, challenge protocol, helper/root operation, installation, or network access.
- No changes to the update worker, VPN helper, main app UI, or the main VPN implementation plan.
- Runtime credential delivery, Keychain adapter and consent UI, OTP prompt lifecycle, and challenge-based MFA remain future work.
