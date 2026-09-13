# Authenticated joint-update preparation

## Implemented boundary

`VPNInstaller.prepareJointUpdate` is an internal, root-only preparation entry for an existing protected installation. It deliberately has no production command-line, updater, Sparkle or UI wiring.

The operation proceeds in this order:

1. Open the existing system VPN directory without provisioning or bootstrap fallback.
2. Acquire the lifecycle lease.
3. Load selected release A from protected storage and require the caller's expected sequence.
4. Authenticate the current process against A's installer policy. Candidate B's pins are not consulted for caller authority, and there is no A/B union policy.
5. Recheck lifecycle ownership after process authentication.
6. Ask the protected store to verify the exact separately signed A→B transition, independently verify B and its artifacts, stage its content-addressed artifacts, and publish a prepared journal.

The test-only per-user entry uses the same ordering and storage operation, substituting A's owner-bound client policy for the production root installer policy.

Preparation does not stop or start the helper, change `release.json`, charge or clear `activation.json`, apply VPN state, or authorize replacement. The existing A service remains selected and running. Journal advancement, candidate selection, completion, cancellation UI and reconciliation wrappers remain future work.

## Focused coverage

- Selected app A can prepare a B release whose application pins contain only B, while A's PID, selected policy, activation budget and readiness remain unchanged.
- A candidate-only application and a separately identified updater are denied because neither matches selected A.
- A bad transition signature, stale expected sequence and held lifecycle lease leave the running PID, selected policy, activation budget and journal state unchanged.
- The ordinary update path still denies old A when B contains only candidate pins; preparation does not weaken its existing same-app preflight.
- The fixture derives the exact transition hashes from the protected previous payload and candidate payload and signs only with its disposable test key.

## Verification

The installer and inherited daemon suites require per-user launchd and local Unix-socket access, so they must be run with the repository's approved elevated test invocation. No production root path, VPN operation, Keychain operation or commit is part of these tests.

- `python3 -m unittest discover -s tests -p test_vpn_installer.py -v`: 28 tests passed in 38.421 seconds, including all four preparation-focused cases and the production no-test-seam compilation performed by suite setup.
- Final root full-daemon integration: all 38 tests passed in 53.596 seconds, including the same preparation checks against the real idle-daemon implementation. Earlier fixture/transient failures and reruns are recorded in `docs/vpn-update-runtime-gates.md`.
- Final Universal candidate build and strict signature verification passed. The internal preparation method has no command-line or Sparkle entry; it does not enable an installed joint update.
