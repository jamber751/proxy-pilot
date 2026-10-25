# Local VPN repair package

This assembler prepares one exact two-leg repair: finish the interrupted A→B
update, clean its authenticated working copies, then update B→C. It uses the
separately authorized rescue executable and the existing signed release key.
It never installs, publishes, tags, generates keys, or changes the current network.

The package remains an acceptance artifact until its complete native Installer
and recovery tests pass. `prepare`, `verify`, and `build` use public verification
only. The explicit `sign` command is the only command that accesses an existing
signing key through `vpn-release-key`.

Current repair packages require macOS 12 or later. The preinstall check rejects
older systems before running payload code or replacing files. Historical A/B
artifacts and their lower compiler targets remain unchanged.

## Inputs

- Native Universal `vpn-rescue` from `app/vpn-rescue/build.sh`.
- Genuine signed source A manifest and the signed A→B transition.
- A standard joint candidate C stage, whose `Payload` includes the genuine signed
  B manifest, signed B→C transition, C app/helper and optional engine.
- The existing `vpn-release-key` tool with rescue commands and matching public key.

Candidate C must seal `ProxyPilotVPNRootOwnedUpdateExecutor=1`. When an engine is
present, the candidate stage must retain the corresponding reviewed
`EngineSources`. Only validated source/archive/license bytes are copied.

## Assemble without installing

All paths below are absolute. Every output must be new; source app bundles and
input sidecars are preserved. A valid signed app's internal framework symlinks
are handled by the existing app verifier and copy helpers.

```sh
python3 app/vpn-rescue/package.py prepare \
  --rescue /absolute/native-build/vpn-rescue \
  --source-manifest /absolute/source-A.manifest \
  --source-signature /absolute/source-A.sig \
  --first-transition /absolute/A-to-B.transition \
  --first-signature /absolute/A-to-B.transition.sig \
  --candidate-stage /absolute/candidate-C/stage \
  --key-tool /absolute/vpn-release-key \
  --output /absolute/new-repair-stage

python3 app/vpn-rescue/package.py sign \
  --stage /absolute/new-repair-stage \
  --key-tool /absolute/vpn-release-key

python3 app/vpn-rescue/package.py verify \
  --stage /absolute/new-repair-stage \
  --key-tool /absolute/vpn-release-key

python3 app/vpn-rescue/package.py build \
  --stage /absolute/new-repair-stage \
  --key-tool /absolute/vpn-release-key \
  --output /absolute/new-repair.pkg
```

`sign` accepts `--keychain /absolute/existing-keychain` when the existing signing
key is stored outside the normal search list. It verifies that key's public half
matches the expected key before signing. It reuses existing valid signatures
when resuming partial signing and refuses unsafe signature destinations.
`--public-key` defaults to the repository's existing public-key file; synthetic
acceptance fixtures supply their own public key explicitly.

The stage contains exactly `Rescue/Executable`, `Rescue/Metadata`, and
`Rescue/Candidate`, with owner-private directories and executable/sidecar modes.
The package installs that material below the fixed
`/Library/Application Support/ProxyPilot/Rescue` path using recommended root
ownership. Candidate C is marked non-relocatable so Installer cannot substitute
it for the live app before the native updater authorizes the exchange.

Preinstall verifies all signed material, the fixed protected ancestors and any
existing repair resources. Postinstall invokes only the fixed native `repair`
entry. An error preserves repair resources and recovery; successful completion
retires only the fixed temporary Rescue component. Sibling VPN state is never
removed by these package scripts.
