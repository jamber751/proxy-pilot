#!/bin/zsh
# Builds an idle service only. Does not install, run, sign a release or use keys.
set -euo pipefail
HERE="${0:A:h}"
[[ $# == 1 && $1 == /* && ! -e "$1" && ! -L "$1" ]] || { print -u2 'Expected a new absolute output directory'; exit 64; }
OUT="$1"
mkdir -m 700 "$OUT"
mkdir "$OUT/ModuleCache"
SOURCES=("$HERE/../VPNConfiguration.swift" "$HERE/../VPNProfileImporter.swift")
for COMPONENT in VPNPeerAuthentication VPNReleaseAuthorization VPNReleaseTrust VPNHelperArtifact \
  VPNReleaseStore VPNDirectoryProvisioner VPNEndpointDirectory VPNHelperProtocol VPNHelperReadiness \
  VPNHelperListener VPNProfileVault VPNLifecycleOwnership VPNActivationBudget VPNActivationCoordinator \
  VPNLaunchdRuntime VPNRecoveryLaunchdJob VPNStagedApplication VPNInstalledApplication VPNSelectedCandidateFinalizer \
  VPNSelectedCandidateRecovery VPNSelectedCandidateRecoveryDaemonEntry VPNHelperRuntime VPNHelperDaemon ServiceMain; do
  SOURCES+=("$HERE/$COMPONENT.swift")
done
for ARCH in arm64 x86_64; do
  /usr/bin/swiftc -O -parse-as-library -D VPN_RECOVERY_DAEMON_ENTRY -module-cache-path "$OUT/ModuleCache" \
    -target "$ARCH-apple-macosx11.0" "${SOURCES[@]}" -o "$OUT/helper-$ARCH"
done
/usr/bin/lipo -create "$OUT/helper-arm64" "$OUT/helper-x86_64" -output "$OUT/vpn-helper"
chmod 700 "$OUT/vpn-helper"
/usr/bin/codesign --force --sign - --options runtime,hard,kill \
  --identifier kz.documentolog.proxypilot.vpn-helper "$OUT/vpn-helper"
/usr/bin/codesign --verify --strict "$OUT/vpn-helper"
print -- "Built idle VPN helper: $OUT/vpn-helper. Nothing installed."
