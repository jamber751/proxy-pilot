#!/bin/zsh
# Builds the service binary only. Does not install, run, sign a release or use keys.
set -euo pipefail
HERE="${0:A:h}"
[[ $# == 1 && $1 == /* && ! -e "$1" && ! -L "$1" ]] || { print -u2 'Expected a new absolute output directory'; exit 64; }
OUT="$1"
mkdir -m 700 "$OUT"
mkdir "$OUT/ModuleCache"
SOURCES=("$HERE/../VPNConfiguration.swift" "$HERE/../VPNProfileImporter.swift")
# Keep one production source graph for the ordinary daemon, recovery roles,
# protected replacement executor and update broker. Swift whole-module -O strips
# unreachable internal entry points; an omitted file would instead produce a
# helper that compiles in tests but cannot resume a real broker transaction.
for SOURCE in "$HERE"/*.swift; do
  SOURCES+=("$SOURCE")
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
print -- "Built VPN helper: $OUT/vpn-helper. Nothing installed."
