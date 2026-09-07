#!/bin/zsh
# Builds only. Never invokes Installer, launchctl or an administrative prompt.
set -euo pipefail
HERE="${0:A:h}"
[[ $# == 1 && $1 == /* ]] || { print -u2 'Expected one new absolute output directory.'; exit 64; }
OUT="$1"
[[ ! -e "$OUT" && ! -L "$OUT" ]] || { print -u2 'Output must not exist.'; exit 73; }
mkdir -m 700 "$OUT"
LABEL=kz.documentolog.proxypilot.vpn-probe
mkdir "$OUT/ModuleCache" "$OUT/install-scripts" "$OUT/remove-scripts"
cp "$HERE/install/preinstall" "$HERE/install/postinstall" "$OUT/install-scripts/"
cp "$HERE/remove/postinstall" "$OUT/remove-scripts/"
chmod 755 "$OUT/install-scripts/preinstall" "$OUT/install-scripts/postinstall" "$OUT/remove-scripts/postinstall"

for VERSION in 0.0.1 0.0.2; do
  STAGE="$OUT/stage-$VERSION"
  mkdir -p "$STAGE/Library/LaunchDaemons" "$STAGE/Library/PrivilegedHelperTools"
  FLAGS=()
  [[ "$VERSION" == 0.0.2 ]] && FLAGS=(-D PROBE_UPGRADE)
  for ARCH in arm64 x86_64; do
    /usr/bin/swiftc -parse-as-library -O -target "$ARCH-apple-macosx11.0" -module-cache-path "$OUT/ModuleCache" \
      "${FLAGS[@]}" "$HERE/Probe.swift" -o "$OUT/probe-$VERSION-$ARCH"
  done
  /usr/bin/lipo -create "$OUT/probe-$VERSION-arm64" "$OUT/probe-$VERSION-x86_64" \
    -output "$STAGE/Library/PrivilegedHelperTools/$LABEL"
  /usr/bin/codesign --force --sign - --identifier "$LABEL" "$STAGE/Library/PrivilegedHelperTools/$LABEL"
  /usr/bin/codesign --verify --strict "$STAGE/Library/PrivilegedHelperTools/$LABEL"
  cp "$HERE/$LABEL.plist" "$STAGE/Library/LaunchDaemons/$LABEL.plist"
  chmod 644 "$STAGE/Library/LaunchDaemons/$LABEL.plist"
  chmod 755 "$STAGE/Library/PrivilegedHelperTools/$LABEL"
  /usr/bin/pkgbuild --root "$STAGE" --identifier "$LABEL" --version "$VERSION" \
    --compression legacy --min-os-version 11.0 \
    --install-location / --ownership recommended --scripts "$OUT/install-scripts" \
    "$OUT/ProxyPilot-VPN-Probe-$VERSION.pkg"
done
/usr/bin/pkgbuild --nopayload --identifier "$LABEL.remove" --version 0.0.1 \
  --compression legacy --min-os-version 11.0 \
  --scripts "$OUT/remove-scripts" "$OUT/Remove-ProxyPilot-VPN-Probe.pkg"
print -- "Built isolated probe packages in $OUT. Nothing installed."
