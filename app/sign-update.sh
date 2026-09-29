#!/bin/zsh
# Local signing uses Keychain. CI reads SPARKLE_PRIVATE_KEY through stdin only.
set -euo pipefail
HERE="${0:A:h}"
ROOT="${HERE:h}"
DIST="${PROXYPILOT_DIST_DIR:-$ROOT/dist}"
[[ "$DIST" == /* && ! -L "$DIST" ]] || {
  print -u2 "distribution input must be an absolute non-symlink path"; exit 1
}
VERSION=$(awk -F'"' '/^readonly PP_VERSION=/{print $2}' "$ROOT/bin/proxypilot")
SPARKLE="$ROOT/vendor/sparkle-2.9.6"
ARCHIVE="$DIST/updates/ProxyPilot-$VERSION.zip"
[[ -s "$ARCHIVE" ]] || { print -u2 "Run ./make-dmg.sh first"; exit 1; }
WORK=$(mktemp -d /tmp/proxypilot-appcast.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
cp "$ARCHIVE" "$WORK/"
cp "$ROOT/.github/update-notes.html" "$WORK/ProxyPilot-$VERSION.html"
typeset -a args
args=(--maximum-deltas 0 --embed-release-notes
  --download-url-prefix "https://github.com/jamber751/proxy-pilot/releases/download/v$VERSION/"
  --link "https://github.com/jamber751/proxy-pilot/releases/tag/v$VERSION" "$WORK")
if [[ -n "${SPARKLE_PRIVATE_KEY:-}" ]]; then
  print -rn -- "$SPARKLE_PRIVATE_KEY" | "$SPARKLE/bin/generate_appcast" --ed-key-file - "${args[@]}"
  print -rn -- "$SPARKLE_PRIVATE_KEY" | "$SPARKLE/bin/sign_update" --ed-key-file - --verify "$WORK/appcast.xml"
else
  "$SPARKLE/bin/generate_appcast" --account kz.documentolog.proxypilot "${args[@]}"
  "$SPARKLE/bin/sign_update" --account kz.documentolog.proxypilot --verify "$WORK/appcast.xml"
fi
mkdir -p "$ROOT/app/build/ModuleCache"
swift -module-cache-path "$ROOT/app/build/ModuleCache" "$HERE/verify-update.swift" \
  "$HERE/updater-public-key.txt" "$ARCHIVE" "$WORK/appcast.xml" "$VERSION"
cp "$WORK/appcast.xml" "$DIST/updates/appcast.xml"
print -- "Signed and verified: $DIST/updates/appcast.xml"
