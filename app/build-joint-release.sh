#!/bin/zsh
# Local-only joint release assembly. Uses the existing VPN key in Keychain,
# never publishes, tags, installs, elevates or overwrites an output directory.
set -euo pipefail

HERE="${0:A:h}"
ROOT="${HERE:h}"
[[ $# == 6 ]] || {
  print -u2 "Usage: $0 SEQUENCE PREVIOUS_MANIFEST PREVIOUS_SIGNATURE ENGINE_ARTIFACT UNIVERSAL_GOST NEW_OUTPUT_DIR"
  exit 64
}
SEQUENCE="$1"
PREVIOUS_MANIFEST="${2:A}"
PREVIOUS_SIGNATURE="${3:A}"
ENGINE_ARTIFACT="${4:A}"
UNIVERSAL_GOST="${5:A}"
OUTPUT="${6:A}"
print -r -- "$SEQUENCE" | /usr/bin/grep -Eq '^[1-9][0-9]{0,18}$' || {
  print -u2 "Expected a canonical positive sequence"; exit 64
}
[[ -f "$PREVIOUS_MANIFEST" && ! -L "$PREVIOUS_MANIFEST" \
   && -f "$PREVIOUS_SIGNATURE" && ! -L "$PREVIOUS_SIGNATURE" \
   && -d "$ENGINE_ARTIFACT" && ! -L "$ENGINE_ARTIFACT" \
   && -f "$UNIVERSAL_GOST" && ! -L "$UNIVERSAL_GOST" \
   && "$OUTPUT" == /* && ! -e "$OUTPUT" && ! -L "$OUTPUT" ]] || {
  print -u2 "Expected fixed previous sidecars, engine artifact, Universal GOST and a new absolute output"
  exit 64
}

VERSION=$(awk -F'"' '/^readonly PP_VERSION=/{print $2}' "$ROOT/bin/proxypilot")
[[ -n "$VERSION" ]] || { print -u2 "Cannot read ProxyPilot version"; exit 1; }
WORK=$(mktemp -d /tmp/proxypilot-joint-release.XXXXXX)
SUCCESS=0
cleanup() {
  /bin/rm -rf -- "$WORK"
  [[ "$SUCCESS" == 1 ]] || /bin/rm -rf -- "$OUTPUT"
}
trap cleanup EXIT
mkdir -m 700 "$OUTPUT"
mkdir -m 700 "$WORK/key" "$WORK/app" "$WORK/helper"
mkdir -m 700 "$WORK/key/ModuleCache"

KEY_TOOL="$WORK/key/vpn-release-key"
/usr/bin/swiftc -O -parse-as-library -module-cache-path "$WORK/key/ModuleCache" \
  "$HERE/vpn-helper/VPNPeerAuthentication.swift" \
  "$HERE/vpn-helper/VPNReleaseAuthorization.swift" \
  "$HERE/vpn-helper/VPNReleaseTrust.swift" \
  "$HERE/vpn-helper/VPNCompanionMetadata.swift" \
  "$HERE/vpn-release-key.swift" -o "$KEY_TOOL"

EXPECTED_KEY=$(< "$HERE/vpn-release-public-key.txt")
ACTUAL_KEY=$("$KEY_TOOL" public)
[[ "$ACTUAL_KEY" == "$EXPECTED_KEY" ]] || {
  print -u2 "Keychain VPN release key does not match the embedded public key"; exit 1
}
"$KEY_TOOL" verify "$PREVIOUS_MANIFEST" "$PREVIOUS_SIGNATURE" \
  "$HERE/vpn-release-public-key.txt"

PROXYPILOT_ISOLATED_UPDATER=1 PROXYPILOT_VPN_INSTALLER=1 \
  PROXYPILOT_VPN_RELEASE_SEQUENCE="$SEQUENCE" \
  zsh "$HERE/build.sh" "$WORK/app"
GOST_ARCHES=$(/usr/bin/lipo -archs "$UNIVERSAL_GOST")
[[ "$GOST_ARCHES" == "arm64 x86_64" || "$GOST_ARCHES" == "x86_64 arm64" ]] || {
  print -u2 "GOST must contain arm64 and x86_64"; exit 1
}
/bin/cp "$UNIVERSAL_GOST" \
  "$WORK/app/ProxyPilot.app/Contents/Resources/bin/gost"
/bin/chmod 700 "$WORK/app/ProxyPilot.app/Contents/Resources/bin/gost"
/usr/bin/codesign --force --sign - --options runtime,hard,kill \
  --identifier kz.documentolog.proxypilot "$WORK/app/ProxyPilot.app"
/usr/bin/codesign --verify --deep --strict "$WORK/app/ProxyPilot.app"
zsh "$HERE/vpn-helper/build.sh" "$WORK/helper/release"

python3 "$HERE/vpn-package/package.py" prepare \
  --app "$WORK/app/ProxyPilot.app" \
  --helper "$WORK/helper/release/vpn-helper" \
  --engine-artifact "$ENGINE_ARTIFACT" --sequence "$SEQUENCE" \
  --output "$WORK/stage"
"$KEY_TOOL" sign "$WORK/stage/Payload/vpn-release.manifest" \
  "$WORK/stage/Payload/vpn-release.sig"
python3 "$HERE/vpn-package/package.py" prepare-update --stage "$WORK/stage" \
  --previous-manifest "$PREVIOUS_MANIFEST" \
  --previous-signature "$PREVIOUS_SIGNATURE"
"$KEY_TOOL" sign-transition \
  "$PREVIOUS_MANIFEST" "$PREVIOUS_SIGNATURE" \
  "$WORK/stage/Payload/vpn-release.manifest" \
  "$WORK/stage/Payload/vpn-release.sig" \
  "$WORK/stage/Payload/vpn-update-transition" \
  "$WORK/stage/Payload/vpn-update-transition.sig"

DMG="$OUTPUT/ProxyPilot-$VERSION-vpn-joint.dmg"
METADATA="$OUTPUT/ProxyPilot-$VERSION-vpn-joint.metadata"
METADATA_SIGNATURE="$METADATA.sig"
python3 "$HERE/vpn-package/package.py" build-companion \
  --stage "$WORK/stage" --output "$DMG"
python3 "$HERE/vpn-package/package.py" prepare-companion-metadata \
  --stage "$WORK/stage" --companion "$DMG" --output "$METADATA"
"$KEY_TOOL" sign-companion "$METADATA" "$METADATA_SIGNATURE"
"$KEY_TOOL" verify-companion-artifact "$METADATA" "$METADATA_SIGNATURE" \
  "$HERE/vpn-release-public-key.txt" "$DMG"

# Preserve the exact signed endpoint as input for the next forward release.
/usr/bin/env COPYFILE_DISABLE=1 /usr/bin/tar --format ustar -czf \
  "$OUTPUT/ProxyPilot-$VERSION-vpn-engine-sources.tar.gz" \
  -C "$WORK/stage" EngineSources
python3 "$HERE/vpn-package/package.py" verify-engine-sources \
  --archive "$OUTPUT/ProxyPilot-$VERSION-vpn-engine-sources.tar.gz" \
  --release-manifest "$WORK/stage/Payload/vpn-release.manifest" \
  --version "$VERSION"
/bin/cp "$WORK/stage/Payload/vpn-release.manifest" \
  "$OUTPUT/ProxyPilot-$VERSION-vpn-release.manifest"
/bin/cp "$WORK/stage/Payload/vpn-release.sig" \
  "$OUTPUT/ProxyPilot-$VERSION-vpn-release.sig"
/bin/chmod 600 "$OUTPUT"/*
SUCCESS=1
print -- "Prepared and verified local joint release assets: $OUTPUT"
print -- "No tag, upload, installation or system change was performed."
