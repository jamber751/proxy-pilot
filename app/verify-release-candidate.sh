#!/bin/zsh
# Verify one already assembled local/draft release. Read-only: no signing,
# installation, publication, privilege escalation or system VPN mutation.
emulate -L zsh
set -euo pipefail

HERE="${0:A:h}"
ROOT="${HERE:h}"
[[ $# == 2 ]] || { print -u2 "Usage: $0 VERSION ABSOLUTE_ASSET_DIRECTORY"; exit 64; }
VERSION="$1"
ASSETS="${2:A}"
print -r -- "$VERSION" | /usr/bin/grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || {
  print -u2 "Expected canonical version"; exit 64
}
[[ "$ASSETS" == /* && -d "$ASSETS" && ! -L "$ASSETS" ]] || {
  print -u2 "Expected an absolute non-symlink asset directory"; exit 64
}

typeset -a names
names=(
  "ProxyPilot-$VERSION.dmg"
  "ProxyPilot-$VERSION.zip"
  "appcast.xml"
  "ProxyPilot-$VERSION-vpn-joint.dmg"
  "ProxyPilot-$VERSION-vpn-joint.metadata"
  "ProxyPilot-$VERSION-vpn-joint.metadata.sig"
  "ProxyPilot-$VERSION-vpn-release.manifest"
  "ProxyPilot-$VERSION-vpn-release.sig"
  "ProxyPilot-$VERSION-vpn-engine-sources.tar.gz"
)
actual=("${(@f)$(/usr/bin/find "$ASSETS" -mindepth 1 -maxdepth 1 -print | /usr/bin/sed 's|.*/||' | /usr/bin/sort)}")
expected=("${(@f)$(print -l -- $names | /usr/bin/sort)}")
[[ "${(j:\n:)actual}" == "${(j:\n:)expected}" ]] || {
  print -u2 "Release asset set is missing, duplicated or unexpected"; exit 1
}
for name in $names; do
  path="$ASSETS/$name"
  [[ -f "$path" && ! -L "$path" && -s "$path" ]] || {
    print -u2 "Unsafe or empty release asset: $name"; exit 1
  }
done
[[ $(/usr/bin/stat -f %z "$ASSETS/ProxyPilot-$VERSION.dmg") -le 1073741824 \
   && $(/usr/bin/stat -f %z "$ASSETS/ProxyPilot-$VERSION.zip") -le 1073741824 \
   && $(/usr/bin/stat -f %z "$ASSETS/ProxyPilot-$VERSION-vpn-joint.dmg") -le 805306368 \
   && $(/usr/bin/stat -f %z "$ASSETS/ProxyPilot-$VERSION-vpn-engine-sources.tar.gz") -le 230686720 ]] || {
  print -u2 "Release asset exceeds its fixed bound"; exit 1
}

scratch=$(/usr/bin/mktemp -d /tmp/proxypilot-release-verify.XXXXXX)
normal_mount="$scratch/normal"
joint_mount="$scratch/joint"
/bin/mkdir -m 700 "$normal_mount" "$joint_mount" "$scratch/zip" "$scratch/key"
cleanup() {
  /usr/bin/hdiutil detach "$normal_mount" >/dev/null 2>&1 || true
  /usr/bin/hdiutil detach "$joint_mount" >/dev/null 2>&1 || true
  /bin/rm -rf -- "$scratch"
}
trap cleanup EXIT

key_tool="$scratch/key/vpn-release-key"
/usr/bin/swiftc -O -parse-as-library -module-cache-path "$scratch/key/ModuleCache" \
  "$HERE/vpn-helper/VPNPeerAuthentication.swift" \
  "$HERE/vpn-helper/VPNReleaseAuthorization.swift" \
  "$HERE/vpn-helper/VPNReleaseTrust.swift" \
  "$HERE/vpn-helper/VPNCompanionMetadata.swift" \
  "$HERE/vpn-release-key.swift" -o "$key_tool"
public_key="$HERE/vpn-release-public-key.txt"
manifest="$ASSETS/ProxyPilot-$VERSION-vpn-release.manifest"
manifest_signature="$ASSETS/ProxyPilot-$VERSION-vpn-release.sig"
metadata="$ASSETS/ProxyPilot-$VERSION-vpn-joint.metadata"
metadata_signature="$metadata.sig"
joint_dmg="$ASSETS/ProxyPilot-$VERSION-vpn-joint.dmg"
"$key_tool" verify "$manifest" "$manifest_signature" "$public_key"
"$key_tool" verify-companion-artifact \
  "$metadata" "$metadata_signature" "$public_key" "$joint_dmg"
/usr/bin/python3 "$HERE/vpn-package/package.py" verify-engine-sources \
  --archive "$ASSETS/ProxyPilot-$VERSION-vpn-engine-sources.tar.gz" \
  --release-manifest "$manifest" --version "$VERSION"

/usr/bin/hdiutil verify -quiet "$ASSETS/ProxyPilot-$VERSION.dmg"
/usr/bin/hdiutil verify -quiet "$joint_dmg"
/usr/bin/hdiutil attach -readonly -nobrowse -noautoopen -owners off \
  -mountpoint "$normal_mount" "$ASSETS/ProxyPilot-$VERSION.dmg" >/dev/null
/usr/bin/hdiutil attach -readonly -nobrowse -noautoopen -owners off \
  -mountpoint "$joint_mount" "$joint_dmg" >/dev/null
/usr/bin/ditto -x -k "$ASSETS/ProxyPilot-$VERSION.zip" "$scratch/zip"

joint_names=("${(@f)$(/usr/bin/find "$joint_mount" -mindepth 1 -maxdepth 1 -print | /usr/bin/sed 's|.*/||' | /usr/bin/sort)}")
joint_expected=(ProxyPilot.app vpn-engine vpn-helper vpn-previous-release.manifest
  vpn-previous-release.sig vpn-release.manifest vpn-release.sig
  vpn-update-transition vpn-update-transition.sig)
joint_expected=("${(@f)$(print -l -- $joint_expected | /usr/bin/sort)}")
[[ "${(j:\n:)joint_names}" == "${(j:\n:)joint_expected}" ]] || {
  print -u2 "Joint image layout mismatch"; exit 1
}
/usr/bin/cmp "$manifest" "$joint_mount/vpn-release.manifest"
/usr/bin/cmp "$manifest_signature" "$joint_mount/vpn-release.sig"
"$key_tool" verify-transition \
  "$joint_mount/vpn-previous-release.manifest" \
  "$joint_mount/vpn-previous-release.sig" \
  "$joint_mount/vpn-release.manifest" "$joint_mount/vpn-release.sig" \
  "$joint_mount/vpn-update-transition" \
  "$joint_mount/vpn-update-transition.sig" "$public_key"

normal_app="$normal_mount/ProxyPilot.app"
joint_app="$joint_mount/ProxyPilot.app"
zip_app="$scratch/zip/ProxyPilot.app"
[[ -d "$normal_app" && -d "$joint_app" && -d "$zip_app" ]] || {
  print -u2 "A release container has no ProxyPilot.app"; exit 1
}
/usr/bin/diff -qr "$normal_app" "$joint_app" >/dev/null
/usr/bin/diff -qr "$normal_app" "$zip_app" >/dev/null
/usr/bin/codesign --verify --deep --strict "$normal_app"
/usr/bin/codesign --verify --deep --strict "$joint_app"
"$joint_app/Contents/MacOS/ProxyPilot" --vpn-support-verify-update

/usr/bin/python3 - "$VERSION" "$metadata" "$manifest" \
  "$joint_mount/vpn-previous-release.manifest" \
  "$joint_app/Contents/Info.plist" "$HERE/vpn-release-sequence.txt" <<'PY'
import plistlib, re, sys
from pathlib import Path

version, metadata_path, manifest_path, previous_path, info_path, sequence_path = sys.argv[1:]
def record(path):
    data = Path(path).read_bytes()
    text = data.decode('ascii')
    if not text.endswith('\n'): raise SystemExit('non-canonical release record')
    result = {}
    for line in text.splitlines():
        if line.count('=') != 1: raise SystemExit('non-canonical release record')
        key, value = line.split('=', 1)
        if not key or not value or key in result: raise SystemExit('non-canonical release record')
        result[key] = value
    return result
metadata, candidate, previous = map(record, (metadata_path, manifest_path, previous_path))
info = plistlib.loads(Path(info_path).read_bytes())
sealed = Path(sequence_path).read_text().strip()
if not re.fullmatch(r'[1-9][0-9]{0,18}', sealed): raise SystemExit('bad sealed sequence')
if not (metadata.get('version') == candidate.get('version') == info.get('CFBundleVersion') == version
        and info.get('CFBundleShortVersionString') == version
        and metadata.get('from-sequence') == previous.get('sequence')
        and metadata.get('to-sequence') == candidate.get('sequence') == sealed
        and info.get('ProxyPilotVPNReleaseSequence') == int(sealed)
        and int(sealed) > int(previous['sequence'])):
    raise SystemExit('release version or sequence mismatch')
PY

/usr/bin/swift -module-cache-path "$scratch/update-module-cache" \
  "$HERE/verify-update.swift" "$HERE/updater-public-key.txt" \
  "$ASSETS/ProxyPilot-$VERSION.zip" "$ASSETS/appcast.xml" "$VERSION"
print -- "Verified exact ProxyPilot $VERSION release candidate"
