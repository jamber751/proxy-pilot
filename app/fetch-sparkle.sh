#!/bin/zsh
# Pinned upstream binary; checksum from Sparkle's tagged Package.swift.
set -euo pipefail
HERE="${0:A:h}"
VERSION=2.9.6
SHA256=8d5fb41d960b43f4a68aa14126bf62b098544ec8d191cdcc73eb14e63a8e7606
DEST="${HERE:h}/vendor/sparkle-$VERSION"
ARCHIVE="$DEST/Sparkle.zip"
mkdir -p "$DEST"
if [[ ! -f "$ARCHIVE" ]]; then
  curl --fail --location --proto '=https' --tlsv1.2 --max-time 180 \
    "https://github.com/sparkle-project/Sparkle/releases/download/$VERSION/Sparkle-for-Swift-Package-Manager.zip" \
    -o "$ARCHIVE.download"
  mv "$ARCHIVE.download" "$ARCHIVE"
fi
[[ "$(shasum -a 256 "$ARCHIVE" | cut -d' ' -f1)" == "$SHA256" ]] || {
  print -u2 "Sparkle checksum mismatch: $ARCHIVE"; exit 1
}
# Always extract the verified archive, not an unchecked framework cache.
ditto -x -k "$ARCHIVE" "$DEST"
print -- "$DEST"
