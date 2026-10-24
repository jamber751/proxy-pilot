#!/bin/zsh
# Builds the separate rescue executable only; no installation or release keys.
set -euo pipefail
umask 077
HERE="${0:A:h}"
[[ $# == 1 && $1 == /* && ! -e "$1" && ! -L "$1" ]] || { print -u2 'Expected a new absolute output directory'; exit 64; }
OUT="$1"
mkdir -m 700 "$OUT"
mkdir "$OUT/ModuleCache"
# Capture one immutable source graph for both architectures. Concurrent work in
# the checkout cannot make ARM and Intel executables come from different inputs.
/usr/bin/python3 - "$HERE/.." "$OUT" <<'PY'
import hashlib
import os
from pathlib import Path
import stat
import sys

app = Path(sys.argv[1]).resolve(strict=True)
output = Path(sys.argv[2]).resolve(strict=True)
snapshot = output / 'Sources'
snapshot.mkdir(mode=0o700)

def source_paths():
    return [app / 'VPNConfiguration.swift', app / 'VPNProfileImporter.swift'] + sorted(
        path for path in (app / 'vpn-helper').glob('*.swift') if path.name != 'ServiceMain.swift')

def facts(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)

def read_bound(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError('Source is not a regular file')
        chunks = []
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        data = b''.join(chunks)
        after = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        if facts(before) != facts(after) or facts(after) != facts(named) or len(data) != before.st_size:
            raise RuntimeError('Source changed while reading')
        return data, facts(before)
    finally:
        os.close(descriptor)

paths = source_paths()
captured = {}
manifest = []
arguments = []
for path in paths:
    relative = Path('app') / path.relative_to(app)
    if '\n' in str(path) or '\n' in str(output):
        raise RuntimeError('Source/output paths must not contain newlines')
    data, identity = read_bound(path)
    digest = hashlib.sha256(data).hexdigest()
    target = snapshot / relative
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.write_bytes(data)
    target.chmod(0o400)
    captured[path] = (digest, identity)
    manifest.append(digest + '  Sources/' + relative.as_posix() + '\n')
    arguments.append(str(target))
if paths != source_paths():
    raise RuntimeError('Source graph changed while capturing')
for path in paths:
    data, identity = read_bound(path)
    if captured[path] != (hashlib.sha256(data).hexdigest(), identity):
        raise RuntimeError('Source changed while capturing graph')
(output / 'Sources.sha256').write_text(''.join(manifest), encoding='utf-8')
(output / 'sources.list').write_text('\n'.join(arguments) + '\n', encoding='utf-8')
PY
SOURCES=()
while IFS= read -r SOURCE; do
  SOURCES+=("$SOURCE")
done < "$OUT/sources.list"
for ARCH in arm64 x86_64; do
  /usr/bin/swiftc -O -parse-as-library \
    -D VPN_RESCUE_SYSTEM_ENTRY -D VPN_EXPLICIT_RESCUE -D VPN_RESCUE_PREPARATION \
    -module-cache-path "$OUT/ModuleCache" -target "$ARCH-apple-macosx11.0" \
    "${SOURCES[@]}" -o "$OUT/rescue-$ARCH"
done
/usr/bin/lipo -create "$OUT/rescue-arm64" "$OUT/rescue-x86_64" -output "$OUT/vpn-rescue"
chmod 700 "$OUT/vpn-rescue"
/usr/bin/codesign --force --sign - --options runtime,hard,kill \
  --identifier kz.documentolog.proxypilot.vpn-rescue "$OUT/vpn-rescue"
/usr/bin/codesign --verify --strict "$OUT/vpn-rescue"
print -- "Built VPN rescue: $OUT/vpn-rescue. Nothing installed."
print -- "Source snapshot hashes: $OUT/Sources.sha256"
