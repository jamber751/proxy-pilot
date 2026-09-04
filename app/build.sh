#!/bin/zsh
# Собирает ProxyPilot.app из main.swift. Нужен только Xcode Command Line Tools.
set -euo pipefail

HERE="${0:A:h}"
OUT="${1:-$HERE/build}"
APP="$OUT/ProxyPilot.app"

# версия — из CLI, единственного источника правды: make-dmg.sh берёт её оттуда же,
# а релиз падает, если PP_VERSION разошёлся с тегом. Раньше здесь был хардкод,
# и бандл с 1.1.0 представлялся системе версией 1.0.0
VERSION=$(awk -F'"' '/^readonly PP_VERSION=/{print $2}' "${HERE:h}/bin/proxypilot")
[[ -n "$VERSION" ]] || { print -u2 "не нашёл PP_VERSION в bin/proxypilot"; exit 1; }

command -v swiftc >/dev/null || {
  print -u2 "нет swiftc. Установи: xcode-select --install"; exit 1
}

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# файл называется main.swift, поэтому код верхнего уровня компилируется как есть.
# Universal (Intel + Apple Silicon): две компиляции + lipo — DMG должен
# запускаться и на x86_64-маках.
swiftc -O -target "arm64-apple-macosx11.0" \
  -o "$APP/Contents/MacOS/ProxyPilot-arm64" "$HERE/main.swift"
swiftc -O -target "x86_64-apple-macosx11.0" \
  -o "$APP/Contents/MacOS/ProxyPilot-x86_64" "$HERE/main.swift"
lipo -create "$APP/Contents/MacOS/ProxyPilot-arm64" "$APP/Contents/MacOS/ProxyPilot-x86_64" \
  -output "$APP/Contents/MacOS/ProxyPilot"
rm -f "$APP/Contents/MacOS/ProxyPilot-arm64" "$APP/Contents/MacOS/ProxyPilot-x86_64"

# иконка (генерится из icon-master.png, см. README)
[ -f "$HERE/AppIcon.icns" ] && cp "$HERE/AppIcon.icns" "$APP/Contents/Resources/"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>            <string>ProxyPilot</string>
  <key>CFBundleDisplayName</key>     <string>ProxyPilot</string>
  <key>CFBundleIdentifier</key>      <string>kz.documentolog.proxypilot</string>
  <key>CFBundleExecutable</key>      <string>ProxyPilot</string>
  <key>CFBundlePackageType</key>     <string>APPL</string>
  <key>CFBundleShortVersionString</key> <string>$VERSION</string>
  <key>CFBundleVersion</key>         <string>1</string>
  <key>LSMinimumSystemVersion</key>  <string>11.0</string>

  <key>CFBundleIconFile</key>        <string>AppIcon</string>

  <!-- только меню-бар, без иконки в Dock -->
  <key>LSUIElement</key>             <true/>

  <!-- macOS 15+: текст в запросе доступа к локальной сети.
       Без доступа мост не достучится до корпоративного прокси. -->
  <key>NSLocalNetworkUsageDescription</key>
  <string>ProxyPilot подключается к корпоративному прокси в локальной сети.</string>
</dict>
</plist>
PLIST

# ad-hoc подпись: без неё macOS не выдаёт стабильный идентификатор,
# и разрешение Local Network будет спрашиваться заново при каждой пересборке
codesign --force --sign - --identifier kz.documentolog.proxypilot "$APP" 2>/dev/null \
  || print -u2 "предупреждение: не удалось подписать (ad-hoc), приложение всё равно запустится"

print -- "собрано: $APP"
