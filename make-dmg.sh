#!/bin/zsh
# Собирает распространяемый ProxyPilot-<версия>.dmg в dist/.
#
# В DMG-варианте приложение самодостаточно: CLI и gost вложены в бандл
# (Contents/Resources/bin), получателю не нужны ни brew, ни репозиторий.
# Source builds also bundle their matching CLI; the DMG adds universal gost.
emulate -L zsh
set -euo pipefail

HERE="${0:A:h}"
DIST="$HERE/dist"
# gost для вкладывания в DMG. Бинарь в git не храним (25 МБ навсегда в истории) —
# качаем официальный релиз go-gost и проверяем по прибитой сумме: мы раздаём
# этот бинарь коллегам, поэтому «скачали и вложили не глядя» недопустимо.
# Обновление версии: сменить GOST_VERSION и суммы (shasum -a 256 <файлы>).
GOST_VERSION="3.2.6"
GOST_SHA256_amd64="0892485bd94e37b67a1f1d0d2372ed12d7dc0f1bc763d56177a0c0ee734855e6"
GOST_SHA256_arm64="e54f6c22e81c00650adfbbb23317c74a4dca9b9b73fa28cfa150f5559cc3ff2e"
VERSION=$(awk -F'"' '/^readonly PP_VERSION=/{print $2}' "$HERE/bin/proxypilot")
[[ -n "$VERSION" ]] || { print -u2 "не смог прочитать версию из bin/proxypilot"; exit 1 }

print -- "ProxyPilot $VERSION → dmg"

# 1) свежая сборка приложения
"$HERE/app/build.sh" >/dev/null
APP="$HERE/app/build/ProxyPilot.app"

# 2) staging: приложение + вложенные CLI и gost + ссылка на /Applications
STAGE=$(mktemp -d /tmp/proxypilot-dmg.XXXXXX)
trap "rm -rf '$STAGE'" EXIT
cp -R "$APP" "$STAGE/"

RES_BIN="$STAGE/ProxyPilot.app/Contents/Resources/bin"
mkdir -p "$RES_BIN"
cp "$HERE/bin/proxypilot" "$RES_BIN/proxypilot"
chmod +x "$RES_BIN/proxypilot"

# gost: нужен universal-бинарь (Intel + Apple Silicon). В git он не лежит
# (25 МБ), поэтому при первой сборке скачиваем официальные релизы go-gost
# для обеих архитектур и склеиваем через lipo — репозиторий самодостаточен.
if [[ ! -x "$HERE/vendor/gost-universal" ]] && command -v curl >/dev/null; then
  print -- "vendor/gost-universal нет — собираю из релизов go-gost $GOST_VERSION…"
  TMPG=$(mktemp -d /tmp/gost-fetch.XXXXXX)
  if for arch in amd64 arm64; do
       curl -fsSL --max-time 180 -o "$TMPG/$arch.tar.gz" \
         "https://github.com/go-gost/gost/releases/download/v$GOST_VERSION/gost_${GOST_VERSION}_darwin_${arch}.tar.gz" || exit 1
       want=$(eval print -- \$GOST_SHA256_$arch)
       got=$(shasum -a 256 "$TMPG/$arch.tar.gz" | cut -d' ' -f1)
       [[ "$got" == "$want" ]] || {
         print -u2 "  ✗ контрольная сумма $arch не совпала!"
         print -u2 "     ожидалась: $want"
         print -u2 "     получена:  $got"
         exit 1
       }
       mkdir -p "$TMPG/$arch" && tar xzf "$TMPG/$arch.tar.gz" -C "$TMPG/$arch" || exit 1
     done
  then
    mkdir -p "$HERE/vendor"
    lipo -create "$TMPG/amd64/gost" "$TMPG/arm64/gost" -output "$HERE/vendor/gost-universal" \
      && chmod +x "$HERE/vendor/gost-universal" \
      && print -- "  ✓ vendor/gost-universal ($(lipo -archs "$HERE/vendor/gost-universal"))"
  else
    print -u2 "  не вышло скачать (нет сети?) — откачусь на локальный gost"
  fi
  rm -rf "$TMPG"
fi

if [[ -x "$HERE/vendor/gost-universal" ]]; then
  cp "$HERE/vendor/gost-universal" "$RES_BIN/gost"
  print -- "gost: universal ($(lipo -archs "$RES_BIN/gost"))"
else
  GOST_BIN="${GOST:-$(command -v gost || print /opt/homebrew/bin/gost)}"
  [[ -x "$GOST_BIN" ]] || { print -u2 "не найден gost для вкладывания (brew install gost)"; exit 1 }
  cp "$GOST_BIN" "$RES_BIN/gost"
  print -u2 "предупреждение: вложен gost только для $(lipo -archs "$RES_BIN/gost") (нет vendor/gost-universal)"
fi

# бандл менялся после подписи в build.sh — переподписать (ad-hoc)
codesign --force --deep --sign - --identifier kz.documentolog.proxypilot \
  "$STAGE/ProxyPilot.app" 2>/dev/null || print -u2 "предупреждение: не удалось переподписать"

ln -s /Applications "$STAGE/Applications"

# installer script: right-click → Open and it does the rest (copy to
# /Applications, clear quarantine, optional login item, first launch)
cat > "$STAGE/Install.command" <<'INSTALLER'
#!/bin/zsh
# ProxyPilot installer. Run it with right-click → Open (a plain double-click
# is blocked by macOS — the app is not signed with an Apple certificate).
set -e
SRC="${0:A:h}/ProxyPilot.app"
DST="/Applications/ProxyPilot.app"

echo "ProxyPilot: installing…"
[[ -d "$SRC" ]] || { echo "ProxyPilot.app is not next to this script"; exit 1 }

pkill -f "ProxyPilot.app/Contents/MacOS/ProxyPilot" 2>/dev/null || true
rm -rf "$DST"
ditto "$SRC" "$DST"
# clearing quarantine is the only way to launch without warnings when unsigned
xattr -dr com.apple.quarantine "$DST" 2>/dev/null || true
echo "✓ installed to $DST"

# The bridge runs as a CHILD of the app (it inherits the Local Network
# permission), so without autostart there is simply no proxy after a reboot.
# This is not an option worth asking about — it is the only working setup.
# Login Items can be managed in macOS System Settings.
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/Applications/ProxyPilot.app", hidden:true}' >/dev/null 2>&1 \
  && echo "✓ starts at login (manage in macOS System Settings)"

# Shell integration, idempotent — the same block install.sh writes.
RC="$HOME/.zshrc"
MARK="# >>> proxypilot >>>"
if ! grep -qF "$MARK" "$RC" 2>/dev/null; then
  cp "$RC" "$RC.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  cat >> "$RC" <<'RCBLOCK'

# >>> proxypilot >>>
# Proxy for the terminal. The address is always 127.0.0.1 — the route is
# switched with `proxypilot`, clients never need a restart.
PP="/Applications/ProxyPilot.app/Contents/Resources/bin/proxypilot"
[[ -x "$PP" ]] && eval "$("$PP" shellenv)"
# <<< proxypilot <<<
RCBLOCK
  echo "✓ shell integration added to ~/.zshrc (backup next to it)"
fi

open "$DST"
echo
echo "Next: allow local network access when macOS asks — that is all."
echo "Press Find automatically in the app, then use the power button to turn the proxy on or off."
INSTALLER
chmod +x "$STAGE/Install.command"

# short note for the recipient, right inside the image
cat > "$STAGE/READ_ME_FIRST.txt" <<EOF
ProxyPilot $VERSION  (Intel + Apple Silicon, macOS 11+)

QUICK PATH:
  right-click "Install.command" → Open → Open. That is the whole install.
  The script copies the app to Applications, clears quarantine, sets it to
  start at login, wires up the terminal and launches ProxyPilot.
  Press Find automatically (Найти автоматически) in the app. If needed,
  open Settings (gear), press +, enter the host/IP and port, and choose SOCKS5 or HTTP.

  (A plain double-click is blocked by macOS — the app is not signed with an
   Apple certificate. Alternative: drag "Install.command" into a Terminal
   window and press Enter.)

MANUALLY (if you don't trust the script — fair enough, read it first):
  1. Drag ProxyPilot.app into Applications.
  2. Right-click ProxyPilot.app → Open (or Privacy & Security → Open Anyway).
  3. Allow local network access when macOS asks.
  4. Add ProxyPilot to Login Items in macOS System Settings if you want
     the app to start after a reboot.

The power button switches the proxy on or off. The gear icon (Настройки)
opens setup again. Turn off (Выключить) removes the app's system proxy;
an existing local bridge forwards directly for already-open terminal clients.

https://github.com/jamber751/proxy-pilot
EOF

# 3) образ
mkdir -p "$DIST"
OUT="$DIST/ProxyPilot-$VERSION.dmg"
rm -f "$OUT"
hdiutil create -volname "ProxyPilot" -srcfolder "$STAGE" -ov -format UDZO "$OUT" >/dev/null
[[ -s "$OUT" ]] || { print -u2 "hdiutil не создал $OUT"; exit 1 }

print -- "готово: $OUT ($(du -h "$OUT" | cut -f1 | tr -d ' '))"
