#!/bin/zsh
# Собирает распространяемый ProxyPilot-<версия>.dmg в dist/.
#
# В DMG-варианте приложение самодостаточно: CLI и gost вложены в бандл
# (Contents/Resources/bin), получателю не нужны ни brew, ни репозиторий.
# На машине разработчика приложение по-прежнему берёт CLI из ~/.local/bin
# (см. порядок кандидатов в app/main.swift).
set -euo pipefail
emulate -L zsh

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

# скрипт-установщик: правый клик → Open — и дальше всё сам (копия в
# /Applications, снятие quarantine, автозапуск по желанию, первый запуск)
cat > "$STAGE/Установить.command" <<'INSTALLER'
#!/bin/zsh
# Установщик ProxyPilot. Запуск: правый клик → Open (обычный даблклик
# macOS заблокирует — приложение без подписи Apple).
set -e
SRC="${0:A:h}/ProxyPilot.app"
DST="/Applications/ProxyPilot.app"

echo "ProxyPilot: установка…"
[[ -d "$SRC" ]] || { echo "рядом со скриптом нет ProxyPilot.app"; exit 1 }

pkill -f "ProxyPilot.app/Contents/MacOS/ProxyPilot" 2>/dev/null || true
rm -rf "$DST"
ditto "$SRC" "$DST"
# снять карантин: без подписи Apple это единственный способ запускаться без предупреждений
xattr -dr com.apple.quarantine "$DST" 2>/dev/null || true
echo "✓ установлено в $DST"

echo -n "Добавить в автозапуск (Login Items)? [y/N] "
read -k1 ans; echo
if [[ "$ans" == [yY] ]]; then
  osascript -e 'tell application "System Events" to make login item at end with properties {path:"/Applications/ProxyPilot.app", hidden:true}' >/dev/null \
    && echo "✓ в автозапуске" \
    || echo "не вышло — добавь руками: System Settings → General → Login Items"
fi

open "$DST"
echo
echo "Дальше:"
echo "  1. Разреши доступ к локальной сети, когда macOS спросит."
echo "  2. В открывшихся Настройках проверь адреса прокси и нажми «Сохранить»."
echo "  3. System Settings → Network → Wi-Fi → Details → Proxies:"
echo "     HTTP и HTTPS → 127.0.0.1:3129, SOCKS — выключить."
echo
echo "Терминальная интеграция (по желанию):"
echo '  echo '\''eval "$(/Applications/ProxyPilot.app/Contents/Resources/bin/proxypilot shellenv)"'\'' >> ~/.zshrc'
INSTALLER
chmod +x "$STAGE/Установить.command"

# короткая памятка получателю — прямо в образе
cat > "$STAGE/ПРОЧТИ_МЕНЯ.txt" <<EOF
ProxyPilot $VERSION  (Intel + Apple Silicon)

БЫСТРЫЙ ПУТЬ:
  правый клик по «Установить.command» → Open → Open.
  Скрипт скопирует приложение в Applications, снимет карантин,
  предложит автозапуск и запустит ProxyPilot.

  (Обычный даблклик macOS заблокирует — приложение без подписи Apple.
   Альтернатива: перетащи «Установить.command» в окно Терминала и нажми Enter.)

ВРУЧНУЮ (если скрипту не доверяешь — справедливо, читай его текст):
  1. Перетащи ProxyPilot.app в Applications.
  2. Правый клик по ProxyPilot.app → Open (или Privacy & Security → Open Anyway).
  3. Разреши доступ к локальной сети, когда macOS спросит.
  4. System Settings → Network → Wi-Fi → Details → Proxies:
     HTTP и HTTPS → 127.0.0.1:3129, SOCKS — выключить.
  5. Автозапуск: System Settings → General → Login Items → «+» → ProxyPilot.

При первом запуске приложение само ищет прокси в сети и открывает
Настройки — проверь адреса и нажми «Сохранить и применить».
EOF

# 3) образ
mkdir -p "$DIST"
OUT="$DIST/ProxyPilot-$VERSION.dmg"
rm -f "$OUT"
hdiutil create -volname "ProxyPilot" -srcfolder "$STAGE" -ov -format UDZO "$OUT" >/dev/null

print -- "готово: $OUT ($(du -h "$OUT" | cut -f1 | tr -d ' '))"
