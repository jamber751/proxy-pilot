#!/bin/zsh
# Установщик proxypilot. Идемпотентен — можно запускать повторно.
set -euo pipefail
emulate -L zsh

HERE="${0:A:h}"
BIN_DIR="$HOME/.local/bin"
# То же место, куда ставит Install.command из DMG. Раньше здесь был
# ~/Applications, и у сделавшего оба способа оказывалось два бандла:
# один запускался, второй тихо протухал.
APP_DIR="/Applications"
SHELL_RC="$HOME/.zshrc"
MARK_BEGIN="# >>> proxypilot >>>"
MARK_END="# <<< proxypilot <<<"

grn() { print -- $'\e[32m'"✓"$'\e[0m'" $*" }
yel() { print -- $'\e[33m'"!"$'\e[0m'" $*" }
red() { print -u2 -- $'\e[31m'"✗"$'\e[0m'" $*" }
step() { print -- ""; print -- $'\e[1m'"$*"$'\e[0m' }

[[ "$(uname -s)" == Darwin ]] || { red "только macOS"; exit 1 }

# ── 1. зависимость: gost ─────────────────────────────────────────────────────
step "1/5  Проверяю gost"
if command -v gost >/dev/null; then
  grn "gost уже стоит: $(command -v gost)"
elif command -v brew >/dev/null; then
  print -- "  ставлю через brew…"
  brew install gost
  grn "gost установлен"
else
  red "нужен gost, а Homebrew не найден."
  print -u2 -- "  Поставь brew (https://brew.sh), затем: brew install gost"
  exit 1
fi

# ── 2. CLI ───────────────────────────────────────────────────────────────────
step "2/5  Ставлю CLI"
mkdir -p "$BIN_DIR"
ln -sf "$HERE/bin/proxypilot" "$BIN_DIR/proxypilot"
chmod +x "$HERE/bin/proxypilot"
grn "$BIN_DIR/proxypilot"
[[ ":$PATH:" == *":$BIN_DIR:"* ]] || yel "$BIN_DIR не в PATH — добавь: export PATH=\"\$HOME/.local/bin:\$PATH\""

# ── 3. конфиг ────────────────────────────────────────────────────────────────
step "3/5  Настраиваю сеть"
CFG="${XDG_CONFIG_HOME:-$HOME/.config}/proxypilot/config"
if [[ -r "$CFG" ]]; then
  grn "конфиг уже есть: $CFG"
  print -- "  (пересоздать: proxypilot detect)"
else
  # Прокси может не быть видно прямо сейчас (ставимся из дома) — это не повод
  # обрывать установку на середине: CLI уже стоит, шелл и приложение впереди.
  "$BIN_DIR/proxypilot" detect || DETECT_FAILED=1
fi

# ── 4. интеграция с шеллом ───────────────────────────────────────────────────
step "4/5  Подключаю к шеллу"
if grep -qF "$MARK_BEGIN" "$SHELL_RC" 2>/dev/null; then
  grn "блок в $SHELL_RC уже есть"
else
  cp "$SHELL_RC" "$SHELL_RC.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
  cat >> "$SHELL_RC" <<EOF

$MARK_BEGIN
# Прокси для терминала. Адрес всегда 127.0.0.1 — режим переключается
# командой proxypilot (socks|http|direct|auto), клиенты не перезапускаются.
[[ -x "\$HOME/.local/bin/proxypilot" ]] && eval "\$("\$HOME/.local/bin/proxypilot" shellenv)"
$MARK_END
EOF
  grn "добавлен блок в $SHELL_RC (бэкап рядом)"
fi

# ── 5. приложение в меню-баре ────────────────────────────────────────────────
step "5/5  Собираю приложение"
if [[ -x "$HERE/app/build.sh" ]] && command -v swiftc >/dev/null; then
  "$HERE/app/build.sh" >/dev/null
  [[ -w "$APP_DIR" ]] || { yel "$APP_DIR недоступен на запись — ставлю в ~/Applications"; APP_DIR="$HOME/Applications" }
  mkdir -p "$APP_DIR"
  rm -rf "$APP_DIR/ProxyPilot.app"
  cp -R "$HERE/app/build/ProxyPilot.app" "$APP_DIR/"
  grn "$APP_DIR/ProxyPilot.app"
  # Мост живёт дочерним процессом приложения, поэтому без автозапуска после
  # перезагрузки прокси просто нет. Ставим сами; выключается тумблером в меню.
  osascript -e "tell application \"System Events\" to make login item at end with properties {path:\"$APP_DIR/ProxyPilot.app\", hidden:true}" >/dev/null 2>&1 \
    && grn "добавлен в автозапуск (выключается в меню-баре)"
else
  yel "swiftc не найден — приложение пропущено (CLI работает и без него)."
  yel "Поставить: xcode-select --install"
fi

# ── итог ─────────────────────────────────────────────────────────────────────
print -- ""
print -- $'\e[1m'"Готово."$'\e[0m'
print -- ""
"$BIN_DIR/proxypilot" status || true
print -- ""
print -- "Дальше:"
print -- "  1. Открой новый таб терминала — прокси подхватится сам."
print -- "  2. Запусти ProxyPilot.app (значок появится в меню-баре)."
print -- "     При первом запуске macOS спросит доступ к локальной сети — разреши,"
print -- "     иначе мост не достучится до корпоративного прокси."
if [[ -n "${DETECT_FAILED:-}" ]]; then
  print -- ""
  yel "Прокси в этой сети не нашлись. В офисе выполни: proxypilot detect"
fi
print -- ""
print -- "  proxypilot bench          — сравнить скорость каналов"
print -- "  proxypilot doctor         — если что-то не работает"
print -- "  proxypilot system status  — системный прокси (браузер, GUI)"
