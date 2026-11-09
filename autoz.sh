#!/bin/bash
# AutoZ — часы UTC+8 и системный часовой пояс по внешнему IP.
# Команды используют локально собранный dist/AutoZ.app.
#
# Использование:
#   ./autoz.sh check              Проверить IP и пояс без изменения системы
#   ./autoz.sh apply              Проверить IP и применить пояс
#   ./autoz.sh set <zone>         Установить пояс IANA
#   ./autoz.sh restore <zone>     То же, что set
#   ./autoz.sh system             Системный пояс и автовыбор
#   ./autoz.sh format             Формат часов и время UTC+8
#   ./autoz.sh menu               Структура меню
#   ./autoz.sh tz-selftest        Проверки часовых поясов и русского интерфейса
#   ./autoz.sh plan [zone]        План действий без выполнения
#   ./autoz.sh backend <b>        helper | native | appleScript
#   ./autoz.sh notify             Проверить уведомления
#   ./autoz.sh notify-status      Сведения об уведомлениях
#   ./autoz.sh helper-status      Состояние помощника
#   ./autoz.sh helper-plan        План установки/удаления помощника
#   ./autoz.sh helper-install     Установить помощник (нужен пароль)
#   ./autoz.sh helper-uninstall   Удалить помощник (нужен пароль)
#   ./autoz.sh helper-selftest    11 проверок помощника без изменения системы
#   ./autoz.sh login-status       Состояние автозапуска
#   ./autoz.sh login-enable       Включить автозапуск
#   ./autoz.sh login-disable      Выключить автозапуск
#   ./autoz.sh install            Собрать и установить в /Applications
#   ./autoz.sh run                Запустить локальную сборку
#
set -uo pipefail

cd "$(dirname "$0")"
APP="$PWD/dist/AutoZ.app"
BIN="$APP/Contents/MacOS/AutoZ"

if [[ ! -x "$BIN" ]]; then
  echo "Сборка не найдена, запускается build.sh…"
  ./build.sh >/dev/null || { echo "Ошибка сборки"; exit 1; }
fi

cmd="${1:-help}"
shift || true

case "$cmd" in
  check|query)   exec "$BIN" --check ;;
  apply|sync)    exec "$BIN" --apply ;;
  set|restore)   [[ $# -ge 1 ]] || { echo "Использование: ./autoz.sh set <пояс IANA>"; exit 1; }
                 exec "$BIN" --set "$1" ;;
  system|status) exec "$BIN" --system ;;
  format|fmt)    exec "$BIN" --format ;;
  menu)          exec "$BIN" --menu ;;
  tz-selftest|tz-test) exec "$BIN" --tz-selftest ;;
  plan)          exec "$BIN" --plan "$@" ;;
  backend)       exec "$BIN" --backend "$@" ;;
  notify|notify-test) exec "$BIN" --notify-test ;;
  notify-status) exec "$BIN" --notify-status ;;
  helper|helper-status) exec "$BIN" --helper-status ;;
  helper-plan)   exec "$BIN" --helper-plan ;;
  helper-install) exec "$BIN" --helper-install ;;
  helper-uninstall) exec "$BIN" --helper-uninstall ;;
  helper-selftest)
    exec "$APP/Contents/Resources/autoz-helper" --selftest ;;
  install)       exec ./build.sh --install ;;
  login-status|login)  exec "$BIN" --login-status ;;
  login-enable)  exec "$BIN" --login-enable ;;
  login-disable) exec "$BIN" --login-disable ;;
  run|start)     exec /usr/bin/open "$APP" ;;
  help|-h|--help)
    # 只打印文件开头的注释块（遇到第一行非注释即停）
    /usr/bin/awk '/^#!/{next} /^#/{sub(/^# ?/,"");print;next} {exit}' "$0" ;;
  *) echo "Неизвестная команда: ${cmd} (справка: ./autoz.sh help)"; exit 1 ;;
esac
