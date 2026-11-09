#!/bin/bash
# AutoZ 构建脚本：把 Sources/ 编成 .app 包（菜单栏程序，无 Dock 图标）
#
# 用法:
#   ./build.sh                构建到 dist/AutoZ.app（默认跟随本机架构）
#   ./build.sh --install      构建后复制到 /Applications
#   ./build.sh --run          构建后直接启动
#
# 环境变量:
#   AUTOZ_VERSION       版本号，写入 Info.plist（默认 0.9.0）
#   AUTOZ_DISPLAY_NAME  对外显示名，写入 CFBundleDisplayName（默认「自适应时区」）
#   AUTOZ_ARCHS         目标架构，空格分隔，如 "arm64 x86_64"（默认本机架构）
#   AUTOZ_MIN_MACOS     最低系统版本（默认 13.0）
#
# 变量引用一律写 ${VAR}，不要写 $VAR 紧跟中文 —— bash 3.2 扫变量名用的是 isalnum()，
# 遇到高位字节（中文首字节）会越界查表，结果随 libc 而异。同一个脚本在本机 macOS 26
# 正常、在 macOS 15 的 CI 上就报 `ARCHS?: unbound variable`。加花括号与 locale 无关，永远安全。
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(pwd)"
APP_NAME="AutoZ"
VERSION="${AUTOZ_VERSION:-0.9.0-ru.2}"
ARCHS="${AUTOZ_ARCHS:-$(uname -m)}"
HOST_ARCH="$(uname -m)"
MIN_MACOS="${AUTOZ_MIN_MACOS:-13.0}"
DIST="$ROOT/dist"
APP="$DIST/$APP_NAME.app"
BUILD="$ROOT/build"
BUNDLE_ID="cn.y10n.autoz"
# 对外显示名（Finder / 系统「关于」里看到的那个名字）。改名只动这一处。
DISPLAY_NAME="${AUTOZ_DISPLAY_NAME:-AutoZ — часовые пояса}"

echo "==> Очистка результатов предыдущей сборки"
rm -rf "$APP" "$BUILD"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$BUILD"

echo "==> Архитектуры: ${ARCHS} (сборка на ${HOST_ARCH}, macOS ${MIN_MACOS}+)"

for ARCH in $ARCHS; do
  mkdir -p "$BUILD/$ARCH"

  echo "==> [$ARCH] Компиляция модуля авторизации C"
  /usr/bin/clang -c "$ROOT/Sources/authshim.c" -o "$BUILD/$ARCH/authshim.o" \
    -Wno-deprecated-declarations -O2 \
    -target "$ARCH-apple-macos$MIN_MACOS" \
    -isysroot "$(xcrun --show-sdk-path)"

  echo "==> [$ARCH] Компиляция приложения Swift"
  /usr/bin/swiftc \
    -O -swift-version 5 \
    -target "$ARCH-apple-macos$MIN_MACOS" \
    -framework Security \
    -o "$BUILD/$ARCH/$APP_NAME" \
    "$ROOT/Sources/main.swift" "$ROOT/Sources/artwork.swift" "$ROOT/Sources/ui.swift" \
    "$BUILD/$ARCH/authshim.o"

  echo "==> [$ARCH] Компиляция помощника autoz-helper"
  /usr/bin/swiftc \
    -O -swift-version 5 \
    -target "$ARCH-apple-macos$MIN_MACOS" \
    -o "$BUILD/$ARCH/autoz-helper" \
    "$ROOT/Sources/helper.swift"
done

# 单架构直接复制，多架构用 lipo 合成通用二进制
join_archs() {
  local out="$1"; shift
  if [[ $# -eq 1 ]]; then
    /bin/cp "$1" "$out"
  else
    /usr/bin/lipo -create "$@" -o "$out"
  fi
}

MAIN_PARTS=(); HELPER_PARTS=()
for ARCH in $ARCHS; do
  MAIN_PARTS+=("$BUILD/$ARCH/$APP_NAME")
  HELPER_PARTS+=("$BUILD/$ARCH/autoz-helper")
done

echo "==> Сборка исполняемого файла"
join_archs "$APP/Contents/MacOS/$APP_NAME" "${MAIN_PARTS[@]}"
/usr/bin/lipo -info "$APP/Contents/MacOS/$APP_NAME" | sed 's/^/    /'

echo "==> Сборка помощника"
join_archs "$APP/Contents/Resources/autoz-helper" "${HELPER_PARTS[@]}"
/bin/chmod +x "$APP/Contents/Resources/autoz-helper"
/usr/bin/lipo -info "$APP/Contents/Resources/autoz-helper" | sed 's/^/    /'

echo "==> Проверка помощника: 11 проверок без изменения системы"
"$BUILD/$HOST_ARCH/autoz-helper" --selftest || { echo "Проверка помощника не пройдена; сборка остановлена"; exit 1; }

echo "==> Проверка часовых поясов и русской локализации"
"$APP/Contents/MacOS/$APP_NAME" --tz-selftest || { echo "Проверка часовых поясов не пройдена; сборка остановлена"; exit 1; }

echo "==> Создание значка приложения"
/usr/bin/swiftc -O -swift-version 5 -parse-as-library \
  -target "$HOST_ARCH-apple-macos$MIN_MACOS" \
  -o "$BUILD/makeicon" \
  "$ROOT/Sources/artwork.swift" "$ROOT/Sources/makeicon.swift"
"$BUILD/makeicon" "$BUILD/AppIcon.iconset"
/usr/bin/iconutil -c icns "$BUILD/AppIcon.iconset" -o "$APP/Contents/Resources/AppIcon.icns"
echo "    Записан Resources/AppIcon.icns ($(du -h "$APP/Contents/Resources/AppIcon.icns" | cut -f1))"

echo "==> Создание Info.plist"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key><string>ru</string>
    <key>CFBundleLocalizations</key><array><string>ru</string></array>
    <key>CFBundleExecutable</key><string>$APP_NAME</string>
    <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundleIconName</key><string>AppIcon</string>
    <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
    <key>CFBundleName</key><string>$APP_NAME</string>
    <key>CFBundleDisplayName</key><string>$DISPLAY_NAME</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>${VERSION%%-*}</string>
    <key>LSUIElement</key><true/>
    <key>LSMinimumSystemVersion</key><string>$MIN_MACOS</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSHumanReadableCopyright</key><string>AutoZ $VERSION</string>
</dict>
</plist>
PLIST

echo "==> Проверка Info.plist"
/usr/bin/plutil -lint "$APP/Contents/Info.plist"

echo "==> Локальная подпись помощника и приложения"
/usr/bin/codesign --force --sign - --timestamp=none "$APP/Contents/Resources/autoz-helper" 2>&1 | sed 's/^/    /' || true
/usr/bin/codesign --force --sign - --timestamp=none "$APP" 2>&1 | sed 's/^/    /'
/usr/bin/codesign --verify --verbose=1 "$APP" 2>&1 | sed 's/^/    /' || true

echo "==> Проверка автономных команд"
"$APP/Contents/MacOS/$APP_NAME" --version | sed 's/^/    /'
"$APP/Contents/MacOS/$APP_NAME" --system | sed 's/^/    /'
"$APP/Contents/MacOS/$APP_NAME" --format | sed 's/^/    /'

echo
echo "Сборка завершена: $APP"
du -sh "$APP"

if [[ "${1:-}" == "--install" ]]; then
  echo "==> Установка в /Applications"
  rm -rf "/Applications/$APP_NAME.app"
  /bin/cp -R "$APP" "/Applications/$APP_NAME.app"
  echo "Установлено: /Applications/$APP_NAME.app"
fi

if [[ "${1:-}" == "--run" || "${1:-}" == "--install" ]]; then
  echo "==> Запуск"
  if [[ "${1:-}" == "--install" ]]; then
    /usr/bin/open "/Applications/$APP_NAME.app"
  else
    /usr/bin/open "$APP"
  fi
fi
