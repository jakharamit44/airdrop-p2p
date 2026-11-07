#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="$(cat "$ROOT_DIR/VERSION" 2>/dev/null || echo "2.0.0")"
RELEASE_DIR="$ROOT_DIR/release"

echo "====================================================="
echo " Building AirDrop P2P Release v${VERSION}"
echo "====================================================="

mkdir -p "$RELEASE_DIR"

# 1. Build Android APK
echo "[1/4] Building Android APK..."
cd "$ROOT_DIR/android"
if [ -z "${JAVA_HOME:-}" ] || [[ "$("${JAVA_HOME}/bin/java" -version 2>&1)" =~ "1.8." ]]; then
    if [ -d "/opt/homebrew/opt/openjdk@17" ]; then
        export JAVA_HOME="/opt/homebrew/opt/openjdk@17"
    elif [ -d "/usr/local/opt/openjdk@17" ]; then
        export JAVA_HOME="/usr/local/opt/openjdk@17"
    fi
fi
./gradlew assembleDebug --no-daemon
APK_SRC="$ROOT_DIR/android/app/build/outputs/apk/debug/app-debug.apk"
APK_DEST="$RELEASE_DIR/AirDrop-P2P-v${VERSION}.apk"
cp -f "$APK_SRC" "$APK_DEST"
echo "  -> Created: $APK_DEST ($(du -h "$APK_DEST" | cut -f1))"

# 2. Build macOS Application Bundle
echo "[2/4] Building macOS Application..."
cd "$ROOT_DIR"
"$ROOT_DIR/macos/build.sh"

# 3. Create macOS DMG Package
echo "[3/4] Creating macOS DMG installer..."
DMG_DEST="$RELEASE_DIR/AirDrop-P2P-v${VERSION}.dmg"
DMG_TMP="$(mktemp -d /tmp/airdrop_dmg_XXXXXX)"
cp -R "$ROOT_DIR/AirDrop P2P.app" "$DMG_TMP/"
ln -s /Applications "$DMG_TMP/Applications"
rm -f "$DMG_DEST"
hdiutil create -volname "AirDrop P2P v${VERSION}" -srcfolder "$DMG_TMP" -ov -format UDZO "$DMG_DEST"
rm -rf "$DMG_TMP"
echo "  -> Created: $DMG_DEST ($(du -h "$DMG_DEST" | cut -f1))"

# 4. Generate SHA256 Checksums
echo "[4/4] Calculating SHA-256 Checksums..."
cd "$RELEASE_DIR"
shasum -a 256 "AirDrop-P2P-v${VERSION}.apk" "AirDrop-P2P-v${VERSION}.dmg" > "$RELEASE_DIR/SHA256SUMS.txt"
cat "$RELEASE_DIR/SHA256SUMS.txt"

echo "====================================================="
echo " Release v${VERSION} build complete in $RELEASE_DIR"
echo "====================================================="

