#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="$(cat "$ROOT_DIR/VERSION" 2>/dev/null || echo "2.0.0")"
RELEASE_DIR="$ROOT_DIR/release"

echo "====================================================="
echo " Building GlideDrop Release v${VERSION}"
echo "====================================================="

mkdir -p "$RELEASE_DIR"

# 1. Build Android APK
echo "[1/4] Building Android APK..."
if [ -n "${GLIDEDROP_KEYSTORE_PATH:-}" ]; then
    if [ ! -f "$GLIDEDROP_KEYSTORE_PATH" ] && [ -f "$ROOT_DIR/$GLIDEDROP_KEYSTORE_PATH" ]; then
        GLIDEDROP_KEYSTORE_PATH="$ROOT_DIR/$GLIDEDROP_KEYSTORE_PATH"
    fi
    if [ -f "$GLIDEDROP_KEYSTORE_PATH" ]; then
        export GLIDEDROP_KEYSTORE_PATH="$(cd "$(dirname "$GLIDEDROP_KEYSTORE_PATH")" && pwd)/$(basename "$GLIDEDROP_KEYSTORE_PATH")"
    fi
fi
cd "$ROOT_DIR/android"
if [ -z "${JAVA_HOME:-}" ] || [[ "$("${JAVA_HOME}/bin/java" -version 2>&1)" =~ "1.8." ]]; then
    if [ -d "/Applications/Android Studio.app/Contents/jbr/Contents/Home" ]; then
        export JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home"
    elif [ -d "/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home" ]; then
        export JAVA_HOME="/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home"
    elif [ -d "/opt/homebrew/opt/openjdk@17" ]; then
        export JAVA_HOME="/opt/homebrew/opt/openjdk@17"
    elif [ -d "/usr/local/opt/openjdk@17" ]; then
        export JAVA_HOME="/usr/local/opt/openjdk@17"
    fi
fi
if [ -n "${GLIDEDROP_KEYSTORE_PATH:-}" ] && [ -n "${GLIDEDROP_KEYSTORE_PASSWORD:-}" ] && [ -n "${GLIDEDROP_KEY_ALIAS:-}" ]; then
    if [ ! -f "$GLIDEDROP_KEYSTORE_PATH" ]; then
        echo "[-] ERROR: GLIDEDROP_KEYSTORE_PATH does not exist: $GLIDEDROP_KEYSTORE_PATH" >&2
        exit 1
    fi
    echo "  -> Building signed non-debuggable release APK..."
    ./gradlew assembleRelease --no-daemon
    APK_SRC="$ROOT_DIR/android/app/build/outputs/apk/release/app-release.apk"
    if [ ! -f "$APK_SRC" ]; then
        echo "[-] ERROR: Expected signed release APK not found at $APK_SRC" >&2
        exit 1
    fi
elif [ "${GLIDEDROP_REQUIRE_RELEASE_SIGNING:-0}" = "1" ]; then
    echo "[-] ERROR: GLIDEDROP_REQUIRE_RELEASE_SIGNING=1 but GLIDEDROP_KEYSTORE_PATH / GLIDEDROP_KEYSTORE_PASSWORD / GLIDEDROP_KEY_ALIAS are not set." >&2
    exit 1
else
    echo "  -> [WARN] Release signing env vars not set; falling back to debug APK (set GLIDEDROP_KEYSTORE_PATH, GLIDEDROP_KEYSTORE_PASSWORD, GLIDEDROP_KEY_ALIAS for signed release)."
    ./gradlew assembleDebug --no-daemon
    APK_SRC="$ROOT_DIR/android/app/build/outputs/apk/debug/app-debug.apk"
fi
APK_DEST="$RELEASE_DIR/GlideDrop-v${VERSION}.apk"
cp -f "$APK_SRC" "$APK_DEST"
echo "  -> Created: $APK_DEST ($(du -h "$APK_DEST" | cut -f1))"

# 2. Build macOS Application Bundle
echo "[2/4] Building macOS Application..."
cd "$ROOT_DIR"
"$ROOT_DIR/macos/build.sh"

# 3. Create macOS DMG Package
echo "[3/4] Creating macOS DMG installer..."
DMG_DEST="$RELEASE_DIR/GlideDrop-v${VERSION}.dmg"
DMG_TMP="$(mktemp -d /tmp/glidedrop_dmg_XXXXXX)"
cp -R "$ROOT_DIR/GlideDrop.app" "$DMG_TMP/"
ln -s /Applications "$DMG_TMP/Applications"
if [ -f "$ROOT_DIR/macos/open-app.command" ]; then
  cp -f "$ROOT_DIR/macos/open-app.command" "$DMG_TMP/Open GlideDrop (Bypass Gatekeeper).command"
  chmod +x "$DMG_TMP/Open GlideDrop (Bypass Gatekeeper).command"
fi

# Set custom volume icon
if [ -f "$ROOT_DIR/macos/AppIcon.icns" ]; then
  cp -f "$ROOT_DIR/macos/AppIcon.icns" "$DMG_TMP/.VolumeIcon.icns"
  if command -v SetFile >/dev/null 2>&1; then
    SetFile -a C "$DMG_TMP" 2>/dev/null || true
  fi
fi

# Provide first-time user guidance for Gatekeeper bypass
cat > "$DMG_TMP/READ ME - HOW TO OPEN.txt" << EOF
===========================================================
  GlideDrop v${VERSION} - Installation & First Launch Guide
===========================================================

1. INSTALLATION:
   Drag "GlideDrop.app" into the "Applications" folder.

2. FIRST TIME OPENING (macOS Gatekeeper):
   If macOS shows:
   "GlideDrop.app is damaged and can't be opened"
   This is macOS Gatekeeper blocking unsigned open-source apps downloaded via Safari.

   To open it instantly:
   Option A (Easiest):
   Double-click: "Open GlideDrop (Bypass Gatekeeper).command"

   Option B (Terminal):
   Open Terminal and paste:
   xattr -cr "/Applications/GlideDrop.app"

   Option C (System Settings):
   Go to System Settings -> Privacy & Security, scroll down and click "Open Anyway".

3. Once opened, GlideDrop will live in your menu bar and radar window!
===========================================================
EOF

xattr -cr "$DMG_TMP"
rm -f "$DMG_DEST"
hdiutil create -volname "GlideDrop v${VERSION}" -srcfolder "$DMG_TMP" -ov -format UDZO "$DMG_DEST"
rm -rf "$DMG_TMP"
echo "  -> Created: $DMG_DEST ($(du -h "$DMG_DEST" | cut -f1))"

# 3b. Create macOS Native PKG installer (auto-unquarantines during install)
PKG_DEST="$RELEASE_DIR/GlideDrop-v${VERSION}.pkg"
if command -v pkgbuild >/dev/null 2>&1; then
  echo "[+] Creating macOS PKG installer..."
  PKG_SCRIPTS="$(mktemp -d /tmp/glidedrop_pkg_scripts_XXXXXX)"
  cat > "$PKG_SCRIPTS/postinstall" << 'EOF'
#!/bin/bash
xattr -cr "/Applications/GlideDrop.app" 2>/dev/null || true
exit 0
EOF
  chmod +x "$PKG_SCRIPTS/postinstall"
  pkgbuild --component "$ROOT_DIR/GlideDrop.app" \
           --install-location "/Applications" \
           --scripts "$PKG_SCRIPTS" \
           "$PKG_DEST"
  rm -rf "$PKG_SCRIPTS"
  echo "  -> Created: $PKG_DEST ($(du -h "$PKG_DEST" | cut -f1))"
fi

# 4. Generate SHA256 Checksums
echo "[4/4] Calculating SHA-256 Checksums..."
cd "$RELEASE_DIR"
FILES_TO_SUM=("GlideDrop-v${VERSION}.apk" "GlideDrop-v${VERSION}.dmg")
if [ -f "$PKG_DEST" ]; then
  FILES_TO_SUM+=("GlideDrop-v${VERSION}.pkg")
fi
shasum -a 256 "${FILES_TO_SUM[@]}" > "$RELEASE_DIR/SHA256SUMS.txt"
cat "$RELEASE_DIR/SHA256SUMS.txt"

echo "====================================================="
echo " Release v${VERSION} build complete in $RELEASE_DIR"
echo "====================================================="

