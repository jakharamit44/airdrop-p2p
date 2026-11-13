#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="$(cat "$ROOT_DIR/VERSION" 2>/dev/null || echo "2.0.0")"

echo "[+] Building GlideDrop macOS daemon (v${VERSION})..."
mkdir -p "$HOME/.glidedrop"
xcrun swiftc -O "$SCRIPT_DIR/glidedrop-daemon.swift" -o "$HOME/.glidedrop/glidedrop-daemon"

APP_DIR="$ROOT_DIR/GlideDrop.app"
APP_MACOS="$APP_DIR/Contents/MacOS"
APP_RES="$APP_DIR/Contents/Resources"
mkdir -p "$APP_MACOS" "$APP_RES"

cp -f "$HOME/.glidedrop/glidedrop-daemon" "$APP_MACOS/GlideDrop"
cp -f "$SCRIPT_DIR/glidedrop.sh" "$APP_RES/glidedrop.sh"
cp -f "$SCRIPT_DIR/claude_processor.py" "$APP_RES/claude_processor.py"
cp -f "$SCRIPT_DIR/glidedrop.sh" "$HOME/.glidedrop/glidedrop.sh"
cp -f "$SCRIPT_DIR/claude_processor.py" "$HOME/.glidedrop/claude_processor.py"
if [ ! -f "$SCRIPT_DIR/AppIcon.icns" ]; then
  echo "[+] Generating AppIcon.icns..."
  swift "$SCRIPT_DIR/generate-icon.swift" "$SCRIPT_DIR/AppIcon.icns"
fi
if [ -f "$SCRIPT_DIR/AppIcon.icns" ]; then
  cp -f "$SCRIPT_DIR/AppIcon.icns" "$APP_RES/AppIcon.icns"
  cp -f "$SCRIPT_DIR/AppIcon.icns" "$HOME/.glidedrop/AppIcon.icns"
fi
chmod +x "$APP_RES/glidedrop.sh" "$APP_RES/claude_processor.py" "$HOME/.glidedrop/glidedrop.sh" "$HOME/.glidedrop/claude_processor.py"

cat > "$APP_DIR/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>GlideDrop</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundleIdentifier</key>
  <string>io.github.jakharamit44.glidedrop.mac</string>
  <key>CFBundleName</key>
  <string>GlideDrop</string>
  <key>CFBundleDisplayName</key>
  <string>GlideDrop</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${VERSION}</string>
  <key>CFBundleVersion</key>
  <string>${VERSION}</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSBluetoothAlwaysUsageDescription</key>
  <string>GlideDrop uses Bluetooth LE L2CAP to discover and transfer files with Android devices.</string>
  <key>NSLocationUsageDescription</key>
  <string>GlideDrop needs Location access so macOS lets it see Wi-Fi network names when joining a nearby phone's Wi-Fi Direct group and returning to your home Wi-Fi. Your location is never read or stored.</string>
  <key>NSLocationWhenInUseUsageDescription</key>
  <string>GlideDrop needs Location access so macOS lets it see Wi-Fi network names when joining a nearby phone's Wi-Fi Direct group and returning to your home Wi-Fi. Your location is never read or stored.</string>
  <key>NSLocalNetworkUsageDescription</key>
  <string>GlideDrop requires local network access to discover nearby devices and transfer files over high-speed Wi-Fi Direct and local sockets.</string>
</dict>
</plist>
PLIST

# Strip extended attributes and seal bundle with deep code signature
echo "[+] Sealing and signing GlideDrop.app bundle..."
xattr -cr "$APP_DIR"
codesign --force --deep --sign - "$APP_DIR"
codesign --verify --deep --strict "$APP_DIR"

if [ -w "/Applications" ] || [ -w "/Applications/GlideDrop.app" ]; then
  echo "[+] Updating /Applications/GlideDrop.app..."
  rm -rf "/Applications/GlideDrop.app"
  cp -R "$APP_DIR" "/Applications/GlideDrop.app"
  xattr -cr "/Applications/GlideDrop.app"
  codesign --force --deep --sign - "/Applications/GlideDrop.app"
fi

echo "[+] GlideDrop.app bundle created at: $APP_DIR"

