#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="$(cat "$ROOT_DIR/VERSION" 2>/dev/null || echo "2.0.0")"

echo "[+] Building AirDrop P2P macOS daemon (v${VERSION})..."
mkdir -p "$HOME/.airdrop-p2p"
xcrun swiftc -O "$SCRIPT_DIR/mac-ble-airdrop.swift" -o "$HOME/.airdrop-p2p/airdrop-p2p-daemon"

APP_DIR="$ROOT_DIR/AirDrop P2P.app"
APP_MACOS="$APP_DIR/Contents/MacOS"
APP_RES="$APP_DIR/Contents/Resources"
mkdir -p "$APP_MACOS" "$APP_RES"

cp -f "$HOME/.airdrop-p2p/airdrop-p2p-daemon" "$APP_MACOS/AirDropP2P"
cp -f "$SCRIPT_DIR/mac-airdrop-p2p.sh" "$APP_RES/mac-airdrop-p2p.sh"
cp -f "$SCRIPT_DIR/claude_processor.py" "$APP_RES/claude_processor.py"
if [ -f "$SCRIPT_DIR/AppIcon.icns" ]; then
  cp -f "$SCRIPT_DIR/AppIcon.icns" "$APP_RES/AppIcon.icns"
fi
chmod +x "$APP_RES/mac-airdrop-p2p.sh" "$APP_RES/claude_processor.py"

cat > "$APP_DIR/Contents/Info.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>AirDropP2P</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundleIdentifier</key>
  <string>com.airdrop.p2p.mac</string>
  <key>CFBundleName</key>
  <string>AirDrop P2P</string>
  <key>CFBundleDisplayName</key>
  <string>AirDrop P2P</string>
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
  <string>AirDrop P2P uses Bluetooth LE L2CAP to discover and transfer files with Android devices.</string>
</dict>
</plist>
PLIST

# Strip extended attributes and seal bundle with deep code signature
echo "[+] Sealing and signing AirDrop P2P.app bundle..."
xattr -cr "$APP_DIR"
codesign --force --deep --sign - "$APP_DIR"
codesign --verify --deep --strict "$APP_DIR"

echo "[+] AirDrop P2P.app bundle created at: $APP_DIR"

