#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
APP_PATH="/Applications/AirDrop P2P.app"

echo "================================================="
echo " AirDrop P2P Launcher & Gatekeeper Unblock"
echo "================================================="

# If not installed in /Applications, copy it over if available in DMG
if [ ! -d "$APP_PATH" ] && [ -d "$DIR/AirDrop P2P.app" ]; then
    echo "[+] Installing AirDrop P2P to /Applications..."
    cp -R "$DIR/AirDrop P2P.app" /Applications/ 2>/dev/null || true
fi

# Clear quarantine on /Applications if present, else run directly
if [ -d "$APP_PATH" ]; then
    echo "[+] Clearing Gatekeeper quarantine attribute on $APP_PATH..."
    xattr -cr "$APP_PATH" 2>/dev/null || true
    echo "[+] Launching AirDrop P2P from /Applications..."
    open "$APP_PATH"
elif [ -d "$DIR/AirDrop P2P.app" ]; then
    echo "[+] Clearing Gatekeeper quarantine attribute on $DIR/AirDrop P2P.app..."
    xattr -cr "$DIR/AirDrop P2P.app" 2>/dev/null || true
    echo "[+] Launching AirDrop P2P..."
    open "$DIR/AirDrop P2P.app"
else
    echo "[-] Error: AirDrop P2P.app not found. Please drag it to Applications first."
    exit 1
fi

echo "[+] Done! AirDrop P2P is now running in your menu bar."

