#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
APP_PATH="/Applications/GlideDrop.app"

echo "================================================="
echo " GlideDrop Launcher & Gatekeeper Unblock"
echo "================================================="

# If not installed in /Applications, copy it over if available in DMG
if [ ! -d "$APP_PATH" ] && [ -d "$DIR/GlideDrop.app" ]; then
    echo "[+] Installing GlideDrop to /Applications..."
    cp -R "$DIR/GlideDrop.app" /Applications/ 2>/dev/null || true
fi

# Clear quarantine on /Applications if present, else run directly
if [ -d "$APP_PATH" ]; then
    echo "[+] Clearing Gatekeeper quarantine attribute on $APP_PATH..."
    xattr -cr "$APP_PATH" 2>/dev/null || true
    echo "[+] Launching GlideDrop from /Applications..."
    open "$APP_PATH"
elif [ -d "$DIR/GlideDrop.app" ]; then
    echo "[+] Clearing Gatekeeper quarantine attribute on $DIR/GlideDrop.app..."
    xattr -cr "$DIR/GlideDrop.app" 2>/dev/null || true
    echo "[+] Launching GlideDrop..."
    open "$DIR/GlideDrop.app"
else
    echo "[-] Error: GlideDrop.app not found. Please drag it to Applications first."
    exit 1
fi

echo "[+] Done! GlideDrop is now running in your menu bar."

