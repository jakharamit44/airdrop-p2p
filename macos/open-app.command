#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
APP_PATH="/Applications/AirDrop P2P.app"
if [ ! -d "$APP_PATH" ]; then
    APP_PATH="$DIR/AirDrop P2P.app"
fi

echo "================================================="
echo " AirDrop P2P Launcher & Gatekeeper Unblock"
echo "================================================="
echo "[+] Clearing Gatekeeper quarantine attribute..."
xattr -cr "$APP_PATH" 2>/dev/null || true
echo "[+] Launching AirDrop P2P..."
open "$APP_PATH"
echo "[+] Done! AirDrop P2P is running."
