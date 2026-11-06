#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = REPO_ROOT / "VERSION"
RELEASE_DIR = REPO_ROOT / "release"

if not VERSION_FILE.exists():
    sys.exit("[-] VERSION file not found")

VERSION = VERSION_FILE.read_text(encoding="utf-8").strip()
TAG = f"v{VERSION}"
OWNER = "jakharamit44"
REPO = "airdrop-p2p"

print(f"[+] Publishing GitHub Release {TAG} for {OWNER}/{REPO}...")

# 1. Get OAuth / PAT Token from git credential-osxkeychain
p = subprocess.Popen(["git", "credential-osxkeychain", "get"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
out, _ = p.communicate("protocol=https\nhost=github.com\n\n")
token = ""
for line in out.splitlines():
    if line.startswith("password="):
        token = line.split("=", 1)[1].strip()

if not token:
    sys.exit("[-] Failed to retrieve GitHub token from keychain")

headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "AirDrop-Release-Script",
}

# 2. Check if release already exists or create new release
get_req = urllib.request.Request(f"https://api.github.com/repos/{OWNER}/{REPO}/releases/tags/{TAG}", headers=headers)
release_id = None
upload_url = None

try:
    with urllib.request.urlopen(get_req) as resp:
        rel_data = json.loads(resp.read().decode("utf-8"))
        release_id = rel_data.get("id")
        upload_url = rel_data.get("upload_url", "").partition("{")[0]
        html_url = rel_data.get("html_url")
        print(f"[+] Found existing release {TAG} (ID: {release_id}): {html_url}")
except urllib.error.HTTPError as e:
    if e.code == 404:
        # Create Release
        release_notes = f"""# AirDrop P2P v{VERSION}

Pure peer-to-peer AirDrop between macOS and all modern Android devices.

### What's New in v{VERSION}
- **Universal Android Support**: Dynamic manufacturer and model discovery across Samsung, Google Pixel, OnePlus, Xiaomi, and other modern Android devices.
- **100% Pure P2P Engine**: High-speed transfers strictly negotiate direct 5GHz Wi-Fi Direct Autonomous Groups (WP2P) and Bluetooth LE L2CAP. Zero shared Wi-Fi router / LAN dependency.
- **ARP Connection Keepalive**: Real-time bidirectional ARP refresh (2.0s ICMP & UDP keepalive pulses) preventing Linux kernel ARP table timeouts during multi-gigabyte transfers.
- **Clean macOS Wi-Fi Restoration**: Automatic disassociation and preferred network pruning returning macOS Wi-Fi to Internet connectivity upon transfer completion.
- **Claude AI Ingestion Engine**: Integrated multimodal Vision OCR, document, code, and PDF summarization generating companion `.claude.md` analysis directly into `~/Downloads`.

### Release Assets
- `AirDrop-P2P-v{VERSION}.apk`: Universal Android application (API 29+).
- `AirDrop-P2P-v{VERSION}.dmg`: macOS standalone drag-and-drop application (macOS 13.0+ Ventura, Sonoma, Sequoia).
- `SHA256SUMS.txt`: Cryptographic checksums.
"""
        create_payload = json.dumps({
            "tag_name": TAG,
            "target_commitish": "main",
            "name": f"AirDrop P2P v{VERSION}",
            "body": release_notes,
            "draft": False,
            "prerelease": False
        }).encode("utf-8")

        post_req = urllib.request.Request(
            f"https://api.github.com/repos/{OWNER}/{REPO}/releases",
            data=create_payload,
            headers={**headers, "Content-Type": "application/json"}
        )
        with urllib.request.urlopen(post_req) as resp:
            rel_data = json.loads(resp.read().decode("utf-8"))
            release_id = rel_data.get("id")
            upload_url = rel_data.get("upload_url", "").partition("{")[0]
            html_url = rel_data.get("html_url")
            print(f"[+] Created release {TAG} (ID: {release_id}): {html_url}")
    else:
        sys.exit(f"[-] HTTP error getting release: {e}")

# 3. List existing assets to avoid duplicate upload error
list_assets_req = urllib.request.Request(f"https://api.github.com/repos/{OWNER}/{REPO}/releases/{release_id}/assets", headers=headers)
existing_assets = {}
with urllib.request.urlopen(list_assets_req) as resp:
    assets_data = json.loads(resp.read().decode("utf-8"))
    for a in assets_data:
        existing_assets[a["name"]] = a["id"]

# 4. Upload assets
assets_to_upload = [
    (RELEASE_DIR / f"AirDrop-P2P-v{VERSION}.apk", "application/vnd.android.package-archive"),
    (RELEASE_DIR / f"AirDrop-P2P-v{VERSION}.dmg", "application/x-apple-diskimage"),
    (RELEASE_DIR / "SHA256SUMS.txt", "text/plain"),
]

for asset_path, ctype in assets_to_upload:
    if not asset_path.exists():
        print(f"[-] Warning: {asset_path} does not exist, skipping")
        continue

    asset_name = asset_path.name
    if asset_name in existing_assets:
        print(f"[*] Deleting previous asset {asset_name} (ID: {existing_assets[asset_name]})...")
        del_req = urllib.request.Request(
            f"https://api.github.com/repos/{OWNER}/{REPO}/releases/assets/{existing_assets[asset_name]}",
            headers=headers,
            method="DELETE"
        )
        urllib.request.urlopen(del_req)

    print(f"[+] Uploading {asset_name} ({asset_path.stat().st_size:,} bytes)...")
    with open(asset_path, "rb") as f:
        data = f.read()

    upload_endpoint = f"{upload_url}?name={asset_name}"
    up_req = urllib.request.Request(
        upload_endpoint,
        data=data,
        headers={
            **headers,
            "Content-Type": ctype,
            "Content-Length": str(len(data))
        }
    )
    with urllib.request.urlopen(up_req) as up_resp:
        result = json.loads(up_resp.read().decode("utf-8"))
        print(f"[+] Successfully uploaded {asset_name}: {result.get('browser_download_url')}")

print(f"\n=======================================================")
print(f" Release {TAG} published successfully!")
print(f" URL: https://github.com/{OWNER}/{REPO}/releases/tag/{TAG}")
print(f"=======================================================")

