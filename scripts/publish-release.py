#!/usr/bin/env python3
import json
import os
import re
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

def load_version_changelog(version: str) -> str:
    changelog_path = REPO_ROOT / "CHANGELOG.md"
    if not changelog_path.exists():
        return ""
    text = changelog_path.read_text(encoding="utf-8")
    pattern = rf"##\s*\[?v?{re.escape(version)}\]?[^\n]*\n\n?(.*?)(?=(?:\n##\s*\[)|\Z)"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return ""

def generate_release_body(version: str) -> str:
    notes = load_version_changelog(version)
    if not notes:
        try:
            prev_tag = subprocess.check_output(["git", "describe", "--tags", "--abbrev=0", "HEAD^"], text=True).strip()
            log_out = subprocess.check_output(["git", "log", f"{prev_tag}..HEAD", "--oneline"], text=True).strip()
            notes = "### Commits\n" + "\n".join(f"- {line}" for line in log_out.splitlines())
        except Exception:
            notes = f"Release v{version}"

    body = f"""# AirDrop P2P v{version}

Pure peer-to-peer AirDrop between macOS and all modern Android devices.

{notes}

### Release Assets
- `AirDrop-P2P-v{version}.apk`: Universal Android application (API 29+).
- `AirDrop-P2P-v{version}.pkg`: macOS Native Installer package (installs directly to /Applications and auto-unquarantines; eliminates Gatekeeper "damaged" alert).
- `AirDrop-P2P-v{version}.dmg`: macOS drag-and-drop application with built-in Gatekeeper launcher.
- `SHA256SUMS.txt`: Cryptographic checksums.
"""
    return body

print(f"[+] Publishing GitHub Release {TAG} for {OWNER}/{REPO}...")

# 1. Get OAuth / PAT Token from environment or git credential-osxkeychain
token = os.environ.get("GITHUB_TOKEN", "").strip() or os.environ.get("GH_TOKEN", "").strip()
if not token:
    try:
        p = subprocess.Popen(["git", "credential-osxkeychain", "get"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        out, _ = p.communicate("protocol=https\nhost=github.com\n\n")
        for line in out.splitlines():
            if line.startswith("password="):
                token = line.split("=", 1)[1].strip()
    except Exception:
        pass

if not token:
    sys.exit("[-] Failed to retrieve GitHub token from environment (GITHUB_TOKEN/GH_TOKEN) or osxkeychain")

headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "AirDrop-Release-Script",
}

# 2. Check if release already exists or create new release
get_req = urllib.request.Request(f"https://api.github.com/repos/{OWNER}/{REPO}/releases/tags/{TAG}", headers=headers)
release_id = None
upload_url = None
release_notes = generate_release_body(VERSION)

try:
    with urllib.request.urlopen(get_req) as resp:
        rel_data = json.loads(resp.read().decode("utf-8"))
        release_id = rel_data.get("id")
        upload_url = rel_data.get("upload_url", "").partition("{")[0]
        html_url = rel_data.get("html_url")
        print(f"[+] Found existing release {TAG} (ID: {release_id}): {html_url}")
        # Update release body with authentic CHANGELOG.md notes
        patch_payload = json.dumps({
            "name": f"AirDrop P2P v{VERSION}",
            "body": release_notes,
        }).encode("utf-8")
        patch_req = urllib.request.Request(
            f"https://api.github.com/repos/{OWNER}/{REPO}/releases/{release_id}",
            data=patch_payload,
            headers={**headers, "Content-Type": "application/json"},
            method="PATCH"
        )
        try:
            with urllib.request.urlopen(patch_req) as pr:
                print(f"[+] Updated release {TAG} body with accurate notes from CHANGELOG.md")
        except Exception as pe:
            print(f"[-] Warning: Failed to update release body: {pe}")
except urllib.error.HTTPError as e:
    if e.code == 404:
        # Create Release
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
    (RELEASE_DIR / f"AirDrop-P2P-v{VERSION}.pkg", "application/octet-stream"),
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

