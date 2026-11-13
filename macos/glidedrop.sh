#!/usr/bin/env bash
set -euo pipefail

# Pure P2P GlideDrop Receiver & Daemon for macOS <-> Android
# Speaks BLE L2CAP + 5GHz Wi-Fi Direct WP2P + internal AWDL proxy + TLS 1.2/1.3
# /Discover, /Ask, /Upload with bplist00 and DVZip 070707/070701 CPIO streaming archives).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${GLIDEDROP_STATE_DIR:-$HOME/.glidedrop}"
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR" 2>/dev/null || true

PID_FILE="$STATE_DIR/daemon.pid"
AWDL_MDNS_PID_FILE="$STATE_DIR/awdl-mdns.pid"
BLE_PID_FILE="$STATE_DIR/ble-daemon.pid"
LOG_FILE="$STATE_DIR/daemon.log"
BLE_LOG_FILE="$STATE_DIR/ble-daemon.log"
if [[ -x "/Applications/GlideDrop.app/Contents/MacOS/GlideDrop" ]]; then
  BLE_BIN="/Applications/GlideDrop.app/Contents/MacOS/GlideDrop"
elif [[ -x "$SCRIPT_DIR/GlideDrop.app/Contents/MacOS/GlideDrop" ]]; then
  BLE_BIN="$SCRIPT_DIR/GlideDrop.app/Contents/MacOS/GlideDrop"
else
  BLE_BIN="$STATE_DIR/glidedrop-daemon"
fi
# Ports are always OS-assigned (bind to 0); the bound values are published via port files
# in $STATE_DIR and exchanged in the handshake. No compiled-in port exists.
PORT=0
PROXY_PORT=0

ensure_cert() {
  if [[ ! -f "$STATE_DIR/cert.pem" || ! -f "$STATE_DIR/key.pem" ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout "$STATE_DIR/key.pem" -out "$STATE_DIR/cert.pem" \
      -days 3650 -nodes -subj "/CN=glidedrop" >/dev/null 2>&1
  fi
}

ensure_ble_bin() {
  if [[ -f "$SCRIPT_DIR/glidedrop-daemon.swift" ]] && [[ ! -x "$BLE_BIN" || "$SCRIPT_DIR/glidedrop-daemon.swift" -nt "$BLE_BIN" ]]; then
    xcrun swiftc -O "$SCRIPT_DIR/glidedrop-daemon.swift" -o "$BLE_BIN" >/dev/null 2>&1 || true
    APP_MACOS="$SCRIPT_DIR/GlideDrop.app/Contents/MacOS"
    APP_RES="$SCRIPT_DIR/GlideDrop.app/Contents/Resources"
    mkdir -p "$APP_MACOS" "$APP_RES"
    cp -f "$BLE_BIN" "$APP_MACOS/GlideDrop" 2>/dev/null || true
    cp -f "$SCRIPT_DIR/glidedrop.sh" "$APP_RES/glidedrop.sh" 2>/dev/null || true
    if [[ -f "$SCRIPT_DIR/AppIcon.icns" ]]; then
      cp -f "$SCRIPT_DIR/AppIcon.icns" "$APP_RES/AppIcon.icns" 2>/dev/null || true
    fi
    chmod +x "$APP_RES/glidedrop.sh" 2>/dev/null || true
    APP_VER="$(cat "$SCRIPT_DIR/../VERSION" 2>/dev/null || echo "2.6.0")"
    cat > "$SCRIPT_DIR/GlideDrop.app/Contents/Info.plist" << PLIST
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
  <string>${APP_VER}</string>
  <key>CFBundleVersion</key>
  <string>${APP_VER}</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSBluetoothAlwaysUsageDescription</key>
  <string>GlideDrop uses Bluetooth LE L2CAP to discover and transfer files with Android devices.</string>
  <key>NSLocalNetworkUsageDescription</key>
  <string>GlideDrop requires local network access to discover nearby devices and transfer files over high-speed Wi-Fi Direct and local sockets.</string>
</dict>
</plist>
PLIST
  fi
}

snapshot_macos_defaults() {
  local snap_file="$STATE_DIR/prev_defaults.json"
  if [[ -f "$snap_file" ]]; then
    return 0
  fi
  python3 - "$snap_file" << 'PYDEF' >/dev/null 2>&1 || true
import json, subprocess, sys
from pathlib import Path

snap_path = Path(sys.argv[1])
targets = [
    ("com.apple.NetworkBrowser", "BrowseAllInterfaces"),
    ("com.apple.Sharing", "BrowseAllInterfaces"),
    ("com.apple.Sharing", "DisableAWDL"),
]
snapshot = {}
for domain, key in targets:
    res = subprocess.run(["defaults", "read", domain, key], capture_output=True, text=True)
    entry_key = f"{domain}:{key}"
    if res.returncode == 0:
        snapshot[entry_key] = {"present": True, "raw": res.stdout.strip()}
    else:
        snapshot[entry_key] = {"present": False}
tmp = snap_path.with_name(f"{snap_path.name}.tmp")
tmp.write_text(json.dumps(snapshot), encoding="utf-8")
tmp.replace(snap_path)
PYDEF
}

restore_macos_defaults() {
  local snap_file="$STATE_DIR/prev_defaults.json"
  if [[ -f "$snap_file" ]]; then
    python3 - "$snap_file" << 'PYDEF' >/dev/null 2>&1 || true
import json, subprocess, sys
from pathlib import Path

snap_path = Path(sys.argv[1])
try:
    snapshot = json.loads(snap_path.read_text(encoding="utf-8"))
except Exception:
    snapshot = {}
targets = [
    ("com.apple.NetworkBrowser", "BrowseAllInterfaces"),
    ("com.apple.Sharing", "BrowseAllInterfaces"),
    ("com.apple.Sharing", "DisableAWDL"),
]
for domain, key in targets:
    info = snapshot.get(f"{domain}:{key}", {})
    if isinstance(info, dict) and info.get("present"):
        raw = str(info.get("raw") or "").strip().lower()
        if raw in ("1", "true", "yes"):
            subprocess.run(["defaults", "write", domain, key, "-bool", "true"], check=False)
        elif raw in ("0", "false", "no"):
            subprocess.run(["defaults", "write", domain, key, "-bool", "false"], check=False)
        else:
            subprocess.run(["defaults", "write", domain, key, str(info.get("raw") or "")], check=False)
    else:
        subprocess.run(["defaults", "delete", domain, key], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
snap_path.unlink(missing_ok=True)
PYDEF
  fi
}

stop_http_daemons() {
  for pf in "$PID_FILE" "$AWDL_MDNS_PID_FILE"; do
    if [[ -f "$pf" ]]; then
      local _p
      _p="$(cat "$pf" 2>/dev/null || true)"
      if [[ -n "$_p" ]]; then
        kill "$_p" 2>/dev/null || true
      fi
      rm -f "$pf"
    fi
  done
  rm -f "$STATE_DIR/mac_rx_port" "$STATE_DIR/finder_proxy_port" "$STATE_DIR/finder_proxy.sock" "$STATE_DIR/finder_proxy_sock" 2>/dev/null || true
}

stop_daemons() {
  stop_http_daemons
  local ble_pid=""
  if [[ -f "$BLE_PID_FILE" ]]; then
    ble_pid="$(cat "$BLE_PID_FILE" 2>/dev/null || true)"
    if [[ -n "$ble_pid" ]]; then
      kill "$ble_pid" 2>/dev/null || true
    fi
    rm -f "$BLE_PID_FILE"
  fi
  pkill -x "glidedrop-daemon" 2>/dev/null || true
  pkill -x "GlideDrop" 2>/dev/null || true
  local _wait=0
  while [[ $_wait -lt 30 ]]; do
    if [[ -n "$ble_pid" ]] && kill -0 "$ble_pid" 2>/dev/null; then
      sleep 0.1
      _wait=$((_wait + 1))
      continue
    fi
    if pgrep -x "GlideDrop" >/dev/null 2>&1 || pgrep -x "glidedrop-daemon" >/dev/null 2>&1; then
      sleep 0.1
      _wait=$((_wait + 1))
      continue
    fi
    break
  done
  rm -f "$STATE_DIR/tx_in_progress.lock" "$STATE_DIR/rx_in_progress.lock" "$STATE_DIR/transfer_progress.json" "$STATE_DIR/cancel_transfer.flag" "$STATE_DIR/lan_fallback_active.flag" "$STATE_DIR/pending_ask.json" "$STATE_DIR/wp2p_authorized_session.json" "$STATE_DIR/p2p_session_token.json" "$STATE_DIR/p2p_outgoing_token.json" "$STATE_DIR/active_p2p_session.json" "$STATE_DIR/awdl_bridge_port" "$STATE_DIR/pinned_peer_tls_fingerprint.txt" 2>/dev/null || true
}

start_daemons() {
  if [[ "${SKIP_BLE_RESTART:-0}" == "1" ]]; then
    stop_http_daemons
  else
    stop_daemons
    rm -f "$STATE_DIR/active_peers.json" "$STATE_DIR/p2p_status"
  fi
  ensure_cert
  ensure_ble_bin

  snapshot_macos_defaults
  defaults write com.apple.NetworkBrowser BrowseAllInterfaces -bool true
  defaults write com.apple.Sharing BrowseAllInterfaces -bool true
  defaults delete com.apple.Sharing DisableAWDL 2>/dev/null || true

  # Pure P2P Mode: Do NOT advertise on shared LAN router mDNS (_airdrop._tcp.local. without interface restriction).
  # Discovery is strictly over Direct Bluetooth LE L2CAP + 5GHz Wi-Fi Direct P2P (and local awdl0 for Finder integration).

  # Start Direct Bluetooth LE L2CAP receiver only if GlideDrop app is not already running
  if [[ "${SKIP_BLE_RESTART:-0}" != "1" ]] && ! pgrep -f "GlideDrop.app" >/dev/null 2>&1 && ! pgrep -x "GlideDrop" >/dev/null 2>&1; then
    if [[ ! -f "$BLE_PID_FILE" ]] || ! kill -0 "$(cat "$BLE_PID_FILE")" 2>/dev/null; then
      if [[ -x "$BLE_BIN" ]]; then
        nohup "$BLE_BIN" daemon >"$BLE_LOG_FILE" 2>&1 < /dev/null &
        echo $! >"$BLE_PID_FILE"
      fi
    fi
  fi

  # Start HTTPS receiver + Finder Share Android proxy (OS-assigned ports)
  nohup python3 -u - "$STATE_DIR/cert.pem" "$STATE_DIR/key.pem" "$PORT" "$PROXY_PORT" "$SCRIPT_DIR/glidedrop.sh" >"$LOG_FILE" 2>&1 << 'PYEOF' &
import gzip, hmac, io, ipaddress, json, os, plistlib, queue, re, select, shutil, socket, ssl, struct, subprocess, sys, tempfile, threading, time, uuid, zlib
from pathlib import Path

CERT_FILE, KEY_FILE, PORT, PROXY_PORT, SCRIPT_PATH = (
    sys.argv[1],
    sys.argv[2],
    int(sys.argv[3]),
    int(sys.argv[4]),
    sys.argv[5],
)
STATE_DIR = Path(CERT_FILE).parent

_CACHED_WIFI_IFACE = None

def get_wifi_interface() -> str:
    global _CACHED_WIFI_IFACE
    if _CACHED_WIFI_IFACE:
        return _CACHED_WIFI_IFACE
    try:
        out = subprocess.check_output(["/usr/sbin/networksetup", "-listallhardwareports"], text=True, stderr=subprocess.DEVNULL)
        lines = out.splitlines()
        is_wifi = False
        for line in lines:
            line_str = line.strip()
            if line_str.startswith("Hardware Port:"):
                port = line_str.split(":", 1)[1].strip().lower()
                is_wifi = ("wi-fi" in port or "wifi" in port or "airport" in port or "wlan" in port)
            elif is_wifi and line_str.startswith("Device:"):
                dev = line_str.split(":", 1)[1].strip()
                if dev:
                    _CACHED_WIFI_IFACE = dev
                    return dev
    except Exception:
        pass
    return "en0"

CLAUDE_QUEUE = queue.Queue(maxsize=128)

def _claude_processor_worker():
    while True:
        try:
            item = CLAUDE_QUEUE.get()
            if item is None:
                break
            claude_script, target_path = item
            proc = None
            try:
                proc = subprocess.Popen([sys.executable, str(claude_script), str(target_path)],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                proc.wait(timeout=120)
            except subprocess.TimeoutExpired:
                if proc:
                    try:
                        proc.kill()
                        proc.wait(timeout=5)
                    except Exception:
                        pass
            except Exception:
                pass
            finally:
                CLAUDE_QUEUE.task_done()
        except Exception:
            pass

for _ in range(2):
    threading.Thread(target=_claude_processor_worker, daemon=True).start()

def enqueue_claude_processing(file_path: Path):
    try:
        candidates = [
            Path(SCRIPT_PATH).resolve().parent / "claude_processor.py",
            Path(SCRIPT_PATH).resolve().parent.parent / "macos" / "claude_processor.py",
            STATE_DIR / "claude_processor.py",
        ]
        claude_py = next((p for p in candidates if p.exists()), None)
        if claude_py:
            try:
                CLAUDE_QUEUE.put_nowait((claude_py, file_path))
            except queue.Full:
                print(f"[-] Claude processor queue full; skipping background processing for {file_path.name}")
    except Exception:
        pass
DOWNLOADS = Path.home() / "Downloads"
try:
    DEFAULT_MAC_NAME = subprocess.check_output(["scutil", "--get", "ComputerName"], text=True).strip() or "MacBook Pro"
except Exception:
    DEFAULT_MAC_NAME = socket.gethostname().split(".")[0] or "MacBook Pro"
MEDIA_CAP = b'{"Version":3,"Codecs":{"hvc1":{"Profiles":{"VTIsHDRAllowedOnDevice":true}}}}'

def load_settings():
    sf = STATE_DIR / "settings.json"
    if sf.exists():
        try:
            return json.loads(sf.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"autoAccept": False, "visible": True, "deviceName": DEFAULT_MAC_NAME}

def current_mac_name():
    return load_settings().get("deviceName") or DEFAULT_MAC_NAME

def write_progress(active: bool, direction: str = "", file_name: str = "", done_bytes: int = 0, total_bytes: int = 0, speed_bps: int = 0, eta_sec: int = 0, pct: int = 0, file_count: int = 1, phase: str = "", peer_name: str = "", is_connecting: bool = False):
    pf = STATE_DIR / "transfer_progress.json"
    tmp = STATE_DIR / "transfer_progress.json.tmp"
    try:
        if not active:
            if pf.exists():
                pf.unlink()
            return
        payload = {
            "active": True,
            "direction": direction,
            "fileName": file_name,
            "fileCount": file_count,
            "doneBytes": int(done_bytes),
            "totalBytes": int(total_bytes),
            "speedBps": int(speed_bps),
            "etaSeconds": int(eta_sec),
            "percent": int(pct),
            "phase": phase,
            "peerName": peer_name,
            "isConnecting": bool(is_connecting),
            "updatedAt": time.time(),
        }
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(pf)
    except Exception:
        pass

def append_history(kind: str, path_or_url: str, size_bytes: int, direction: str, peer_name: str):
    rx_log = STATE_DIR / "received.log"
    try:
        with rx_log.open("a", encoding="utf-8") as lf:
            lf.write(f"{int(time.time())}\t{kind}\t{path_or_url}\t{int(size_bytes)}\t{direction}\t{peer_name}\n")
    except Exception:
        pass

PEERS_LOCK = threading.Lock()

def record_active_peer(peer_id: str, name: str, transport: str, address: str, rssi: int = -52, psm: int = 0):
    pf = STATE_DIR / "active_peers.json"
    tmp = STATE_DIR / f"active_peers.json.tmp.{threading.get_ident()}"
    now = time.time()
    with PEERS_LOCK:
        try:
            peers = json.loads(pf.read_text(encoding="utf-8")) if pf.exists() else {}
            if not isinstance(peers, dict):
                peers = {}
        except Exception:
            peers = {}
        pruned = {}
        for k, v in peers.items():
            if not isinstance(v, dict):
                continue
            try:
                if (now - float(v.get("lastSeen") or 0.0)) <= 30.0:
                    pruned[str(k)] = v
            except Exception:
                continue
        prev = pruned.get(peer_id)
        if isinstance(prev, dict) and int(prev.get("psm") or 0) > 0 and psm == 0:
            psm = int(prev.get("psm") or 0)
            address = str(prev.get("address") or address)
            rssi = int(prev.get("rssi") or rssi)
            transport = f"5GHz P2P • BLE PSM {psm}"
        pruned[peer_id] = {
            "id": peer_id,
            "name": name,
            "transport": transport,
            "address": address,
            "psm": int(psm),
            "rssi": int(rssi),
            "lastSeen": now,
        }
        if len(pruned) > 16:
            ordered = sorted(pruned.items(), key=lambda kv: float(kv[1].get("lastSeen") or 0.0), reverse=True)[:16]
            pruned = dict(ordered)
        try:
            tmp.write_text(json.dumps(pruned), encoding="utf-8")
            tmp.replace(pf)
        except Exception:
            pass

def get_active_peers(max_age: float = 10.0) -> list:
    pf = STATE_DIR / "active_peers.json"
    now = time.time()
    try:
        if not pf.exists():
            return []
        peers = json.loads(pf.read_text(encoding="utf-8"))
        if not isinstance(peers, dict):
            return []
        return [v for v in peers.values() if isinstance(v, dict) and (now - float(v.get("lastSeen", 0))) <= max_age]
    except Exception:
        return []

def safe_notify(message: str, title: str):
    try:
        subprocess.Popen([
            "osascript",
            "-e", "on run argv",
            "-e", 'display notification (item 1 of argv) with title (item 2 of argv) sound name "Glass"',
            "-e", "end run",
            "--",
            str(message)[:240],
            str(title)[:120],
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def _is_tls_peer_closed(conn) -> bool:
    if conn is None:
        return False
    try:
        r, _, _ = select.select([conn], [], [], 0.0)
        if not r:
            return False
        prev_timeout = conn.gettimeout()
        try:
            conn.settimeout(0.05)
            chunk = conn.recv(1)
            return chunk == b""
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            return False
        except (ssl.SSLEOFError, BrokenPipeError, ConnectionResetError, ConnectionAbortedError, EOFError, OSError):
            return True
        finally:
            try:
                conn.settimeout(prev_timeout)
            except Exception:
                pass
    except (ValueError, OSError):
        return True

def _is_local_rx_cancelled() -> bool:
    flag = STATE_DIR / "cancel_transfer.flag"
    if not flag.exists():
        return False
    try:
        ts = float(flag.read_text(encoding="utf-8").strip())
        return (time.time() - ts) < 10.0
    except Exception:
        try:
            return (time.time() - flag.stat().st_mtime) < 10.0
        except Exception:
            return False

CONSENT_LOCK = threading.Lock()

def wait_for_user_accept(sender_name: str, file_names: list, total_bytes: int, conn=None, session_token="", peer_ip="") -> bool:
    with CONSENT_LOCK:
        return _wait_for_user_accept(sender_name, file_names, total_bytes, conn, session_token, peer_ip)

def _wait_for_user_accept(sender_name: str, file_names: list, total_bytes: int, conn=None, session_token="", peer_ip="") -> bool:
    s = load_settings()
    if s.get("autoAccept", False):
        return True
    auth_session_file = STATE_DIR / "wp2p_authorized_session.json"
    if auth_session_file.exists():
        try:
            auth_data = json.loads(auth_session_file.read_text(encoding="utf-8"))
            auth_time = float(auth_data.get("authorizedAt", 0))
            session = load_active_p2p_session()
            bound_token = str(auth_data.get("token") or "").strip().lower()
            if (0 <= time.time() - auth_time < 60.0 and session
                    and re.fullmatch(r"[0-9a-f]{64}", session_token)
                    and hmac.compare_digest(bound_token, session_token)
                    and auth_data.get("senderName") == sender_name
                    and auth_data.get("peerIp") == peer_ip == session["gatewayIp"]
                    and auth_data.get("ssid") == session["ssid"]):
                print(f"[P2P-Receiver] Reusing session-bound WP2P approval for {sender_name}")
                auth_session_file.unlink(missing_ok=True)
                return True
        except Exception:
            pass
    req_id = str(uuid.uuid4())
    ask_file = STATE_DIR / "pending_ask.json"
    dec_file = STATE_DIR / "ask_decision.json"
    try:
        if dec_file.exists():
            dec_file.unlink()
        ask_file.write_text(json.dumps({
            "id": req_id,
            "senderName": sender_name,
            "fileNames": file_names,
            "totalBytes": int(total_bytes),
            "timestamp": time.time(),
        }), encoding="utf-8")

        summary = f"{len(file_names)} file(s)" if len(file_names) > 1 else (file_names[0] if file_names else "items")
        def prompt_dialog():
            time.sleep(0.5)
            if dec_file.exists():
                return
            # If GlideDrop GUI is running, it renders the modal inside the window.
            # Do NOT prompt with osascript to prevent double accept prompts.
            try:
                out = subprocess.check_output(["pgrep", "-x", "GlideDrop"], text=True)
                if out.strip():
                    return
            except Exception:
                pass
            try:
                res = subprocess.check_output([
                    "osascript",
                    "-e", "on run argv",
                    "-e", 'tell application "System Events" to display dialog ((item 1 of argv) & " wants to share " & (item 2 of argv) & " with you.") with title "GlideDrop" buttons {"Decline", "Accept"} default button "Accept" giving up after 40',
                    "-e", "end run",
                    "--",
                    str(sender_name)[:80],
                    str(summary)[:120]
                ], text=True, stderr=subprocess.DEVNULL).strip()
                if "button returned:Accept" in res:
                    dec_file.write_text(json.dumps({"id": req_id, "accepted": True}), encoding="utf-8")
                elif "button returned:Decline" in res:
                    dec_file.write_text(json.dumps({"id": req_id, "accepted": False}), encoding="utf-8")
            except Exception:
                pass
        threading.Thread(target=prompt_dialog, daemon=True).start()

        t_start = time.time()
        while time.time() - t_start < 45.0:
            if _is_local_rx_cancelled():
                print(f"[P2P-Receiver] Cancelled transfer prompt from {sender_name}")
                return False
            if _is_tls_peer_closed(conn):
                print(f"[P2P-Receiver] Sender {sender_name} cancelled /Ask before acceptance")
                return False
            if dec_file.exists():
                try:
                    d = json.loads(dec_file.read_text(encoding="utf-8"))
                    if d.get("id") == req_id:
                        return bool(d.get("accepted", False))
                except Exception:
                    pass
            time.sleep(0.15)
    finally:
        try:
            if ask_file.exists():
                ask_file.unlink()
        except Exception:
            pass
    return False

MAX_HTTP_LINE_BYTES = 8192
MAX_HTTP_HEADER_LINES = 64
MAX_HTTP_HEADER_BYTES = 16384
MAX_NON_UPLOAD_BODY_BYTES = 1048576
DEFAULT_MAX_DECOMPRESSED_BYTES = 2_000_000_000
MIN_DISK_FREE_HEADROOM_BYTES = 10_000_000


class HttpFramingError(ValueError):
    def __init__(self, status_code: int, reason: str, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.reason = reason


def read_line(f, max_len: int = MAX_HTTP_LINE_BYTES):
    line = f.readline(max_len + 1)
    if not line:
        return None
    if len(line) > max_len:
        raise HttpFramingError(431, "Request Header Fields Too Large", f"HTTP line exceeded {max_len} bytes")
    if line.endswith(b"\r\n"):
        stripped = line[:-2]
    elif line.endswith(b"\n"):
        stripped = line[:-1]
    else:
        stripped = line
    if b"\r" in stripped or b"\x00" in stripped or any((b < 0x20 and b != 0x09) for b in stripped):
        raise HttpFramingError(400, "Bad Request", "Malformed control character in HTTP line")
    return stripped.decode("iso-8859-1")


def parse_non_negative_int(raw: str, field_name: str) -> int:
    clean = str(raw or "").strip()
    if not re.fullmatch(r"[0-9]+", clean):
        raise HttpFramingError(400, "Bad Request", f"Invalid {field_name} header")
    return int(clean)


def parse_http_request_head(f, max_lines: int = MAX_HTTP_HEADER_LINES, max_bytes: int = MAX_HTTP_HEADER_BYTES):
    req_line = read_line(f)
    if not req_line:
        return None
    total_bytes = len(req_line) + 2
    if total_bytes > max_bytes:
        raise HttpFramingError(431, "Request Header Fields Too Large", "HTTP request line exceeded header byte limit")
    parts = [p for p in req_line.split(" ") if p]
    if len(parts) not in (2, 3) or not re.fullmatch(r"[A-Z]+", parts[0]) or not parts[1].startswith("/"):
        raise HttpFramingError(400, "Bad Request", "Malformed HTTP request line")
    method, path = parts[0], parts[1]

    headers = {}
    hdr_lines = 0
    while True:
        l = read_line(f)
        if l is None:
            raise HttpFramingError(400, "Bad Request", "Truncated HTTP headers")
        if l == "":
            break
        hdr_lines += 1
        total_bytes += len(l) + 2
        if hdr_lines > max_lines or total_bytes > max_bytes:
            raise HttpFramingError(431, "Request Header Fields Too Large", "HTTP headers exceeded limit")
        colon = l.find(":")
        if colon <= 0:
            raise HttpFramingError(400, "Bad Request", "Malformed HTTP header line")
        raw_name = l[:colon]
        if not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", raw_name):
            raise HttpFramingError(400, "Bad Request", "Invalid HTTP header name")
        name = raw_name.lower()
        val = l[colon + 1:].strip()
        if name == "content-length":
            if "content-length" in headers:
                raise HttpFramingError(400, "Bad Request", "Duplicate Content-Length header")
            parse_non_negative_int(val, "Content-Length")
        elif name == "totalbytes":
            parse_non_negative_int(val, "TotalBytes")
        headers[name] = val

    if "content-length" in headers and "transfer-encoding" in headers:
        raise HttpFramingError(400, "Bad Request", "Conflicting Content-Length and Transfer-Encoding headers")
    if "transfer-encoding" in headers and headers["transfer-encoding"].lower() != "chunked":
        raise HttpFramingError(400, "Bad Request", "Unsupported Transfer-Encoding")
    return method, path, headers


def read_http_trailers(f):
    total = 0
    for count in range(MAX_HTTP_HEADER_LINES + 1):
        line = read_line(f)
        if line is None:
            raise EOFError("Missing chunked body terminator")
        total += len(line) + 2
        if total > MAX_HTTP_HEADER_BYTES:
            raise ValueError("HTTP trailers exceed limit")
        if line == "":
            return
        if count == MAX_HTTP_HEADER_LINES or ":" not in line:
            raise ValueError("Malformed or excessive HTTP trailers")
    raise ValueError("Too many HTTP trailers")


def parse_chunk_size_line(line: str) -> int:
    raw_hex = str(line or "").split(";", 1)[0].strip()
    if not re.fullmatch(r"[0-9a-fA-F]+", raw_hex):
        raise ValueError(f"Invalid chunk size line: {line!r}")
    sz = int(raw_hex, 16)
    if sz < 0:
        raise ValueError(f"Negative chunk size: {sz}")
    return sz

def load_active_p2p_session(max_age: float = 1800.0):
    sf = STATE_DIR / "active_p2p_session.json"
    try:
        if not sf.exists():
            return None
        obj = json.loads(sf.read_text(encoding="utf-8"))
        if not isinstance(obj, dict):
            return None
        updated = float(obj.get("updatedAt") or 0.0)
        if not 0 <= time.time() - updated <= max_age:
            return None
        # Swift writes this only after OS-confirmed DIRECT-* association/subnet discovery.
        iface = str(obj.get("interface") or obj.get("interfaceName") or "")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,31}", iface):
            return None
        if not str(obj.get("ssid") or "").startswith("DIRECT-"):
            return None
        net = ipaddress.ip_network(str(obj.get("cidr") or ""), strict=False)
        gateway = ipaddress.ip_address(str(obj.get("gatewayIp") or ""))
        if (net.prefixlen == 0 or gateway not in net or gateway.is_loopback
                or gateway.is_unspecified or gateway.is_multicast or gateway.is_link_local):
            return None
        if not 1 <= int(obj.get("httpsPort") or 0) <= 65535:
            return None
        obj["interface"] = iface
        return obj
    except Exception:
        return None


def validate_peer_route(host: str, port: int):
    session = load_active_p2p_session()
    if not session:
        raise ValueError("No OS-confirmed Wi-Fi Direct session")
    addr = ipaddress.ip_address(str(host).split("%", 1)[0])
    if addr != ipaddress.ip_address(session["gatewayIp"]) or port != int(session["httpsPort"]):
        raise ValueError("Peer endpoint does not match the active Wi-Fi Direct session")
    family = "-inet6" if addr.version == 6 else "-inet"
    route = subprocess.check_output(["/sbin/route", "-n", "get", family, str(addr)], text=True, timeout=3.0)
    match = re.search(r"^\s*interface:\s*(\S+)\s*$", route, re.MULTILINE)
    if not match or match.group(1) != session["interface"]:
        raise ValueError("Peer route is not on the confirmed Wi-Fi Direct interface")
    return session


def get_active_p2p_networks():
    nets = []
    session = load_active_p2p_session()
    if session:
        raw_cidr = str(session.get("cidr") or "").strip()
        if raw_cidr:
            try:
                net = ipaddress.ip_network(raw_cidr, strict=False)
                if net.prefixlen > 0 and net not in nets:
                    nets.append(net)
            except Exception:
                pass
    return nets

def is_active_p2p_peer_ip(peer_ip: str) -> bool:
    clean = str(peer_ip or "").split("%", 1)[0].strip()
    try:
        addr = ipaddress.ip_address(clean)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return any(addr.version == net.version and addr in net for net in get_active_p2p_networks())

def get_active_p2p_https_port() -> int:
    """Peer HTTPS port from the OS-confirmed session; 0 when the session carries none (no fallback)."""
    session = load_active_p2p_session()
    if session:
        try:
            p = int(session.get("httpsPort") or 0)
            if 1 <= p <= 65535:
                return p
        except Exception:
            pass
    return 0

def active_p2p_endpoint(peer_ip: str) -> str:
    port = get_active_p2p_https_port()
    return format_peer_endpoint(peer_ip, port) if port else ""

def format_peer_endpoint(host: str, port: int) -> str:
    clean = str(host or "").strip()
    if ":" in clean and not clean.startswith("["):
        return f"[{clean}]:{port}"
    return f"{clean}:{port}"

def is_transfer_cancelled() -> bool:
    cf = STATE_DIR / "cancel_transfer.flag"
    if not cf.exists():
        return False
    try:
        ts = float(cf.read_text(encoding="utf-8").strip())
        return (time.time() - ts) < 10.0
    except FileNotFoundError:
        return False
    except Exception:
        try:
            return (time.time() - cf.stat().st_mtime) < 10.0
        except FileNotFoundError:
            return False
        except Exception:
            return True


def read_body_bytes(
    f,
    headers,
    track_progress: bool = False,
    file_label: str = "Incoming File",
    expected_total: int = 0,
    file_count: int = 1,
    max_bytes: int = MAX_NON_UPLOAD_BODY_BYTES,
):
    t0 = time.time()
    last_emit = 0.0
    if "chunked" in headers.get("transfer-encoding", "").lower():
        out = bytearray()
        while True:
            if track_progress and is_transfer_cancelled():
                write_progress(False)
                raise RuntimeError("Transfer cancelled by user")
            sz_line = read_line(f)
            if sz_line is None:
                raise ValueError("Truncated chunked body")
            sz = parse_chunk_size_line(sz_line)
            if sz == 0:
                read_http_trailers(f)
                break
            if max_bytes is not None and (len(out) + sz) > max_bytes:
                raise HttpFramingError(413, "Payload Too Large", f"Request body exceeds {max_bytes} byte limit")
            rem = sz
            while rem > 0:
                if track_progress and is_transfer_cancelled():
                    write_progress(False)
                    raise RuntimeError("Transfer cancelled by user")
                step = min(65536, rem)
                chunk = f.read(step)
                if not chunk:
                    raise ValueError("Truncated chunk payload")
                out.extend(chunk)
                rem -= len(chunk)
                if track_progress:
                    now = time.time()
                    if now - last_emit >= 0.08:
                        last_emit = now
                        done = len(out)
                        tot = max(expected_total, done, 1)
                        el = max(0.08, now - t0)
                        spd = int(done / el)
                        eta = int(max(0, tot - done) / max(1, spd))
                        pct = min(99, int((done * 100) / tot))
                        write_progress(True, "Receiving", file_label, done, tot, spd, eta, pct, file_count)
            crlf = bytearray()
            while len(crlf) < 2:
                part = f.read(2 - len(crlf))
                if not part:
                    break
                crlf.extend(part)
            if bytes(crlf) != b"\r\n":
                raise ValueError("Missing CRLF terminator after chunk")
        if track_progress:
            write_progress(False)
        return bytes(out)
    clen = parse_non_negative_int(headers["content-length"], "Content-Length") if "content-length" in headers else 0
    if max_bytes is not None and clen > max_bytes:
        raise HttpFramingError(413, "Payload Too Large", f"Content-Length {clen} exceeds {max_bytes} byte limit")
    if clen <= 0:
        return b""
    out = bytearray()
    rem = clen
    while rem > 0:
        if track_progress and is_transfer_cancelled():
            write_progress(False)
            raise RuntimeError("Transfer cancelled by user")
        step = min(65536, rem)
        chunk = f.read(step)
        if not chunk:
            break
        out.extend(chunk)
        rem -= len(chunk)
        if track_progress:
            now = time.time()
            if now - last_emit >= 0.08:
                last_emit = now
                done = len(out)
                tot = max(expected_total, clen, 1)
                el = max(0.08, now - t0)
                spd = int(done / el)
                eta = int(max(0, tot - done) / max(1, spd))
                pct = min(99, int((done * 100) / tot))
                write_progress(True, "Receiving", file_label, done, tot, spd, eta, pct, file_count)
    if track_progress:
        write_progress(False)
    return bytes(out)

class ChunkedReader:
    def __init__(self, f, on_bytes=None):
        self.f = f
        self.on_bytes = on_bytes
        self.chunk_rem = 0
        self.eof = False
        self.last_cancel_check = 0.0

    def read(self, n):
        if n <= 0:
            return b""
        if self.eof:
            return b""
        while self.chunk_rem == 0:
            now = time.time()
            if now - self.last_cancel_check >= 0.1:
                self.last_cancel_check = now
                if is_transfer_cancelled():
                    write_progress(False)
                    raise RuntimeError("Transfer cancelled by user")
            line = read_line(self.f)
            if line is None:
                raise ValueError("Truncated chunked stream")
            sz = parse_chunk_size_line(line)
            if sz == 0:
                read_http_trailers(self.f)
                self.eof = True
                return b""
            self.chunk_rem = sz

        want = min(n, self.chunk_rem)
        chunk = self.f.read(want)
        if not chunk:
            raise ValueError("Truncated chunk payload")
        self.chunk_rem -= len(chunk)
        if self.chunk_rem == 0:
            crlf_buf = bytearray()
            while len(crlf_buf) < 2:
                part = self.f.read(2 - len(crlf_buf))
                if not part:
                    break
                crlf_buf.extend(part)
            if bytes(crlf_buf) != b"\r\n":
                raise ValueError("Missing CRLF terminator after HTTP chunk")
        if self.on_bytes:
            self.on_bytes(len(chunk))
        return chunk

    def read_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            part = self.read(n - len(buf))
            if not part:
                break
            buf.extend(part)
        return bytes(buf)


class FixedLengthReader:
    def __init__(self, f, total, on_bytes=None):
        self.f = f
        self.rem = total
        self.on_bytes = on_bytes
        self.last_cancel_check = 0.0

    def read(self, n):
        if self.rem <= 0:
            return b""
        now = time.time()
        if now - self.last_cancel_check >= 0.1:
            self.last_cancel_check = now
            if is_transfer_cancelled():
                write_progress(False)
                raise RuntimeError("Transfer cancelled by user")
        want = min(n, self.rem)
        chunk = self.f.read(want)
        if not chunk:
            raise EOFError("Truncated fixed-length HTTP body")
        self.rem -= len(chunk)
        if self.on_bytes:
            self.on_bytes(len(chunk))
        return chunk

    def read_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            part = self.read(n - len(buf))
            if not part:
                break
            buf.extend(part)
        return bytes(buf)


class StreamDecompressor:
    def __init__(self, raw_reader, max_decompressed_bytes: int = DEFAULT_MAX_DECOMPRESSED_BYTES):
        self.raw = raw_reader
        self.max_decompressed_bytes = int(max_decompressed_bytes)
        self.total_decompressed = 0
        self.buf = bytearray()
        self.mode = "unknown"
        self.decompressor = None
        self.dvzip_stored = False
        self.dvzip_rem = 0
        self.eof = False
        self._init_stream()

    def _account_decompressed(self, count: int):
        self.total_decompressed += count
        if self.total_decompressed > self.max_decompressed_bytes:
            raise ValueError(f"Decompressed stream exceeded limit ({self.total_decompressed} > {self.max_decompressed_bytes})")

    def _append_decompressed(self, data: bytes):
        if not data:
            return
        self._account_decompressed(len(data))
        self.buf.extend(data)

    def _decompress_bounded(self, decomp, chunk: bytes):
        if not chunk:
            return
        remaining = self.max_decompressed_bytes - self.total_decompressed
        step_cap = min(1048576, max(1, remaining + 1))
        out = decomp.decompress(chunk, max_length=step_cap)
        self._append_decompressed(out)
        while decomp.unconsumed_tail:
            remaining = self.max_decompressed_bytes - self.total_decompressed
            step_cap = min(1048576, max(1, remaining + 1))
            out = decomp.decompress(decomp.unconsumed_tail, max_length=step_cap)
            if not out and not decomp.unconsumed_tail:
                break
            self._append_decompressed(out)
            if not out and decomp.unconsumed_tail:
                break

    def _flush_bounded(self, decomp):
        if decomp is None:
            return
        if not decomp.eof or decomp.unused_data:
            raise ValueError("Incomplete compressed stream or trailing compressed data")
        remaining = self.max_decompressed_bytes - self.total_decompressed
        step_cap = min(1048576, max(1, remaining + 1))
        out = decomp.flush(step_cap)
        self._append_decompressed(out)

    def _init_stream(self):
        # Four bytes identify DVZip without stealing bytes from a one-byte first block.
        prefix = self.raw.read_exact(4)
        if len(prefix) < 4:
            self._append_decompressed(prefix)
            self.mode = "raw"
            return
        if len(prefix) >= 2 and prefix[0] == 0x1F and prefix[1] == 0x8B:
            self.mode = "gzip"
            self.decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            self._decompress_bounded(self.decompressor, prefix)
        elif prefix == b"0707":
            self.mode = "raw"
            self._append_decompressed(prefix)
        else:
            self.mode = "dvzip"
            v = struct.unpack(">I", prefix[:4])[0]
            self.dvzip_stored = bool(v & 0x80000000)
            self.dvzip_rem = v & 0x7FFFFFFF
            if not self.dvzip_stored:
                self.decompressor = zlib.decompressobj()
            if v == 0:
                self.eof = True

    def read(self, n):
        if n <= 0:
            return b""
        # Zero-copy fast path for stored DVZip blocks (eliminates intermediate self.buf copies & memmoves)
        if self.mode == "dvzip" and not self.buf and not self.eof:
            if self.dvzip_rem == 0:
                hdr4 = self.raw.read_exact(4)
                if len(hdr4) < 4:
                    if hdr4:
                        raise EOFError("Truncated DVZip block header")
                    if self.decompressor:
                        self._flush_bounded(self.decompressor)
                        self.decompressor = None
                    self.eof = True
                else:
                    v = struct.unpack(">I", hdr4)[0]
                    if v == 0:
                        if self.decompressor:
                            self._flush_bounded(self.decompressor)
                            self.decompressor = None
                        self.eof = True
                    else:
                        self.dvzip_stored = bool(v & 0x80000000)
                        self.dvzip_rem = v & 0x7FFFFFFF
                        self.decompressor = None if self.dvzip_stored else zlib.decompressobj()
            if not self.eof and self.dvzip_stored and self.dvzip_rem > 0:
                want = min(n, self.dvzip_rem)
                chunk = self.raw.read(want)
                if not chunk:
                    raise EOFError("Truncated stored DVZip block")
                self._account_decompressed(len(chunk))
                self.dvzip_rem -= len(chunk)
                return chunk

        while len(self.buf) < n and not self.eof:
            if self.mode == "raw":
                chunk = self.raw.read(max(262144, n - len(self.buf)))
                if not chunk:
                    self.eof = True
                    break
                self._append_decompressed(chunk)
            elif self.mode == "gzip":
                chunk = self.raw.read(262144)
                if not chunk:
                    if self.decompressor:
                        self._flush_bounded(self.decompressor)
                    self.eof = True
                    break
                self._decompress_bounded(self.decompressor, chunk)
            elif self.mode == "dvzip":
                if self.dvzip_rem > 0:
                    want = min(1048576 if self.dvzip_stored else 65536, self.dvzip_rem)
                    chunk = self.raw.read(want) if self.dvzip_stored else self.raw.read_exact(want)
                    if not chunk:
                        raise EOFError("Truncated DVZip block")
                    self.dvzip_rem -= len(chunk)
                    if self.dvzip_stored:
                        self._append_decompressed(chunk)
                    else:
                        if self.decompressor is None:
                            self.decompressor = zlib.decompressobj()
                        self._decompress_bounded(self.decompressor, chunk)
                        if self.dvzip_rem == 0:
                            self._flush_bounded(self.decompressor)
                            self.decompressor = None
                else:
                    hdr4 = self.raw.read_exact(4)
                    if len(hdr4) < 4:
                        if hdr4:
                            raise EOFError("Truncated DVZip block header")
                        if self.decompressor:
                            self._flush_bounded(self.decompressor)
                            self.decompressor = None
                        self.eof = True
                        break
                    v = struct.unpack(">I", hdr4)[0]
                    if v == 0:
                        if self.decompressor:
                            self._flush_bounded(self.decompressor)
                            self.decompressor = None
                        self.eof = True
                        break
                    self.dvzip_stored = bool(v & 0x80000000)
                    self.dvzip_rem = v & 0x7FFFFFFF
                    self.decompressor = None if self.dvzip_stored else zlib.decompressobj()

        take = min(n, len(self.buf))
        out = bytes(self.buf[:take])
        if take == len(self.buf):
            self.buf.clear()
        else:
            del self.buf[:take]
        return out

    def read_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            part = self.read(n - len(buf))
            if not part:
                break
            buf.extend(part)
        return bytes(buf)


def publish_noclobber(staged: Path, target: Path):
    stem, suffix = target.stem, target.suffix
    idx = 0
    while True:
        candidate = target if idx == 0 else target.with_name(f"{stem}_{idx}{suffix}")
        try:
            os.link(staged, candidate, follow_symlinks=False)
            staged.unlink()
            return candidate
        except FileExistsError:
            idx += 1


def extract_cpio_stream(stream, dest_dir: Path, fsync_files: bool = True, approved_manifest=None):
    if dest_dir.is_symlink():
        raise ValueError("Destination directory must not be a symlink")
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest_dir.resolve()
    saved = []
    remaining_manifest = list(approved_manifest) if approved_manifest is not None else None
    while True:
        magic = stream.read_exact(6)
        if len(magic) == 0:
            raise EOFError("Missing CPIO trailer")
        if len(magic) < 6:
            raise EOFError("Truncated CPIO magic")
        if magic == b"070707":
            rest = stream.read_exact(70)
            if len(rest) < 70:
                raise EOFError("Truncated 070707 CPIO header")
            hdr = (magic + rest).decode("ascii")
            mode = int(hdr[18:24], 8)
            namesize = int(hdr[59:65], 8)
            filesize = int(hdr[65:76], 8)
            is_newc = False
        elif magic in (b"070701", b"070702"):
            rest = stream.read_exact(104)
            if len(rest) < 104:
                raise EOFError("Truncated newc CPIO header")
            hdr = (magic + rest).decode("ascii")
            mode = int(hdr[14:22], 16)
            filesize = int(hdr[54:62], 16)
            namesize = int(hdr[94:102], 16)
            is_newc = True
        elif magic == b"070764":
            rest = stream.read_exact(96)
            if len(rest) < 96:
                raise EOFError("Truncated 070764 CPIO header")
            hdr = (magic + rest).decode("ascii")
            mode = int(hdr[22:30], 16)
            filesize = int(hdr[70:86], 16)
            namesize = int(hdr[86:94], 16)
            is_newc = False
        else:
            raise ValueError(f"Invalid CPIO magic: {magic!r}")
        if not (1 <= namesize <= 4097):
            raise ValueError(f"Invalid CPIO namesize: {namesize}")
        if filesize < 0:
            raise ValueError(f"Invalid CPIO filesize: {filesize}")
        name_raw = stream.read_exact(namesize)
        if len(name_raw) < namesize:
            raise EOFError("Truncated CPIO entry name")
        if not name_raw.endswith(b"\x00") or b"\x00" in name_raw[:-1]:
            raise ValueError("Invalid CPIO entry name terminator")
        name = name_raw[:-1].decode("utf-8", "strict")
        if is_newc and (110 + namesize) % 4 != 0:
            pad_len = 4 - ((110 + namesize) % 4)
            if len(stream.read_exact(pad_len)) < pad_len:
                raise EOFError("Truncated CPIO name padding")
        if name == "TRAILER!!!":
            if filesize:
                raise ValueError("Invalid CPIO trailer size")
            padding = 0
            while True:
                tail = stream.read(65536)
                if not tail:
                    break
                padding += len(tail)
                if padding > 1048576 or any(tail):
                    raise ValueError("Unexpected data after CPIO trailer")
            if remaining_manifest:
                raise ValueError("Upload is missing approved files")
            break
        if (mode & 0o170000) == 0o100000:
            raw_base = os.path.basename(name.replace("\\", "/"))
            if raw_base.startswith("._"):
                rem = filesize
                while rem > 0:
                    c = stream.read(min(262144, rem))
                    if not c:
                        break
                    rem -= len(c)
                if rem > 0:
                    raise IOError(f"Transfer stream truncated on metadata: expected {filesize} bytes, missing {rem} bytes")
            else:
                if remaining_manifest is not None:
                    item = (raw_base, filesize)
                    if item not in remaining_manifest:
                        raise ValueError("CPIO entry does not match approved file manifest")
                    remaining_manifest.remove(item)
                safe_name = raw_base.lstrip(".") or "glidedrop_file"
                target = dest_dir / safe_name
                if target.resolve().parent == dest_resolved:
                    free_bytes = shutil.disk_usage(dest_resolved).free
                    if free_bytes < filesize + MIN_DISK_FREE_HEADROOM_BYTES:
                        raise OSError(f"Insufficient disk space for {safe_name}: need {filesize + MIN_DISK_FREE_HEADROOM_BYTES}, free {free_bytes}")
                    idx = 1
                    orig_stem = target.stem
                    orig_suffix = target.suffix
                    while target.exists() or target.is_symlink():
                        target = dest_dir / f"{orig_stem}_{idx}{orig_suffix}"
                        idx += 1
                    part_target = target.with_name(target.name + ".part")
                    while part_target.exists() or part_target.is_symlink():
                        if part_target.is_symlink():
                            raise ValueError(f"Refusing symlink staging path: {part_target}")
                        target = dest_dir / f"{orig_stem}_{idx}{orig_suffix}"
                        part_target = target.with_name(target.name + ".part")
                        idx += 1
                    fd = None
                    try:
                        o_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                        fd = os.open(str(part_target), o_flags, 0o600)
                        with os.fdopen(fd, "wb", buffering=2097152) as out_f:
                            rem = filesize
                            while rem > 0:
                                c = stream.read(min(1048576, rem))
                                if not c:
                                    break
                                out_f.write(c)
                                rem -= len(c)
                            out_f.flush()
                            if fsync_files:
                                os.fsync(out_f.fileno())
                        if rem > 0:
                            part_target.unlink(missing_ok=True)
                            raise IOError(f"Transfer stream truncated: expected {filesize} bytes, missing {rem} bytes")
                        target = publish_noclobber(part_target, target)
                        try:
                            subprocess.run(["xattr", "-w", "com.apple.quarantine", "0081;00000000;GlideDrop;", str(target)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        except Exception:
                            pass
                        saved.append(target)
                    except Exception:
                        if fd is not None:
                            part_target.unlink(missing_ok=True)
                        raise
                else:
                    rem = filesize
                    while rem > 0:
                        c = stream.read(min(262144, rem))
                        if not c:
                            break
                        rem -= len(c)
                    if rem > 0:
                        raise IOError(f"Transfer stream truncated: expected {filesize} bytes, missing {rem} bytes")
        else:
            rem = filesize
            while rem > 0:
                c = stream.read(min(262144, rem))
                if not c:
                    break
                rem -= len(c)
            if rem > 0:
                raise IOError(f"Transfer stream truncated: expected {filesize} bytes, missing {rem} bytes")
        if is_newc and filesize % 4 != 0:
            data_pad = 4 - (filesize % 4)
            if len(stream.read_exact(data_pad)) < data_pad:
                raise EOFError("Truncated CPIO data padding")
    return saved


def stream_upload_to_dir(f, headers, dest_dir: Path, track_progress: bool = False, file_label: str = "Incoming File", expected_total: int = 0, file_count: int = 1, peer_name: str = "Android Peer", fsync_files: bool = True, approved_manifest=None):
    t0 = time.time()
    last_emit = [0.0]
    last_term_log = [0.0]
    last_touch = [0.0]
    done = [0]
    rx_lock = STATE_DIR / "rx_in_progress.lock"

    if track_progress:
        write_progress(True, "Receiving", file_label, 0, max(1, expected_total), 0, 0, 0, file_count, phase="Receiving files", peer_name=peer_name, is_connecting=False)

    def on_bytes_read(n):
        if is_transfer_cancelled():
            write_progress(False)
            try:
                rx_lock.unlink(missing_ok=True)
            except Exception:
                pass
            raise RuntimeError("Transfer cancelled by user")
        done[0] += n
        now = time.time()
        if now - last_touch[0] >= 1.0:
            last_touch[0] = now
            try:
                tmp_lock = STATE_DIR / f"rx_in_progress.lock.{threading.get_ident()}.tmp"
                tmp_lock.write_text(f"{os.getpid()}\tactive\t{now}")
                tmp_lock.replace(rx_lock)
            except Exception:
                pass
        if track_progress:
            if now - last_emit[0] >= 0.35:
                last_emit[0] = now
                tot = max(expected_total, done[0], 1)
                el = max(0.08, now - t0)
                spd = int(done[0] / el)
                eta = int(max(0, tot - done[0]) / max(1, spd))
                pct = min(99, int((done[0] * 100) / tot))
                write_progress(True, "Receiving", file_label, min(done[0], tot), tot, spd, eta, pct, file_count, phase="Receiving files", peer_name=peer_name, is_connecting=False)
                if now - last_term_log[0] >= 2.0 or done[0] >= tot:
                    last_term_log[0] = now
                    mb_done = done[0] / (1024 * 1024)
                    mb_tot = tot / (1024 * 1024)
                    spd_mb = spd / (1024 * 1024)
                    print(f"[P2P-Receiver] Receiving '{file_label}': {mb_done:.1f} MB / {mb_tot:.1f} MB ({pct}%, {spd_mb:.1f} MB/s, ETA {eta}s)")
                    sys.stdout.flush()

    try:
        is_chunked = "chunked" in headers.get("transfer-encoding", "").lower()
        clen = parse_non_negative_int(headers["content-length"], "Content-Length") if "content-length" in headers else 0
        if is_chunked:
            raw_reader = ChunkedReader(f, on_bytes=on_bytes_read)
        else:
            raw_reader = FixedLengthReader(f, clen, on_bytes=on_bytes_read)

        max_decomp = (expected_total + max(67_108_864, expected_total // 10)) if (expected_total > 0 or approved_manifest is not None) else DEFAULT_MAX_DECOMPRESSED_BYTES
        decompressor = StreamDecompressor(raw_reader, max_decompressed_bytes=max_decomp)
        if dest_dir.is_symlink():
            raise ValueError("Destination directory must not be a symlink")
        dest_dir.mkdir(parents=True, exist_ok=True)
        # Publish only after archive, compression integrity and HTTP framing all validate.
        with tempfile.TemporaryDirectory(prefix=".glidedrop-receive-", dir=dest_dir) as staging:
            staged = extract_cpio_stream(decompressor, Path(staging), fsync_files=fsync_files,
                                         approved_manifest=approved_manifest)
            if raw_reader.read(1):
                raise ValueError("Trailing data after compressed archive")
            saved = [publish_noclobber(p, dest_dir / p.name) for p in staged]
        if track_progress:
            write_progress(False)
        return saved, done[0]
    finally:
        if track_progress:
            write_progress(False)

FORWARD_LOCK = threading.Lock()
RECENT_UPLOADS_LOCK = threading.Lock()
RECENT_UPLOADS = {}
RECENT_UPLOADS_TTL = 60.0
RECENT_UPLOADS_MAX = 256

def check_and_record_recent_upload(sig, now: float = None) -> bool:
    if not sig:
        return False
    ts = time.time() if now is None else now
    with RECENT_UPLOADS_LOCK:
        expired = [k for k, v in RECENT_UPLOADS.items() if (ts - v) >= RECENT_UPLOADS_TTL]
        for k in expired:
            del RECENT_UPLOADS[k]
        if sig in RECENT_UPLOADS:
            return True
        while len(RECENT_UPLOADS) >= RECENT_UPLOADS_MAX:
            oldest_k = min(RECENT_UPLOADS, key=RECENT_UPLOADS.get)
            del RECENT_UPLOADS[oldest_k]
        RECENT_UPLOADS[sig] = ts
        return False

def is_valid_p2p_session_token(presented: str, now: float = None) -> bool:
    clean = str(presented or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", clean):
        return False
    token_file = STATE_DIR / "p2p_session_token.json"
    try:
        raw = token_file.read_text(encoding="utf-8")
        obj = json.loads(raw)
    except Exception:
        return False
    if not isinstance(obj, dict):
        return False
    ts = time.time() if now is None else now
    entries = obj.get("tokens")
    if isinstance(entries, list):
        matched = False
        for item in entries:
            if not isinstance(item, dict):
                continue
            tok = str(item.get("token") or "").strip().lower()
            try:
                exp = float(item.get("expires_at") or 0.0)
            except Exception:
                exp = 0.0
            if tok and exp > ts and hmac.compare_digest(clean, tok):
                matched = True
        return matched
    tok = str(obj.get("token") or "").strip().lower()
    try:
        exp = float(obj.get("expires_at") or 0.0)
    except Exception:
        exp = 0.0
    return bool(tok and exp > ts and hmac.compare_digest(clean, tok))

def forward_to_peer_worker(tmp_dir: Path, saved_files):
    with FORWARD_LOCK:
        try:
            if saved_files:
                cmd = [SCRIPT_PATH, "send"]
                session = load_active_p2p_session(max_age=300.0)
                pin_file = STATE_DIR / "pinned_peer_tls_fingerprint.txt"
                if session and pin_file.exists() and (time.time() - pin_file.stat().st_mtime) < 300.0:
                    gw = str(session.get("gatewayIp") or "").strip()
                    hp = int(session.get("httpsPort") or 0)
                    fp = pin_file.read_text(encoding="utf-8").strip().replace(":", "").replace("-", "").lower()
                    if gw and 1 <= hp <= 65535 and re.fullmatch(r"[0-9a-f]{64}", fp):
                        # Hand the pin to the child via a fresh one-time 0600 file (child deletes it); never argv.
                        pin_file.unlink(missing_ok=True)
                        fd = os.open(str(pin_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(fd, "w", encoding="utf-8") as pf:
                            pf.write(fp)
                        cmd.extend(["--peer", format_peer_endpoint(gw, hp)])
                result = subprocess.run(cmd + [str(p) for p in saved_files], check=False)
                if result.returncode == 0:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                    return True
            print(f"[-] Finder forwarding failed; recover files from {tmp_dir}")
            safe_notify(f"Android delivery failed. Files retained at {tmp_dir}", "GlideDrop delivery failed")
            return False
        except Exception as e:
            print(f"[-] Finder forwarding error: {e}; files retained at {tmp_dir}")
            return False

def send_resp(conn, status: int, reason: str, body: bytes = b"", close: bool = False):
    conn_hdr = "Connection: close\r\n" if close else ""
    hdr = f"HTTP/1.1 {status} {reason}\r\n{conn_hdr}Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    conn.sendall(hdr + body)

def build_url_prompt_osascript_argv(target_url: str, sender_name: str) -> list:
    return [
        "osascript",
        "-e", "on run argv",
        "-e", "set targetSender to item 1 of argv",
        "-e", "set targetUrl to item 2 of argv",
        "-e", 'set res to display alert "GlideDrop Link Received" message ("Link from " & targetSender & ":" & return & targetUrl & return & return & "(Copied to clipboard)") buttons {"Dismiss", "Open in Browser"} default button "Dismiss"',
        "-e", 'if button returned of res is "Open in Browser" then open location targetUrl',
        "-e", "end run",
        "--",
        str(sender_name)[:80],
        str(target_url)[:2048],
    ]


def handle_client(conn, addr, is_p2p_proxy: bool = False):
    last_sender = "Android Peer"
    last_label = "Incoming File"
    last_total = 0
    last_count = 1
    ask_approved = False
    approved_token = ""
    approved_manifest = None
    owns_rx_lock = False
    if isinstance(addr, tuple) and len(addr) >= 1:
        peer_ip = str(addr[0]).replace("::ffff:", "")
    else:
        peer_ip = "unix"
    rx_lock = STATE_DIR / "rx_in_progress.lock"
    upload_done_flag = STATE_DIR / "upload_completed.flag"

    def touch_rx_lock():
        nonlocal owns_rx_lock
        try:
            tmp_lock = STATE_DIR / f"rx_in_progress.lock.{threading.get_ident()}.tmp"
            tmp_lock.write_text(f"{os.getpid()}\t{peer_ip}\t{time.time()}")
            tmp_lock.replace(rx_lock)
            owns_rx_lock = True
        except Exception:
            pass

    try:
        conn.settimeout(30.0)
        f = conn.makefile("rb", buffering=1048576)
        while True:
            try:
                head = parse_http_request_head(f)
            except HttpFramingError as he:
                send_resp(conn, he.status_code, he.reason, b"", close=True)
                break
            if head is None:
                break
            method, path, headers = head
            if not is_p2p_proxy:
                if not is_valid_p2p_session_token(headers.get("x-glidedrop-token", "")):
                    print(f"[P2P-Receiver] Rejected unauthorized {method} {path} from {addr} (invalid or missing X-GlideDrop-Token)")
                    sys.stdout.flush()
                    send_resp(conn, 401, "Unauthorized", b"", close=True)
                    break
                touch_rx_lock()
            elif peer_ip not in ("127.0.0.1", "::1", "unix"):
                print(f"[Finder-Proxy] Rejected non-loopback connection from {addr}")
                sys.stdout.flush()
                send_resp(conn, 403, "Forbidden", b"", close=True)
                break
            is_upload = (method == "POST" and path == "/Upload")
            exp_tot = last_total
            if is_upload and "totalbytes" in headers:
                claimed_total = parse_non_negative_int(headers["totalbytes"], "TotalBytes")
                if claimed_total not in (last_total, max(1, last_total)):
                    send_resp(conn, 400, "Bad Request", b"", close=True)
                    break
            try:
                body = b"" if is_upload else read_body_bytes(
                    f,
                    headers,
                    track_progress=False,
                    file_label=last_label,
                    expected_total=exp_tot,
                    file_count=last_count,
                    max_bytes=MAX_NON_UPLOAD_BODY_BYTES,
                )
            except HttpFramingError as he:
                send_resp(conn, he.status_code, he.reason, b"", close=True)
                break
            except ValueError:
                send_resp(conn, 400, "Bad Request", b"", close=True)
                break
            role = "Finder-Proxy" if is_p2p_proxy else "P2P-Receiver"
            if not is_upload:
                print(f"[{role}] {method} {path} from {addr} ({len(body)} B)")
            else:
                tot_mb = exp_tot / (1024 * 1024)
                print(f"[{role}] {method} {path} from {addr} (streaming incoming file: '{last_label}', ~{tot_mb:.1f} MB)...")
            sys.stdout.flush()

            active_peer_name = (get_active_peers(12.0)[0].get("name") if get_active_peers(12.0) else "Android Peer")
            if method == "POST" and path == "/Discover":
                if not is_p2p_proxy and is_active_p2p_peer_ip(peer_ip):
                    p2p_ep = active_p2p_endpoint(peer_ip)
                    if p2p_ep:
                        record_active_peer(f"p2p-{peer_ip}", active_peer_name, "5GHz Wi-Fi Direct P2P", p2p_ep, -48, 0)
                    write_progress(True, "Receiving", "Incoming transfer", 0, 0, 0, 0, 0, 1, phase="Handshaking over 5GHz Wi-Fi Direct…", peer_name=active_peer_name, is_connecting=True)
                resp = plistlib.dumps({
                    "ReceiverComputerName": active_peer_name if is_p2p_proxy else current_mac_name(),
                    "ReceiverModelName": "iPhone16,2" if is_p2p_proxy else "MacBookPro18,2",
                    "ReceiverMediaCapabilities": MEDIA_CAP,
                    "IsAirDropable": True,  # Apple AWDL Discover wire-protocol bplist key
                }, fmt=plistlib.FMT_BINARY)
                close_conn = headers.get("connection", "").lower() == "close"
                send_resp(conn, 200, "OK", resp, close=close_conn)
                if close_conn:
                    break
            elif method == "POST" and path == "/Ask":
                try:
                    info = plistlib.loads(body) if body else {}
                except Exception:
                    info = {}
                if not isinstance(info, dict):
                    info = {}
                items = info.get("Items") or []
                files = info.get("Files") or []
                if not isinstance(items, list) or not isinstance(files, list) or len(files) > 4096:
                    send_resp(conn, 400, "Bad Request", b"", close=True)
                    break
                approved_manifest = []
                for fd in files:
                    if not isinstance(fd, dict):
                        raise ValueError("Invalid approved file metadata")
                    name = fd.get("FileName")
                    size = fd.get("FileSize")
                    if (not isinstance(name, str) or not name or "\x00" in name
                            or os.path.basename(name.replace("\\", "/")) != name
                            or len(name.encode("utf-8")) > 4096
                            or type(size) is not int or not 0 <= size <= 0x7FFFFFFFFFFFFFFF):
                        raise ValueError("Invalid approved filename or size")
                    approved_manifest.append((name, size))
                if is_p2p_proxy and items:
                    send_resp(conn, 400, "Bad Request", b"URL forwarding is not supported by the Finder proxy", close=True)
                    break
                last_sender = str(info.get("SenderComputerName") or active_peer_name)
                if not is_p2p_proxy and is_active_p2p_peer_ip(peer_ip):
                    p2p_ep = active_p2p_endpoint(peer_ip)
                    if p2p_ep:
                        record_active_peer(f"p2p-{peer_ip}", last_sender, "5GHz Wi-Fi Direct P2P", p2p_ep, -48, 0)
                fnames = [str(fd.get("FileName") or "file") for fd in files if isinstance(fd, dict)]
                last_label = fnames[0] if fnames else (str(items[0]) if items else "Incoming File")
                last_count = max(1, len(fnames))
                last_total = sum(int(fd.get("FileSize") or 0) for fd in files if isinstance(fd, dict))

                if not is_p2p_proxy:
                    try:
                        upload_done_flag.unlink(missing_ok=True)
                    except Exception:
                        pass
                    touch_rx_lock()
                    ask_phase = "Starting incoming stream…" if load_settings().get("autoAccept", False) else f"Waiting for approval from {current_mac_name()}…"
                    write_progress(True, "Receiving", last_label, 0, last_total, 0, 0, 0, last_count, phase=ask_phase, peer_name=last_sender, is_connecting=True)
                    conn.settimeout(60.0)
                    if not wait_for_user_accept(last_sender, fnames if fnames else [str(x) for x in items], last_total,
                                                conn=conn, session_token=headers.get("x-glidedrop-token", "").strip().lower(), peer_ip=peer_ip):
                        write_progress(False)
                        print(f"[P2P-Receiver] Declined transfer from {last_sender}")
                        send_resp(conn, 403, "Forbidden", b"")
                        break
                    conn.settimeout(30.0)
                    touch_rx_lock()
                    ask_approved = True
                    approved_token = headers.get("x-glidedrop-token", "").strip().lower()
                    for it in items:
                        if isinstance(it, str) and (it.startswith("http://") or it.startswith("https://")):
                            if not re.match(r"^https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$", it):
                                print(f"[-] Dropping malformed or suspicious URL: {it}")
                                continue
                            append_history("URL", it, len(it), "received", last_sender)
                            # Copy received URL to NSPasteboard via pbcopy
                            try:
                                p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
                                p.communicate(input=it.encode("utf-8"), timeout=2.0)
                            except Exception:
                                pass
                            safe_notify(f"Received link (copied to clipboard): {it}", f"GlideDrop from {last_sender}")
                            # Prompt user with an action button instead of auto-launching browser
                            def prompt_user_url_action(target_url: str, sender_name: str):
                                try:
                                    subprocess.run(
                                        build_url_prompt_osascript_argv(target_url, sender_name),
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL,
                                    )
                                except Exception:
                                    pass
                            threading.Thread(target=prompt_user_url_action, args=(it, last_sender), daemon=True).start()
                resp = plistlib.dumps({
                    "ReceiverComputerName": active_peer_name if is_p2p_proxy else current_mac_name(),
                    "ReceiverModelName": "iPhone16,2" if is_p2p_proxy else "MacBookPro18,2",
                    "ReceiverMediaCapabilities": MEDIA_CAP,
                    "IsAirDropable": True,  # Apple AWDL Discover wire-protocol bplist key
                }, fmt=plistlib.FMT_BINARY)
                if is_p2p_proxy:
                    ask_approved = True
                close_conn = headers.get("connection", "").lower() == "close"
                send_resp(conn, 200, "OK", resp, close=close_conn)
                if close_conn:
                    break
            elif method == "POST" and path == "/Upload":
                if (not ask_approved or (not is_p2p_proxy and not hmac.compare_digest(
                        approved_token, headers.get("x-glidedrop-token", "").strip().lower()))):
                    print(f"[{role}] Rejected unauthorized /Upload from {addr} without session-matched /Ask")
                    send_resp(conn, 403, "Forbidden", b"")
                    break
                conn.settimeout(30.0)
                if is_p2p_proxy:
                    recovery = STATE_DIR / "finder_recovery"
                    recovery.mkdir(mode=0o700, parents=True, exist_ok=True)
                    if recovery.is_symlink():
                        raise ValueError("Finder recovery directory must not be a symlink")
                    tmp_dir = Path(tempfile.mkdtemp(prefix="transfer-", dir=recovery))
                    try:
                        saved, rx_len = stream_upload_to_dir(f, headers, tmp_dir, track_progress=False, file_label=last_label, expected_total=exp_tot, file_count=last_count, fsync_files=False, approved_manifest=approved_manifest)
                    except HttpFramingError as he:
                        shutil.rmtree(tmp_dir, ignore_errors=True)
                        send_resp(conn, he.status_code, he.reason, b"", close=True)
                        break
                    except ValueError:
                        shutil.rmtree(tmp_dir, ignore_errors=True)
                        send_resp(conn, 400, "Bad Request", b"", close=True)
                        break
                    except Exception:
                        shutil.rmtree(tmp_dir, ignore_errors=True)
                        raise
                    print(f"[{role}] {method} {path} from {addr} ({rx_len} B)")
                    # No name/size deduplication: it drops distinct same-length revisions.
                    if forward_to_peer_worker(tmp_dir, saved):
                        send_resp(conn, 200, "OK", b"")
                    else:
                        send_resp(conn, 502, "Bad Gateway", b"Android forwarding failed; files retained for recovery", close=True)
                    break
                else:
                    try:
                        upload_done_flag.unlink(missing_ok=True)
                    except Exception:
                        pass
                    touch_rx_lock()
                    try:
                        saved, rx_len = stream_upload_to_dir(f, headers, DOWNLOADS, track_progress=True, file_label=last_label, expected_total=exp_tot, file_count=last_count, peer_name=last_sender, approved_manifest=approved_manifest)
                    except HttpFramingError as he:
                        send_resp(conn, he.status_code, he.reason, b"", close=True)
                        break
                    except ValueError:
                        send_resp(conn, 400, "Bad Request", b"", close=True)
                        break
                    print(f"[{role}] {method} {path} from {addr} ({rx_len} B)")
                    for p in saved:
                        sz = p.stat().st_size
                        print(f"[+] Saved to {p} ({sz} B)")
                        append_history("FILE", str(p), sz, "received", last_sender)
                        safe_notify(f"Saved {p.name} to Downloads", f"GlideDrop from {last_sender}")
                        # Automatic Claude AI Analysis & Ingestion Hook (concurrency bounded)
                        enqueue_claude_processing(p)
                    send_resp(conn, 200, "OK", b"")
                    try:
                        upload_done_flag.write_text(str(time.time()))
                    except Exception:
                        pass
                    break
            else:
                send_resp(conn, 400, "Bad Request", b"")
                break
    except Exception as e:
        if owns_rx_lock:
            write_progress(False)
        if isinstance(e, (ValueError, EOFError)):
            try:
                send_resp(conn, 400, "Bad Request", b"", close=True)
            except Exception:
                pass
        print(f"[-] Client {addr} error: {e}")
        sys.stdout.flush()
    finally:
        if owns_rx_lock:
            write_progress(False)
            try:
                rx_lock.unlink(missing_ok=True)
            except Exception:
                pass
        try:
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        except Exception:
            pass
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.load_cert_chain(CERT_FILE, KEY_FILE)
try:
    if hasattr(ctx, "set_ciphersuites"):
        ctx.set_ciphersuites("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
except Exception:
    pass

def set_high_throughput_sockbufs(s):
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        for sz in (4194304, 2097152, 1048576):
            try:
                s.setsockopt(socket.SOL_SOCKET, opt, sz)
                break
            except Exception:
                continue

def is_authorized_peer_ip(peer_ip: str) -> bool:
    clean = str(peer_ip or "").split("%", 1)[0].strip()
    try:
        addr = ipaddress.ip_address(clean)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.is_loopback or addr.is_link_local:
        return False
    try:
        validate_peer_route(str(addr), get_active_p2p_https_port())
        return True
    except Exception:
        return False

def write_bound_port_file(filename: str, value):
    try:
        target = STATE_DIR / filename
        tmp = STATE_DIR / f"{filename}.tmp.{threading.get_ident()}"
        tmp.write_text(str(value), encoding="utf-8")
        tmp.replace(target)
    except Exception:
        pass

CLIENT_SLOTS = threading.BoundedSemaphore(16)

def serve_tls_client(raw, addr, is_p2p_proxy):
    try:
        raw.settimeout(15.0)
        set_high_throughput_sockbufs(raw)
        if not is_p2p_proxy:
            ip = str(addr[0]).replace("::ffff:", "")
            if not is_authorized_peer_ip(ip):
                raw.close()
                return
        with ctx.wrap_socket(raw, server_side=True) as tls:
            if not is_p2p_proxy:
                if not is_authorized_peer_ip(ip):
                    return
                session = load_active_p2p_session()
                local_ip = ipaddress.ip_address(tls.getsockname()[0].replace("::ffff:", "").split("%", 1)[0])
                if not session or local_ip not in ipaddress.ip_network(session["cidr"], strict=False):
                    return
            handle_client(tls, addr, is_p2p_proxy)
    except Exception:
        raw.close()
    finally:
        CLIENT_SLOTS.release()


def serve_port(bind_port: int, is_p2p_proxy: bool, unix_sock_path=None, on_bound=None):
    is_unix = bool(is_p2p_proxy and unix_sock_path is not None)
    if is_unix:
        sock_path = Path(unix_sock_path)
        sock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            sock_path.unlink(missing_ok=True)
        except Exception:
            pass
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        set_high_throughput_sockbufs(sock)
        old_umask = os.umask(0o177)
        try:
            sock.bind(str(sock_path))
        finally:
            os.umask(old_umask)
        try:
            os.chmod(sock_path, 0o600)
        except Exception:
            pass
        write_bound_port_file("finder_proxy_sock", str(sock_path))
        bind_desc = f"unix:{sock_path}"
    elif is_p2p_proxy:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        set_high_throughput_sockbufs(sock)
        bind_host = "127.0.0.1"
        sock.bind((bind_host, bind_port))
        actual_port = sock.getsockname()[1]
        write_bound_port_file("finder_proxy_port", actual_port)
        bind_desc = f"127.0.0.1:{actual_port}"
    else:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        set_high_throughput_sockbufs(sock)
        bind_host = "::"
        sock.bind((bind_host, bind_port))
        actual_port = sock.getsockname()[1]
        write_bound_port_file("mac_rx_port", actual_port)
        bind_desc = f"*:{actual_port}"
    sock.listen(32)
    if on_bound is not None:
        on_bound(sock)
    label = "Finder Share Proxy" if is_p2p_proxy else f"5GHz Wi-Fi Direct P2P Receiver ('{current_mac_name()}')"
    print(f"[+] {label} listening on {bind_desc}")
    while True:
        try:
            raw, addr = sock.accept()
        except OSError:
            break
        try:
            if not is_unix:
                peer_ip = str(addr[0]).replace("::ffff:", "")
                if is_p2p_proxy:
                    if peer_ip not in ("127.0.0.1", "localhost", "::1"):
                        print(f"[-] Dropping non-loopback connection to internal proxy: {addr[0]}")
                        raw.close()
                        continue
                raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if not CLIENT_SLOTS.acquire(blocking=False):
                raw.close()
                continue
            try:
                threading.Thread(target=serve_tls_client, args=(raw, addr, is_p2p_proxy), daemon=True).start()
            except Exception:
                CLIENT_SLOTS.release()
                raise
        except Exception:
            raw.close()

def _is_lock_active(lock_path: Path, ttl: float) -> bool:
    if not lock_path.exists():
        return False
    try:
        raw = lock_path.read_text(encoding="utf-8").strip()
        ts = float(raw.split("\t")[-1])
        if (time.time() - ts) < ttl:
            return True
    except Exception:
        try:
            if (time.time() - lock_path.stat().st_mtime) < ttl:
                return True
        except Exception:
            return False
    try:
        lock_path.unlink(missing_ok=True)
    except Exception:
        pass
    return False

def get_awdl_instance_id() -> str:
    id_file = STATE_DIR / "awdl_instance_id"
    try:
        if id_file.exists():
            raw = id_file.read_text(encoding="utf-8").strip().lower()
            if re.fullmatch(r"[0-9a-f]{12}", raw):
                return raw
    except Exception:
        pass
    inst_id = uuid.uuid4().hex[:12]
    try:
        tmp = STATE_DIR / f"awdl_instance_id.tmp.{threading.get_ident()}"
        tmp.write_text(inst_id, encoding="utf-8")
        tmp.replace(id_file)
    except Exception:
        pass
    return inst_id

def read_awdl_bridge_port() -> int:
    """OS-assigned AWDL bridge port published by the daemon; 0 when not yet published."""
    pf = STATE_DIR / "awdl_bridge_port"
    try:
        if pf.exists():
            p = int(pf.read_text(encoding="utf-8").strip())
            if 1 <= p <= 65535:
                return p
    except Exception:
        pass
    return 0

def watch_awdl_mdns():
    pid_file = STATE_DIR / "awdl-mdns.pid"
    rx_lock = STATE_DIR / "rx_in_progress.lock"
    tx_lock = STATE_DIR / "tx_in_progress.lock"
    instance_id = get_awdl_instance_id()
    cur_ip = None
    cur_port = None
    proc = None
    while True:
        try:
            if _is_lock_active(rx_lock, 30.0) or _is_lock_active(tx_lock, 180.0):
                if proc and proc.poll() is None:
                    proc.terminate()
                proc = None
                cur_ip = None
                cur_port = None
                if pid_file.exists():
                    pid_file.unlink(missing_ok=True)
                time.sleep(2.0)
                continue
            active_peers = get_active_peers(12.0)
            if not active_peers:
                if proc and proc.poll() is None:
                    proc.terminate()
                proc = None
                cur_ip = None
                cur_port = None
                if pid_file.exists():
                    pid_file.unlink(missing_ok=True)
                time.sleep(2.0)
                continue
            bridge_port = read_awdl_bridge_port()
            if bridge_port <= 0:
                time.sleep(2.0)
                continue
            out = subprocess.check_output(["ifconfig", "awdl0"], text=True, stderr=subprocess.DEVNULL)
            new_ip = None
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet6 fe80:"):
                    new_ip = line.split()[1].split("%")[0]
                    break
            if new_ip and (new_ip != cur_ip or bridge_port != cur_port or (proc and proc.poll() is not None)):
                if proc and proc.poll() is None:
                    proc.terminate()
                proc = subprocess.Popen(
                    # Required by Apple sharingd on awdl0 for Finder Share Sheet peer discovery
                    ["dns-sd", "-i", "awdl0", "-P", instance_id, "_airdrop._tcp", "local.", str(bridge_port), "glidedrop.local.", new_ip, "flags=136"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                pid_file.write_text(str(proc.pid))
                cur_ip = new_ip
                cur_port = bridge_port
                print(f"[AWDL-mDNS] Advertising active peer ({active_peers[0].get('name')}) on awdl0 at {cur_ip}:{bridge_port} (id={instance_id}, PID {proc.pid})")
        except Exception:
            pass
        time.sleep(2.0)

FINDER_PROXY_SOCK = STATE_DIR / "finder_proxy.sock"
threading.Thread(target=watch_awdl_mdns, daemon=True).start()
threading.Thread(target=serve_port, args=(PROXY_PORT, True, FINDER_PROXY_SOCK), daemon=True).start()
serve_port(PORT, False)
PYEOF
  echo $! >"$PID_FILE"
  echo "[+] 5GHz Wi-Fi Direct P2P Receiver (OS-assigned port, see $STATE_DIR/mac_rx_port) + Native Finder Share Proxy running."
}

MODE="${1:-status}"

case "$MODE" in
  on)
    start_daemons
    ;;
  restart-receiver|restart|restart-lan)
    SKIP_BLE_RESTART=1 start_daemons
    ;;
  off)
    stop_daemons
    restore_macos_defaults
    echo "[+] Stopped GlideDrop daemons and restored defaults."
    ;;
  status)
    echo "=== GlideDrop (5GHz Wi-Fi Direct + BLE L2CAP + Native Finder Share Bridge) Status ==="
    _rx_port="$(cat "$STATE_DIR/mac_rx_port" 2>/dev/null || echo "unassigned")"
    _fp_sock="$(cat "$STATE_DIR/finder_proxy_sock" 2>/dev/null || echo "$STATE_DIR/finder_proxy.sock")"
    _awdl_port="$(cat "$STATE_DIR/awdl_bridge_port" 2>/dev/null || echo "unassigned")"
    _awdl_id="$(cat "$STATE_DIR/awdl_instance_id" 2>/dev/null || echo "unregistered")"
    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      echo "5GHz P2P Receiver:    RUNNING (PID $(cat "$PID_FILE"), port $_rx_port -> ~/Downloads, Unix Proxy $_fp_sock)"
    else
      echo "5GHz P2P Receiver:    STOPPED"
    fi
    if [[ -f "$AWDL_MDNS_PID_FILE" ]] && kill -0 "$(cat "$AWDL_MDNS_PID_FILE")" 2>/dev/null; then
      echo "Finder Share Proxy: ADVERTISING on awdl0 (${_awdl_id}._airdrop._tcp.local.:${_awdl_port} -> Android Peer)"
    else
      echo "Finder Share Proxy: STOPPED"
    fi
    if [[ -f "$BLE_PID_FILE" ]] && kill -0 "$(cat "$BLE_PID_FILE")" 2>/dev/null; then
      echo "Direct BLE L2CAP RX:  RUNNING (PID $(cat "$BLE_PID_FILE") -> ~/Downloads + AWDL ${_awdl_port} Bridge)"
    else
      echo "Direct BLE L2CAP RX:  STOPPED"
    fi
    ;;
  send)
    shift
    if [[ $# -lt 1 ]]; then
      SELECTED="$(osascript -e 'tell application "Finder"
        if (count of selection) > 0 then
          return POSIX path of (item 1 of (get selection) as alias)
        end if
      end tell' 2>/dev/null || true)"
      if [[ -z "$SELECTED" || ! -f "$SELECTED" ]]; then
        SELECTED="$(osascript -e 'POSIX path of (choose file with prompt "Select a file to send via GlideDrop to Android device:")' 2>/dev/null || true)"
      fi
      if [[ -z "$SELECTED" ]]; then
        exit 0
      fi
      set -- "$SELECTED"
    fi
    ensure_ble_bin
    HAS_PEER_ARG=0
    _scan_args=("$@")
    _idx=0
    while [[ $_idx -lt ${#_scan_args[@]} ]]; do
      _cur="${_scan_args[$_idx]}"
      if [[ "$_cur" == "--peer" ]]; then
        HAS_PEER_ARG=1
        break
      elif [[ "$_cur" == "--pin" ]]; then
        _idx=$((_idx + 2))
      else
        break
      fi
    done
    PY_PID=""
    SIGNAL_CANCELLED=0
    cleanup_send_py() {
      SIGNAL_CANCELLED=1
      if [[ -n "$PY_PID" ]]; then
        kill -TERM "$PY_PID" 2>/dev/null || true
      fi
    }
    trap cleanup_send_py TERM INT
    rc=0
    STATE_DIR="$STATE_DIR" python3 - "$@" << 'PYEOF' &
import hashlib, hmac, ipaddress, json, os, plistlib, re, signal, socket, ssl, struct, subprocess, sys, time, zlib
from pathlib import Path

STATE_DIR = Path(os.environ.get("GLIDEDROP_STATE_DIR") or os.environ.get("STATE_DIR") or (Path.home() / ".glidedrop"))
_active_raw_sock = [None]

def write_progress(active: bool, direction: str = "", file_name: str = "", done_bytes: int = 0, total_bytes: int = 0, speed_bps: int = 0, eta_sec: int = 0, pct: int = 0, file_count: int = 1, phase: str = "", peer_name: str = "", is_connecting: bool = False):
    pf = STATE_DIR / "transfer_progress.json"
    tmp = STATE_DIR / "transfer_progress.json.tmp"
    try:
        if not active:
            if pf.exists():
                pf.unlink()
            return
        payload = {
            "active": True,
            "direction": direction,
            "fileName": file_name,
            "fileCount": file_count,
            "doneBytes": int(done_bytes),
            "totalBytes": int(total_bytes),
            "speedBps": int(speed_bps),
            "etaSeconds": int(eta_sec),
            "percent": int(pct),
            "phase": phase,
            "peerName": peer_name,
            "isConnecting": bool(is_connecting),
            "updatedAt": time.time(),
        }
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        tmp.replace(pf)
    except Exception:
        pass

def append_history(kind: str, path_or_url: str, size_bytes: int, direction: str, peer_name: str):
    rx_log = STATE_DIR / "received.log"
    try:
        with rx_log.open("a", encoding="utf-8") as lf:
            lf.write(f"{int(time.time())}\t{kind}\t{path_or_url}\t{int(size_bytes)}\t{direction}\t{peer_name}\n")
    except Exception:
        pass

def safe_notify(message: str, title: str):
    try:
        subprocess.Popen([
            "osascript",
            "-e", "on run argv",
            "-e", 'display notification (item 1 of argv) with title (item 2 of argv) sound name "Glass"',
            "-e", "end run",
            "--",
            str(message)[:240],
            str(title)[:120],
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def is_transfer_cancelled() -> bool:
    cf = STATE_DIR / "cancel_transfer.flag"
    if not cf.exists():
        return False
    try:
        ts = float(cf.read_text(encoding="utf-8").strip())
        return (time.time() - ts) < 10.0
    except FileNotFoundError:
        return False
    except Exception:
        try:
            return (time.time() - cf.stat().st_mtime) < 10.0
        except FileNotFoundError:
            return False
        except Exception:
            return True

def _on_cancel_signal(_signum, _frame):
    rs = _active_raw_sock[0]
    if rs is not None:
        try:
            rs.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            rs.close()
        except Exception:
            pass
    write_progress(False)
    sys.exit(44)

signal.signal(signal.SIGTERM, _on_cancel_signal)
signal.signal(signal.SIGINT, _on_cancel_signal)

args = sys.argv[1:]
peer_override = None
peer_pin = None
while args:
    if args[0] == "--peer" and len(args) >= 2:
        peer_override = args[1]
        args = args[2:]
    elif args[0] == "--pin" and len(args) >= 2:
        peer_pin = args[1]
        args = args[2:]
    else:
        break

if peer_pin is None:
    pin_file = STATE_DIR / "pinned_peer_tls_fingerprint.txt"
    if pin_file.exists():
        try:
            mtime = pin_file.stat().st_mtime
            if time.time() - mtime < 60.0:
                file_pin = pin_file.read_text(encoding="utf-8").strip()
                if file_pin:
                    peer_pin = file_pin
            pin_file.unlink(missing_ok=True)
        except Exception:
            pass

def parse_peer_target(raw_peer: str):
    s = str(raw_peer or "").strip()
    if not s:
        raise ValueError("Empty peer target")
    if s.startswith("["):
        end_br = s.find("]")
        if end_br == -1:
            raise ValueError(f"Malformed bracketed peer target: {raw_peer}")
        host = s[1:end_br].strip()
        rest = s[end_br + 1:].strip()
        if rest.startswith(":"):
            port_val = int(rest[1:].strip())
        elif not rest:
            raise ValueError(f"Peer target is missing a port: {raw_peer}")
        else:
            raise ValueError(f"Unexpected trailing characters in peer target: {raw_peer}")
    elif s.count(":") == 1:
        host_part, _, port_s = s.partition(":")
        host = host_part.strip()
        if not port_s.strip():
            raise ValueError(f"Peer target is missing a port: {raw_peer}")
        port_val = int(port_s.strip())
    else:
        raise ValueError(f"Peer target is missing a port: {raw_peer}")
    if not host or not (1 <= port_val <= 65535):
        raise ValueError(f"Invalid peer target or port: {raw_peer}")
    return host, port_val

def load_active_p2p_session(max_age: float = 1800.0):
    sf = STATE_DIR / "active_p2p_session.json"
    try:
        if not sf.exists():
            return None
        obj = json.loads(sf.read_text(encoding="utf-8"))
        if not isinstance(obj, dict):
            return None
        updated = float(obj.get("updatedAt") or 0.0)
        if not 0 <= time.time() - updated <= max_age:
            return None
        iface = str(obj.get("interface") or obj.get("interfaceName") or "")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,31}", iface):
            return None
        if not str(obj.get("ssid") or "").startswith("DIRECT-"):
            return None
        net = ipaddress.ip_network(str(obj.get("cidr") or ""), strict=False)
        gateway = ipaddress.ip_address(str(obj.get("gatewayIp") or ""))
        if (net.prefixlen == 0 or gateway not in net or gateway.is_loopback
                or gateway.is_unspecified or gateway.is_multicast or gateway.is_link_local):
            return None
        if not 1 <= int(obj.get("httpsPort") or 0) <= 65535:
            return None
        obj["interface"] = iface
        return obj
    except Exception:
        return None


def validate_peer_route(host: str, port: int):
    session = load_active_p2p_session()
    if not session:
        raise ValueError("No OS-confirmed Wi-Fi Direct session")
    addr = ipaddress.ip_address(str(host).split("%", 1)[0])
    if addr != ipaddress.ip_address(session["gatewayIp"]) or port != int(session["httpsPort"]):
        raise ValueError("Peer endpoint does not match the active Wi-Fi Direct session")
    family = "-inet6" if addr.version == 6 else "-inet"
    route = subprocess.check_output(["/sbin/route", "-n", "get", family, str(addr)], text=True, timeout=3.0)
    match = re.search(r"^\s*interface:\s*(\S+)\s*$", route, re.MULTILINE)
    if not match or match.group(1) != session["interface"]:
        raise ValueError("Peer route is not on the confirmed Wi-Fi Direct interface")
    return session


def load_outgoing_p2p_token(target_host: str = "") -> str:
    # Secrets are never read from the environment (visible via process inspection);
    # the daemon hands the bearer token over through a mode-0600 state file.
    os.environ.pop("GLIDEDROP_P2P_TOKEN", None)
    now = time.time()
    tf = STATE_DIR / "p2p_outgoing_token.json"
    try:
        if tf.exists():
            obj = json.loads(tf.read_text(encoding="utf-8"))
            if isinstance(obj, dict):
                tok = str(obj.get("token") or "").strip().lower()
                exp = float(obj.get("expires_at") or 0.0)
                rec_host = str(obj.get("host") or "").strip().strip("[]")
                clean_target = target_host.split("%", 1)[0].strip("[]")
                if re.fullmatch(r"[0-9a-f]{64}", tok) and exp > now:
                    if not rec_host or not clean_target or rec_host == clean_target:
                        return tok
    except Exception:
        pass
    sf = STATE_DIR / "p2p_session_token.json"
    try:
        if sf.exists():
            obj = json.loads(sf.read_text(encoding="utf-8"))
            if isinstance(obj, dict):
                entries = obj.get("tokens") if isinstance(obj.get("tokens"), list) else [obj]
                for entry in reversed(entries):
                    if not isinstance(entry, dict):
                        continue
                    tok = str(entry.get("token") or "").strip().lower()
                    exp = float(entry.get("expires_at") or 0.0)
                    if re.fullmatch(r"[0-9a-f]{64}", tok) and exp > now:
                        return tok
    except Exception:
        pass
    return ""

def discover_android(expected_fp=None):
    if not expected_fp:
        raise RuntimeError("Deferring to BLE L2CAP + 5GHz Wi-Fi Direct P2P (unpinned TLS disabled)")
    session = load_active_p2p_session()
    candidates = []
    if session:
        gw = str(session.get("gatewayIp") or "").strip().strip("[]")
        try:
            hp = int(session.get("httpsPort") or 0)
        except Exception:
            hp = 0
        if gw and 1 <= hp <= 65535:
            candidates.append((gw, hp))
    for cand_host, cand_port in candidates:
        try:
            validate_peer_route(cand_host, cand_port)
            return cand_host, cand_port
        except Exception:
            pass
    raise RuntimeError("Deferring to BLE L2CAP + 5GHz Wi-Fi Direct P2P")

transfer_succeeded = False
terminal_exit_code = None
post_handshake = False
in_ask_or_upload = False
peer_name = "Android Device"

try:
    expected_fp = None
    if peer_pin is not None:
        normalized_pin = peer_pin.replace(":", "").replace("-", "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", normalized_pin):
            print("[-] Invalid SHA-256 peer TLS certificate fingerprint", file=sys.stderr)
            sys.exit(45)
        expected_fp = normalized_pin

    urls = [a for a in args if a.startswith("http://") or a.startswith("https://")]
    file_args = [a for a in args if a not in urls]
    files = [Path(a).expanduser().resolve() for a in file_args]
    for f in files:
        if not f.is_file():
            print(f"File not found: {f}", file=sys.stderr)
            sys.exit(45)

    total_bytes = sum(f.stat().st_size for f in files)

    if peer_override:
        host, port = parse_peer_target(peer_override)
    else:
        host, port = discover_android(expected_fp)

    try:
        p2p_session = validate_peer_route(host, port)
    except Exception as e:
        print(f"[-] Refusing non-P2P peer route: {e}", file=sys.stderr)
        sys.exit(46)
    if not expected_fp:
        print("[-] Refusing HTTPS without a session TLS fingerprint", file=sys.stderr)
        sys.exit(46)
    outgoing_token = load_outgoing_p2p_token(host)
    if not outgoing_token:
        print("[-] Missing active P2P bearer token", file=sys.stderr)
        sys.exit(46)
    token_hdr = f"X-GlideDrop-Token: {outgoing_token}\r\n" if outgoing_token else ""
    clean_hdr_host = host.split("%", 1)[0]
    host_header = f"[{clean_hdr_host}]:{port}" if ":" in clean_hdr_host else f"{clean_hdr_host}:{port}"

    first_label = files[0].name if files else (urls[0] if urls else "Outgoing transfer")
    fcount_init = max(1, len(files))
    write_progress(True, "Sending", first_label, 0, total_bytes, 0, 0, 0, fcount_init, phase="Opening 5GHz TLS channel…", peer_name="Android Device", is_connecting=True)

    print(f"[+] Connecting to Android peer over 5GHz Wi-Fi at {host}:{port}...")
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if expected_fp:
        # Self-signed P2P certificates are verified immediately post-handshake against the W2P2 SHA-256 pin.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        if hasattr(ctx, "set_ciphersuites"):
            ctx.set_ciphersuites("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
    except Exception:
        pass

    def read_http_response(f):
        def response_line():
            line = f.readline(8193)
            if not line:
                raise EOFError("Truncated HTTP response")
            if len(line) > 8192 or not line.endswith(b"\r\n"):
                raise ValueError("Oversized or malformed HTTP response line")
            raw = line[:-2]
            if any(c < 32 and c != 9 for c in raw) or b"\x7f" in raw:
                raise ValueError("Control character in HTTP response")
            return raw.decode("iso-8859-1")
        status_line = response_line()
        if not re.fullmatch(r"HTTP/1\.[01] [1-5][0-9]{2}(?: [^\r\n]*)?", status_line):
            raise ValueError("Malformed HTTP response status")
        headers = {}
        total = len(status_line) + 2
        for count in range(65):
            line = response_line()
            total += len(line) + 2
            if total > 16384:
                raise ValueError("HTTP response headers exceed limit")
            if not line:
                break
            if count == 64 or ":" not in line:
                raise ValueError("Too many or malformed HTTP response headers")
            k, v = line.split(":", 1)
            if not re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", k):
                raise ValueError("Invalid HTTP response header")
            k = k.lower()
            if k in headers and k in ("content-length", "transfer-encoding"):
                raise ValueError("Duplicate HTTP framing header")
            headers[k] = v.strip()
        if "transfer-encoding" in headers:
            raise ValueError("Unsupported HTTP response transfer encoding")
        length = headers.get("content-length", "")
        if not re.fullmatch(r"[0-9]{1,10}", length) or int(length) > 1048576:
            raise ValueError("Invalid or oversized HTTP response Content-Length")
        remaining = int(length)
        body = bytearray()
        while remaining:
            part = f.read(min(65536, remaining))
            if not part:
                raise EOFError("Truncated HTTP response body")
            body.extend(part)
            remaining -= len(part)
        return status_line, bytes(body)

    t0 = time.time()
    raw = None
    last_conn_err = None
    max_attempts = 20 if peer_override else 1
    for attempt in range(max_attempts):
        if is_transfer_cancelled():
            write_progress(False)
            print("[-] Transfer cancelled by user", file=sys.stderr)
            sys.exit(44)
        try:
            addr_infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except Exception as e:
            last_conn_err = e
            addr_infos = []
        for family, socktype, proto, _canonname, sockaddr in addr_infos:
            cand = None
            try:
                cand = socket.socket(family, socktype, proto)
                cand.settimeout(1.5)
                cand.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                cand.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                for opt in (socket.SO_SNDBUF, socket.SO_RCVBUF):
                    for sz in (4194304, 2097152, 1048576):
                        try:
                            cand.setsockopt(socket.SOL_SOCKET, opt, sz)
                            break
                        except Exception:
                            continue
                validate_peer_route(host, port)
                if sys.platform != "darwin":
                    raise ValueError("Wi-Fi Direct interface binding requires macOS")
                iface_index = socket.if_nametoindex(p2p_session["interface"])
                if family == socket.AF_INET:
                    cand.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_BOUND_IF", 25), iface_index)
                else:
                    cand.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_BOUND_IF", 125), iface_index)
                cand.connect(sockaddr)
                raw = cand
                break
            except Exception as e:
                if cand is not None:
                    try:
                        cand.close()
                    except Exception:
                        pass
                last_conn_err = e
        if raw is not None:
            break
        if attempt + 1 < max_attempts:
            time.sleep(0.35)
    if raw is None:
        err_msg = str(last_conn_err) if last_conn_err else "connection timed out"
        print(f"[-] Could not connect to {host}:{port}: {err_msg}", file=sys.stderr)
        sys.exit(1)

    with raw:
        _active_raw_sock[0] = raw
        raw.settimeout(300.0)
        sni_host = host.split("%", 1)[0]
        with ctx.wrap_socket(raw, server_hostname=sni_host) as s:
            s.settimeout(300.0)
            if expected_fp:
                der_cert = s.getpeercert(binary_form=True)
                if not der_cert:
                    raise ssl.SSLError("Android peer did not provide a TLS certificate")
                actual_fp = hashlib.sha256(der_cert).hexdigest().lower()
                if not hmac.compare_digest(actual_fp, expected_fp):
                    print(f"[-] FATAL: Peer TLS certificate fingerprint mismatch! Expected {expected_fp}, got {actual_fp}")
                    raise ssl.SSLError(f"Certificate fingerprint pinning failed! Expected {expected_fp}, got {actual_fp}")
                print(f"[+] Verified peer TLS certificate fingerprint: {actual_fp}")
            post_handshake = True
            f = s.makefile("rb", buffering=262144)
            disc = plistlib.dumps({"DeviceSupportFlags": 111611}, fmt=plistlib.FMT_BINARY)
            s.sendall(f"POST /Discover HTTP/1.1\r\nHost: {host_header}\r\n{token_hdr}Content-Type: application/octet-stream\r\nContent-Length: {len(disc)}\r\nConnection: keep-alive\r\n\r\n".encode() + disc)
            st, body = read_http_response(f)
            if st.split(" ", 2)[1] == "401":
                sys.exit("[-] Unauthorized: peer rejected X-GlideDrop-Token (401)")
            if st.split(" ", 2)[1] != "200":
                sys.exit(f"[-] Peer /Discover failed: {st}")
            peer_name = plistlib.loads(body).get("ReceiverComputerName", "Android Device") if body else "Android Device"
            print(f"[+] Discovered receiver: {peer_name} ({st})")
            write_progress(True, "Sending", first_label, 0, total_bytes, 0, 0, 0, fcount_init, phase=f"Waiting for {peer_name} to accept…", peer_name=peer_name, is_connecting=True)

            sender_name = "MacBook Pro"
            try:
                sf = STATE_DIR / "settings.json"
                if sf.exists():
                    sender_name = json.loads(sf.read_text(encoding="utf-8")).get("deviceName") or sender_name
            except Exception:
                pass

            ask = plistlib.dumps({
                "SenderComputerName": sender_name,
                "SenderModelName": "MacBookPro18,2",
                "BundleID": "com.apple.Safari" if (urls and not files) else "com.apple.finder",
                "ConvertMediaFormats": False,
                "Items": urls,
                "Files": [{
                    "FileName": p.name,
                    "FileType": "public.data",
                    "FileSize": p.stat().st_size,
                    "FileBomPath": "./" + p.name,
                    "FileIsDirectory": False,
                    "ConvertMediaFormats": 0
                } for p in files]
            }, fmt=plistlib.FMT_BINARY)
            in_ask_or_upload = True
            s.sendall(f"POST /Ask HTTP/1.1\r\nHost: {host_header}\r\n{token_hdr}Content-Type: application/octet-stream\r\nContent-Length: {len(ask)}\r\nConnection: keep-alive\r\n\r\n".encode() + ask)
            st2, _ = read_http_response(f)
            if st2.split(" ", 2)[1] == "403":
                print(f"[-] Transfer declined by {peer_name}")
                sys.exit(43)
            if st2.split(" ", 2)[1] != "200":
                sys.exit(f"[-] Transfer declined or failed: {st2}")
            if files:
                label = files[0].name
                fcount = len(files)
                tot = max(1, sum(p.stat().st_size for p in files))
                print(f"[+] /Ask accepted ({st2}), streaming DVZip CPIO archive over 5GHz Wi-Fi Direct...")
                hdr_bytes = (
                    f"POST /Upload HTTP/1.1\r\n"
                    f"Host: {host_header}\r\n"
                    f"{token_hdr}"
                    f"Content-Type: application/x-dvzip\r\n"
                    f"TotalBytes: {tot}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                ).encode("ascii")
                s.sendall(hdr_bytes)
                tx_start = time.time()
                last_emit = 0.0
                last_lock_refresh = time.time()
                off = 0
                write_progress(True, "Sending", label, 0, tot, 0, 0, 0, fcount, phase="Sending files", peer_name=peer_name, is_connecting=False)

                def send_dvzip_block(raw_block: bytes):
                    if not raw_block:
                        return
                    if is_transfer_cancelled():
                        write_progress(False)
                        try:
                            raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                        except Exception:
                            pass
                        print("[-] Transfer cancelled by user", file=sys.stderr)
                        sys.exit(44)
                    hdr4 = struct.pack(">I", 0x80000000 | len(raw_block))
                    pkt_len = 4 + len(raw_block)
                    s.sendall(f"{pkt_len:x}\r\n".encode("ascii") + hdr4 + raw_block + b"\r\n")

                def make_odc_hdr(ino: int, mode: int, name: str, fsize: int) -> bytes:
                    nb = name.encode("utf-8") + b"\x00"
                    if fsize > 0x1FFFFFFFF:
                        return f"070764{ino:016x}{mode:08x}{0:08x}{0:08x}{1:08x}{int(time.time()):016x}{fsize:016x}{len(nb):08x}{0:08x}".encode("ascii") + nb
                    return f"070707{0:06o}{ino:06o}{mode:06o}{0:06o}{0:06o}{1:06o}{0:06o}{int(time.time()):011o}{len(nb):06o}{fsize:011o}".encode("ascii") + nb

                send_dvzip_block(make_odc_hdr(1, 0o040755, ".", 0))
                ino = 2
                for p in files:
                    fsize = p.stat().st_size
                    send_dvzip_block(make_odc_hdr(ino, 0o100644, "./" + p.name, fsize))
                    ino += 1
                    with p.open("rb", buffering=2097152) as pf:
                        while True:
                            chunk = pf.read(1048576)
                            if not chunk:
                                break
                            send_dvzip_block(chunk)
                            off += len(chunk)
                            now = time.time()
                            if now - last_lock_refresh >= 30.0:
                                last_lock_refresh = now
                                tx_lock = STATE_DIR / "tx_in_progress.lock"
                                if tx_lock.exists():
                                    try:
                                        tx_lock.write_text(str(now), encoding="utf-8")
                                    except Exception:
                                        pass
                            if now - last_emit >= 0.25 or off >= tot:
                                last_emit = now
                                el = max(0.08, now - tx_start)
                                spd = int(off / el)
                                eta = int(max(0, tot - off) / max(1, spd))
                                pct = min(99, int((off * 100) / max(1, tot)))
                                write_progress(True, "Sending", label, min(off, tot), tot, spd, eta, pct, fcount, phase="Sending files", peer_name=peer_name, is_connecting=False)
                send_dvzip_block(make_odc_hdr(0, 0, "TRAILER!!!", 0))
                s.sendall(b"0\r\n\r\n")
                write_progress(True, "Sending", label, tot, tot, 0, 0, 99, fcount, phase="Finalizing transfer…", peer_name=peer_name, is_connecting=False)
                st3, _ = read_http_response(f)
                if st3.split(" ", 2)[1] != "200":
                    print(f"[-] Peer rejected /Upload: {st3}", file=sys.stderr)
                    sys.exit(47)
                elapsed = time.time() - t0
                print(f"[+] /Upload complete: {st3} ({elapsed:.2f}s)")
                names = ", ".join(p.name for p in files)
                for p in files:
                    append_history("FILE", str(p), p.stat().st_size, "sent", peer_name)
            else:
                elapsed = time.time() - t0
                print(f"[+] Link sent via /Ask ({elapsed:.2f}s)")
                names = ", ".join(urls)
                for u in urls:
                    append_history("URL", u, len(u), "sent", peer_name)
            transfer_succeeded = True
            safe_notify(f"Sent {names} to {peer_name} in {elapsed:.1f}s", "GlideDrop Complete")
except SystemExit as se:
    terminal_exit_code = se.code
    raise
except ssl.SSLEOFError as e:
    if post_handshake and in_ask_or_upload:
        print(f"[-] Transfer cancelled or closed by {peer_name}: {e}", file=sys.stderr)
        terminal_exit_code = 44
        sys.exit(44)
    print(f"[-] FATAL TLS/pinning verification failure: {e}", file=sys.stderr)
    terminal_exit_code = 46
    sys.exit(46)
except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, EOFError) as e:
    if post_handshake and in_ask_or_upload:
        print(f"[-] Transfer cancelled or closed by {peer_name}: {e}", file=sys.stderr)
        terminal_exit_code = 44
        sys.exit(44)
    print(f"[-] P2P connection dropped before transfer: {e}", file=sys.stderr)
    terminal_exit_code = 1
    sys.exit(1)
except ssl.SSLError as e:
    print(f"[-] FATAL TLS/pinning verification failure: {e}", file=sys.stderr)
    terminal_exit_code = 46
    sys.exit(46)
except ValueError as e:
    print(f"[-] Invalid peer response or transfer input: {e}", file=sys.stderr)
    terminal_exit_code = 47
    sys.exit(47)
except RuntimeError as e:
    if not peer_override and "Deferring to BLE" in str(e):
        print(f"[*] {e}")
        terminal_exit_code = 1
        sys.exit(1)
    raise
finally:
    _active_raw_sock[0] = None
    # Preserve transfer_progress.json when falling back from glidedrop.sh to "$BLE_BIN" send.
    # Only clear progress when --peer is set, transfer succeeded, or terminal decline/cancel/input/pinning error occurred.
    if peer_override or transfer_succeeded or terminal_exit_code in (43, 44, 45, 46, 47):
        write_progress(False)
PYEOF
    PY_PID=$!
    wait "$PY_PID" || rc=$?
    if [[ "$SIGNAL_CANCELLED" -eq 1 ]]; then
      wait "$PY_PID" 2>/dev/null || true
      rm -f "$STATE_DIR/transfer_progress.json" "$STATE_DIR/tx_in_progress.lock"
      rc=44
    fi
    trap - TERM INT
    if [[ "$rc" -ne 0 ]]; then
      if [[ "$rc" -eq 45 ]]; then
        exit 1
      fi
      if [[ "$rc" -eq 43 || "$rc" -eq 44 || "$rc" -eq 46 || "$rc" -eq 47 || "$HAS_PEER_ARG" -eq 1 ]]; then
        if [[ "$HAS_PEER_ARG" -ne 1 ]]; then
          rm -f "$STATE_DIR/cancel_transfer.flag"
        fi
        exit "$rc"
      fi
      echo "[*] Launching GlideDrop P2P engine..."
      if [[ -x "$BLE_BIN" ]]; then
        if "$BLE_BIN" send "$@"; then
          osascript -e "display notification \"Sent to Android device\" with title \"GlideDrop Complete\"" 2>/dev/null || true
        else
          ble_rc=$?
          rm -f "$STATE_DIR/transfer_progress.json" "$STATE_DIR/tx_in_progress.lock"
          exit "$ble_rc"
        fi
      else
        rm -f "$STATE_DIR/transfer_progress.json" "$STATE_DIR/tx_in_progress.lock"
        echo "[-] GlideDrop BLE binary not found at $BLE_BIN" >&2
        exit 1
      fi
    fi
    ;;
  ui)
    start_daemons
    if [[ -f "$BLE_PID_FILE" ]]; then
      kill "$(cat "$BLE_PID_FILE")" 2>/dev/null || true
      rm -f "$BLE_PID_FILE"
    fi
    nohup "$BLE_BIN" >"$BLE_LOG_FILE" 2>&1 < /dev/null &
    echo $! >"$BLE_PID_FILE"
    echo "[+] Opened GlideDrop macOS UI window (PID $!)."
    ;;
  *)
    echo "Usage: $0 {on|off|status|ui|send [files_or_urls...]}"
    exit 1
    ;;
esac
