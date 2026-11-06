#!/usr/bin/env bash
set -euo pipefail

# Pure P2P AirDrop Receiver & Daemon for macOS <-> Android
# Speaks Apple AirDrop 1.0 (BLE L2CAP + 5GHz Wi-Fi Direct WP2P + mDNS AWDL bridge + TLS 1.2/1.3
# /Discover, /Ask, /Upload with bplist00 and DVZip 070707/070701 CPIO streaming archives).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${AIRDROP_P2P_STATE_DIR:-$HOME/.airdrop-p2p}"
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR" 2>/dev/null || true

PID_FILE="$STATE_DIR/daemon.pid"
MDNS_PID_FILE="$STATE_DIR/mdns.pid"
AWDL_MDNS_PID_FILE="$STATE_DIR/awdl-mdns.pid"
BLE_PID_FILE="$STATE_DIR/ble-daemon.pid"
LOG_FILE="$STATE_DIR/daemon.log"
BLE_LOG_FILE="$STATE_DIR/ble-daemon.log"
BLE_BIN="$STATE_DIR/airdrop-p2p-daemon"
PORT=8772
PROXY_PORT=8773
MAC_SERVICE_ID="airdrop77a8b9c0"

ensure_cert() {
  if [[ ! -f "$STATE_DIR/cert.pem" || ! -f "$STATE_DIR/key.pem" ]]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout "$STATE_DIR/key.pem" -out "$STATE_DIR/cert.pem" \
      -days 3650 -nodes -subj "/CN=airdrop" >/dev/null 2>&1
  fi
}

ensure_ble_bin() {
  if [[ -f "$SCRIPT_DIR/mac-ble-airdrop.swift" ]] && [[ ! -x "$BLE_BIN" || "$SCRIPT_DIR/mac-ble-airdrop.swift" -nt "$BLE_BIN" ]]; then
    xcrun swiftc -O "$SCRIPT_DIR/mac-ble-airdrop.swift" -o "$BLE_BIN" >/dev/null 2>&1 || true
    APP_MACOS="$SCRIPT_DIR/AirDrop P2P.app/Contents/MacOS"
    APP_RES="$SCRIPT_DIR/AirDrop P2P.app/Contents/Resources"
    mkdir -p "$APP_MACOS" "$APP_RES"
    cp -f "$BLE_BIN" "$APP_MACOS/AirDropP2P" 2>/dev/null || true
    cp -f "$SCRIPT_DIR/mac-airdrop-p2p.sh" "$APP_RES/mac-airdrop-p2p.sh" 2>/dev/null || true
    chmod +x "$APP_RES/mac-airdrop-p2p.sh" 2>/dev/null || true
    cat > "$SCRIPT_DIR/AirDrop P2P.app/Contents/Info.plist" << 'PLIST'
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
  <string>2.0</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>NSBluetoothAlwaysUsageDescription</key>
  <string>AirDrop P2P uses Bluetooth LE L2CAP to discover and transfer files with Android devices.</string>
</dict>
</plist>
PLIST
  fi
}

stop_http_daemons() {
  for pf in "$PID_FILE" "$MDNS_PID_FILE" "$AWDL_MDNS_PID_FILE"; do
    if [[ -f "$pf" ]]; then
      kill "$(cat "$pf")" 2>/dev/null || true
      rm -f "$pf"
    fi
  done
  pkill -f "airdropp2p.local." 2>/dev/null || true
  pkill -f "airdrop-p2p.local." 2>/dev/null || true
  pkill -f "$MAC_SERVICE_ID" 2>/dev/null || true
}

stop_daemons() {
  stop_http_daemons
  if [[ -f "$BLE_PID_FILE" ]]; then
    kill "$(cat "$BLE_PID_FILE")" 2>/dev/null || true
    rm -f "$BLE_PID_FILE"
  fi
  pkill -f "airdrop-p2p-daemon" 2>/dev/null || true
  pkill -f "mac-ble-airdrop daemon" 2>/dev/null || true
}

start_daemons() {
  if [[ "${SKIP_BLE_RESTART:-0}" == "1" ]]; then
    stop_http_daemons
  else
    stop_daemons
    rm -f "$STATE_DIR/active_peers.json" "$STATE_DIR/p2p_status" "$STATE_DIR/last_peer_ip"
  fi
  ensure_cert
  ensure_ble_bin

  defaults write com.apple.NetworkBrowser BrowseAllInterfaces -bool true
  defaults write com.apple.Sharing BrowseAllInterfaces -bool true
  defaults delete com.apple.Sharing DisableAWDL 2>/dev/null || true

  # Pure P2P Mode: Do NOT advertise on shared LAN router mDNS (_airdrop._tcp.local. without interface restriction).
  # Discovery is strictly over Direct Bluetooth LE L2CAP + 5GHz Wi-Fi Direct P2P (and local awdl0 for Finder integration).

  # Start Direct Bluetooth LE L2CAP receiver + AWDL 8774->8773 PeerToPeer bridge + Menu Bar item
  if [[ "${SKIP_BLE_RESTART:-0}" != "1" ]]; then
    if [[ ! -f "$BLE_PID_FILE" ]] || ! kill -0 "$(cat "$BLE_PID_FILE")" 2>/dev/null; then
      if [[ -x "$BLE_BIN" ]]; then
        nohup "$BLE_BIN" daemon >"$BLE_LOG_FILE" 2>&1 < /dev/null &
        echo $! >"$BLE_PID_FILE"
      fi
    fi
  fi

  # Start HTTPS AirDrop 1.0 receiver (8772) + Native Finder AirDrop Android proxy (8773)
  nohup python3 -u - "$STATE_DIR/cert.pem" "$STATE_DIR/key.pem" "$PORT" "$PROXY_PORT" "$SCRIPT_DIR/mac-airdrop-p2p.sh" >"$LOG_FILE" 2>&1 << 'PYEOF' &
import gzip, io, json, os, plistlib, shutil, socket, ssl, struct, subprocess, sys, tempfile, threading, time, uuid, zlib
from pathlib import Path

CERT_FILE, KEY_FILE, PORT, PROXY_PORT, SCRIPT_PATH = (
    sys.argv[1],
    sys.argv[2],
    int(sys.argv[3]),
    int(sys.argv[4]),
    sys.argv[5],
)
STATE_DIR = Path(CERT_FILE).parent
DOWNLOADS = Path.home() / "Downloads"
DEFAULT_MAC_NAME = subprocess.check_output(["scutil", "--get", "ComputerName"], text=True).strip() or "MacBook Pro"
MEDIA_CAP = b'{"Version":3,"Codecs":{"hvc1":{"Profiles":{"VTIsHDRAllowedOnDevice":true}}}}'

def load_settings():
    sf = STATE_DIR / "settings.json"
    if sf.exists():
        try:
            return json.loads(sf.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"autoAccept": True, "visible": True, "deviceName": DEFAULT_MAC_NAME}

def current_mac_name():
    return load_settings().get("deviceName") or DEFAULT_MAC_NAME

def write_progress(active: bool, direction: str = "", file_name: str = "", done_bytes: int = 0, total_bytes: int = 0, speed_bps: int = 0, eta_sec: int = 0, pct: int = 0, file_count: int = 1):
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
    tmp = STATE_DIR / "active_peers.json.tmp"
    now = time.time()
    with PEERS_LOCK:
        try:
            peers = json.loads(pf.read_text(encoding="utf-8")) if pf.exists() else {}
            if not isinstance(peers, dict):
                peers = {}
        except Exception:
            peers = {}
        existing = next(iter(peers.values()), None) if peers else None
        if isinstance(existing, dict) and int(existing.get("psm") or 0) > 0 and psm == 0:
            peer_id = str(existing.get("id") or peer_id)
            address = str(existing.get("address") or address)
            psm = int(existing.get("psm") or 0)
            rssi = int(existing.get("rssi") or rssi)
            transport = f"5GHz P2P • BLE PSM {psm}"
        peers = {
            peer_id: {
                "id": peer_id,
                "name": name,
                "transport": transport,
                "address": address,
                "psm": int(psm),
                "rssi": int(rssi),
                "lastSeen": now,
            }
        }
        try:
            tmp.write_text(json.dumps(peers), encoding="utf-8")
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
    subprocess.Popen([
        "osascript",
        "-e", "on run argv",
        "-e", 'display notification (item 1 of argv) with title (item 2 of argv) sound name "Glass"',
        "-e", "end run",
        "--",
        str(message)[:240],
        str(title)[:120],
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def wait_for_user_accept(sender_name: str, file_names: list, total_bytes: int) -> bool:
    s = load_settings()
    if s.get("autoAccept", True):
        return True
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
            time.sleep(1.0)
            if dec_file.exists():
                return
            try:
                res = subprocess.check_output([
                    "osascript",
                    "-e", "on run argv",
                    "-e", 'tell application "System Events" to display dialog ((item 1 of argv) & " wants to share " & (item 2 of argv) & " with you.") with title "AirDrop P2P" buttons {"Decline", "Accept"} default button "Accept" giving up after 40',
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

def read_line(f):
    line = f.readline()
    if not line:
        return None
    return line.decode("iso-8859-1").rstrip("\r\n")

def restore_internet_wifi():
    try:
        for b_name in ["airdrop-p2p-daemon", "mac-ble-airdrop"]:
            ble_bin = STATE_DIR / b_name
            if ble_bin.exists() and os.access(str(ble_bin), os.X_OK):
                subprocess.run([str(ble_bin), "restore-wifi"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                return
        prev_file = STATE_DIR / "previous_wifi_ssid.txt"
        target_ssid = ""
        if prev_file.exists():
            try:
                target_ssid = prev_file.read_text(encoding="utf-8").strip()
            except Exception:
                pass
        # 1. Remove ephemeral P2P networks from preferred list so macOS never reconnects to them
        try:
            pref_out = subprocess.check_output(["/usr/sbin/networksetup", "-listpreferredwirelessnetworks", "en0"], text=True, stderr=subprocess.DEVNULL)
            for line in pref_out.splitlines():
                s = line.strip()
                if s.startswith("DIRECT-"):
                    subprocess.run(["/usr/sbin/networksetup", "-removepreferredwirelessnetwork", "en0", s], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                elif not target_ssid and not s.startswith("Preferred networks"):
                    target_ssid = s
        except Exception:
            pass
        # 2. Fast reassociation directly to preferred home network without cycling card power
        if target_ssid and not target_ssid.startswith("DIRECT-"):
            subprocess.run(["/usr/sbin/networksetup", "-setairportnetwork", "en0", target_ssid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        else:
            subprocess.run(
                ["/usr/sbin/networksetup", "-setairportpower", "en0", "off"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
            )
            time.sleep(0.3)
            subprocess.run(
                ["/usr/sbin/networksetup", "-setairportpower", "en0", "on"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
            )
        if prev_file.exists():
            try:
                prev_file.unlink(missing_ok=True)
            except Exception:
                pass
    except Exception:
        pass

def read_body_bytes(f, headers, track_progress: bool = False, file_label: str = "Incoming File", expected_total: int = 0, file_count: int = 1):
    t0 = time.time()
    last_emit = 0.0
    cancel_file = STATE_DIR / "cancel_transfer.flag"
    if "chunked" in headers.get("transfer-encoding", "").lower():
        out = bytearray()
        while True:
            if track_progress and cancel_file.exists():
                cancel_file.unlink(missing_ok=True)
                write_progress(False)
                raise RuntimeError("Transfer cancelled by user")
            sz_line = read_line(f)
            if sz_line is None:
                break
            sz_line = sz_line.strip()
            if not sz_line:
                continue
            try:
                sz = int(sz_line.split(";", 1)[0].strip(), 16)
            except ValueError:
                continue
            if sz == 0:
                while True:
                    tr = read_line(f)
                    if tr is None or not tr.strip():
                        break
                break
            rem = sz
            while rem > 0:
                if track_progress and cancel_file.exists():
                    cancel_file.unlink(missing_ok=True)
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
                        tot = max(expected_total, done, 1)
                        el = max(0.08, now - t0)
                        spd = int(done / el)
                        eta = int(max(0, tot - done) / max(1, spd))
                        pct = min(99, int((done * 100) / tot))
                        write_progress(True, "Receiving", file_label, done, tot, spd, eta, pct, file_count)
            f.read(2)  # CRLF
        if track_progress:
            write_progress(False)
        return bytes(out)
    clen = int(headers.get("content-length", "0"))
    if clen <= 0:
        return b""
    out = bytearray()
    rem = clen
    while rem > 0:
        if track_progress and cancel_file.exists():
            cancel_file.unlink(missing_ok=True)
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
    def __init__(self, f, on_bytes=None, cancel_file=None):
        self.f = f
        self.on_bytes = on_bytes
        self.cancel_file = cancel_file
        self.chunk_rem = 0
        self.eof = False
        self.last_cancel_check = 0.0

    def read(self, n):
        if self.eof:
            return b""
        while self.chunk_rem == 0:
            now = time.time()
            if now - self.last_cancel_check >= 0.5:
                self.last_cancel_check = now
                if self.cancel_file and self.cancel_file.exists():
                    self.cancel_file.unlink(missing_ok=True)
                    raise RuntimeError("Transfer cancelled by user")
            line = read_line(self.f)
            if line is None:
                self.eof = True
                return b""
            line = line.strip()
            if not line:
                continue
            try:
                sz = int(line.split(";", 1)[0].strip(), 16)
            except ValueError:
                continue
            if sz == 0:
                while True:
                    trailer = read_line(self.f)
                    if trailer is None or not trailer.strip():
                        break
                self.eof = True
                return b""
            self.chunk_rem = sz

        want = min(n, self.chunk_rem)
        chunk = self.f.read(want)
        if not chunk:
            self.eof = True
            return b""
        self.chunk_rem -= len(chunk)
        if self.chunk_rem == 0:
            crlf_buf = bytearray()
            while len(crlf_buf) < 2:
                part = self.f.read(min(2 - len(crlf_buf), 2))
                if not part:
                    break
                crlf_buf.extend(part)
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
    def __init__(self, f, total, on_bytes=None, cancel_file=None):
        self.f = f
        self.rem = total
        self.on_bytes = on_bytes
        self.cancel_file = cancel_file
        self.last_cancel_check = 0.0

    def read(self, n):
        if self.rem <= 0:
            return b""
        now = time.time()
        if now - self.last_cancel_check >= 0.5:
            self.last_cancel_check = now
            if self.cancel_file and self.cancel_file.exists():
                self.cancel_file.unlink(missing_ok=True)
                raise RuntimeError("Transfer cancelled by user")
        want = min(n, self.rem)
        chunk = self.f.read(want)
        if not chunk:
            self.rem = 0
            return b""
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
    def __init__(self, raw_reader):
        self.raw = raw_reader
        self.buf = bytearray()
        self.mode = "unknown"
        self.decompressor = None
        self.dvzip_stored = False
        self.dvzip_rem = 0
        self.eof = False
        self._init_stream()

    def _init_stream(self):
        prefix = self.raw.read_exact(6)
        if len(prefix) < 6:
            self.buf.extend(prefix)
            self.mode = "raw"
            return
        if len(prefix) >= 2 and prefix[0] == 0x1F and prefix[1] == 0x8B:
            self.mode = "gzip"
            self.decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            self.buf.extend(self.decompressor.decompress(prefix))
        elif prefix[:6] in (b"070707", b"070701", b"070702"):
            self.mode = "raw"
            self.buf.extend(prefix)
        else:
            self.mode = "dvzip"
            v = struct.unpack(">I", prefix[:4])[0]
            self.dvzip_stored = bool(v & 0x80000000)
            self.dvzip_rem = v & 0x7FFFFFFF
            if not self.dvzip_stored:
                self.decompressor = zlib.decompressobj()
            first_data = prefix[4:]
            if first_data:
                take = min(len(first_data), self.dvzip_rem)
                bpart = first_data[:take]
                self.dvzip_rem -= len(bpart)
                if self.dvzip_stored:
                    self.buf.extend(bpart)
                else:
                    self.buf.extend(self.decompressor.decompress(bpart))

    def read(self, n):
        while len(self.buf) < n and not self.eof:
            if self.mode == "raw":
                chunk = self.raw.read(max(65536, n - len(self.buf)))
                if not chunk:
                    self.eof = True
                    break
                self.buf.extend(chunk)
            elif self.mode == "gzip":
                chunk = self.raw.read(65536)
                if not chunk:
                    if self.decompressor:
                        self.buf.extend(self.decompressor.flush())
                    self.eof = True
                    break
                self.buf.extend(self.decompressor.decompress(chunk))
            elif self.mode == "dvzip":
                if self.dvzip_rem > 0:
                    want = min(65536, self.dvzip_rem)
                    chunk = self.raw.read_exact(want)
                    if not chunk:
                        self.eof = True
                        break
                    self.dvzip_rem -= len(chunk)
                    if self.dvzip_stored:
                        self.buf.extend(chunk)
                    else:
                        self.buf.extend(self.decompressor.decompress(chunk))
                else:
                    hdr4 = self.raw.read_exact(4)
                    if len(hdr4) < 4:
                        if self.decompressor:
                            self.buf.extend(self.decompressor.flush())
                        self.eof = True
                        break
                    v = struct.unpack(">I", hdr4)[0]
                    self.dvzip_stored = bool(v & 0x80000000)
                    self.dvzip_rem = v & 0x7FFFFFFF
                    if not self.dvzip_stored:
                        self.decompressor = zlib.decompressobj()

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


def extract_cpio_stream(stream, dest_dir: Path):
    saved = []
    while True:
        magic = stream.read_exact(6)
        if len(magic) < 6:
            break
        if magic == b"070707":
            rest = stream.read_exact(70)
            if len(rest) < 70:
                break
            hdr = (magic + rest).decode("ascii")
            mode = int(hdr[18:24], 8)
            namesize = int(hdr[59:65], 8)
            filesize = int(hdr[65:76], 8)
            name = stream.read_exact(namesize).rstrip(b"\x00").decode("utf-8", "replace")
            is_newc = False
        elif magic in (b"070701", b"070702"):
            rest = stream.read_exact(104)
            if len(rest) < 104:
                break
            hdr = (magic + rest).decode("ascii")
            mode = int(hdr[14:22], 16)
            filesize = int(hdr[54:62], 16)
            namesize = int(hdr[94:102], 16)
            name = stream.read_exact(namesize).rstrip(b"\x00").decode("utf-8", "replace")
            if (110 + namesize) % 4 != 0:
                stream.read_exact(4 - ((110 + namesize) % 4))
            is_newc = True
        else:
            break
        if name == "TRAILER!!!":
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
                safe_name = raw_base.lstrip(".") or "airdrop_file"
                target = dest_dir / safe_name
                if target.resolve().parent == dest_dir.resolve():
                    idx = 1
                    while target.exists():
                        target = dest_dir / f"{target.stem}_{idx}{target.suffix}"
                        idx += 1
                    with target.open("wb", buffering=1048576) as out_f:
                        rem = filesize
                        while rem > 0:
                            c = stream.read(min(262144, rem))
                            if not c:
                                break
                            out_f.write(c)
                            rem -= len(c)
                    if rem > 0:
                        saved_bytes = filesize - rem
                        print(f"[!] Warning: Transfer stream truncated: preserved {saved_bytes} of {filesize} bytes in {target}")
                        saved.append(target)
                        raise IOError(f"Transfer stream truncated: expected {filesize} bytes, missing {rem} bytes")
                    saved.append(target)
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
            stream.read_exact(4 - (filesize % 4))
    return saved


def stream_upload_to_dir(f, headers, dest_dir: Path, track_progress: bool = False, file_label: str = "Incoming File", expected_total: int = 0, file_count: int = 1):
    t0 = time.time()
    last_emit = [0.0]
    last_term_log = [0.0]
    last_touch = [0.0]
    done = [0]
    cancel_file = STATE_DIR / "cancel_transfer.flag"
    rx_lock = STATE_DIR / "rx_in_progress.lock"

    def on_bytes_read(n):
        done[0] += n
        now = time.time()
        if now - last_touch[0] >= 1.0:
            last_touch[0] = now
            try:
                rx_lock.write_text(f"{os.getpid()}\tactive\t{now}")
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
                write_progress(True, "Receiving", file_label, min(done[0], tot), tot, spd, eta, pct, file_count)
                if now - last_term_log[0] >= 2.0 or done[0] >= tot:
                    last_term_log[0] = now
                    mb_done = done[0] / (1024 * 1024)
                    mb_tot = tot / (1024 * 1024)
                    spd_mb = spd / (1024 * 1024)
                    print(f"[P2P-Receiver] Receiving '{file_label}': {mb_done:.1f} MB / {mb_tot:.1f} MB ({pct}%, {spd_mb:.1f} MB/s, ETA {eta}s)")
                    sys.stdout.flush()

    try:
        is_chunked = "chunked" in headers.get("transfer-encoding", "").lower()
        if is_chunked:
            raw_reader = ChunkedReader(f, on_bytes=on_bytes_read, cancel_file=cancel_file)
        else:
            clen = int(headers.get("content-length", "0"))
            raw_reader = FixedLengthReader(f, clen, on_bytes=on_bytes_read, cancel_file=cancel_file)

        decompressor = StreamDecompressor(raw_reader)
        saved = extract_cpio_stream(decompressor, dest_dir)
        if track_progress:
            write_progress(False)
        return saved, done[0]
    finally:
        if track_progress:
            write_progress(False)

FORWARD_LOCK = threading.Lock()
RECENT_UPLOADS = {}

def forward_to_peer_worker(tmp_dir: Path, saved_files):
    with FORWARD_LOCK:
        try:
            if saved_files:
                subprocess.run([SCRIPT_PATH, "send"] + [str(p) for p in saved_files], check=False)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

def send_resp(conn, status: int, reason: str, body: bytes = b""):
    hdr = f"HTTP/1.1 {status} {reason}\r\nContent-Length: {len(body)}\r\n\r\n".encode("ascii")
    conn.sendall(hdr + body)

def handle_client(conn, addr, is_p2p_proxy: bool = False):
    last_sender = "Android Peer"
    last_label = "Incoming File"
    last_total = 0
    last_count = 1
    peer_ip = str(addr[0]).replace("::ffff:", "")
    rx_lock = STATE_DIR / "rx_in_progress.lock"
    if not is_p2p_proxy and peer_ip.startswith("192.168.49."):
        try:
            rx_lock.write_text(f"{os.getpid()}\t{peer_ip}\t{time.time()}")
        except Exception:
            pass
    try:
        conn.settimeout(300.0)
        f = conn.makefile("rb", buffering=262144)
        while True:
            req_line = read_line(f)
            if not req_line:
                break
            parts = req_line.split(" ")
            method, path = parts[0], (parts[1] if len(parts) > 1 else "/")
            headers = {}
            while True:
                l = read_line(f)
                if not l:
                    break
                if ":" in l:
                    k, v = l.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            is_upload = (method == "POST" and path == "/Upload")
            exp_tot = int(headers.get("totalbytes", "0") or 0) or last_total
            body = b"" if is_upload else read_body_bytes(
                f,
                headers,
                track_progress=False,
                file_label=last_label,
                expected_total=exp_tot,
                file_count=last_count,
            )
            role = "Finder-Proxy" if is_p2p_proxy else "P2P-Receiver"
            if not is_upload:
                print(f"[{role}] {method} {path} from {addr} ({len(body)} B)")
            else:
                tot_mb = exp_tot / (1024 * 1024)
                print(f"[{role}] {method} {path} from {addr} (streaming incoming file: '{last_label}', ~{tot_mb:.1f} MB)...")
            sys.stdout.flush()
            peer_ip = addr[0].replace("::ffff:", "")
            if not is_p2p_proxy:
                try:
                    if not peer_ip.startswith("127.") and not peer_ip.startswith("::1") and not peer_ip.startswith("fe80:"):
                        (STATE_DIR / "last_peer_ip").write_text(peer_ip)
                except Exception:
                    pass

            active_peer_name = (get_active_peers(12.0)[0].get("name") if get_active_peers(12.0) else "Android Peer")
            if method == "POST" and path == "/Discover":
                if not is_p2p_proxy and peer_ip.startswith("192.168.49."):
                    record_active_peer(f"p2p-{peer_ip}", active_peer_name, "5GHz Wi-Fi Direct P2P", f"{peer_ip}:8771", -48, 0)
                resp = plistlib.dumps({
                    "ReceiverComputerName": active_peer_name if is_p2p_proxy else current_mac_name(),
                    "ReceiverModelName": "iPhone16,2" if is_p2p_proxy else "MacBookPro18,2",
                    "ReceiverMediaCapabilities": MEDIA_CAP,
                    "IsAirDropable": True,
                }, fmt=plistlib.FMT_BINARY)
                send_resp(conn, 200, "OK", resp)
            elif method == "POST" and path == "/Ask":
                try:
                    info = plistlib.loads(body) if body else {}
                except Exception:
                    info = {}
                if not isinstance(info, dict):
                    info = {}
                items = info.get("Items") or []
                files = info.get("Files") or []
                last_sender = str(info.get("SenderComputerName") or active_peer_name)
                if not is_p2p_proxy and peer_ip.startswith("192.168.49."):
                    record_active_peer(f"p2p-{peer_ip}", last_sender, "5GHz Wi-Fi Direct P2P", f"{peer_ip}:8771", -48, 0)
                fnames = [str(fd.get("FileName") or "file") for fd in files if isinstance(fd, dict)]
                last_label = fnames[0] if fnames else (str(items[0]) if items else "Incoming File")
                last_count = max(1, len(fnames))
                last_total = sum(int(fd.get("FileSize") or 0) for fd in files if isinstance(fd, dict))

                if not is_p2p_proxy:
                    if not wait_for_user_accept(last_sender, fnames if fnames else [str(x) for x in items], last_total):
                        print(f"[P2P-Receiver] Declined transfer from {last_sender}")
                        send_resp(conn, 403, "Forbidden", b"")
                        break
                    for it in items:
                        if isinstance(it, str) and (it.startswith("http://") or it.startswith("https://")):
                            append_history("URL", it, len(it), "received", last_sender)
                            subprocess.Popen(["open", it])
                resp = plistlib.dumps({
                    "ReceiverComputerName": active_peer_name if is_p2p_proxy else current_mac_name(),
                    "ReceiverModelName": "iPhone16,2" if is_p2p_proxy else "MacBookPro18,2",
                    "ReceiverMediaCapabilities": MEDIA_CAP,
                    "IsAirDropable": True,
                }, fmt=plistlib.FMT_BINARY)
                send_resp(conn, 200, "OK", resp)
            elif method == "POST" and path == "/Upload":
                if is_p2p_proxy:
                    tmp_dir = Path(tempfile.mkdtemp(prefix="airdrop_finder_proxy_"))
                    saved, rx_len = stream_upload_to_dir(f, headers, tmp_dir, track_progress=False, file_label=last_label, expected_total=exp_tot, file_count=last_count)
                    print(f"[{role}] {method} {path} from {addr} ({rx_len} B)")
                    sig = tuple((p.name, p.stat().st_size) for p in saved)
                    now = time.time()
                    send_resp(conn, 200, "OK", b"")
                    if sig and (now - RECENT_UPLOADS.get(sig, 0.0)) < 60.0:
                        print(f"[Finder-Proxy] Skipping duplicate retry for {[p.name for p in saved]}")
                        shutil.rmtree(tmp_dir, ignore_errors=True)
                    else:
                        if sig:
                            RECENT_UPLOADS[sig] = now
                        print(f"[Finder-Proxy] Forwarding {len(saved)} file(s) from Finder AirDrop to {active_peer_name}: {[p.name for p in saved]}")
                        threading.Thread(target=forward_to_peer_worker, args=(tmp_dir, saved), daemon=True).start()
                    break
                else:
                    saved, rx_len = stream_upload_to_dir(f, headers, DOWNLOADS, track_progress=True, file_label=last_label, expected_total=exp_tot, file_count=last_count)
                    print(f"[{role}] {method} {path} from {addr} ({rx_len} B)")
                    for p in saved:
                        sz = p.stat().st_size
                        print(f"[+] Saved to {p} ({sz} B)")
                        append_history("FILE", str(p), sz, "received", last_sender)
                        safe_notify(f"Saved {p.name} to Downloads", f"AirDrop from {last_sender}")
                        # Automatic Claude AI Analysis & Ingestion Hook
                        try:
                            claude_py = SCRIPT_DIR / "claude_processor.py"
                            if not claude_py.exists():
                                claude_py = Path(__file__).resolve().parent / "claude_processor.py"
                            if claude_py.exists():
                                subprocess.Popen([sys.executable, str(claude_py), str(p)])
                        except Exception:
                            pass
                    send_resp(conn, 200, "OK", b"")
                    try:
                        (STATE_DIR / "upload_completed.flag").write_text(str(time.time()))
                    except Exception:
                        pass
                    break
            else:
                send_resp(conn, 400, "Bad Request", b"")
                break
    except Exception as e:
        write_progress(False)
        print(f"[-] Client {addr} error: {e}")
    finally:
        write_progress(False)
        try:
            rx_lock.unlink(missing_ok=True)
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT_FILE, KEY_FILE)

def serve_port(bind_port: int, is_p2p_proxy: bool):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", bind_port))
    sock.listen(16)
    label = "Finder AirDrop Proxy" if is_p2p_proxy else f"5GHz Wi-Fi Direct P2P Receiver ('{current_mac_name()}')"
    print(f"[+] {label} listening on *:{bind_port}")
    while True:
        raw, addr = sock.accept()
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
            except Exception:
                pass
            tls = ctx.wrap_socket(raw, server_side=True)
            threading.Thread(target=handle_client, args=(tls, addr, is_p2p_proxy), daemon=True).start()
        except Exception:
            raw.close()

def watch_awdl_mdns():
    pid_file = STATE_DIR / "awdl-mdns.pid"
    rx_lock = STATE_DIR / "rx_in_progress.lock"
    cur_ip = None
    proc = None
    while True:
        try:
            if rx_lock.exists():
                time.sleep(2.0)
                continue
            active_peers = get_active_peers(12.0)
            if not active_peers:
                if proc and proc.poll() is None:
                    proc.terminate()
                proc = None
                cur_ip = None
                if pid_file.exists():
                    pid_file.unlink()
                time.sleep(2.0)
                continue
            out = subprocess.check_output(["ifconfig", "awdl0"], text=True, stderr=subprocess.DEVNULL)
            new_ip = None
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet6 fe80:"):
                    new_ip = line.split()[1].split("%")[0]
                    break
            if new_ip and (new_ip != cur_ip or (proc and proc.poll() is not None)):
                if proc and proc.poll() is None:
                    proc.terminate()
                proc = subprocess.Popen(
                    ["dns-sd", "-i", "awdl0", "-P", "380d472980b9", "_airdrop._tcp", "local.", "8774", "airdropp2p.local.", new_ip, "flags=136"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                pid_file.write_text(str(proc.pid))
                cur_ip = new_ip
                print(f"[AWDL-mDNS] Advertising active peer ({active_peers[0].get('name')}) on awdl0 at {cur_ip}:8774 (PID {proc.pid})")
        except Exception:
            pass
        time.sleep(2.0)

threading.Thread(target=watch_awdl_mdns, daemon=True).start()
threading.Thread(target=serve_port, args=(PROXY_PORT, True), daemon=True).start()
serve_port(PORT, False)
PYEOF
  echo $! >"$PID_FILE"
  echo "[+] 5GHz Wi-Fi Direct P2P Receiver ($PORT) + Native Finder AirDrop Proxy (8774->8773) running."
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
    defaults delete com.apple.NetworkBrowser BrowseAllInterfaces 2>/dev/null || true
    defaults delete com.apple.Sharing BrowseAllInterfaces 2>/dev/null || true
    defaults delete com.apple.Sharing DisableAWDL 2>/dev/null || true
    echo "[+] Stopped AirDrop P2P daemons and restored defaults."
    ;;
  status)
    echo "=== AirDrop P2P (5GHz Wi-Fi Direct + BLE L2CAP + Native Finder AirDrop) Status ==="
    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      echo "5GHz P2P Receiver:    RUNNING (PID $(cat "$PID_FILE"), port $PORT -> ~/Downloads, Proxy $PROXY_PORT)"
    else
      echo "5GHz P2P Receiver:    STOPPED"
    fi
    if [[ -f "$AWDL_MDNS_PID_FILE" ]] && kill -0 "$(cat "$AWDL_MDNS_PID_FILE")" 2>/dev/null; then
      echo "Finder AirDrop Proxy: ADVERTISING on awdl0 (380d472980b9._airdrop._tcp.local.:8774 -> Android Peer)"
    else
      echo "Finder AirDrop Proxy: STOPPED"
    fi
    if [[ -f "$BLE_PID_FILE" ]] && kill -0 "$(cat "$BLE_PID_FILE")" 2>/dev/null; then
      echo "Direct BLE L2CAP RX:  RUNNING (PID $(cat "$BLE_PID_FILE") -> ~/Downloads + AWDL 8774 Bridge)"
    else
      echo "Direct BLE L2CAP RX:  STOPPED"
    fi
    ;;
    if [[ -f "$BLE_PID_FILE" ]] && kill -0 "$(cat "$BLE_PID_FILE")" 2>/dev/null; then
      echo "Direct BLE L2CAP RX:  RUNNING (PID $(cat "$BLE_PID_FILE") -> ~/Downloads + AWDL 8774 Bridge)"
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
        SELECTED="$(osascript -e 'POSIX path of (choose file with prompt "Select a file to AirDrop to Android device:")' 2>/dev/null || true)"
      fi
      if [[ -z "$SELECTED" ]]; then
        exit 0
      fi
      set -- "$SELECTED"
    fi
    ensure_ble_bin
    if ! STATE_DIR="$STATE_DIR" python3 - "$@" << 'PYEOF'
import json, os, plistlib, re, socket, ssl, struct, subprocess, sys, time, zlib
from pathlib import Path

STATE_DIR = Path(os.environ.get("AIRDROP_P2P_STATE_DIR", Path.home() / ".airdrop-p2p"))

def write_progress(active: bool, direction: str = "", file_name: str = "", done_bytes: int = 0, total_bytes: int = 0, speed_bps: int = 0, eta_sec: int = 0, pct: int = 0, file_count: int = 1):
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
    subprocess.Popen([
        "osascript",
        "-e", "on run argv",
        "-e", 'display notification (item 1 of argv) with title (item 2 of argv) sound name "Glass"',
        "-e", "end run",
        "--",
        str(message)[:240],
        str(title)[:120],
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

args = sys.argv[1:]
peer_override = None
if len(args) >= 2 and args[0] == "--peer":
    peer_override = args[1]
    args = args[2:]

urls = [a for a in args if a.startswith("http://") or a.startswith("https://")]
file_args = [a for a in args if a not in urls]
files = [Path(a).expanduser().resolve() for a in file_args]
for f in files:
    if not f.is_file():
        sys.exit(f"File not found: {f}")

total_bytes = sum(f.stat().st_size for f in files)
joined_p2p = False

def discover_android():
    global joined_p2p
    try:
        with socket.create_connection(("192.168.49.1", 8771), timeout=0.25):
            return "192.168.49.1", 8771
    except Exception:
        pass
    raise RuntimeError("Deferring to BLE L2CAP + 5GHz Wi-Fi Direct P2P")

try:
    if peer_override:
        host, _, port_s = peer_override.partition(":")
        port = int(port_s) if port_s else 8771
    else:
        host, port = discover_android()

    print(f"[+] Connecting to Android peer over 5GHz Wi-Fi at {host}:{port}...")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    def read_http_response(f):
        status_line = f.readline().decode("iso-8859-1").strip()
        headers = {}
        while True:
            line = f.readline().decode("iso-8859-1").strip()
            if not line:
                break
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
        clen = int(headers.get("content-length", "0"))
        body = f.read(clen) if clen else b""
        return status_line, body

    t0 = time.time()
    raw = None
    last_conn_err = None
    max_attempts = 14 if peer_override else 1
    for attempt in range(max_attempts):
        try:
            raw = socket.create_connection((host, port), timeout=1.5)
            break
        except Exception as e:
            last_conn_err = e
            if attempt + 1 < max_attempts:
                time.sleep(0.35)
    if raw is None:
        raise last_conn_err or RuntimeError(f"Could not connect to {host}:{port}")

    with raw:
        raw.settimeout(300.0)
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.settimeout(300.0)
            f = s.makefile("rb")
            disc = plistlib.dumps({"DeviceSupportFlags": 111611}, fmt=plistlib.FMT_BINARY)
            s.sendall(f"POST /Discover HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/octet-stream\r\nContent-Length: {len(disc)}\r\nConnection: keep-alive\r\n\r\n".encode() + disc)
            st, body = read_http_response(f)
            peer_name = plistlib.loads(body).get("ReceiverComputerName", "Android Device") if body else "Android Device"
            print(f"[+] Discovered receiver: {peer_name} ({st})")

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
            s.sendall(f"POST /Ask HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/octet-stream\r\nContent-Length: {len(ask)}\r\nConnection: keep-alive\r\n\r\n".encode() + ask)
            st2, _ = read_http_response(f)
            if "403" in st2:
                print(f"[-] Transfer declined by {peer_name}")
                sys.exit(43)
            if "200" not in st2:
                sys.exit(f"[-] Transfer declined or failed: {st2}")
            if files:
                label = files[0].name
                fcount = len(files)
                tot = max(1, sum(p.stat().st_size for p in files))
                print(f"[+] /Ask accepted ({st2}), streaming DVZip CPIO archive over 5GHz Wi-Fi Direct...")
                hdr_bytes = (
                    f"POST /Upload HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"Content-Type: application/x-dvzip\r\n"
                    f"TotalBytes: {tot}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Connection: keep-alive\r\n\r\n"
                ).encode("ascii")
                s.sendall(hdr_bytes)
                tx_start = time.time()
                last_emit = 0.0
                off = 0
                cancel_file = STATE_DIR / "cancel_transfer.flag"
                write_progress(True, "Sending", label, 0, tot, 0, 0, 0, fcount)

                def send_dvzip_block(raw_block: bytes):
                    if not raw_block:
                        return
                    if cancel_file.exists():
                        write_progress(False)
                        sys.exit("[-] Transfer cancelled by user")
                    pkt = struct.pack(">I", 0x80000000 | len(raw_block)) + raw_block
                    s.sendall(f"{len(pkt):x}\r\n".encode("ascii") + pkt + b"\r\n")

                def make_odc_hdr(ino: int, mode: int, name: str, fsize: int) -> bytes:
                    nb = name.encode("utf-8") + b"\x00"
                    return f"070707{0:06o}{ino:06o}{mode:06o}{0:06o}{0:06o}{1:06o}{0:06o}{int(time.time()):011o}{len(nb):06o}{fsize:011o}".encode("ascii") + nb

                send_dvzip_block(make_odc_hdr(1, 0o040755, ".", 0))
                ino = 2
                for p in files:
                    fsize = p.stat().st_size
                    send_dvzip_block(make_odc_hdr(ino, 0o100644, "./" + p.name, fsize))
                    ino += 1
                    with p.open("rb") as pf:
                        while True:
                            chunk = pf.read(262144)
                            if not chunk:
                                break
                            send_dvzip_block(chunk)
                            off += len(chunk)
                            now = time.time()
                            if now - last_emit >= 0.08 or off >= tot:
                                last_emit = now
                                el = max(0.08, now - tx_start)
                                spd = int(off / el)
                                eta = int(max(0, tot - off) / max(1, spd))
                                pct = min(99, int((off * 100) / max(1, tot)))
                                write_progress(True, "Sending", label, min(off, tot), tot, spd, eta, pct, fcount)
                send_dvzip_block(make_odc_hdr(0, 0, "TRAILER!!!", 0))
                s.sendall(b"0\r\n\r\n")
                write_progress(False)
                st3, _ = read_http_response(f)
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
            safe_notify(f"Sent {names} to {peer_name} in {elapsed:.1f}s", "AirDrop Complete")
finally:
    write_progress(False)
PYEOF
    then
      if [[ "${1:-}" == "--peer" || -f "$STATE_DIR/cancel_transfer.flag" ]]; then
        rm -f "$STATE_DIR/cancel_transfer.flag"
        exit 1
      fi
      echo "[*] Wi-Fi unreachable — switching to Direct Bluetooth LE L2CAP..."
      "$BLE_BIN" send "$@"
      osascript -e "display notification \"Sent to Android device over Direct Bluetooth\" with title \"AirDrop Complete\"" 2>/dev/null || true
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
    echo "[+] Opened AirDrop P2P macOS UI window (PID $!)."
    ;;
  *)
    echo "Usage: $0 {on|off|status|ui|send [files_or_urls...]}"
    exit 1
    ;;
esac
