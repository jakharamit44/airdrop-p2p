# AirDrop P2P Architecture & Protocol Specification

AirDrop P2P transfers files, links, and text notes directly between Android (API 31+) and macOS (13+) without a shared Wi-Fi router, local area network (LAN), cloud relay, or USB cable.

## 1. Bidirectional Transfer Flow

```
[Android Device]                                              [MacBook / macOS]
       |                                                             |
       |  1. BLE L2CAP Discovery & Ping/Pong                         |
       |<----------------------------------------------------------->|
       |     * Advertises custom 128-bit BLE service & L2CAP PSM     |
       |     * Exchanges localized device name, PSM, and RSSI        |
       |                                                             |
       |  2. Ephemeral ECDH P-256 Handshake (W2P2)                   |
       |<----------------------------------------------------------->|
       |     * Exchanges secp256r1 DER public keys & SHA-256 TLS     |
       |       certificate fingerprints                              |
       |     * Derives AES-256-GCM session key via SHA-256           |
       |     * Transfers encrypted 5 GHz Wi-Fi Direct SSID + key     |
       |                                                             |
       |  3. Wi-Fi Direct Association & Address Assignment           |
       |     * Mac prompts user before joining DIRECT-* SSID         |
       |       (unless Auto-Accept is enabled in macOS settings)     |
       |     * Mac associates via CoreWLAN / networksetup            |
       |     * Mac receives P2P DHCP IP (192.168.49.x)               |
       |     * Optional: Mac points SOCKS5/HTTP proxy to :1080       |
       |                                                             |
       |  4. Pinned TLS HTTPS Stream (/Discover, /Ask, /Upload)      |
       |     * POST /Discover (bplist00 capability negotiation)      |
       |     * POST /Ask (bplist00 file/URL metadata & approval)     |
       |     * POST /Upload (DVZip/CPIO chunked archive stream)      |
       |<===========================================================>| (45+ MB/s)
       |     * 2.0s UDP ARP keepalive over 192.168.49.x              |
       |                                                             |
       |  5. Clean Teardown & Network Restore                        |
       |     * Mac restores snapshot proxy settings (no sudo)        |
       |     * Mac removes DIRECT-* from preferred networks          |
       |     * CoreWLAN disassociates so airportd rejoins home Wi-Fi |
       |     * Cloudflare WARP resumes if previously active          |
       |                                                             |
       |  6. Optional Sidecar Analysis (macOS Receiver)              |
       |     * Off by default; runs Apple Vision OCR / Ollama /      |
       |       Anthropic Claude with local Privacy Guard             |
```

## 2. Core Subsystems

### A. Discovery & Fallback Layer (BLE L2CAP)

* **L2CAP CoC Channels**: Android and macOS open direct Bluetooth Low Energy L2CAP Connection-Oriented Channels (`CBPeripheralManager` / `BluetoothServerSocket.listenUsingL2capChannel`) using dynamically assigned PSMs, avoiding GATT MTU bottlenecks.
* **Hardware-Agnostic Naming**: Android builds names from `${Build.MANUFACTURER} ${Build.MODEL}` (or user override); macOS uses `Host.current().localizedName` or `scutil --get ComputerName`.
* **Direct BLE Transfers (`ADRE`)**: Payloads under 64 KiB, URLs, and transfers where Wi-Fi Direct association fails fall back to AES-256-GCM `ADRE` frames over BLE L2CAP (using the built-in BLE frame key, capped at 30 MB on Android to avoid JVM out-of-memory failures).

### B. Transport Layer (5 GHz Wi-Fi Direct + CPIO Streaming)

* **Autonomous 5 GHz Group**: Android creates a temporary Wi-Fi Direct Group Owner (GO) on 5 GHz (Band 4 / UNII-3) with a per-session random 12-hex-character WPA2 passphrase.
* **DVZip + Extended 64-bit CPIO**: Archives stream directly from source file descriptors over HTTP/1.1 chunked encoding to `/Upload` (`port 8772` on macOS, `port 8771` on Android). Files up to 8 GiB use standard POSIX `070707` headers; files 8 GiB and larger switch to extended `070764` headers with 64-bit hex sizes, writing safely via `.part` staging and canonical destination checks.
* **macOS Finder AirDrop Proxy (`awdl0`)**: When an Android peer is nearby, macOS advertises `_airdrop._tcp` on `awdl0:8774`, receives drops on `127.0.0.1:8773`, and forwards them to the Android peer.

### C. Kernel Neighbor Cache Keepalive

Unidirectional HTTP uploads at 45+ MB/s can starve reverse ARP traffic, causing the Linux neighbor table on Android to mark the peer `STALE` after roughly 30 seconds and drop packets. During active 5 GHz sessions, `AirDropNode` emits UDP keepalive pulses every 2.0 seconds to port `8774` over the `p2p-wlan0-*` network so the neighbor entry stays in `NUD_REACHABLE` throughout multi-gigabyte transfers.

### D. Embedded Dual-Protocol Internet Proxy (`port 1080`)

When macOS switches Wi-Fi to the offline `DIRECT-*` SSID, [`EmbeddedProxyServer.kt`](../android/app/src/main/java/com/airdrop/p2p/EmbeddedProxyServer.kt) can serve SOCKS5 (RFC 1928) and HTTP `CONNECT`/Forward traffic on port `1080`, binding outbound sockets to Android's active validated internet network or cellular fallback (`ConnectivityManager`).

* Only `192.168.49.0/24` and loopback clients are accepted.
* Post-DNS SSRF checks block connections back to loopback/P2P control ports (`8771`, `1080`) and the `192.168.49.0/24` subnet.
* On macOS, `mac-ble-airdrop.swift` serializes snapshot and restore operations under an advisory file lock (`proxy_state.lock`) via `networksetup`, preserving existing proxy settings and bypass domains without `sudo`.

### E. macOS Wi-Fi & VPN Recovery

Before joining a Wi-Fi Direct SSID, macOS records the active Wi-Fi network, pauses Cloudflare WARP (`warp-cli`) if connected, and ensures `DIRECT-*` entries are purged from preferred networks afterwards. Disassociating via CoreWLAN lets `airportd` rejoin the user's primary Wi-Fi without power-cycling the shared Wi-Fi/Bluetooth radio.

### F. Optional AI Sidecar Processor (`claude_processor.py`)

When explicitly enabled, received files on macOS pass through a local Privacy Guard (blocking private keys, `.pem`, `.key`, `.env*`, and API tokens by filename and regex inspection). Benign files can be summarized offline via macOS Apple Vision OCR and a local Ollama instance (`http://localhost:11434`), or via Anthropic's Messages API (`claude-3-5-sonnet-latest` with fallback to Haiku/Opus).
