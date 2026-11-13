# GlideDrop Architecture & Protocol Specification

GlideDrop transfers files, links, and text notes directly between Android (API 31+) and macOS (13+) without a shared Wi-Fi router, local area network (LAN), cloud relay, or USB cable.

## 1. Bidirectional Transfer Flow

```
[Android Device]                                              [MacBook / macOS]
       |                                                             |
       |  1. BLE L2CAP Discovery & Ping/Pong                         |
       |<----------------------------------------------------------->|
       |     * Advertises 128-bit BLE service UUID & PSM only        |
       |       (device name is not advertised)                       |
       |     * Name exchanged after connect, inside L2CAP            |
       |                                                             |
       |  2. Ephemeral ECDH P-256 Handshake (W2P2)                   |
       |<----------------------------------------------------------->|
       |     * W2P2 v3: pubkey + TLS fingerprint + random session ID |
       |     * HKDF-SHA256 -> AES key, bearer token, 6-digit code    |
       |     * Phone consent dialog shows code; optional per-Mac     |
       |       fingerprint trust                                     |
       |     * Encrypted random SSID/passphrase + OS-assigned ports  |
       |                                                             |
       |  3. Wi-Fi Direct Association & Address Assignment           |
       |     * Mac always prompts before joining DIRECT-* SSID       |
       |       (`forcePrompt: true`, even when Auto-Accept is on)    |
       |     * Mac associates via CoreWLAN / networksetup            |
       |     * Mac receives dynamic OS P2P DHCP IP (active CIDR)     |
       |     * Optional: Mac points SOCKS5/HTTP proxy to exchanged port|
       |                                                             |
       |  4. Pinned TLS HTTPS Stream (OS-assigned ports) (/Discover, /Ask, /Upload)      |
       |     * POST /Discover (bplist00 capability negotiation)      |
       |     * POST /Ask (bplist00 file/URL metadata & approval)     |
       |     * POST /Upload (DVZip/CPIO chunked archive stream)      |
       |<===========================================================>| (45+ MB/s)
       |     * 2.0s UDP ARP keepalive over active P2P subnet         |
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

### 0. Handshake v3 and Requirements

* **Both sides must match**: `W2P2` v3 is incompatible with earlier builds. A v1/v2 request gets an update-required reply and no downgrade. Update Mac and Android together.
* **Key schedule**: ECDH P-256 shared secret is expanded with HKDF-SHA256 (salt = random 16-byte session ID; info = `GlideDrop-v3/<label>` plus length-prefixed public keys and TLS fingerprints of both sides). Separate labels produce the AES-256-GCM key, the bearer token, and the 6-digit verification code.
* **Consent**: the phone shows a consent dialog (20 s window) with the code before creating a group. The user may trust that Mac's TLS fingerprint for later sessions. Pending replies and handshake rates are bounded.
* **L2CAP server limits (Android)**: 30 s pre-auth idle timeout, 4 concurrent connections, 6 handshakes per 60 s per peer and 12 per 60 s globally.
* **Ports**: no fixed ports are compiled in. Every listener binds port 0 and the assigned port is sent in the handshake. Listeners bind the wildcard address, and non-P2P source addresses are dropped before TLS. Port numbers such as 8771/8772/8774/1080 seen in older docs are historical defaults, not current behavior.
* **Local secrets**: the peer TLS pin and token reach child processes through `0600` one-time files, not argv or environment.
* **macOS Location Services**: needed so macOS reveals Wi-Fi names (CoreWLAN) during join and restore. The app falls back to interface-state checks when it is denied.

### A. Discovery & Fallback Layer (BLE L2CAP)

* **L2CAP CoC Channels**: Android and macOS open direct Bluetooth Low Energy L2CAP Connection-Oriented Channels (`CBPeripheralManager` / `BluetoothServerSocket.listenUsingL2capChannel`) using dynamically assigned PSMs, avoiding GATT MTU bottlenecks.
* **Hardware-Agnostic Naming**: BLE advertisements omit the name. Android builds names from `${Build.MANUFACTURER} ${Build.MODEL}` (or user override); macOS uses `Host.current().localizedName` or `scutil --get ComputerName`.
* **Direct BLE Transfers (`BLEK` & `ADRE`)**: Payloads under 64 KiB, URLs, and transfers where Wi-Fi Direct association fails run an ephemeral ECDH P-256 handshake (`BLEK`) before sending AES-256-GCM encrypted `ADRE` frames over BLE L2CAP (capped at 30 MB on Android to avoid JVM out-of-memory failures). Legacy unencrypted `ADRP` and unpinned `WP2P` fallbacks fail closed.

### B. Transport Layer (5 GHz Wi-Fi Direct + CPIO Streaming)

* **Autonomous 5 GHz Group**: Android creates a temporary Wi-Fi Direct Group Owner (GO) on 5 GHz (Band 4 / UNII-3) with a per-session random SSID and WPA2 passphrase.
* **DVZip + Extended 64-bit CPIO**: Archives stream directly from source file descriptors over HTTP/1.1 chunked encoding to `/Upload` (OS-assigned HTTPS port on each side). Files up to 8 GiB use standard POSIX `070707` headers; files 8 GiB and larger switch to extended `070764` headers with 64-bit hex sizes, writing safely via `.part` staging and canonical destination checks.
* **macOS Finder Share Proxy (`awdl0`)**: When an Android peer is nearby, macOS advertises internal `_airdrop._tcp` on `awdl0` (OS-assigned port) (`glidedrop.local.`), verifies `awdl*` interface/endpoint provenance in `AwdlLoopbackBridge`, forwards over a mode-`0600` Unix domain socket (`~/.glidedrop/finder_proxy.sock`) inside `0700` `~/.glidedrop`, and dispatches received items to the Android peer.

### C. Kernel Neighbor Cache Keepalive

Unidirectional HTTP uploads at 45+ MB/s can starve reverse ARP traffic, causing the Linux neighbor table on Android to mark the peer `STALE` after roughly 30 seconds and drop packets. During active 5 GHz sessions, `GlideDropNode` emits UDP keepalive pulses every 2.0 seconds to the peer's exchanged keepalive port over the `p2p-wlan0-*` network so the neighbor entry stays in `NUD_REACHABLE` throughout multi-gigabyte transfers.

### D. Embedded Dual-Protocol Internet Proxy (OS-assigned port)

When macOS switches Wi-Fi to the offline `DIRECT-*` SSID, [`EmbeddedProxyServer.kt`](../android/app/src/main/java/io/github/jakharamit44/glidedrop/EmbeddedProxyServer.kt) can serve SOCKS5 (RFC 1928) and HTTP `CONNECT`/Forward traffic on an OS-assigned port, binding outbound sockets to Android's active validated internet network or cellular fallback (`ConnectivityManager`).

* Only active OS-resolved Wi-Fi Direct P2P subnet clients are accepted (opt-in setting, off by default; loopback denied in production).
* Pre- and post-DNS SSRF checks reject loopback, wildcard, RFC 1918 private LAN, link-local (`169.254.0.0/16`, `fe80::/10`), IPv6 ULA (`fc00::/7`), NAT64, `.localdomain`, and multicast destinations across all ports, while header filtering rejects `TE.CL`/`CL.CL` request smuggling (`400 Bad Request`), strips `Proxy-Authorization`, and blocks `Upgrade` smuggling.
* On macOS, `glidedrop-daemon.swift` serializes snapshot and restore operations under an advisory file lock (`proxy_state.lock`) via `networksetup`, preserving existing proxy settings and bypass domains without `sudo`.

### E. macOS Wi-Fi & VPN Recovery

Before joining a Wi-Fi Direct SSID, macOS records the active Wi-Fi network, pauses Cloudflare WARP (`warp-cli`) if connected, and ensures `DIRECT-*` entries are purged from preferred networks afterwards. Disassociating via CoreWLAN lets `airportd` rejoin the user's primary Wi-Fi without power-cycling the shared Wi-Fi/Bluetooth radio.

### F. Optional AI Sidecar Processor (`claude_processor.py`)

When explicitly enabled, received files on macOS pass through a streaming full-file Privacy Guard (blocking private keys, `.pem`, `.key`, `.env*`, and API tokens by filename, regex inspection across text/code extensions, and Vision OCR pre-scanning on images). Benign files can be summarized offline via macOS Apple Vision OCR and a local Ollama instance (`http://localhost:11434`), or via Anthropic's Messages API (`claude-sonnet-4-6` with fallback to `claude-haiku-4-5` / `claude-opus-4-6`) with `<untrusted_file_content>` prompt-injection delimiters.
