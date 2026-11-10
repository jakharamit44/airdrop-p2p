# Security Policy & Beta Stage Advisory

## Public Beta Advisory

> [!WARNING]
> **Active Public Beta Stage (v2.4.1)**
> Core peer-to-peer protocols (BLE L2CAP, ECDH P-256 credential exchange, pinned TLS 1.2/1.3, 5 GHz Wi-Fi Direct, and the embedded proxy) are functional and backed by automated tests, while hardware and OS edge cases are still being refined.
>
> * Do not transfer unencrypted regulated data in hostile RF environments.
> * Verify the peer device name before accepting incoming transfers or Wi-Fi Direct prompts.

## Supported Versions

| Version | Supported | Status |
| :--- | :--- | :--- |
| **2.4.x** | Yes | Active Beta |
| **< 2.4.0** | No | Unsupported |

## Threat Model & Security Controls

### 1. BLE Discovery & Key Agreement (`W2P2`)
* **Ephemeral ECDH P-256**: During 5 GHz Wi-Fi Direct negotiation, Android and macOS generate ephemeral `secp256r1` keypairs, derive a 32-byte session key (`SHA-256(shared_secret || "AirDropP2P-v2-SessionKey")`), and encrypt the Wi-Fi Direct SSID and WPA2 passphrase with AES-256-GCM.
* **Wi-Fi Join Approval (`Ask First` Default)**: Under the default `Ask First` receive mode (`autoAccept: false`), `handleIncomingWp2pJoin` prompts for user approval before joining a `DIRECT-*` network and creates an authorized session (`wp2p_authorized_session.json`) so `/Ask` does not prompt twice. Enabling `Auto-Accept` in macOS settings skips prompts for incoming Wi-Fi Direct joins and transfers.
* **Bounded BLE Frames**: Both sides enforce size ceilings on incoming BLE L2CAP headers (1 MB metadata limit on Android, 10 MB on macOS). Encrypted `ADRE` fallback frames (AES-256-GCM with the built-in BLE frame key) are capped at 30 MB on Android.

### 2. 5 GHz Wi-Fi Direct & Transport Layer
* **Ephemeral Credentials**: Android generates a random 12-hex-character WPA2 passphrase per session using `SecureRandom` (`WifiP2pConfig.Builder`) and tears down the group after completion or cancellation, while macOS deletes `DIRECT-*` entries from preferred wireless networks.
* **Pinned TLS Certificates**: Both peers exchange SHA-256 fingerprints of their local self-signed EC P-256 TLS certificates inside the `W2P2` handshake and verify them during `TLSv1.3`/`TLSv1.2` connections on `/Discover`, `/Ask`, and `/Upload`.
* **Port Confinement**: Android's HTTPS receiver (`8771`) drops connections outside `192.168.49.x` and loopback. macOS's HTTPS receiver (`8772`) enforces `192.168.49.x` and loopback unless `lan_fallback_active.flag` is active during a 180-second WARP-locked LAN fallback window. The macOS Finder AWDL proxy (`8773`) binds to `127.0.0.1` only, and `AwdlLoopbackBridge` (`8774`) rejects non-P2P interfaces.

### 3. Embedded Internet Proxy (`EmbeddedProxyServer.kt`)
* **Client Allowlist**: Port `1080` accepts connections only from `192.168.49.0/24` and loopback (`127.0.0.1`, `::1`), capped at 128 concurrent clients and 8,192-byte HTTP header blocks.
* **SSRF Prevention**: Hostnames and post-DNS resolved IP addresses are checked to block loopback and `192.168.49.0/24` targets on sensitive ports (`8771`, `1080`).
* **Advisory Proxy Lock on macOS**: `mac-ble-airdrop.swift` snapshots and restores existing `networksetup` proxy settings under an advisory `flock` lock (`proxy_state.lock`) and only touches loopback port `1080` on crash cleanup without a snapshot.

### 4. Archive Extraction, URLs & AI Sidecars
* **Path Traversal Protection**: CPIO extractors verify canonical destination paths (`File.canonicalPath.startsWith(destDirCanonical)` on Android, `target.resolve().parent == dest_dir.resolve()` on macOS), strip leading dots/separators, and stage writes via `.part` files.
* **Safe URL Handling**: Incoming URLs are regex-validated (`http://` or `https://`), copied to the macOS clipboard, and presented in a confirmation dialog rather than auto-launched.
* **Subprocess & OCR Safety**: System tools (`osascript`, `networksetup`, `/usr/bin/swift` Vision OCR) receive arguments via argv arrays without shell string interpolation.
* **AI Privacy Guard (Opt-In Only)**: Cloud processing is off by default (`is_claude_enabled()`). When enabled, `claude_processor.py` blocks `.pem`, `.key`, `.env*`, SSH keys, and files containing private key headers or API token patterns from leaving the device, and offers an offline path via Apple Vision OCR and local Ollama (`localhost:11434`). Config files saved with `--set-key` use `0o600` inside `0o700` `~/.airdrop-p2p`.

## Reporting a Vulnerability

Please report security issues privately rather than opening a public issue:

1. **GitHub Private Reporting**: Open an advisory at [GitHub Security Advisories](https://github.com/jakharamit44/airdrop-p2p/security/advisories/new).
2. **Email**: Contact `jakharamit44@gmail.com`.

Target response times: initial acknowledgment within 48 hours, triage within 5 business days, and prioritized fixes for confirmed vulnerabilities within 14 business days. Please include attack vector details, reproduction steps, and OS/version information.
