# Security Policy & Beta Stage Advisory

## Public Beta Advisory

> [!WARNING]
> **Active Public Beta Stage (v2.6.0)**
> Core peer-to-peer protocols (BLE L2CAP, ECDH P-256 credential exchange, ephemeral BLE payload encryption, pinned TLS 1.2/1.3, 5 GHz Wi-Fi Direct, and the embedded proxy) are functional and backed by automated tests, while hardware and OS edge cases are still being refined.
>
> * Do not transfer unencrypted regulated data in hostile RF environments.
> * Verify the peer device name before accepting incoming transfers or Wi-Fi Direct prompts.

## Supported Versions

| Version | Supported | Status |
| :--- | :--- | :--- |
| **2.6.x** | Yes | Active Beta |
| **< 2.6.0** | No | Unsupported |

## Threat Model & Security Controls

### 1. BLE Discovery & Key Agreement (`W2P2` & `BLEK`)
* **Ephemeral ECDH P-256 (TOFU Scope)**: During 5 GHz Wi-Fi Direct negotiation, Android and macOS generate ephemeral `secp256r1` keypairs, derive a 32-byte session key (`SHA-256(shared_secret || "GlideDrop-v2-SessionKey")`) and bearer token (`SHA-256(shared_secret || "GlideDrop-v2-BearerToken")`), and encrypt the Wi-Fi Direct SSID, passphrase, gateway IP, and proxy port with AES-256-GCM. Direct BLE fallback frames (`ADRE`) also negotiate ephemeral `secp256r1` session keys via `BLEK`; legacy unencrypted `ADRP` and unpinned `WP2P` paths fail closed. Because nearby peers do not share pre-provisioned PKI certificates, BLE key agreement operates under Trust-On-First-Use (TOFU) anchored by the user's explicit confirmation prompt.
* **Mandatory Wi-Fi Join Approval (`forcePrompt: true`)**: Even when `Auto-Accept` is enabled in macOS settings for file transfers, `handleIncomingWp2pJoin` enforces `forcePrompt: true` so a nearby BLE peer cannot silently disconnect Cloudflare WARP, hijack Wi-Fi to a `DIRECT-*` SSID, or modify system proxy settings without explicit user approval. Under a WARP-locked LAN fallback, macOS keeps `wp2p_authorized_session.json` active until `upload_completed.flag` (or bounded timeout), never enables `enableMacInternetProxy`, and cleans up both `wp2p_authorized_session.json` and `lan_fallback_active.flag` on completion.
* **Bounded BLE Frames & Archive Extraction**: Both sides enforce size ceilings on incoming BLE L2CAP headers (1 MB metadata limit on Android, 10 MB on macOS). Encrypted `ADRE` fallback frames (AES-256-GCM with ephemeral `BLEK` session keys) are capped at 30 MB on Android. `extractDvzipCpioToDownloads` validates CPIO `namesize` (`1..4097`), non-negative file sizes, `shutil.disk_usage` free-space headroom, symlink-free `O_NOFOLLOW` staging, and `zlib.decompressobj().decompress(..., max_length=...)` zip-bomb caps (`<= 100 MB` decompressed for BLE frames), replying `OK\r\n` only after extraction succeeds.

### 2. 5 GHz Wi-Fi Direct & Transport Layer
* **Ephemeral Credentials & Per-Session Bearer Token**: Android generates a random 12-hex-character WPA2 passphrase per session using `SecureRandom` (`WifiP2pConfig.Builder`) and tears down the group after completion or cancellation (preserving session reuse state across the 5-second grace window on P2P success while immediately tearing down orphaned groups on LAN fallback or failure). macOS deletes `DIRECT-*` entries from preferred wireless networks. `W2P2` exchanges a per-session token (`X-GlideDrop-Token`) validated in constant time on macOS `:8772` and Android `:8771`.
* **Pinned TLS Certificates**: Both peers exchange SHA-256 fingerprints of their local self-signed EC P-256 TLS certificates inside the `W2P2` handshake and verify them during `TLSv1.3`/`TLSv1.2` connections on `/Discover`, `/Ask`, and `/Upload`.
* **Dynamic P2P Port Confinement & Finder Unix Socket**: Android's HTTPS receiver (`8771`) and macOS's HTTPS receiver (`8772`) enforce the **OS-resolved dynamic Wi-Fi Direct P2P subnet CIDR** (from `ConnectivityManager`/`LinkProperties` on Android and `getifaddrs()`/`active_p2p_session.json` on macOS — with no hardcoded `192.168.49.*` defaults). Token-gated LAN fallback on `:8771` requires a live incoming session token plus strict IP checks rejecting loopback, IPv4-mapped loopback, CGNAT, and APIPA; on `:8772`, `lan_fallback_active.flag` is scoped strictly to active WARP-locked LAN fallback sessions and requires constant-time `X-GlideDrop-Token` verification. The macOS Finder Share Proxy listens exclusively on a mode-`0600` Unix domain socket inside `0700` `~/.glidedrop/` (`finder_proxy.sock`, eliminating `127.0.0.1` TCP injection), and `AwdlLoopbackBridge` (`8774`) validates `awdl*` interface names and endpoints before forwarding to the Unix socket.
* **HTTP Framing & Resource Bounds**: Both HTTP receivers bound request/header lines (`<= 8 KiB`), header counts (`<= 64`), cumulative header bytes (`<= 16 KiB`), and non-upload `/Discover` & `/Ask` bodies (`<= 1 MiB` -> `413 Payload Too Large`), and reject negative/malformed chunk sizes, `Content-Length`, `TotalBytes`, and conflicting `CL+TE` headers (`400 Bad Request` / `431 Request Header Fields Too Large`) before authentication or body reads.

### 3. Embedded Internet Proxy (`EmbeddedProxyServer.kt`)
* **Opt-In Dynamic Client Allowlist**: Disabled by default (`shareCellularInternet = false`). When enabled in Android Settings, port `1080` accepts connections only from the active OS-resolved Wi-Fi Direct P2P subnets (`allowedP2pSubnetsProvider`; loopback clients denied in production), capped at 128 concurrent clients and 8,192-byte HTTP header blocks.
* **SSRF & Header Smuggling Protection**: Pre- and post-DNS resolution checks block loopback (`127.0.0.0/8`, `::1`), wildcard, RFC 1918 private LAN (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`), IPv6 ULA (`fc00::/7`), NAT64 (`64:ff9b:1::/48`), `.localdomain`, and multicast destinations across all ports. Bare CR / control characters, `TE.CL` (`Content-Length` + `Transfer-Encoding`), duplicate/conflicting `Content-Length` (`CL.CL`) headers (`400 Bad Request`), `Upgrade` tunneling, and `Proxy-Authorization` headers are rejected or stripped.
* **Advisory Proxy Lock on macOS**: `glidedrop-daemon.swift` snapshots and restores existing `networksetup` proxy settings under an advisory `flock` lock (`proxy_state.lock`) and only touches loopback/session-tracked proxies on fallback cleanup without a snapshot.

### 4. Archive Extraction, URLs & AI Sidecars
* **Path Traversal & Zip-Bomb Protection**: CPIO extractors verify canonical destination paths (`File.canonicalPath.startsWith(destDirCanonical)` on Android, `target.resolve().parent == dest_dir.resolve()` on macOS), strip leading dots/separators, enforce `1 <= namesize <= 4097` and non-negative file sizes, verify free disk space, stage writes via `O_NOFOLLOW`/non-symlink `.part` files, and enforce bounded streaming decompression (`zlib` `max_length` + cumulative limits).
* **Safe URL Handling**: Incoming URLs are regex-validated (`http://` or `https://`), copied to the macOS clipboard, and presented in a confirmation dialog rather than auto-launched.
* **Subprocess & OCR Safety**: System tools (`osascript`, `networksetup`, `/usr/bin/swift` Vision OCR) receive arguments via `argv` arrays (`on run argv` for AppleScript dialogs and notifications) without shell or AppleScript string interpolation.
* **AI Privacy Guard (Opt-In Only)**: Cloud processing is off by default (`is_claude_enabled()`). When enabled, `claude_processor.py` blocks `.pem`, `.key`, `.env*`, SSH keys, and streams full file content across text/code extensions (`.kt`, `.swift`, `.csv`, `.rs`, `.go`, etc.) plus Vision OCR output to block private key headers or API token patterns from reaching `call_claude_api()`. Untrusted file content sent to Claude is wrapped in explicit `<untrusted_file_content>` delimiters with prompt-injection system framing (`LLM01`), and an offline path via Apple Vision OCR and local Ollama (`localhost:11434`) is provided. Config files saved with `--set-key` use `0o600` inside `0o700` `~/.glidedrop`.

## Reporting a Vulnerability

Please report security issues privately rather than opening a public issue:

1. **GitHub Private Reporting**: Open an advisory at [GitHub Security Advisories](https://github.com/jakharamit44/glidedrop/security/advisories/new).
2. **Email**: Contact `jakharamit44@gmail.com`.

Target response times: initial acknowledgment within 48 hours, triage within 5 business days, and prioritized fixes for confirmed vulnerabilities within 14 business days. Please include attack vector details, reproduction steps, and OS/version information.
