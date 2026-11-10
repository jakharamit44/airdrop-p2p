# Changelog

All notable changes to AirDrop P2P are documented in this file.

## [v2.4.1] - 2026-11-10

### Fixed
- **macOS Local Proxy Safety & Cross-Process Locking (`mac-ble-airdrop.swift`)**: Restricted snapshot-free fallback proxy cleanup on `127.0.0.1` strictly to port `1080` so pre-existing local loopback proxies on other ports are never altered on startup, serialized proxy snapshot/restore with an advisory file lock (`proxy_state.lock`) to eliminate UI vs sender teardown races, and increased proxy reachability pre-check timeout to `500 ms`.
- **Clean Child Process Cancellation (`mac-ble-airdrop.swift`, `mac-airdrop-p2p.sh`)**: Forwarded `SIGINT`/`SIGTERM` from `BleAirDropSender` and `mac-airdrop-p2p.sh` directly to active Python HTTPS transfer subprocesses with immediate `SO_LINGER` TCP RST and exit code `44` so cancelled transfers never orphan subprocesses.
- **Exact HTTP Proxy Header Limit (`EmbeddedProxyServer.kt`)**: Fixed an off-by-one boundary check so valid HTTP proxy request headers of exact `8,192` bytes are processed rather than rejected with `431`.
- **Standalone macOS Bundle Metadata (`mac-airdrop-p2p.sh`)**: Synced standalone `ensure_ble_bin` `Info.plist` generation with `VERSION`, `CFBundleVersion`, and `NSLocalNetworkUsageDescription`.

## [v2.4.0] - 2026-11-10

### Added
- **Dual-Protocol Embedded Proxy (`EmbeddedProxyServer.kt`)**: Added an embedded SOCKS5 (RFC 1928) and HTTP `CONNECT` / Forward proxy server on port `1080` during Android 5 GHz Wi-Fi Direct sessions, allowing connected macOS peers to maintain internet connectivity via Android's upstream cellular or active validated network (`CHANGE_NETWORK_STATE` + `ConnectivityManager.requestNetwork`).
- **SSRF & Client Isolation Controls**: Enforced strict client IP allowlisting (`192.168.49.0/24` and loopback), bounded concurrency (128 clients) and header parsing (8 KB), and pre/post-DNS SSRF blocking targeting internal AirDrop (`8771`) and proxy (`1080`) ports.
- **Android Settings Toggle**: Added a persistent **Mac Internet Sharing Proxy** toggle (`Share Internet` / `Disabled`) in Android Settings with live start/stop lifecycle binding during active Wi-Fi Direct sessions and 13 unit tests in `EmbeddedProxyServerTest.kt`.
- **macOS Zero-Sudo Proxy Lifecycle & Crash Recovery (`mac-ble-airdrop.swift`)**: Added dynamic Wi-Fi network service discovery (`getWifiServiceName()`), TCP reachability pre-checks (`isTcpPortReachable`), and automatic snapshot/restore (`prev_proxy_settings.json`) for macOS SOCKS/HTTP/HTTPS proxy settings and bypass domains using `networksetup` without sudo, backed by `SIGINT`/`SIGTERM` handlers, `atexit` hooks, and startup crash recovery.

### Fixed
- **5 GHz Wi-Fi Direct Pre-Flight & BLE Fallback (`mac-ble-airdrop.swift`)**: Verified `192.168.49.x` DHCP lease acquisition (`hasWifiP2pIp()`) prior to launching HTTPS transfers, preventing stalled connection attempts and immediately falling back to Direct BLE L2CAP when Wi-Fi Direct association fails.
- **Transfer Cancellation & Process Cleanup (`mac-airdrop-p2p.sh`, `mac-ble-airdrop.swift`)**: Fixed `FileNotFoundError` handling in `is_transfer_cancelled()` so missing cancel flags no longer report false cancellations, preserved exit codes (`43` declined, `44` cancelled) for `--peer` transfers, added `SO_LINGER` TCP RST on sender-side cancellation, and expanded `pkill` patterns for UI cancellation.
- **Complete P2P Wi-Fi Detection (`mac-ble-airdrop.swift`)**: Updated `restoreMacInternetWifi()` to check both `DIRECT-` SSID association and active `192.168.49.x` P2P interface addresses (`onP2p`) before skipping CoreWLAN disassociation.

## [v2.3.1] - 2026-11-09

### Fixed
- **Discoverable Nearby Toggle Asymmetry**: Fixed CoreBluetooth advertising teardown in `mac-ble-airdrop.swift` by stopping advertising without removing registered GATT services, and decoupled `receiverRunning` state in `MacAirDropViewModel` from ephemeral daemon PID checks so `settings.visible` is never overwritten. Android peer TTL was lowered to 4.5s (`PEER_TTL_MS = 4500L`) for prompt disappearance when Mac turns off discovery.
- **Single-Click Transfer Acceptance (Eliminated Double Prompt)**: Replaced the duplicate user prompt with an atomic authorization session (`wp2p_authorized_session.json`). When the user accepts the incoming transfer in the Mac UI on BLE L2CAP, the session token is verified on subsequent HTTP `/Ask` and `/Upload` requests, requiring only a single Accept click.
- **Single-Click Cancellation & Immediate Android Sync**: Fixed a race condition where `cancel_transfer.flag` was prematurely deleted by Python before Swift could read it. The cancel flag now carries a 10s timestamp TTL. On cancellation, Mac immediately issues a hard TCP RST (`SO_LINGER(1, 0)`) to the Android sender socket, instantly clearing the transfer card and notification on Android.
- **Post-Cancel Reconnection & Mac Radio Disappearance**: Eliminated destructive `-setairportpower en0 off/on` power-cycling in `restoreMacInternetWifi()`. Mac now cleanly disassociates via CoreWLAN without restarting the combined Wi-Fi/Bluetooth chip, preventing the Mac from disappearing from Android's radar and allowing immediate subsequent transfers.

## [v2.3.0] - 2026-11-09

### AI Subsystem Hardening & Audit
- **SSE Real-Time Token Streaming**: Added Server-Sent Events (`text/event-stream`) streaming support to `claude_processor.py`, parsing `content_block_delta` tokens as they arrive.
- **Local Ollama Integration**: Added zero-cloud offline processing via local Ollama (`http://localhost:11434`), supporting `llama3.2`, `mistral`, `qwen2.5`, and `phi3` models with automatic health detection.
- **Content Regex Token Exfiltration Prevention**: Privacy Guard now scans text content for exposed API keys (Anthropic, OpenAI, AWS, GitHub, Slack) and blocks transmission to cloud endpoints.
- **Zero-Injection Apple Vision OCR**: Passed image paths securely via `CommandLine.arguments` to `/usr/bin/swift`, eliminating arbitrary code injection vulnerabilities with malformed or quoted filenames.
- **9/9 Forensic Audit Suite**: Added automated CLI audit (`python3 macos/claude_processor.py --audit`) and 11 unit tests (`macos/test_claude_processor.py`).

### macOS UI Polish & SwiftUI Performance Rewrite ("Unslop")
- **Isolated Animation Architecture**: Extracted `MacRadarScannerView`, `MacConnectingBridgeLine`, and `MacIndeterminateConnectingBar` into dedicated subviews with local animation models, eliminating 120 FPS view invalidation thrashing on the root window view.
- **Restored Connecting Telemetry Bar**: Re-linked indeterminate progress bar physics in `LiveConnectionBridgeCard`.
- **Apple HIG Spring Transitions & Traffic Light Breathing Room**: Added smooth scale-and-fade modal springs on incoming file transfer requests (`response: 0.28, dampingFraction: 0.82`) and added top clearance for macOS Sequoia window controls.
- **Modern Squircle macOS App Icon**: Re-rendered `AppIcon.icns` with exact macOS 13+ superellipse/squircle geometry, multi-layer concentric ripple radar artwork, and all 10 canonical Retina resolutions (16x16 to 1024x1024).
- **Auto-Detecting JDK in `gradlew`**: `gradlew` now automatically discovers modern JDKs (Android Studio JBR / Homebrew OpenJDK 17) without requiring manual `JAVA_HOME` configuration.

## [v2.2.1] - 2026-11-09

### Code Cleanup, Dead Code Removal & Modernization (Phase 3)
- **Dead Dependency & Plugin Pruning**: Stripped unused `androidx.navigation3` (`navigation3-runtime`, `navigation3-ui`, `lifecycle-viewmodel-navigation3`) and `org.jetbrains.kotlin.plugin.serialization` from Gradle configurations and version catalogs.
- **Permission Surface Minimization**: Removed `MANAGE_EXTERNAL_STORAGE` and redundant media permissions (`READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, `READ_MEDIA_AUDIO`, `READ_MEDIA_VISUAL_USER_SELECTED`), relying solely on Storage Access Framework (SAF) URI grants.
- **Android 14+ FGS Compliance**: Replaced legacy `specialUse` foreground service type with `connectedDevice` (`FOREGROUND_SERVICE_CONNECTED_DEVICE`) across manifest and service lifecycle.
- **macOS 15 Sequoia Local Network Access**: Added `NSLocalNetworkUsageDescription` to the macOS application bundle `Info.plist` to comply with Sequoia local socket privacy controls.
- **Production Claude AI Model Alignment**: Migrated model identifiers to valid production endpoints (`claude-3-5-sonnet-latest`, `claude-3-5-haiku-latest`, `claude-3-opus-latest`) and implemented resilient cascading fallback across active models on retirement or error.
- **Reliable Daemon & Process Teardown**: Added `AirDropP2P` process termination and state lock file purge to `stop_daemons()` in `mac-airdrop-p2p.sh`.
- **CI / CD Publishing Portability**: Added `GITHUB_TOKEN` and `GH_TOKEN` environment variable fallbacks in `publish-release.py` for headless automated GitHub release publishing.

### Stability, Reliability & Performance Optimization (Phase 2)
- **Eliminated Subprocess Flooding on macOS**: Replaced periodic 1.5s/250ms `/usr/sbin/lsof` and `/sbin/ifconfig` polling loops with `getifaddrs()` kernel queries and lock freshness verification, eliminating persistent MacBook CPU wakeups and background battery drain.
- **Dynamic Wi-Fi Hardware Interface Resolution**: Replaced hardcoded `en0` assumptions across Swift and Shell with dynamic interface discovery via `CWWiFiClient` and `networksetup -listallhardwareports` with thread-safe caching, ensuring seamless operation on Mac mini, Mac Studio, Mac Pro, and docks.
- **Unified Clean Teardown**: Consolidated app quit routines into `performCleanShutdown()`, ensuring Wi-Fi is restored to original networks, Cloudflare WARP is unpaused, BLE radios are stopped, and all lock and progress files are purged.
- **Android Memory Pressure Lifecycle Fix**: `AirDropService.onDestroy()` now always calls `instance?.stop()` even during active transfers, preventing orphaned server sockets, BLE advertising, and Wi-Fi Direct groups on system kills.
- **JVM Out-of-Memory Protection**: Strictly capped encrypted BLE fallback archives to 30 MB (`MAX_ENCRYPTED_BLE_ARCHIVE_BYTES`), preventing Android OOM crashes on multi-hundred-megabyte payloads.
- **Multi-File Staging Telemetry**: Fixed staged transfer calculation in `AirDropNode.kt` to sum aggregate bytes across all URIs and format labels (`file.jpg (+N more)`), ensuring accurate sizes in the connecting notification.
- **Bounded Claude Processing Concurrency**: Added bounded worker execution with strict 120s timeout and SIGKILL enforcement to prevent zombie processes during batch file transfers.

## [v2.2.0] - 2026-11-09

### Security & Protocol Hardening (Phase 1)
- **Eliminated Remote Wi-Fi Hijacking (CVE-level fix)**: Gated `handleIncomingWp2pJoin` in `mac-ble-airdrop.swift` behind mandatory explicit user confirmation (`forcePrompt: true`). Even if `autoAccept` is enabled in settings, nearby unauthorized BLE devices can no longer silently force macOS to drop its Wi-Fi connection and join a rogue access point.
- **Ephemeral ECDH P-256 Key Exchange & AES-256-GCM Credential Encryption**: Implemented real ephemeral ECDH (`secp256r1`) key negotiation over Bluetooth LE L2CAP. Wi-Fi Direct SSIDs and WPA2 passphrases are now encrypted using ephemeral AES-256-GCM session keys, replacing plaintext transmission and static symmetric keys.
- **TLS Certificate Fingerprint Pinning**: Self-signed TLS certificate SHA-256 fingerprints are exchanged over the authenticated BLE control channel and pinned in both Android (`AirDropNode.kt`) and macOS (`mac-airdrop-p2p.sh`), neutralizing Man-in-the-Middle (MITM) attacks and ARP spoofing.
- **Port 8773 & 8774 Confinement**: Restricted internal proxy port 8773 strictly to loopback (`127.0.0.1`), and restricted AWDL bridge port 8774 to verify non-LAN interfaces before pumping data, preventing unauthenticated remote LAN uploads to `/tmp`.
- **Eliminated Drive-By URL Auto-Execution**: Safe URL handling in `mac-airdrop-p2p.sh` now validates URLs with strict regex, copies them to `NSPasteboard` (`pbcopy`), and displays an interactive dialog with "Open in Browser" and "Dismiss" buttons instead of auto-spawning the web browser.
- **10 New Cryptographic & Protocol Security Unit Tests**: Added `AirDropSecurityTest.kt` verifying P-256 keypair generation, HKDF session key derivation, AES-GCM encryption/decryption, AEAD tampering rejection, and backward-compatible versioned/unversioned `W2P2` parsing.

## [v2.1.2] - 2026-11-08

### Fixed
- **Android Background Lifecycle**: `AirDropService` now stops when the user exits or dismisses the app from Recent Tasks (unless an active file transfer is in progress). Foreground service changed from `START_STICKY` to `START_NOT_STICKY` and added an explicit "Stop" action button in the notification.
- **Mac Radio & Discovery Toggle**: When incoming transfers ("Discoverable Nearby") are switched off on Mac, CoreBluetooth advertising and scanning immediately stop and active peer records are cleared. Android devices reliably prune the Mac from discovery within 6 seconds.
- **Eliminated Duplicate macOS Accept Prompts**: Suppressed redundant AppleScript `System Events` fallback dialogs while the native `AirDrop P2P.app` SwiftUI modal is active, ensuring only a single in-window prompt is shown.
- **Single-Instance BLE Daemon & Persistent Permissions**: Prevented background bash scripts from spawning unbundled `airdrop-p2p-daemon` subprocesses when `AirDrop P2P.app` is already running. Eliminates duplicate Bluetooth authorization dialogs and preserves persistent permission under the signed app bundle.
- **Repository Privacy & Git Hygiene**: Expanded `.gitignore` to block user downloads, media payloads, temporary `.part` archives, credentials, certificates, and local state locks from being committed to GitHub. Scoped token patterns to auth token files to avoid colliding with design tokens.
- **macOS Native PKG Installer**: Added automated `.pkg` package builder with a `postinstall` script that installs directly to `/Applications` and unquarantines the app bundle, eliminating Gatekeeper "damaged" alerts.

## [v2.1.1] - 2026-11-08

### Fixed
- **64-bit Extended CPIO Format (`070764`) for Files > 8 GiB**: Fixed the POSIX CPIO `odc` format octal field constraint (`0x1FFFFFFFFL` / 8,589,934,591 bytes) that caused transfers of files $\ge 8$ GiB (including 16.50 GB archives) to fail with an `IllegalArgumentException` before transmission.
- **Arbitrary 64-bit Payload Streaming**: Android (`AirDropCodec.kt`) and macOS daemon (`mac-airdrop-p2p.sh` and `mac-ble-airdrop.swift`) now stream and extract 64-bit archives without size limits (16.5 GB, 50 GB, 100+ GB) using the `070764` extended header.
- **Full Backward Compatibility**: Files $\le 8$ GiB continue using standard POSIX `070707` CPIO headers, preserving compatibility with legacy receivers.
- **Accurate Release Changelog Pipeline**: Replaced static release descriptions in `scripts/publish-release.py` with automatic extraction from `CHANGELOG.md`, ensuring every release notes entry reflects actual technical changes.

## [v2.1.0] - 2026-11-07

### Added
- **QuickShare 4-Tab Navigation**: Redesigned Android UI with dedicated Send, Receive, History, and Settings tabs with modern Material 3 styling and light/dark theme support.
- **File Staging Queue**: Users can select and inspect multiple files before initiating transfer, with remove/clear controls and size summaries.
- **Connecting Phase Telemetry**: Visible connecting message and spinner during Wi-Fi Direct P2P negotiation and BLE discovery so the user is informed while connecting.

### Improved
- **5GHz Wi-Fi Direct Socket Throughput**: 1 MiB chunk buffering and socket send/receive tuning for transfer speeds up to 45 MB/s.

## [v2.0.2] - 2026-11-07

### Fixed
- **Cloudflare WARP Firewall Drop**: Automatically pauses Cloudflare WARP during active P2P transfers and restores it upon completion, eliminating the 36-second socket timeout caused by local tunnel firewall rules.
- **ARP Keepalive Pulses**: Bidirectional 2.0s ICMP/UDP keepalive to prevent Linux kernel ARP cache entry expiration on multi-gigabyte transfers.

## [v2.0.1] - 2026-11-07

### Fixed
- **macOS Gatekeeper Unblocker**: Added `Open AirDrop P2P (Bypass Gatekeeper).command` and `/Applications` symlink inside the DMG installer to simplify opening on macOS without manual Terminal commands.
- **Multi-Resolution App Icon**: Packaged 16x16 to 512x512@2x icons into `AppIcon.icns` for macOS Dock and menu bar.

## [v2.0.0] - 2026-11-07

### Added
- **Pure P2P Transfer Engine**: Direct 5GHz Wi-Fi Direct Autonomous Group (WP2P) and Bluetooth LE L2CAP transfer between Android and macOS without shared Wi-Fi router or LAN requirements.
- **Native AirDrop Protocol Emulation**: Implemented `/Discover`, `/Ask`, and `/Upload` endpoints with binary property lists (`bplist00`) and streaming CPIO archives.

