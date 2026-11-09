# Changelog

All notable changes to AirDrop P2P are documented in this file.

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

