# AirDrop P2P: AirDrop Between Android and Mac

Send files, photos, videos, links, and text notes directly between Android and macOS over Bluetooth Low Energy and 5 GHz Wi-Fi Direct. AirDrop P2P is an open-source AirDrop and Quick Share alternative that runs peer-to-peer without a shared Wi-Fi router, USB cable, cloud account, or file size limit.

**Website & Documentation:** [jakharamit44.github.io/airdrop-p2p](https://jakharamit44.github.io/airdrop-p2p/)

[![Release: v2.4.1](https://img.shields.io/badge/Release-v2.4.1-5360F5.svg)](https://github.com/jakharamit44/airdrop-p2p/releases/latest)
[![Platform: Android 12+](https://img.shields.io/badge/Android-12%2B%20%28API%2031%2B%29-16A34A.svg)](https://github.com/jakharamit44/airdrop-p2p/releases/latest)
[![Platform: macOS 13+](https://img.shields.io/badge/macOS-13%2B%20%28Apple%20Silicon%20%26%20Intel%29-0284C7.svg)](https://github.com/jakharamit44/airdrop-p2p/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-334155.svg)](LICENSE)
[![Status: Public Beta](https://img.shields.io/badge/Status-Public%20Beta-D97706.svg)](SECURITY.md)

> [!WARNING]
> **Public Beta (v2.4.1)**
> Core BLE L2CAP, 5 GHz Wi-Fi Direct, and TLS transport layers are functional and covered by unit tests, while OEM Wi-Fi chipset and macOS edge cases continue to be refined. Review [SECURITY.md](SECURITY.md) before transferring sensitive data in untrusted RF spaces, and open issues via [CONTRIBUTING.md](CONTRIBUTING.md).

## Downloads (v2.4.1)

Pre-compiled binaries and SHA-256 verification hashes are available on the [latest GitHub Release](https://github.com/jakharamit44/airdrop-p2p/releases/latest).

| Platform | Package | Target Requirements | Notes |
| :--- | :--- | :--- | :--- |
| **Android** | [`AirDrop-P2P-v2.4.1.apk`](https://github.com/jakharamit44/airdrop-p2p/releases/latest/download/AirDrop-P2P-v2.4.1.apk) | Android 12+ (API 31+) | Universal APK for Samsung, Pixel, OnePlus, Xiaomi, Motorola, and AOSP devices |
| **macOS (PKG)** | [`AirDrop-P2P-v2.4.1.pkg`](https://github.com/jakharamit44/airdrop-p2p/releases/latest/download/AirDrop-P2P-v2.4.1.pkg) | macOS 13+ (Ventura, Sonoma, Sequoia) | Recommended installer; places the app in `/Applications` and removes Gatekeeper quarantine flags |
| **macOS (DMG)** | [`AirDrop-P2P-v2.4.1.dmg`](https://github.com/jakharamit44/airdrop-p2p/releases/latest/download/AirDrop-P2P-v2.4.1.dmg) | macOS 13+ (Apple Silicon & Intel) | Drag-and-drop image containing a helper script for Gatekeeper (`xattr -cr`) |
| **Checksums** | [`SHA256SUMS.txt`](https://github.com/jakharamit44/airdrop-p2p/releases/latest/download/SHA256SUMS.txt) | All | SHA-256 hashes for verifying downloaded packages |

If you install from the `.dmg` and macOS reports that the unsigned app cannot be opened, run the included `Open AirDrop P2P (Bypass Gatekeeper).command` script or clear the quarantine attribute in Terminal:

```bash
xattr -cr "/Applications/AirDrop P2P.app"
```

## What It Transfers and How It Works

Transfers run in both directions between Android and macOS. From Android, pick files inside the app or send directly from the system Share Sheet (`SEND` and `SEND_MULTIPLE`). From macOS, drop files onto the menu bar icon or Send window, pick by file category, pull the active Finder selection or clipboard, compose a link or note, or send through Finder's AirDrop menu via the local AWDL proxy.

Supported items include single or multiple files (photos, videos, PDFs, documents, audio, archives, APKs), HTTP/HTTPS URLs, and text notes (`Note-*.txt`). Raw directory trees are not sent directly yet; select the files inside a directory or compress it into a zip archive first.

```
Android Device                                         macOS (Menu Bar + Daemon)
      |                                                           |
      |  1. BLE L2CAP discovery + ECDH P-256 handshake (W2P2)     |
      |<--------------------------------------------------------->|
      |  2. AES-256-GCM encrypted 5 GHz Wi-Fi Direct credentials  |
      |     + TLS SHA-256 certificate fingerprints                |
      |---------------------------------------------------------->|
      |  3. HTTPS stream (/Discover, /Ask, /Upload) on 5 GHz      |
      |     64-bit CPIO (070764) + 2.0s UDP ARP keepalive         |
      |<=========================================================>|  45+ MB/s
      |  4. Optional SOCKS5 / HTTP CONNECT proxy on port 1080     |
      |<--------------------------------------------------------->|
      |  5. Clean Wi-Fi Direct teardown + CoreWLAN restore        |
      |     + Optional Apple Vision OCR / Ollama / Claude summary |
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for wire framing, CPIO headers, and proxy lifecycle details.

## Key Technical Details

| Component | Behavior in v2.4.1 | Source |
| :--- | :--- | :--- |
| **Radio Discovery & Fallback** | Discovers peers over Bluetooth Low Energy L2CAP CoC without a router. Transfers of 64 KiB or more negotiate a 5 GHz Band 4 Wi-Fi Direct group; smaller items, URLs, or unreachable Wi-Fi Direct peers fall back to AES-256-GCM `ADRE` frames over BLE L2CAP (capped at 30 MB on Android). | [`AirDropNode.kt`](android/app/src/main/java/com/airdrop/p2p/AirDropNode.kt), [`mac-ble-airdrop.swift`](macos/mac-ble-airdrop.swift) |
| **64-bit Large File Streaming** | Streams files up to 8 GiB with POSIX `070707` CPIO headers and switches to 64-bit extended `070764` CPIO headers above 8 GiB so 10 GB+ files move directly from file descriptors without memory buffering. | [`AirDropCodec.kt`](android/app/src/main/java/com/airdrop/p2p/AirDropCodec.kt), [`mac-airdrop-p2p.sh`](macos/mac-airdrop-p2p.sh) |
| **Mac Internet Sharing Proxy** | Because macOS temporarily switches off its router Wi-Fi to join Android's `DIRECT-*` network, Android runs an embedded dual-protocol SOCKS5 and HTTP `CONNECT` proxy on port `1080` (toggleable under Settings) over its active internet or cellular connection. macOS snapshots prior proxy settings under an advisory file lock, applies the proxy without `sudo`, and restores everything afterward. | [`EmbeddedProxyServer.kt`](android/app/src/main/java/com/airdrop/p2p/EmbeddedProxyServer.kt), [`mac-ble-airdrop.swift`](macos/mac-ble-airdrop.swift) |
| **Kernel Stall & VPN Handling** | Periodic 2.0s UDP keepalives from Android reset its Linux neighbor cache (`NUD_REACHABLE`) so multi-gigabyte streams do not stall around 35 seconds. On macOS, Cloudflare WARP (`warp-cli`) is paused cleanly before joining the offline P2P SSID and resumed after completion. | [`AirDropNode.kt`](android/app/src/main/java/com/airdrop/p2p/AirDropNode.kt), [`mac-ble-airdrop.swift`](macos/mac-ble-airdrop.swift) |
| **Cryptography & Pinning** | `W2P2` negotiates ephemeral ECDH P-256 (`secp256r1`) session keys to encrypt Wi-Fi Direct credentials with AES-256-GCM and exchanges SHA-256 TLS certificate fingerprints for pinning on `TLSv1.3`/`TLSv1.2` transfers. Under the default `Ask First` mode, Mac prompts before joining a new Wi-Fi Direct group. | [`AirDropNode.kt`](android/app/src/main/java/com/airdrop/p2p/AirDropNode.kt), [`AirDropSecurityTest.kt`](android/app/src/test/java/com/airdrop/p2p/AirDropSecurityTest.kt) |

## Comparison With Other Transfer Methods

| Method | Shared Wi-Fi Required | USB Cable | Typical Speed | File Size Cap | Trade-offs |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AirDrop P2P** | No | No | 45+ MB/s (5 GHz) | None (64-bit CPIO) | Requires installing the app on Android and Mac |
| **LAN Tools (LocalSend / PairDrop)** | Yes | No | Router dependent | Device memory / app dependent | Fails when devices sit on different networks or AP client isolation is on |
| **Quick Share / Nearby Share** | No (Android/Windows) | No | Wi-Fi Direct / BLE | None | No official Google Quick Share client for macOS |
| **USB / MTP (Android File Transfer)** | No | Yes | 20 to 40 MB/s | None | Needs a cable and third-party MTP software on macOS |
| **Cloud Drives / Chat Apps** | Internet on both | No | Upload speed bound | 2 to 15 GB | Uploads to remote servers and uses cellular or home bandwidth |

## Measured 5 GHz Performance

Measured on pure 5 GHz Wi-Fi Direct (Band 4, 80 MHz channel width) with 1 MiB chunk framing and 4 MiB socket buffers:

| Payload Size | Elapsed Time | Average Speed | Notes |
| :--- | :--- | :--- | :--- |
| **100 MB** (Photos / Documents) | ~2.1 s | 47.6 MB/s | Verified |
| **1.50 GB** (Video Clip) | ~32.8 s | 45.7 MB/s | Verified |
| **3.00 GB** (1080p Film) | ~66.2 s | 45.3 MB/s | Continuous stream, no stall |
| **10.0+ GB** (Large Media Archive) | ~221.0 s | 45.2 MB/s | Extended `070764` CPIO stream |

## Build From Source

### Prerequisites

* **Android**: Android 12 (API level 31) or newer with BLE and Wi-Fi Direct hardware; JDK 17+ and Android SDK (compileSdk 36) to build.
* **macOS**: macOS 13 Ventura or newer on Apple Silicon or Intel; Xcode Command Line Tools (`xcode-select --install`) and Python 3.9+ to build.

### 1. macOS App & CLI Daemon

Compile `AirDrop P2P.app` and install the local binary into `~/.airdrop-p2p`:

```bash
cd macos
chmod +x build.sh mac-airdrop-p2p.sh
./build.sh
```

Control the background receiver from the terminal if preferred over the GUI app:

```bash
./mac-airdrop-p2p.sh on      # start receiver and BLE daemon
./mac-airdrop-p2p.sh status  # inspect running ports and PIDs
./mac-airdrop-p2p.sh send    # send Finder selection or pick files
./mac-airdrop-p2p.sh off     # stop all daemons
```

### 2. Android Client

Build the APK and run unit tests with Gradle:

```bash
cd android
./gradlew testDebugUnitTest
./gradlew assembleDebug
adb install -r -g app/build/outputs/apk/debug/app-debug.apk
```

### 3. Deterministic Release Packaging

To generate versioned `.apk`, `.dmg`, `.pkg`, and `SHA256SUMS.txt` artifacts under `release/`:

```bash
./scripts/build-release.sh
```

## Optional File Analysis (Local or Claude API)

`macos/claude_processor.py` can write a companion `<filename>.claude.md` summary alongside files received in `~/Downloads`. This hook is **disabled by default** so nothing leaves your Mac unless you opt in.

When enabled without an API key, the local offline path uses macOS Apple Vision OCR for images, structural code/text outlines, and a local Ollama server (`http://localhost:11434`, preferring `llama3.2`, `llama3.1`, `llama3`, `mistral`, `qwen2.5`, or `phi3`).

If you configure an Anthropic key, `claude_processor.py` runs a Privacy Guard before any upload: it blocks `.pem`, `.key`, `.env*`, SSH keys, certificate stores, and text files containing private key headers or API token patterns (`sk-ant-`, `sk-`, `AKIA`, `ghp_`, `xoxb-`).

```bash
# Enable local/offline processing or configure Anthropic Claude
python3 macos/claude_processor.py --enable
python3 macos/claude_processor.py --set-key "your-anthropic-api-key"

# Verify API connectivity and run the 9-check privacy/OCR audit
python3 macos/claude_processor.py --test
python3 macos/claude_processor.py --audit
```

Optional model overrides (`ANTHROPIC_MODEL`, `ANTHROPIC_FAST_MODEL`, `ANTHROPIC_OPUS_MODEL`, `ANTHROPIC_VERSION`, `ANTHROPIC_BETA`, `OLLAMA_HOST`) default to `claude-3-5-sonnet-latest`, `claude-3-5-haiku-latest`, and `claude-3-opus-latest` with automatic fallback if a model returns HTTP 404/429/529.

## FAQ

**Can I transfer files from Mac to Android as well as Android to Mac?**
Yes. Both apps act as sender and receiver. On Mac, drag files onto the menu bar icon or the Send tab, click a file category, import the current Finder selection or clipboard, or share through Finder's AirDrop menu when an Android peer is nearby.

**Why does AirDrop P2P ask before joining a Wi-Fi network on Mac?**
Leaving your home Wi-Fi to join an unknown `DIRECT-*` hotspot without confirmation would let a nearby BLE broadcaster redirect your Mac's Wi-Fi interface. Under the default `Ask First` mode, Mac prompts once before joining the Wi-Fi Direct SSID (and reuses that approval for the HTTP transfer so you are not asked twice). If you switch macOS to `Auto-Accept`, incoming Wi-Fi Direct joins and transfers run without a prompt.

**How do I keep internet access on my Mac during a large transfer?**
Open **Settings** on the Android app and make sure **Mac Internet Sharing Proxy** is set to **Share Internet**. Android starts an SSRF-filtered SOCKS5 and HTTP `CONNECT` proxy on port `1080` bound to your active upstream mobile data or internet interface, while macOS configures and restores system proxy settings without `sudo`.

**Where do received files go?**
macOS writes received files to `~/Downloads` (with duplicate filename numbering and `com.apple.quarantine` attributes set). Android writes received files to `Downloads/AirDrop` and triggers Android's MediaScanner so photos and videos show up in your gallery.

## Security & Contributing

* **Security Architecture & Disclosure**: Read [SECURITY.md](SECURITY.md) for the four-layer threat model, SSRF controls, and vulnerability disclosure process.
* **Contributing**: Read [CONTRIBUTING.md](CONTRIBUTING.md) for repository layout, coding conventions, and local test commands.
* **Release History**: See [CHANGELOG.md](CHANGELOG.md).

## License

MIT License. See [LICENSE](LICENSE).
