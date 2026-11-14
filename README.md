# GlideDrop: Open-Source AirDrop Alternative for Android and Mac

Send files, photos, videos, links, and text notes directly between Android and Mac over Bluetooth Low Energy and 5 GHz Wi-Fi Direct. GlideDrop is an open-source alternative to Apple AirDrop® and Google Quick Share™ that lets you send files between Android and Mac without Wi-Fi, USB cables, cloud accounts, or file size limits.

**Website & Documentation:** [jakharamit44.github.io/glidedrop](https://jakharamit44.github.io/glidedrop/)

[![Release: v3.0.3](https://img.shields.io/badge/Release-v3.0.3-5360F5.svg)](https://github.com/jakharamit44/glidedrop/releases/latest)
[![Platform: Android 12+](https://img.shields.io/badge/Android-12%2B%20%28API%2031%2B%29-16A34A.svg)](https://github.com/jakharamit44/glidedrop/releases/latest)
[![Platform: macOS 13+](https://img.shields.io/badge/macOS-13%2B%20%28Apple%20Silicon%20%26%20Intel%29-0284C7.svg)](https://github.com/jakharamit44/glidedrop/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-334155.svg)](LICENSE)
[![Status: Public Beta](https://img.shields.io/badge/Status-Public%20Beta-D97706.svg)](SECURITY.md)

> [!WARNING]
> **Public Beta (v3.0.3)**
> Core BLE L2CAP, 5 GHz Wi-Fi Direct, and TLS transport layers are functional and covered by unit tests, while OEM Wi-Fi chipset and macOS edge cases continue to be refined. Review [SECURITY.md](SECURITY.md) before transferring sensitive data in untrusted RF spaces, and open issues via [CONTRIBUTING.md](CONTRIBUTING.md).

## Downloads (v3.0.3)

Pre-compiled binaries and SHA-256 verification hashes are available on the [latest GitHub Release](https://github.com/jakharamit44/glidedrop/releases/latest).

| Platform | Package | Target Requirements | Notes |
| :--- | :--- | :--- | :--- |
| **Android** | [`GlideDrop-v3.0.3.apk`](https://github.com/jakharamit44/glidedrop/releases/latest/download/GlideDrop-v3.0.3.apk) | Android 12+ (API 31+) | Universal APK for Samsung, Pixel, OnePlus, Xiaomi, Motorola, and AOSP devices |
| **macOS (PKG)** | [`GlideDrop-v3.0.3.pkg`](https://github.com/jakharamit44/glidedrop/releases/latest/download/GlideDrop-v3.0.3.pkg) | macOS 13+ (Ventura, Sonoma, Sequoia) | Installs the app in `/Applications`. The app is not notarized (see below) |
| **macOS (DMG)** | [`GlideDrop-v3.0.3.dmg`](https://github.com/jakharamit44/glidedrop/releases/latest/download/GlideDrop-v3.0.3.dmg) | macOS 13+ (Apple Silicon & Intel) | Drag-and-drop image. The app is not notarized (see below) |
| **Checksums** | [`SHA256SUMS.txt`](https://github.com/jakharamit44/glidedrop/releases/latest/download/SHA256SUMS.txt) | All | SHA-256 hashes for verifying downloaded packages |

### Unnotarized macOS app and Gatekeeper

The macOS build is not Apple-notarized, so Gatekeeper may refuse to open it. Do not strip quarantine flags blindly. Clearing the quarantine attribute  or using a bypass script turns off a protection macOS applies to every downloaded app, so only do it for a build whose SHA-256 you have verified against `SHA256SUMS.txt` from the official release, or one you built yourself from source. Otherwise use **System Settings > Privacy & Security > Open Anyway** for that one app, or build from source.

### Requirements for Mac to Android transfers

* **Update both devices together.** The secure handshake is now `W2P2` protocol v3. Older Mac or Android builds cannot talk to v3 builds, and a mismatch is reported as an update-required error rather than falling back to the old handshake.
* **Location Services on the Mac.** macOS hides Wi-Fi network names from apps that lack Location access. Allow **GlideDrop** in **System Settings > Privacy & Security > Location Services**. GlideDrop uses this only so it can recognize the phone's Wi-Fi Direct network and your home network; it does not read or store your location. If it is denied, joining may still work but is less reliable.
* **Phone consent.** The first time a Mac sends to your phone, the phone shows a consent dialog with a 6-digit verification code that should match the code on the Mac. You can choose to trust that Mac (by its TLS certificate fingerprint) for later transfers.

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
      |  4. Optional SOCKS5 / HTTP CONNECT proxy on an OS-assigned port    |
      |<--------------------------------------------------------->|
      |  5. Clean Wi-Fi Direct teardown + CoreWLAN restore        |
      |     + Optional Apple Vision OCR / Ollama / Claude summary |
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for wire framing, CPIO headers, and proxy lifecycle details.

## Key Technical Details

| Component | Behavior in v3.0.3 | Source |
| :--- | :--- | :--- |
| **Radio Discovery & Fallback** | Discovers peers over Bluetooth Low Energy L2CAP CoC without a router. Transfers of 64 KiB or more negotiate a 5 GHz Band 4 Wi-Fi Direct group; smaller items, URLs, or unreachable Wi-Fi Direct peers fall back to ephemeral ECDH AES-256-GCM `ADRE` frames (`BLEK`) over BLE L2CAP (capped at 30 MB on Android). | [`GlideDropNode.kt`](android/app/src/main/java/io/github/jakharamit44/glidedrop/GlideDropNode.kt), [`glidedrop-daemon.swift`](macos/glidedrop-daemon.swift) |
| **64-bit Large File Streaming** | Streams files up to 8 GiB with POSIX `070707` CPIO headers and switches to 64-bit extended `070764` CPIO headers above 8 GiB so 10 GB+ files move directly from file descriptors without memory buffering. | [`GlideDropCodec.kt`](android/app/src/main/java/io/github/jakharamit44/glidedrop/GlideDropCodec.kt), [`glidedrop.sh`](macos/glidedrop.sh) |
| **Mac Internet Sharing Proxy** | Opt-in in Android Settings (**Disabled** by default). When enabled while macOS joins Android's `DIRECT-*` network, Android runs an SSRF-filtered SOCKS5 and HTTP `CONNECT` proxy on an OS-assigned port over its active internet or cellular connection. macOS snapshots prior proxy settings under an advisory file lock, applies the proxy without `sudo`, and restores everything afterward. | [`EmbeddedProxyServer.kt`](android/app/src/main/java/io/github/jakharamit44/glidedrop/EmbeddedProxyServer.kt), [`glidedrop-daemon.swift`](macos/glidedrop-daemon.swift) |
| **Kernel Stall & VPN Handling** | Periodic 2.0s UDP keepalives from Android reset its Linux neighbor cache (`NUD_REACHABLE`) so multi-gigabyte streams do not stall around 35 seconds. On macOS, Cloudflare WARP (`warp-cli`) is paused cleanly before joining the offline P2P SSID and resumed after completion. | [`GlideDropNode.kt`](android/app/src/main/java/io/github/jakharamit44/glidedrop/GlideDropNode.kt), [`glidedrop-daemon.swift`](macos/glidedrop-daemon.swift) |
| **Cryptography & Pinning** | `W2P2` protocol v3 runs an ephemeral ECDH P-256 exchange bound to a random session ID and both TLS fingerprints, then derives the AES-256-GCM key, the bearer token, and a 6-digit verification code with HKDF-SHA256 using separate labels. Wi-Fi Direct credentials are encrypted with that key and TLS certificates are pinned by SHA-256 fingerprint. The phone asks for consent (with the verification code) before starting a group, and can remember a Mac by its fingerprint. Mac prompts before joining a Wi-Fi Direct group under default `Ask First` mode. Wi-Fi Direct SSID and passphrase are random per session, and HTTPS/proxy ports are assigned by the OS and sent in the handshake, so there are no fixed ports. The code is not independently audited. | [`GlideDropNode.kt`](android/app/src/main/java/io/github/jakharamit44/glidedrop/GlideDropNode.kt), [`GlideDropSecurityTest.kt`](android/app/src/test/java/io/github/jakharamit44/glidedrop/GlideDropSecurityTest.kt) |

## Comparison With Other Transfer Methods

| Method | Shared Wi-Fi Required | USB Cable | Typical Speed | File Size Cap | Trade-offs |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **GlideDrop** | No | No | 45+ MB/s (5 GHz) | None (64-bit CPIO) | Requires installing the app on Android and Mac |
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

* **Android**: Android 12 (API level 31) or newer with BLE and Wi-Fi Direct hardware; JDK 17+ and Android SDK (compileSdk 37) to build.
* **macOS**: macOS 13 Ventura or newer on Apple Silicon or Intel; Xcode Command Line Tools (`xcode-select --install`) and Python 3.9+ to build.

### 1. macOS App & CLI Daemon

Compile `GlideDrop.app` and install the local binary into `~/.glidedrop`:

```bash
cd macos
chmod +x build.sh glidedrop.sh
./build.sh
```

Control the background receiver from the terminal if preferred over the GUI app:

```bash
./glidedrop.sh on      # start receiver and BLE daemon
./glidedrop.sh status  # inspect running ports and PIDs
./glidedrop.sh send    # send Finder selection or pick files
./glidedrop.sh off     # stop all daemons
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

Optional model overrides (`ANTHROPIC_MODEL`, `ANTHROPIC_FAST_MODEL`, `ANTHROPIC_OPUS_MODEL`, `ANTHROPIC_VERSION`, `ANTHROPIC_BETA`, `OLLAMA_HOST`) default to `claude-sonnet-4-6`, `claude-haiku-4-5`, and `claude-opus-4-6` with automatic fallback if a model returns HTTP 404/429/529.

## FAQ

**Can I transfer files from Mac to Android as well as Android to Mac?**
Yes. Both apps act as sender and receiver. On Mac, drag files onto the menu bar icon or the Send tab, click a file category, import the current Finder selection or clipboard, or share through Finder's AirDrop menu when an Android peer is nearby.

**Why does GlideDrop ask before joining a Wi-Fi network on Mac?**
Leaving your home Wi-Fi to join an unknown `DIRECT-*` hotspot without confirmation would let a nearby BLE broadcaster redirect your Mac's Wi-Fi interface. For incoming joins the Mac always asks, even with `Auto-Accept` on. For sends from the Mac, the phone shows its own consent dialog with the verification code.

**How do I keep internet access on my Mac during a large transfer?**
Open **Settings** on the Android app and make sure **Mac Internet Sharing Proxy** is set to **Share Internet**. Android starts an SSRF-filtered SOCKS5 and HTTP `CONNECT` proxy on an OS-assigned port bound to your active upstream mobile data or internet interface, while macOS configures and restores system proxy settings without `sudo`.

**Where do received files go?**
macOS writes received files to `~/Downloads` (with duplicate filename numbering and `com.apple.quarantine` attributes set). Android writes received files to `Downloads/GlideDrop` and triggers Android's MediaScanner so photos and videos show up in your gallery.

## Security & Contributing

* **Security Architecture & Disclosure**: Read [SECURITY.md](SECURITY.md) for the four-layer threat model, SSRF controls, and vulnerability disclosure process.
* **Contributing**: Read [CONTRIBUTING.md](CONTRIBUTING.md) for repository layout, coding conventions, and local test commands.
* **Release History**: See [CHANGELOG.md](CHANGELOG.md).

## License

MIT License. See [LICENSE](LICENSE).

---

*AirDrop and macOS are trademarks of Apple Inc., registered in the U.S. and other countries and regions. Android and Quick Share are trademarks of Google LLC. GlideDrop is an independent open-source project and is not affiliated with, endorsed by, or sponsored by Apple Inc. or Google LLC.*
