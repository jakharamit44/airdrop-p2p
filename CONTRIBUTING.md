# Contributing to GlideDrop

Contributions, bug reports, protocol fixes, and documentation improvements are welcome. Please review this guide before opening an issue or pull request.

## Core Design Rules

1. **Pure Peer-to-Peer**: File transfers must run directly over BLE L2CAP and 5 GHz Wi-Fi Direct without requiring a shared LAN router or remote relay server.
2. **Hardware-Agnostic Code**: Never hardcode device names, serial numbers, MAC addresses, personal Wi-Fi names, or local LAN IPs. Resolve device properties dynamically through standard Android and macOS APIs.
3. **Minimal Dependencies**: Core transport and security paths use AOSP/Jetpack APIs on Android, standard Apple frameworks (`CoreBluetooth`, `CoreWLAN`, `CryptoKit`, `SwiftUI`) on macOS, and Python standard library modules (`urllib`, `plistlib`, `ssl`, `socket`, `struct`).

## Prerequisites

* **macOS**: macOS 13 (Ventura), 14 (Sonoma), or 15 (Sequoia) with Xcode Command Line Tools (`xcode-select --install`) and Python 3.9+.
* **Android**: JDK 17+ and Android SDK (compileSdk 36, minSdk 31). Gradle wrapper is included at `android/gradlew`.

## Repository Layout

```text
├── android/
│   └── app/src/
│       ├── main/java/io/github/jakharamit44/glidedrop/
│       │   ├── MainActivity.kt        # Jetpack Compose UI (Send, Receive, History, Settings)
│       │   ├── GlideDropNode.kt         # BLE L2CAP, ECDH P-256, 5 GHz Wi-Fi Direct & TLS engine
│       │   ├── GlideDropCodec.kt        # bplist00 & DVZip/CPIO (070707 / 070764) codec
│       │   ├── EmbeddedProxyServer.kt # Dual-protocol SOCKS5 + HTTP CONNECT proxy (:1080)
│       │   └── GlideDropService.kt      # Connected-device foreground service & notifications
│       └── test/java/io/github/jakharamit44/glidedrop/ # Codec, security, and proxy unit tests
├── macos/
│   ├── glidedrop-daemon.swift          # SwiftUI app, menu bar daemon, BLE & proxy lifecycle
│   ├── glidedrop.sh             # HTTPS AirDrop receiver/sender & awdl0 Finder proxy
│   ├── claude_processor.py            # Optional offline (Vision OCR/Ollama) & Claude AI hook
│   ├── test_claude_processor.py       # Python unit tests for AI & Privacy Guard
│   ├── generate-icon.swift            # macOS squircle AppIcon.icns generator
│   └── build.sh                       # Builds GlideDrop.app bundle
├── docs/
│   ├── index.html                     # Project landing page (GitHub Pages)
│   └── ARCHITECTURE.md                # Protocol & subsystem specification
├── scripts/
│   ├── build-release.sh               # Builds APK, DMG, PKG, and SHA256SUMS.txt
│   └── publish-release.py             # Publishes release artifacts & backup branch
└── VERSION                            # Semantic version string
```

## Local Build & Test Commands

### Android

```bash
cd android
./gradlew testDebugUnitTest
./gradlew assembleDebug
```

Install the debug APK to a connected device:

```bash
adb install -r -g app/build/outputs/apk/debug/app-debug.apk
```

### macOS

Build `GlideDrop.app`:

```bash
cd macos
chmod +x build.sh glidedrop.sh
./build.sh
```

Run the CLI receiver or check status:

```bash
./glidedrop.sh on
./glidedrop.sh status
tail -f ~/.glidedrop/daemon.log
```

### Python AI & Privacy Tests

```bash
python3 -m unittest macos/test_claude_processor.py
python3 macos/claude_processor.py --audit
```

## Coding & Privacy Hygiene

* **Kotlin**: Wrap streams and file descriptors in `.use { ... }`, validate coroutine cancellation, and enforce canonical destination checks during file extraction.
* **Swift**: Isolate CoreBluetooth work to explicit dispatch queues and pass arguments to `Process` via `executableURL` and `arguments` rather than shell interpolation.
* **Python**: Stay within the Python standard library and sanitize strings passed to `osascript`.
* **Never commit private test data**: Keep device serial numbers, personal Wi-Fi SSIDs, local LAN IPs, downloaded test payloads, and API keys out of commits, docs, and issues.

## Pull Request Process

1. Create a branch (`feature/...` or `fix/...`).
2. Follow Conventional Commits (`feat:`, `fix:`, `docs:`, `security:`, `refactor:`, `test:`).
3. Verify Android unit tests, macOS build (`./macos/build.sh`), and Python tests pass after your final edit.
4. Explain the problem, code changes, and verification commands run in your PR description.
