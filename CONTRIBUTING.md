# Contributing to AirDrop P2P

Thank you for your interest in contributing to **AirDrop P2P**! We welcome bug reports, protocol enhancements, documentation improvements, and code contributions.

Please review this guide before submitting issues or pull requests.

---

## Core Project Tenets

When writing code or designing features for AirDrop P2P, adhere strictly to these core architectural invariants:

1. **Pure Peer-to-Peer Only**:
   * All file transfers must operate directly over point-to-point wireless links (5GHz Wi-Fi Direct and BLE L2CAP).
   * Never introduce dependencies on shared local Wi-Fi routers (LAN), cloud intermediaries, or centralized signaling servers.
2. **Universal Hardware Compatibility**:
   * Never hardcode IP addresses, device names, MAC addresses, or model strings.
   * Android logic must work across all manufacturers (Samsung, Google Pixel, OnePlus, Xiaomi, etc.) using standard Android Jetpack and AOSP APIs.
3. **Zero AI Slop & Minimalist Dependencies**:
   * Code must be concise, readable, and technically sound.
   * Avoid unvetted external dependencies. Core macOS and Android communication engines rely strictly on platform standard libraries (AOSP SDK, macOS CoreBluetooth/Network/Security, Python standard library).

---

## Development Prerequisites

### macOS Development
* **Operating System**: macOS 13 (Ventura), macOS 14 (Sonoma), or macOS 15 (Sequoia).
* **Compiler**: Xcode Command Line Tools (`xcode-select --install`).
* **Runtime**: Python 3.9+ (pre-installed on macOS).

### Android Development
* **Operating System**: macOS, Linux, or Windows.
* **JDK**: OpenJDK 17 or newer (`java -version`).
* **Android SDK**: API level 34 (Android 14) platform and build tools.
* **Build System**: Gradle (wrapper included in `android/gradlew`).

---

## Codebase Layout

```
├── android/                        # Android Client Application
│   ├── app/src/main/java/com/airdrop/p2p/
│   │   ├── MainActivity.kt        # Jetpack Compose UI & State
│   │   ├── AirDropNode.kt         # Core Wi-Fi Direct & BLE Engine
│   │   ├── AirDropCodec.kt        # bplist00 & DVZip CPIO Streaming Codec
│   │   ├── AirDropP2PReceiverService.kt # Foreground Transfer Service
│   │   └── AirDropTileService.kt  # Quick Settings Tile
│   └── app/src/test/java/         # Unit Tests
├── macos/                          # macOS Daemon & Receiver
│   ├── mac-ble-airdrop.swift       # Swift SwiftUI Menu Bar App & BLE Daemon
│   ├── mac-airdrop-p2p.sh          # Wi-Fi Direct HTTPS Receiver & Finder Proxy
│   ├── claude_processor.py         # Claude AI Ingestion & Analysis Engine
│   └── build.sh                    # Native Swift & App Bundle Builder
├── scripts/                        # Automation & Release Tools
│   ├── build-release.sh           # Deterministic Multi-Platform Release Builder
│   └── publish-release.py         # GitHub Releases Publisher
└── VERSION                         # Canonical Semantic Version (e.g. 2.0.0)
```

---

## Building & Testing Locally

### 1. Android Client

To compile the debug APK:
```bash
cd android
./gradlew assembleDebug
```
The resulting APK is generated at `android/app/build/outputs/apk/debug/app-debug.apk`.

To run the unit test suite:
```bash
./gradlew testDebugUnitTest
```

To install directly to a connected device:
```bash
adb install -r -g app/build/outputs/apk/debug/app-debug.apk
```

### 2. macOS Daemon & Receiver

To compile the native Swift daemon and generate `AirDrop P2P.app`:
```bash
cd macos
chmod +x build.sh mac-airdrop-p2p.sh
./build.sh
```

To run the daemon in foreground for testing:
```bash
./mac-airdrop-p2p.sh status
./mac-airdrop-p2p.sh on
```

To inspect live protocol logs:
```bash
tail -f ~/.airdrop-p2p/daemon.log
```

### 3. Claude AI Engine

To verify your Claude API integration locally:
```bash
python3 macos/claude_processor.py --test
```

---

## Coding Standards

### Kotlin (Android)
* Follow official [Android Kotlin Style Guides](https://developer.android.com/kotlin/style-guide).
* Always handle coroutine cancellations cleanly.
* Ensure streams and file descriptors are wrapped in `.use { ... }` blocks to prevent descriptor leaks.
* Guard against path traversal vulnerabilities by verifying `file.canonicalPath.startsWith(destDir.canonicalPath)` when extracting archives.

### Swift (macOS)
* Follow Swift API Design Guidelines.
* Keep Bluetooth CoreBluetooth operations thread-safe on explicit dispatch queues.
* Never use raw `/bin/bash -c` shell execution with unescaped arguments; use parameterized `Process.executableURL` and `Process.arguments`.

### Python (macOS Scripts)
* Adhere to PEP 8.
* Restrict code to Python standard library modules (`urllib`, `json`, `plistlib`, `ssl`, `socket`, `struct`).
* Sanitize all input strings passed to system utilities like `osascript`.

---

## Pull Request Guidelines

1. **Create a Topic Branch**:
   ```bash
   git checkout -b feature/awesome-feature
   # or
   git checkout -b fix/streaming-stall
   ```
2. **Commit Convention**:
   Use Conventional Commits formatting:
   * `feat:` New functionality
   * `fix:` Bug fixes
   * `docs:` Documentation updates
   * `security:` Security hardening or vulnerability remediation
   * `refactor:` Code cleanup without behavioral changes
   * `test:` Adding or updating tests
3. **Verify Locally Before Opening PR**:
   * Android unit tests pass: `./gradlew testDebugUnitTest`
   * macOS build succeeds: `./macos/build.sh`
   * Code adheres to security guidelines in [SECURITY.md](SECURITY.md).
4. **Submit Pull Request**:
   * Clearly describe the problem, the solution, and the testing steps performed.
   * Include before/after throughput or behavior comparisons if modifying transfer pipelines.

