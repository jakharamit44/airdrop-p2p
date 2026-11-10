# AirDrop P2P

[![Views](https://komarev.com/ghpvc/?username=jakharamit44&repo=airdrop-p2p&color=blue)](https://github.com/jakharamit44/airdrop-p2p)

> High-speed, pure peer-to-peer file transfer between any Android device and macOS, powered by 5GHz Wi-Fi Direct and BLE L2CAP, with automated file intelligence via the Anthropic Claude API.

[![Platform: Android](https://img.shields.io/badge/Platform-Android%2012%2B-green.svg)](https://developer.android.com)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS%2013%2B%20%28Apple%20Silicon%20%26%20Intel%29-blue.svg)](https://apple.com/macos)
[![Protocol: AirDrop 1.0](https://img.shields.io/badge/Protocol-Apple%20AirDrop%201.0%20%2B%20WP2P-orange.svg)](docs/ARCHITECTURE.md)
[![AI Engine: Claude 3.5](https://img.shields.io/badge/AI-Claude%203.5%20Sonnet%20%2F%20Haiku-purple.svg)](https://anthropic.com)
[![Release: v2.4.1](https://img.shields.io/badge/Release-v2.4.1-blueviolet.svg)](https://github.com/jakharamit44/airdrop-p2p/releases/latest)
[![Security: Hardened](https://img.shields.io/badge/Security-Audit%20Hardened-success.svg)](SECURITY.md)
[![Status: Public Beta](https://img.shields.io/badge/Status-Public%20Beta-amber.svg)](SECURITY.md)

> [!WARNING]
> **Active Public Beta Stage (v2.4.1)**
> AirDrop P2P is currently in active public beta. The protocol and transport layers are functional and audited, but edge cases across different OEM Wi-Fi chipsets and macOS versions are actively being refined.
> Please review [SECURITY.md](SECURITY.md) and report any issues or contributions via [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Downloads

Get pre-compiled release artifacts from [Releases](https://github.com/jakharamit44/airdrop-p2p/releases/latest):

| Platform | Asset | Description |
| :--- | :--- | :--- |
| **Android** | [`AirDrop-P2P-v2.4.1.apk`](https://github.com/jakharamit44/airdrop-p2p/releases/latest/download/AirDrop-P2P-v2.4.1.apk) | Universal APK for Android (Samsung, Pixel, OnePlus, Xiaomi) |
| **macOS (PKG)** | [`AirDrop-P2P-v2.4.1.pkg`](https://github.com/jakharamit44/airdrop-p2p/releases/latest/download/AirDrop-P2P-v2.4.1.pkg) | Native Installer package (recommended for macOS 13+) |
| **macOS (DMG)** | [`AirDrop-P2P-v2.4.1.dmg`](https://github.com/jakharamit44/airdrop-p2p/releases/latest/download/AirDrop-P2P-v2.4.1.dmg) | Drag-and-drop installer for macOS 13+ (Ventura, Sonoma, Sequoia) |
| **Checksums** | [`SHA256SUMS.txt`](https://github.com/jakharamit44/airdrop-p2p/releases/latest/download/SHA256SUMS.txt) | Cryptographic SHA-256 verification hashes |

---

## Highlights

* **100% Off-Grid Peer-to-Peer**: Operates entirely without an external Wi-Fi router, local network, mobile data, or internet connection.
* **45+ MB/s Real-World Throughput**: Transfers multi-gigabyte files (movies, RAW photos, APKs) over dedicated 5GHz Wi-Fi Direct channels.
* **Universal Android Support**: Compatible with any modern Android device (Samsung, Google Pixel, OnePlus, Xiaomi, Motorola, etc.). Device names and models are resolved dynamically from hardware properties.
* **Kernel ARP Keepalive Engine**: Prevents Linux kernel neighbor cache timeouts during sustained multi-gigabyte unidirectional HTTP streaming.
* **Native macOS Wi-Fi Auto-Reassociation**: Ephemeral P2P credentials are removed upon completion, automatically restoring primary Wi-Fi connections via CoreWLAN without manual toggling.
* **Claude AI Ingestion Pipeline**: Automatically extracts OCR text from images, generates summaries for documents and code, and produces structured markdown sidecars for received files using Anthropic's Claude 3.5 Sonnet and Haiku models.

---

## Architecture Overview

```
                      +-----------------------------+
                      |   Bluetooth Low Energy      |
                      |   Discovery & PSM Exchange  |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   5GHz Wi-Fi Direct (P2P)   |
                      |   Autonomous Group Owner    |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   TLS 1.3 Streaming Engine  |
                      |   Chunked DVZip / CPIO Pipe |
                      +--------------+--------------+
                                     |
                       Bidirectional Keepalive (2.0s)
                                     |
                                     v
                      +-----------------------------+
                      |   Automated Wi-Fi Recovery  |
                      |   Clean Network Reset       |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   Claude AI Analysis Hook   |
                      |   OCR, Summaries, Metadata  |
                      +-----------------------------+
```

For full protocol details, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Performance

Measured transfer metrics over pure 5GHz Wi-Fi Direct (Band 4, 80 MHz channel width):

| Payload Size | Transfer Time | Average Speed | Status |
| :--- | :--- | :--- | :--- |
| **100 MB** (Photos / Documents) | ~2.1 seconds | 47.6 MB/s | Verified |
| **1.50 GB** (Video Clip) | ~32.8 seconds | 45.7 MB/s | Verified |
| **3.00 GB** (1080p BluRay Film) | ~66.2 seconds | 45.3 MB/s | Verified (No Stall) |
| **10.0+ GB** (Large Media Archives) | ~221.0 seconds | 45.2 MB/s | Verified (Continuous Stream) |

---

## Getting Started

### Prerequisites

* **Android**: Android 12 (API level 31) or newer with Wi-Fi Direct and BLE support.
* **macOS**: macOS 13 (Ventura), macOS 14 (Sonoma), or macOS 15 (Sequoia). Works on Apple Silicon (M1/M2/M3/M4) and Intel Macs.
* **Tools**:
  * macOS: Xcode Command Line Tools (`xcode-select --install`) and Python 3.9+.
  * Android: Android Studio or JDK 17+ with the Android SDK.

---

### Installation

#### 1. macOS Receiver & Daemon

Build and package the native daemon:

```bash
cd macos
chmod +x build.sh mac-airdrop-p2p.sh
./build.sh
```

To start the background daemon:

```bash
./mac-airdrop-p2p.sh on
```

To check daemon status:

```bash
./mac-airdrop-p2p.sh status
```

To stop the daemon:

```bash
./mac-airdrop-p2p.sh off
```

#### 2. Android Client

Build and install the debug APK:

```bash
cd android
./gradlew assembleDebug
adb install -r -g app/build/outputs/apk/debug/app-debug.apk
```

---

## Claude AI Ingestion Engine

AirDrop P2P features an automated AI processing pipeline that analyzes files as soon as they are received on macOS:

* **Images (`.png`, `.jpg`, `.webp`)**: Runs Claude 3.5 Sonnet Vision to extract text (OCR), transcribe tables and receipts, or describe UI screens.
* **Documents & Code (`.pdf`, `.txt`, `.md`, `.py`, `.kt`, `.json`)**: Generates a structured summary, key takeaways, and semantic topic tags.
* **Output**: Writes a companion `<filename>.claude.md` alongside the downloaded file in `~/Downloads`.

### Configuring Claude AI

Set your Anthropic API key in your environment:

```bash
export ANTHROPIC_API_KEY="your-anthropic-api-key"
```

Or save it permanently to the local config:

```bash
python3 macos/claude_processor.py --set-key "your-anthropic-api-key"
```

To verify connectivity:

```bash
python3 macos/claude_processor.py --test
```

#### Protocol Versioning & Advanced Features
* **Protocol Version (`ANTHROPIC_VERSION`)**: In Anthropic's Messages REST API (`/v1/messages`), `2023-06-01` is the canonical protocol specification version identifier (similar to HTTP/1.1 or TLS 1.3). Future capability flags and features are negotiated via beta headers.
* **Modern Model Configuration**: Default models use current active Anthropic endpoints (`claude-3-5-sonnet-latest` and `claude-3-5-haiku-latest`). Fallback models include `claude-3-opus-latest`. The integration includes automatic fallback across valid production models. Override anytime via:
  ```bash
  export ANTHROPIC_MODEL="claude-3-5-sonnet-latest"
  export ANTHROPIC_FAST_MODEL="claude-3-5-haiku-latest"
  export ANTHROPIC_BETA="prompt-caching-2024-07-31,pdfs-2024-09-25"
  ```

---

## Usage

1. Open the **AirDrop P2P** app on your Android device.
2. Select any file, video, or photo in your gallery/file manager and tap **Share** -> **AirDrop P2P**.
3. Your Mac will appear in the peer radar. Tap your Mac's name to begin the transfer.
4. The file will transfer at 45+ MB/s directly into `~/Downloads`.
5. If Claude AI is configured, a structured `.claude.md` summary will be generated immediately after reception.

---

## Security & Privacy

* **Direct Point-to-Point**: Files travel directly over encrypted peer-to-peer Wi-Fi frames without passing through external routers or cloud intermediaries.
* **End-to-End Encryption**: BLE handshakes and HTTPS transports utilize ephemeral ECDH key pairs (curve P-256) and AES-GCM-256.
* **Ephemeral Credentials**: Wi-Fi Direct passphrases are generated randomly per session and purged immediately upon connection teardown.

---

## Contributing & Security

* **Contributing**: Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, development guidelines, and pull request procedures.
* **Security & Vulnerabilities**: Please review [SECURITY.md](SECURITY.md) for our security architecture, public beta boundary advisory, and responsible disclosure process.

---

## License

MIT License. See [LICENSE](LICENSE) for details.

