# Security Policy & Beta Stage Advisory

## Public Beta Advisory

> [!WARNING]
> **Active Public Beta Stage (v2.0.0)**
> AirDrop P2P is currently in active public beta. While the core peer-to-peer transport protocols (BLE L2CAP, 5GHz Wi-Fi Direct, TLS 1.3) are functional and hardened, protocol edge cases are being actively discovered and resolved.
> 
> * Do not use for transferring highly sensitive or unencrypted regulated data in hostile RF environments.
> * Always verify the identity of the discovered peer before accepting incoming transfers.
> * Maintain awareness of your RF environment when operating in public spaces.

---

## Supported Versions

| Version | Supported | Status |
| :--- | :--- | :--- |
| **2.0.x** | :white_check_mark: | Active Beta |
| < 2.0.0 | :x: | Deprecated (Unsupported) |

---

## Threat Model & Security Architecture

AirDrop P2P operates across four distinct defensive layers:

### 1. Radio Layer (BLE L2CAP)
* **Out-of-Band Channel Negotiation**: macOS and Android exchange channel parameters (L2CAP PSM, Wi-Fi Direct SSID, WPA2 passphrase) over direct Bluetooth Low Energy.
* **Payload Encryption**: Out-of-band BLE payload blocks are encrypted with AES-256-GCM using ephemeral session keys.
* **Scan Isolation**: Advertisements use compact service UUIDs to avoid leaking user identifiable metadata.

### 2. Transport Layer (5GHz Wi-Fi Direct)
* **Ephemeral Credentials**: Wi-Fi Direct group owner passphrases are randomly generated per session using cryptographic random byte generators (`java.security.SecureRandom` on Android, `arc4random_buf` on macOS).
* **Credential Zeroing**: Wi-Fi credentials are deleted from persistent storage immediately upon transfer completion or cancellation. Ephemeral `DIRECT-*` networks are purged from the macOS preferred wireless networks list.
* **Air-Gapped Operation**: Transfers require zero Internet access, zero cellular data, and zero shared local router access.

### 3. Application Layer (HTTP / TLS / Archive Codec)
* **TLS 1.3 Transport**: Point-to-point HTTP requests (`/Discover`, `/Ask`, `/Upload`) operate over dedicated TLS sockets.
* **Path Traversal & CPIO Slip Defense**: File extraction in both Android and macOS implementations strictly verifies canonical file path boundaries (`File.canonicalPath.startsWith(destDir.canonicalPath)`). Any archive entry containing directory traversal elements (`../`, absolute paths, null bytes) is rejected with a `SecurityException`.
* **Bounded Deserialization**: Binary plist decoders (`bplist00`) enforce recursion depth limits and payload size ceilings to mitigate deserialization memory exhaustion attacks.
* **Process Execution Safety**: All system utility invocations (e.g. `osascript`, `networksetup`) pass arguments strictly via argv arrays (`on run argv`) without shell string interpolation, eliminating subprocess injection risks.

### 4. Claude AI & API Credential Safety
* **Local Storage Isolation**: Configuration files (`~/.airdrop-p2p/claude_config.json`) are stored with strict file permissions (`0o600` for files, `0o700` for directories).
* **Zero Dependency Ingestion**: The Claude ingestion processor uses Python standard library `urllib` without unverified third-party HTTP client libraries.
* **Payload Ceilings**: Files processed by Claude AI are bounded by strict payload guards (`MAX_IMAGE_BYTES = 15 MB`, `MAX_TEXT_CHARS = 120,000`) to prevent API credit exhaustion and out-of-memory crashes.

---

## Reporting a Vulnerability

We appreciate responsible disclosure of security vulnerabilities:

1. **Email Disclosure**: Email security reports directly to `jakharamit44@gmail.com`.
2. **GitHub Private Vulnerability Reporting**: Submit an advisory through [GitHub Security Advisories](https://github.com/jakharamit44/airdrop-p2p/security/advisories/new).
3. **Response Timeline**:
   * **Acknowledgment**: Within 48 hours.
   * **Triage & Assessment**: Within 5 business days.
   * **Patch Release**: Bounded security fixes are prioritized for release within 14 business days.

Please include:
* Description of the vulnerability and attack vector.
* Reproducible proof-of-concept steps or payload.
* Affected platform and version (Android version, macOS version, hardware architecture).
