# AirDrop P2P — Architecture & Protocol Specification

AirDrop P2P enables high-speed, off-grid file transfers between Android and macOS without requiring an external Wi-Fi router, local area network (LAN), cloud relay, or USB connection.

---

## 1. High-Level Flow

```
[Android Device]                                              [MacBook / macOS]
       |                                                             |
       |  1. BLE L2CAP Discovery & Pairing                           |
       |------------------------------------------------------------>|
       |     • Advertises custom 128-bit BLE service & PSM           |
       |     • Dynamic device model & PSM handshake                  |
       |                                                             |
       |  2. 5GHz Wi-Fi Direct (P2P) Group Negotiation               |
       |     • Android creates autonomous 5GHz P2P Group             |
       |     • Signals SSID + Passphrase over BLE L2CAP channel      |
       |------------------------------------------------------------>|
       |                                                             |
       |  3. Connection & Dynamic Addressing                         |
       |     • Mac associates to 5GHz Wi-Fi Direct SSID              |
       |     • Mac obtains dynamic IP via P2P DHCP (192.168.49.x)    |
       |     • Sends handshake confirmation: "OK <Mac-P2P-IP>"       |
       |<------------------------------------------------------------|
       |                                                             |
       |  4. TLS 1.3 / HTTPS Stream with Bidirectional Keepalive     |
       |     • POST /Ask (Metadata, file list, sizes)                |
       |------------------------------------------------------------>|
       |     • 200 OK (Accepted by user or auto-accept)              |
       |<------------------------------------------------------------|
       |     • POST /Upload (Apple DVZip/CPIO chunked stream)        |
       |============================================================>| (45+ MB/s)
       |     • Bidirectional ICMP/UDP Heartbeat (every 2.0s)         |
       |<------------------------------------------------------------>| (Prevents ARP stall)
       |     • 200 OK (Transfer complete)                            |
       |<------------------------------------------------------------|
       |                                                             |
       |  5. Wi-Fi Teardown & Auto-Reconnection                      |
       |     • Android tears down P2P Group                          |
       |     • Mac purges P2P SSID from preferred networks           |
       |     • Mac CoreWLAN disassociates -> airportd rejoins Wi-Fi  |
       |                                                             |
       |  6. Claude AI Ingestion & Processing                        |
       |     • Auto-analyzes images/OCR/documents/code via Claude    |
```

---

## 2. Core Subsystems

### A. Discovery Layer: Bluetooth Low Energy (BLE L2CAP)
* **Standard AirDrop Compatibility**: Emulates native Apple AirDrop discovery packets alongside a custom BLE L2CAP direct socket protocol.
* **Dynamic Device Naming**: Dynamically resolves device hardware (`"${Build.MANUFACTURER} ${Build.MODEL}"` on Android, `Host.current().localizedName` on macOS).
* **Credit-Based Flow Control**: Direct L2CAP channel established over dynamic PSMs (Protocol/Service Multiplexers), bypassing GATT attribute size constraints.

### B. Transport Layer: 5GHz Wi-Fi Direct (P2P)
* **Off-Grid Independent Network**: Android acts as the Wi-Fi Direct Group Owner (GO) operating strictly on 5GHz (Band 4 / UNII-3) for minimal interference and maximum throughput.
* **Apple DVZip / CPIO Streaming**: Files are compressed on-the-fly and streamed directly from file descriptors into an HTTP chunked upload pipe. Mac extracts files sequentially to `~/Downloads` without memory double-buffering.

### C. Kernel Resilience: Bidirectional ARP Keepalive
* **The 35-Second Linux Stall Problem**: Standard HTTP uploads are unidirectional. Linux neighbor discovery on Android marks the Mac's neighbor entry as `STALE` after ~30 seconds, then `FAILED` after dropped unicast probes under 45 MB/s data flooding.
* **The Fix**: During active transfers, both Mac and Android emit periodic ICMP/UDP keepalive packets every 2.0 seconds. Android's kernel receives valid inbound packets from the Mac's IP, resetting the neighbor state to `NUD_REACHABLE` (`0x2`) continuously throughout multi-gigabyte transfers.

### D. Clean Wi-Fi Restoration
* **macOS Sequoia Compatibility**: Ephemeral P2P SSIDs are unconditionally removed from macOS's preferred wireless networks list. Calling `CoreWLAN.disassociate()` signals macOS native `airportd` to immediately re-associate with the user's primary Wi-Fi network without manual interaction.

### E. Claude AI Ingestion Pipeline
* **Intelligent File Processing**: Configurable Anthropic Claude API hook (`claude_processor.py`).
* **Multimodal Vision (Claude 3.5 Sonnet)**: Extracts OCR text, inspects receipts, analyzes UI screenshots, and describes photos.
* **Document Synthesis**: Generates executive summaries, key takeaways, and action items for text, PDF, and code files.
