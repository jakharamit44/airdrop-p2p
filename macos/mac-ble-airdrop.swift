import Foundation
import CoreBluetooth
import AppKit
import SwiftUI
import Network
import UniformTypeIdentifiers
import CryptoKit
import CoreWLAN
import Darwin

private let BLE_E2EE_KEY = SymmetricKey(data: SHA256.hash(data: Data("AirDropP2P-E2EE-AES256GCM-v2".utf8)))

func encryptBlePayload(_ plain: Data) -> Data {
    guard let sealed = try? AES.GCM.seal(plain, using: BLE_E2EE_KEY),
          let combined = sealed.combined else {
        fatalError("[BLE-Security] BLE encryption failed - refusing to transmit unencrypted payload")
    }
    return combined
}

func decryptBlePayload(_ packet: Data) -> Data? {
    guard packet.count > 28 else { return nil }
    if let box = try? AES.GCM.SealedBox(combined: packet),
       let opened = try? AES.GCM.open(box, using: BLE_E2EE_KEY) {
        return opened
    }
    return nil
}

func readUInt32BE(_ data: Data, offset: Int) -> Int {
    let b0 = Int(data[data.startIndex + offset]) << 24
    let b1 = Int(data[data.startIndex + offset + 1]) << 16
    let b2 = Int(data[data.startIndex + offset + 2]) << 8
    let b3 = Int(data[data.startIndex + offset + 3])
    return b0 | b1 | b2 | b3
}

let MAC_SERVICE_UUID = CBUUID(string: "52300001-A12D-4000-8000-523A12D00001")
let MAC_PSM_CHAR_UUID = CBUUID(string: "52300002-A12D-4000-8000-523A12D00002")
let P2P_SERVICE_UUID = CBUUID(string: "52300003-A12D-4000-8000-523A12D00003")
let P2P_PSM_CHAR_UUID = CBUUID(string: "52300004-A12D-4000-8000-523A12D00004")
let P2P_DATA_UUID = CBUUID(string: "CAFE")
let SHOW_UI_NOTIFICATION = Notification.Name("com.airdrop.p2p.showWindow")

func resolveRepoRoot() -> URL {
    if let env = ProcessInfo.processInfo.environment["AIRDROP_P2P_HOME"],
       (FileManager.default.fileExists(atPath: "\(env)/macos/mac-airdrop-p2p.sh") || FileManager.default.fileExists(atPath: "\(env)/mac-airdrop-p2p.sh")) {
        return URL(fileURLWithPath: env)
    }
    // 1. If running inside AirDrop P2P.app bundle, check Resources
    if let res = Bundle.main.resourceURL,
       (FileManager.default.fileExists(atPath: res.appendingPathComponent("mac-airdrop-p2p.sh").path) ||
        FileManager.default.fileExists(atPath: res.appendingPathComponent("macos/mac-airdrop-p2p.sh").path)) {
        return res
    }
    // 2. Check enclosing directory
    let enclosing = Bundle.main.bundleURL.deletingLastPathComponent()
    if FileManager.default.fileExists(atPath: enclosing.appendingPathComponent("macos/mac-airdrop-p2p.sh").path) ||
       FileManager.default.fileExists(atPath: enclosing.appendingPathComponent("mac-airdrop-p2p.sh").path) {
        return enclosing
    }
    // 3. Argument 0 walking
    var url = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent()
    for _ in 0..<6 {
        if FileManager.default.fileExists(atPath: url.appendingPathComponent("macos/mac-airdrop-p2p.sh").path) ||
           FileManager.default.fileExists(atPath: url.appendingPathComponent("mac-airdrop-p2p.sh").path) ||
           FileManager.default.fileExists(atPath: url.appendingPathComponent("mac-airdrop-lan.sh").path) {
            return url
        }
        url.deleteLastPathComponent()
    }
    let pwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    if FileManager.default.fileExists(atPath: pwd.appendingPathComponent("macos/mac-airdrop-p2p.sh").path) {
        return pwd
    }
    return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".airdrop-p2p")
}

let REPO_ROOT = resolveRepoRoot()
let STATE_DIR: URL = {
    if let env = ProcessInfo.processInfo.environment["AIRDROP_P2P_STATE_DIR"], !env.isEmpty {
        let u = URL(fileURLWithPath: env)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }
    let u = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".airdrop-p2p")
    try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
    return u
}()
let SCRIPT_PATH: String = {
    if let p = Bundle.main.path(forResource: "mac-airdrop-p2p", ofType: "sh"), FileManager.default.fileExists(atPath: p) {
        return p
    }
    if let res = Bundle.main.resourceURL?.appendingPathComponent("mac-airdrop-p2p.sh").path, FileManager.default.fileExists(atPath: res) {
        return res
    }
    let p0 = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".airdrop-p2p/mac-airdrop-p2p.sh").path
    if FileManager.default.fileExists(atPath: p0) { return p0 }
    let p1 = REPO_ROOT.appendingPathComponent("macos/mac-airdrop-p2p.sh").path
    if FileManager.default.fileExists(atPath: p1) { return p1 }
    let p2 = REPO_ROOT.appendingPathComponent("mac-airdrop-p2p.sh").path
    if FileManager.default.fileExists(atPath: p2) { return p2 }
    return p1
}()

func currentMacLanIp() -> String {
    var ifaddr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else { return "" }
    defer { freeifaddrs(ifaddr) }
    for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
        let flags = Int32(ptr.pointee.ifa_flags)
        if (flags & (IFF_UP|IFF_RUNNING|IFF_LOOPBACK)) == (IFF_UP|IFF_RUNNING) {
            let name = String(cString: ptr.pointee.ifa_name)
            if name == "en0" || name.starts(with: "en") {
                guard let sa = ptr.pointee.ifa_addr else { continue }
                if sa.pointee.sa_family == UInt8(AF_INET) {
                    var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    if getnameinfo(sa, socklen_t(sa.pointee.sa_len), &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST) == 0 {
                        let ip = String(cString: hostname)
                        if !ip.starts(with: "192.168.49.") && !ip.starts(with: "127.") && !ip.starts(with: "169.254.") {
                            return ip
                        }
                    }
                }
            }
        }
    }
    return ""
}

func runProcessCapture(_ executablePath: String, _ arguments: [String]) -> (Int32, String) {
    let p = Process()
    let pipe = Pipe()
    p.executableURL = URL(fileURLWithPath: executablePath)
    p.arguments = arguments
    p.standardOutput = pipe
    p.standardError = FileHandle.nullDevice
    guard (try? p.run()) != nil else {
        try? pipe.fileHandleForWriting.close()
        try? pipe.fileHandleForReading.close()
        return (-1, "")
    }
    try? pipe.fileHandleForWriting.close()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    try? pipe.fileHandleForReading.close()
    p.waitUntilExit()
    return (p.terminationStatus, String(data: data, encoding: .utf8) ?? "")
}

func hasActiveTcpReceiverConnection() -> Bool {
    let (_, out) = runProcessCapture("/usr/sbin/lsof", ["-n", "-P", "-iTCP:8772"])
    return out.contains("ESTABLISHED")
}

func formatByteSize(_ bytes: Int64) -> String {
    if bytes <= 0 { return "0 B" }
    let kb = 1024.0
    let mb = kb * 1024.0
    let gb = mb * 1024.0
    let d = Double(bytes)
    if d >= gb { return String(format: "%.2f GB", d / gb) }
    if d >= mb { return String(format: "%.1f MB", d / mb) }
    if d >= kb { return String(format: "%.1f KB", d / kb) }
    return "\(bytes) B"
}

func formatTransferSpeed(_ bps: Int64) -> String {
    if bps <= 0 { return "0 KB/s" }
    return "\(formatByteSize(bps))/s"
}

func writeProgressJson(
    active: Bool,
    direction: String = "",
    fileName: String = "",
    fileCount: Int = 1,
    doneBytes: Int64 = 0,
    totalBytes: Int64 = 0,
    speedBps: Int64 = 0,
    etaSeconds: Int64 = 0,
    percent: Int = 0,
    phase: String = "",
    peerName: String = "",
    isConnecting: Bool = false
) {
    let pf = STATE_DIR.appendingPathComponent("transfer_progress.json")
    let tmp = STATE_DIR.appendingPathComponent("transfer_progress.json.tmp")
    if !active {
        try? FileManager.default.removeItem(at: pf)
        return
    }
    let dict: [String: Any] = [
        "active": true,
        "direction": direction,
        "fileName": fileName,
        "fileCount": fileCount,
        "doneBytes": doneBytes,
        "totalBytes": totalBytes,
        "speedBps": speedBps,
        "etaSeconds": etaSeconds,
        "percent": percent,
        "phase": phase,
        "peerName": peerName,
        "isConnecting": isConnecting,
        "updatedAt": Date().timeIntervalSince1970
    ]
    if let data = try? JSONSerialization.data(withJSONObject: dict, options: []) {
        try? data.write(to: tmp)
        _ = try? FileManager.default.replaceItemAt(pf, withItemAt: tmp)
    }
}

func appendReceivedLog(kind: String, value: String, sizeBytes: Int64 = 0, direction: String = "received", peerName: String = "Nearby Peer") {
    let rxLog = STATE_DIR.appendingPathComponent("received.log")
    let line = "\(Int(Date().timeIntervalSince1970))\t\(kind)\t\(value)\t\(sizeBytes)\t\(direction)\t\(peerName)\n"
    if let data = line.data(using: .utf8) {
        if FileManager.default.fileExists(atPath: rxLog.path),
           let fh = try? FileHandle(forWritingTo: rxLog) {
            fh.seekToEndOfFile()
            fh.write(data)
            try? fh.close()
        } else {
            try? data.write(to: rxLog)
        }
    }
}

struct MacDiscoveredPeer: Identifiable, Equatable {
    let id: String
    let name: String
    let transport: String
    let address: String
    let psm: Int
    let rssi: Int
    let lastSeen: TimeInterval
}

private let activePeersLock = NSLock()
private let PEER_LIVE_TTL_SECONDS: TimeInterval = 10.0

func recordActivePeerOnDisk(
    id: String,
    name: String,
    transport: String,
    address: String,
    psm: Int,
    rssi: Int
) {
    activePeersLock.lock()
    defer { activePeersLock.unlock() }
    let pf = STATE_DIR.appendingPathComponent("active_peers.json")
    let tmp = STATE_DIR.appendingPathComponent("active_peers.json.tmp")
    let now = Date().timeIntervalSince1970
    var dict: [String: [String: Any]] = [:]
    if let d = try? Data(contentsOf: pf),
       let raw = (try? JSONSerialization.jsonObject(with: d)) as? [String: [String: Any]] {
        for (k, v) in raw {
            let ls = (v["lastSeen"] as? NSNumber)?.doubleValue ?? 0
            if now - ls <= PEER_LIVE_TTL_SECONDS {
                dict[k] = v
            }
        }
    }
    let incomingIsFallback = name.hasPrefix("Android Peer (") || name == "Android Peer"
    for (_, existing) in dict {
        let exName = (existing["name"] as? String) ?? ""
        let exPsm = (existing["psm"] as? NSNumber)?.intValue ?? 0
        let exLastSeen = (existing["lastSeen"] as? NSNumber)?.doubleValue ?? 0
        let exIsFallback = exName.hasPrefix("Android Peer (") || exName == "Android Peer"
        if !exIsFallback && incomingIsFallback {
            // Ignore unnamed zombie BLE advertisements when a named peer is already live
            return
        }
        if psm > 0 && exPsm > 0 && psm < exPsm && (now - exLastSeen) < 4.5 {
            // Ignore older leaked BLE advertising sets with lower PSMs while the newest PSM is active
            return
        }
    }
    // Keep a single canonical active peer entry so BLE RPA / PSM rotation never creates duplicate cards
    dict.removeAll()
    dict[id] = [
        "id": id,
        "name": name,
        "transport": transport,
        "address": address,
        "psm": psm,
        "rssi": rssi,
        "lastSeen": now
    ]
    if let out = try? JSONSerialization.data(withJSONObject: dict, options: []) {
        try? out.write(to: tmp)
        _ = try? FileManager.default.replaceItemAt(pf, withItemAt: tmp)
    }
}

func loadActivePeersFromDisk(maxAge: TimeInterval = PEER_LIVE_TTL_SECONDS) -> [MacDiscoveredPeer] {
    activePeersLock.lock()
    defer { activePeersLock.unlock() }
    let pf = STATE_DIR.appendingPathComponent("active_peers.json")
    let now = Date().timeIntervalSince1970
    guard let d = try? Data(contentsOf: pf),
          let raw = (try? JSONSerialization.jsonObject(with: d)) as? [String: [String: Any]] else {
        return []
    }
    var list: [MacDiscoveredPeer] = []
    for (_, v) in raw {
        let lastSeen = (v["lastSeen"] as? NSNumber)?.doubleValue ?? 0
        guard now - lastSeen <= maxAge else { continue }
        let id = (v["id"] as? String) ?? UUID().uuidString
        let name = (v["name"] as? String) ?? "Android Peer"
        let transport = (v["transport"] as? String) ?? "5GHz P2P • BLE"
        let address = (v["address"] as? String) ?? ""
        let psm = (v["psm"] as? NSNumber)?.intValue ?? 0
        let rssi = (v["rssi"] as? NSNumber)?.intValue ?? -60
        list.append(MacDiscoveredPeer(
            id: id,
            name: name,
            transport: transport,
            address: address,
            psm: psm,
            rssi: rssi,
            lastSeen: lastSeen
        ))
    }
    return list.sorted { $0.rssi > $1.rssi }
}

func safeMacNotification(message: String, title: String) {
    let notify = Process()
    notify.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
    notify.arguments = [
        "-e", "on run argv",
        "-e", "display notification (item 1 of argv) with title (item 2 of argv) sound name \"Glass\"",
        "-e", "end run",
        "--",
        String(message.prefix(240)),
        String(title.prefix(120))
    ]
    try? notify.run()
}

func loadMacSettings() -> (autoAccept: Bool, visible: Bool, deviceName: String, themeMode: String) {
    let defaultName = Host.current().localizedName ?? "MacBook Pro"
    let sf = STATE_DIR.appendingPathComponent("settings.json")
    if let d = try? Data(contentsOf: sf),
       let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] {
        let auto = (obj["autoAccept"] as? Bool) ?? false
        let vis = (obj["visible"] as? Bool) ?? true
        let name = (obj["deviceName"] as? String) ?? defaultName
        let rawTheme = (obj["themeMode"] as? String) ?? "system"
        let theme = ["light", "dark", "system"].contains(rawTheme) ? rawTheme : "system"
        return (auto, vis, name.isEmpty ? defaultName : name, theme)
    }
    return (false, true, defaultName, "system")
}

func saveMacSettings(autoAccept: Bool, visible: Bool, deviceName: String, themeMode: String? = nil) {
    let resolvedTheme = themeMode ?? loadMacSettings().themeMode
    let sf = STATE_DIR.appendingPathComponent("settings.json")
    let dict: [String: Any] = [
        "autoAccept": autoAccept,
        "visible": visible,
        "deviceName": deviceName,
        "themeMode": resolvedTheme
    ]
    if let d = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted]) {
        try? d.write(to: sf, options: [.atomic])
    }
}

func waitForMacUserAccept(senderName: String, fileNames: [String], totalBytes: Int64) -> Bool {
    let settings = loadMacSettings()
    if settings.autoAccept { return true }

    let reqId = UUID().uuidString
    let askFile = STATE_DIR.appendingPathComponent("pending_ask.json")
    let decFile = STATE_DIR.appendingPathComponent("ask_decision.json")
    try? FileManager.default.removeItem(at: decFile)

    let payload: [String: Any] = [
        "id": reqId,
        "senderName": senderName,
        "fileNames": fileNames,
        "totalBytes": totalBytes,
        "timestamp": Date().timeIntervalSince1970
    ]
    if let d = try? JSONSerialization.data(withJSONObject: payload) {
        try? d.write(to: askFile, options: [.atomic])
    }
    DistributedNotificationCenter.default().postNotificationName(
        SHOW_UI_NOTIFICATION,
        object: nil,
        userInfo: nil,
        deliverImmediately: true
    )

    defer {
        try? FileManager.default.removeItem(at: askFile)
    }

    let deadline = Date().addingTimeInterval(60.0)
    while Date() < deadline {
        if let d = try? Data(contentsOf: decFile),
           let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
           (obj["id"] as? String) == reqId {
            return (obj["accepted"] as? Bool) ?? false
        }
        Thread.sleep(forTimeInterval: 0.15)
    }
    return false
}

func isTransferCancelled() -> Bool {
    return FileManager.default.fileExists(atPath: STATE_DIR.appendingPathComponent("cancel_transfer.flag").path)
}

func clearCancelFlag() {
    try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("cancel_transfer.flag"))
}

let PREV_WIFI_FILE = STATE_DIR.appendingPathComponent("previous_wifi_ssid.txt")
let WARP_PAUSED_FILE = STATE_DIR.appendingPathComponent("warp_was_active.flag")
let LAN_FALLBACK_FILE = STATE_DIR.appendingPathComponent("lan_fallback_active.flag")

func resolveWarpCliPath() -> String? {
    let candidates = [
        "/Applications/Cloudflare WARP.app/Contents/Resources/warp-cli",
        "/usr/local/bin/warp-cli",
        "/opt/homebrew/bin/warp-cli"
    ]
    for path in candidates {
        if FileManager.default.isExecutableFile(atPath: path) {
            return path
        }
    }
    return nil
}

/// Pauses Cloudflare WARP before associating `en0` with an offline `DIRECT-*` Wi-Fi Direct SSID.
/// Without an explicit manual disconnect, WARP's Happy Eyeballs check times out at ~36s on offline P2P
/// networks and activates its fail-closed base firewall (`catch all policy Deny`), dropping 192.168.49.0/24.
/// Returns `true` if WARP is absent or cleanly disconnected; `false` if corporate MDM locked the WARP switch.
func pauseCloudflareWarpIfNeeded() -> Bool {
    guard let warpCli = resolveWarpCliPath() else { return true }
    let (_, statusOut) = runProcessCapture(warpCli, ["--accept-tos", "status"])
    if statusOut.isEmpty { return true }

    if statusOut.contains("Status update: Disconnected") && statusOut.contains("Manual Disconnection") {
        return true
    }

    let (_, settingsOut) = runProcessCapture(warpCli, ["--accept-tos", "settings"])
    let wasActive = statusOut.contains("Status update: Connected") ||
                    statusOut.contains("Status update: Connecting") ||
                    settingsOut.contains("Always On: true")
    guard wasActive else { return true }

    if settingsOut.contains("Switch Locked: true") {
        print("[BLE-Daemon] Cloudflare WARP switch is locked by organization policy — cannot disconnect for offline P2P")
        fflush(stdout)
        return false
    }

    try? String(Date().timeIntervalSince1970).write(to: WARP_PAUSED_FILE, atomically: true, encoding: .utf8)
    _ = runProcessCapture(warpCli, ["--accept-tos", "disconnect"])

    let deadline = Date().addingTimeInterval(2.0)
    while Date() < deadline {
        let (_, checkOut) = runProcessCapture(warpCli, ["--accept-tos", "status"])
        if checkOut.contains("Status update: Disconnected") {
            print("[BLE-Daemon] Paused Cloudflare WARP for offline 5GHz Wi-Fi Direct transfer")
            fflush(stdout)
            return true
        }
        Thread.sleep(forTimeInterval: 0.15)
    }

    try? FileManager.default.removeItem(at: WARP_PAUSED_FILE)
    print("[BLE-Daemon] Warning: Cloudflare WARP did not transition to Disconnected")
    fflush(stdout)
    return false
}

func keepCloudflareWarpPausedIfFlagged() {
    guard FileManager.default.fileExists(atPath: WARP_PAUSED_FILE.path),
          let warpCli = resolveWarpCliPath() else { return }
    let (_, statusOut) = runProcessCapture(warpCli, ["--accept-tos", "status"])
    if !statusOut.isEmpty && !statusOut.contains("Status update: Disconnected") {
        print("[BLE-Daemon] Re-pausing Cloudflare WARP after auto-connect timer")
        fflush(stdout)
        _ = runProcessCapture(warpCli, ["--accept-tos", "disconnect"])
    }
}

func resumeCloudflareWarpIfNeeded() {
    guard FileManager.default.fileExists(atPath: WARP_PAUSED_FILE.path) else { return }
    defer { try? FileManager.default.removeItem(at: WARP_PAUSED_FILE) }
    guard let warpCli = resolveWarpCliPath() else { return }
    _ = runProcessCapture(warpCli, ["--accept-tos", "connect"])
    print("[BLE-Daemon] Resumed Cloudflare WARP connection")
    fflush(stdout)
}

func currentWifiSsid() -> String {
    let (_, out) = runProcessCapture("/usr/sbin/networksetup", ["-getairportnetwork", "en0"])
    if out.contains("Current Wi-Fi Network: ") {
        let name = out.components(separatedBy: "Current Wi-Fi Network: ").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if !name.isEmpty && !name.hasPrefix("DIRECT-") && !name.contains("not associated") {
            return name
        }
    }
    return ""
}

func saveCurrentWifiSsid() {
    var ssid = currentWifiSsid()
    if ssid.isEmpty {
        ssid = topPreferredWifiNetwork()
    }
    if !ssid.isEmpty {
        try? ssid.write(to: PREV_WIFI_FILE, atomically: true, encoding: .utf8)
        print("[BLE-Daemon] Preserved home Wi-Fi network: '\(ssid)'")
        fflush(stdout)
    }
}

func topPreferredWifiNetwork() -> String {
    let (_, out) = runProcessCapture("/usr/sbin/networksetup", ["-listpreferredwirelessnetworks", "en0"])
    for line in out.split(separator: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty && !trimmed.hasPrefix("Preferred networks") && !trimmed.hasPrefix("DIRECT-") {
            return trimmed
        }
    }
    return ""
}

func restoreMacInternetWifi(ssid: String = "DIRECT-") {
    try? FileManager.default.removeItem(at: LAN_FALLBACK_FILE)

    // 1. ALWAYS unconditionally remove any ephemeral P2P network from preferred list so macOS never stays stuck or reconnects to it
    let (_, prefOut) = runProcessCapture("/usr/sbin/networksetup", ["-listpreferredwirelessnetworks", "en0"])
    for net in prefOut.components(separatedBy: "\n") {
        let trimmed = net.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("DIRECT-") {
            _ = runProcessCapture("/usr/sbin/networksetup", ["-removepreferredwirelessnetwork", "en0", trimmed])
        }
    }

    func en0HasNormalIpv4() -> Bool {
        let (_, outStr) = runProcessCapture("/sbin/ifconfig", ["en0"])
        if outStr.contains("inet 192.168.49.") { return false }
        return outStr.contains("inet 192.168.") || outStr.contains("inet 10.") || outStr.contains("inet 172.")
    }

    // 2. Check if en0 is already back on normal Wi-Fi
    if en0HasNormalIpv4() {
        print("[BLE-Daemon] en0 connected to normal Wi-Fi. P2P removed from preferred list.")
        fflush(stdout)
        try? FileManager.default.removeItem(at: PREV_WIFI_FILE)
        resumeCloudflareWarpIfNeeded()
        return
    }

    print("[BLE-Daemon] Restoring Mac Internet Wi-Fi (disconnecting P2P)...")
    fflush(stdout)

    // 3. Resolve target home network to restore
    let savedSsid = (try? String(contentsOf: PREV_WIFI_FILE, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    let targetSsid = (!savedSsid.isEmpty && !savedSsid.hasPrefix("DIRECT-")) ? savedSsid : topPreferredWifiNetwork()

    // 4. Disassociate en0 using CoreWLAN to cleanly detach from P2P
    if let iface = CWWiFiClient.shared().interface(withName: "en0") {
        iface.disassociate()
    }
    Thread.sleep(forTimeInterval: 1.5)

    // 5. If target network is known and not yet reconnected, reassociate
    let activeNow = currentWifiSsid()
    if activeNow.isEmpty && !targetSsid.isEmpty {
        print("[BLE-Daemon] Fast-reassociating en0 to home Wi-Fi '\(targetSsid)'...")
        fflush(stdout)
        _ = runProcessCapture("/usr/sbin/networksetup", ["-setairportnetwork", "en0", targetSsid])
    }

    // 6. Wait synchronously up to 4.5s for en0 to obtain normal Wi-Fi IPv4 before resuming WARP
    let waitDeadline = Date().addingTimeInterval(4.5)
    while Date() < waitDeadline {
        if en0HasNormalIpv4() { break }
        Thread.sleep(forTimeInterval: 0.25)
    }

    // 7. Fallback safety verification: only cycle power if en0 is still wedged without valid IPv4
    if !en0HasNormalIpv4() {
        print("[BLE-Daemon] Network did not reassociate automatically — power cycling radio as fallback...")
        fflush(stdout)
        _ = runProcessCapture("/usr/sbin/networksetup", ["-setairportpower", "en0", "off"])
        Thread.sleep(forTimeInterval: 0.3)
        _ = runProcessCapture("/usr/sbin/networksetup", ["-setairportpower", "en0", "on"])
        let cycleDeadline = Date().addingTimeInterval(4.0)
        while Date() < cycleDeadline {
            if en0HasNormalIpv4() { break }
            Thread.sleep(forTimeInterval: 0.25)
        }
    }

    try? FileManager.default.removeItem(at: PREV_WIFI_FILE)
    resumeCloudflareWarpIfNeeded()
    print("[BLE-Daemon] Wi-Fi restored and auto-reassociation completed.")
    fflush(stdout)
}

func readExact(
    _ stream: InputStream,
    count: Int,
    trackProgress: Bool = false,
    fileLabel: String = "Incoming File",
    fileCount: Int = 1
) -> Data? {
    var data = Data(count: count)
    var offset = 0
    let startTime = Date()
    var lastEmit = Date.distantPast
    while offset < count {
        if trackProgress && isTransferCancelled() {
            clearCancelFlag()
            writeProgressJson(active: false)
            return nil
        }
        let readCount = data.withUnsafeMutableBytes { ptr -> Int in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            return stream.read(base.advanced(by: offset), maxLength: min(32768, count - offset))
        }
        if readCount > 0 {
            offset += readCount
            if trackProgress {
                let now = Date()
                if now.timeIntervalSince(lastEmit) >= 0.1 || offset == count {
                    lastEmit = now
                    let elapsed = max(0.1, now.timeIntervalSince(startTime))
                    let speed = Int64(Double(offset) / elapsed)
                    let rem = Int64(max(0, count - offset))
                    let eta = speed > 0 ? (rem / speed) : 0
                    let pct = min(99, (offset * 100) / max(1, count))
                    writeProgressJson(
                        active: true,
                        direction: "Receiving",
                        fileName: fileLabel,
                        fileCount: fileCount,
                        doneBytes: Int64(offset),
                        totalBytes: Int64(count),
                        speedBps: speed,
                        etaSeconds: eta,
                        percent: pct
                    )
                }
            }
        } else if readCount == 0 {
            Thread.sleep(forTimeInterval: 0.01)
            if stream.streamStatus == .atEnd || stream.streamStatus == .error || stream.streamStatus == .closed {
                if trackProgress { writeProgressJson(active: false) }
                return nil
            }
        } else {
            if trackProgress { writeProgressJson(active: false) }
            return nil
        }
    }
    if trackProgress { writeProgressJson(active: false) }
    return data
}

func writeAll(
    _ stream: OutputStream,
    data: Data,
    trackProgress: Bool = false,
    fileLabel: String = "Sending File",
    fileCount: Int = 1
) -> Bool {
    var offset = 0
    let total = data.count
    var idleLoops = 0
    var lastLoggedPct = -10
    let startTime = Date()
    var lastEmit = Date.distantPast
    while offset < total {
        if trackProgress && isTransferCancelled() {
            clearCancelFlag()
            writeProgressJson(active: false)
            return false
        }
        if !stream.hasSpaceAvailable {
            Thread.sleep(forTimeInterval: 0.001)
            idleLoops += 1
            if idleLoops > 120000 {
                if trackProgress { writeProgressJson(active: false) }
                return false
            }
            continue
        }
        idleLoops = 0
        let written = data.withUnsafeBytes { ptr -> Int in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return -1 }
            return stream.write(base.advanced(by: offset), maxLength: min(32768, total - offset))
        }
        if written > 0 {
            offset += written
            let pct = (offset * 100) / max(1, total)
            if trackProgress && (pct >= lastLoggedPct + 10 || offset == total) {
                lastLoggedPct = pct
                print("[BLE-Send] Progress: \(pct)% (\(offset / 1024) KB / \(total / 1024) KB)")
                fflush(stdout)
            }
            if trackProgress {
                let now = Date()
                if now.timeIntervalSince(lastEmit) >= 0.1 || offset == total {
                    lastEmit = now
                    let elapsed = max(0.1, now.timeIntervalSince(startTime))
                    let speed = Int64(Double(offset) / elapsed)
                    let rem = Int64(max(0, total - offset))
                    let eta = speed > 0 ? (rem / speed) : 0
                    writeProgressJson(
                        active: true,
                        direction: "Sending",
                        fileName: fileLabel,
                        fileCount: fileCount,
                        doneBytes: Int64(offset),
                        totalBytes: Int64(total),
                        speedBps: speed,
                        etaSeconds: eta,
                        percent: min(99, pct)
                    )
                }
            }
        } else if written == 0 {
            Thread.sleep(forTimeInterval: 0.002)
        } else {
            if trackProgress { writeProgressJson(active: false) }
            return false
        }
    }
    if trackProgress { writeProgressJson(active: false) }
    return true
}

private let wp2pJoinLock = NSLock()
private var wp2pJoinActive = false

func currentEn0P2pIp() -> String {
    let (_, outStr) = runProcessCapture("/sbin/ifconfig", ["en0"])
    for line in outStr.split(separator: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("inet 192.168.49.") {
            let toks = trimmed.split(separator: " ")
            if toks.count >= 2 { return String(toks[1]) }
        }
    }
    return ""
}

func handleIncomingWp2pJoin(ssid: String, pass: String, out: OutputStream) {
    guard ssid.hasPrefix("DIRECT-"), !pass.isEmpty else {
        print("[BLE-Daemon] Rejected invalid WP2P request: SSID '\(ssid)' does not start with DIRECT-")
        _ = writeAll(out, data: Data("ERR\n".utf8))
        return
    }

    wp2pJoinLock.lock()
    if wp2pJoinActive {
        let existingIp = currentEn0P2pIp()
        wp2pJoinLock.unlock()
        if !existingIp.isEmpty {
            print("[BLE-Daemon] Reusing in-flight 5GHz P2P session at \(existingIp)")
            fflush(stdout)
            _ = writeAll(out, data: Data("OK \(existingIp)\n".utf8))
            return
        }
        // Wait briefly for in-flight join to finish obtaining DHCP
        let waitJoin = Date().addingTimeInterval(8.0)
        while Date() < waitJoin {
            let ip = currentEn0P2pIp()
            if !ip.isEmpty {
                _ = writeAll(out, data: Data("OK \(ip)\n".utf8))
                return
            }
            Thread.sleep(forTimeInterval: 0.25)
        }
        _ = writeAll(out, data: Data("ERR\n".utf8))
        return
    }
    wp2pJoinActive = true
    wp2pJoinLock.unlock()

    defer {
        wp2pJoinLock.lock()
        wp2pJoinActive = false
        wp2pJoinLock.unlock()
    }

    let uploadDoneFile = STATE_DIR.appendingPathComponent("upload_completed.flag")
    try? FileManager.default.removeItem(at: uploadDoneFile)

    // Pause Cloudflare WARP before associating en0 to offline DIRECT-* P2P so WARP's 36s Happy Eyeballs
    // fail-closed firewall never drops 192.168.49.0/24 traffic mid-transfer.
    let warpCleared = pauseCloudflareWarpIfNeeded()
    if !warpCleared {
        let lanIp = currentMacLanIp()
        if !lanIp.isEmpty {
            try? String(Date().timeIntervalSince1970).write(to: LAN_FALLBACK_FILE, atomically: true, encoding: .utf8)
            print("[BLE-Daemon] WARP switch locked; keeping en0 on LAN (\(lanIp)) for Split-Tunnel transfer")
            fflush(stdout)
            _ = writeAll(out, data: Data("OK \(lanIp)\n".utf8))
            return
        }
    }

    saveCurrentWifiSsid()
    let incomingPeerName = loadActivePeersFromDisk(maxAge: 30.0).first?.name ?? "Nearby Device"
    writeProgressJson(
        active: true,
        direction: "Receiving",
        fileName: "Incoming transfer",
        fileCount: 1,
        percent: 0,
        phase: "Joining 5 GHz Wi-Fi Direct (\(ssid))…",
        peerName: incomingPeerName,
        isConnecting: true
    )
    print("[BLE-Daemon] Incoming WP2P 5GHz Wi-Fi Direct request: joining \(ssid)...")
    fflush(stdout)

    var macP2pIp = currentEn0P2pIp()
    if macP2pIp.isEmpty {
        _ = runProcessCapture("/usr/sbin/networksetup", ["-setairportnetwork", "en0", ssid, pass])

        let deadline = Date().addingTimeInterval(12.0)
        var retriedJoin = false
        while Date() < deadline {
            macP2pIp = currentEn0P2pIp()
            if !macP2pIp.isEmpty { break }
            if !retriedJoin && deadline.timeIntervalSinceNow < 6.0 {
                retriedJoin = true
                _ = runProcessCapture("/usr/sbin/networksetup", ["-setairportnetwork", "en0", ssid, pass])
            }
            Thread.sleep(forTimeInterval: 0.2)
        }
    }

    if macP2pIp.isEmpty {
        writeProgressJson(active: false)
        restoreMacInternetWifi(ssid: ssid)
        _ = writeAll(out, data: Data("ERR\n".utf8))
        return
    }

    writeProgressJson(
        active: true,
        direction: "Receiving",
        fileName: "Incoming transfer",
        fileCount: 1,
        percent: 0,
        phase: "Waiting for sender handshake (\(macP2pIp))…",
        peerName: incomingPeerName,
        isConnecting: true
    )
    print("[BLE-Daemon] Joined \(ssid) at \(macP2pIp), signaling peer...")
    fflush(stdout)
    if !writeAll(out, data: Data("OK \(macP2pIp)\n".utf8)) {
        print("[BLE-Daemon] Warning: BLE L2CAP reply stream closed while sending OK \(macP2pIp); waiting briefly for TCP fallback")
        fflush(stdout)
    }

    let askFile = STATE_DIR.appendingPathComponent("pending_ask.json")
    let txFile = STATE_DIR.appendingPathComponent("transfer_progress.json")
    let rxLock = STATE_DIR.appendingPathComponent("rx_in_progress.lock")

    // Phase 1: Wait up to 30s for the peer to initiate the HTTPS transfer
    let startDeadline = Date().addingTimeInterval(30.0)
    var transferDetected = false
    while Date() < startDeadline {
        let detected = autoreleasepool { () -> Bool in
            if FileManager.default.fileExists(atPath: askFile.path) ||
               FileManager.default.fileExists(atPath: rxLock.path) ||
               hasActiveTcpReceiverConnection() {
                return true
            }
            if let data = try? Data(contentsOf: txFile),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               (obj["isConnecting"] as? Bool) == false {
                return true
            }
            return false
        }
        if detected {
            transferDetected = true
            break
        }
        Thread.sleep(forTimeInterval: 0.25)
    }

    if !transferDetected {
        print("[BLE-Daemon] Peer did not initiate HTTPS transfer within 30s — restoring Wi-Fi")
        fflush(stdout)
        writeProgressJson(active: false)
        restoreMacInternetWifi(ssid: ssid)
        return
    }

    // Phase 2: Transfer is active. Keep link alive until completion or prolonged silence.
    var idleCount = 0
    var lastActivity = Date()
    var lastKeepAlivePing = Date.distantPast
    var lastWarpCheck = Date()

    while true {
        let shouldBreak = autoreleasepool { () -> Bool in
            if Date().timeIntervalSince(lastKeepAlivePing) >= 2.0 {
                lastKeepAlivePing = Date()
                DispatchQueue.global(qos: .utility).async {
                    _ = runProcessCapture("/sbin/ping", ["-c", "1", "-t", "1", "-W", "500", "192.168.49.1"])
                }
            }

            if Date().timeIntervalSince(lastWarpCheck) >= 8.0 {
                lastWarpCheck = Date()
                keepCloudflareWarpPausedIfFlagged()
            }

            if FileManager.default.fileExists(atPath: uploadDoneFile.path) {
                try? FileManager.default.removeItem(at: uploadDoneFile)
                print("[BLE-Daemon] Upload completed successfully — restoring Wi-Fi immediately")
                fflush(stdout)
                Thread.sleep(forTimeInterval: 1.0)
                return true
            }

            let isAsk = FileManager.default.fileExists(atPath: askFile.path)
            let now = Date().timeIntervalSince1970

            var isRxLockActive = false
            if FileManager.default.fileExists(atPath: rxLock.path) {
                if let attrs = try? FileManager.default.attributesOfItem(atPath: rxLock.path),
                   let mtime = attrs[.modificationDate] as? Date {
                    if now - mtime.timeIntervalSince1970 < 30.0 { isRxLockActive = true }
                }
                if !isRxLockActive, let content = try? String(contentsOf: rxLock, encoding: .utf8) {
                    let parts = content.split(separator: "\t")
                    if parts.count >= 3, let ts = Double(parts[2]) {
                        if (now - ts) < 30.0 { isRxLockActive = true }
                    }
                }
            }

            var isProgressActive = false
            if let data = try? Data(contentsOf: txFile),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let active = obj["active"] as? Bool, active,
               let updatedAt = obj["updatedAt"] as? Double {
                if (now - updatedAt) < 30.0 { isProgressActive = true }
            }

            let isActiveTcp = hasActiveTcpReceiverConnection()

            if isAsk || isRxLockActive || isProgressActive || isActiveTcp {
                lastActivity = Date()
                idleCount = 0
            } else if Date().timeIntervalSince(lastActivity) > 30.0 {
                idleCount += 1
                if idleCount >= 20 {
                    print("[BLE-Daemon] Transfer stream ended (idle timeout) — restoring Wi-Fi")
                    fflush(stdout)
                    return true
                }
            }
            return false
        }
        if shouldBreak { break }
        Thread.sleep(forTimeInterval: 0.5)
    }

    restoreMacInternetWifi(ssid: ssid)
}

func buildDvzipCpio(files: [URL]) throws -> (Data, [[String: Any]]) {
    guard !files.isEmpty else { return (Data(), []) }
    var fileDicts: [[String: Any]] = []
    var ino = 1

    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/gzip")
    proc.arguments = ["-1", "-c"]
    let inPipe = Pipe()
    let outPipe = Pipe()
    proc.standardInput = inPipe
    proc.standardOutput = outPipe
    try proc.run()

    func makeOdcHdr(path: String, mode: Int, size: Int64) -> Data {
        let nameBytes = Array(path.utf8) + [0]
        let header = String(
            format: "070707%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o",
            0, ino, mode, 501, 20, 1, 0, Int(Date().timeIntervalSince1970), nameBytes.count, size
        )
        ino += 1
        var d = Data(header.utf8)
        d.append(contentsOf: nameBytes)
        return d
    }

    for url in files {
        let name = url.lastPathComponent
        if name.hasPrefix("._") { continue }
        let sz = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int64) ?? 0
        fileDicts.append([
            "FileName": name,
            "FileType": "public.data",
            "FileSize": sz,
            "FileBomPath": "./\(name)",
            "FileIsDirectory": false,
            "ConvertMediaFormats": false
        ])
    }

    DispatchQueue.global(qos: .userInitiated).async {
        let wh = inPipe.fileHandleForWriting
        wh.write(makeOdcHdr(path: ".", mode: 0o040755, size: 0))
        for url in files {
            let name = url.lastPathComponent
            if name.hasPrefix("._") { continue }
            guard let handle = try? FileHandle(forReadingFrom: url) else { continue }
            let sz = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int64) ?? 0
            wh.write(makeOdcHdr(path: "./\(name)", mode: 0o100644, size: sz))
            while true {
                let chunk = handle.readData(ofLength: 65536)
                if chunk.isEmpty { break }
                wh.write(chunk)
            }
            try? handle.close()
        }
        wh.write(makeOdcHdr(path: "TRAILER!!!", mode: 0, size: 0))
        try? wh.close()
    }

    let gzData = outPipe.fileHandleForReading.readDataToEndOfFile()
    proc.waitUntilExit()
    return (gzData, fileDicts)
}

func extractDvzipCpioToDownloads(archiveData: Data, metaDict: [String: Any]) {
    let downloads = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
    let sender = (metaDict["SenderComputerName"] as? String) ?? "Android Peer"

    if let items = metaDict["Items"] as? [Any] {
        for item in items {
            if let s = item as? String,
               let parsed = URL(string: s),
               let scheme = parsed.scheme?.lowercased(),
               (scheme == "http" || scheme == "https"),
               parsed.host != nil {
                print("[BLE-RX] Received URL from \(sender): \(s)")
                appendReceivedLog(kind: "URL", value: s, sizeBytes: Int64(s.utf8.count), direction: "received", peerName: sender)
                DispatchQueue.main.async {
                    let pb = NSPasteboard.general
                    pb.clearContents()
                    pb.setString(s, forType: .string)
                }
                safeMacNotification(message: "\(s)\n(Copied to clipboard)", title: "AirDrop link from \(sender)")
            }
        }
    }

    var savedFiles: [String] = []
    if !archiveData.isEmpty {
        let tmpBin = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("airdrop_ble_\(UUID().uuidString).dvzip")
        try? archiveData.write(to: tmpBin)
        let py = Process()
        py.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        py.arguments = [
            "-c",
            """
            import gzip, io, os, struct, sys, zlib
            from pathlib import Path

            class DvzipReader(io.RawIOBase):
                def __init__(self, raw):
                    self.raw = raw
                    self.buf = bytearray()
                    self.eof = False
                    self.cur_stored = False
                    self.cur_rem = 0
                    self.decompressor = None

                def readinto(self, b):
                    while len(self.buf) < len(b) and not self.eof:
                        if self.cur_rem > 0:
                            chunk = self.raw.read(min(65536, self.cur_rem))
                            if not chunk:
                                self.eof = True
                                break
                            self.cur_rem -= len(chunk)
                            if self.cur_stored:
                                self.buf.extend(chunk)
                            else:
                                if self.decompressor is None:
                                    self.decompressor = zlib.decompressobj()
                                self.buf.extend(self.decompressor.decompress(chunk))
                                if self.cur_rem == 0:
                                    self.buf.extend(self.decompressor.flush())
                                    self.decompressor = None
                        else:
                            hdr4 = self.raw.read(4)
                            if len(hdr4) < 4:
                                if self.decompressor:
                                    self.buf.extend(self.decompressor.flush())
                                    self.decompressor = None
                                self.eof = True
                                break
                            v = struct.unpack(">I", hdr4)[0]
                            if v == 0:
                                if self.decompressor:
                                    self.buf.extend(self.decompressor.flush())
                                    self.decompressor = None
                                self.eof = True
                                break
                            self.cur_stored = bool(v & 0x80000000)
                            self.cur_rem = v & 0x7FFFFFFF
                            self.decompressor = None if self.cur_stored else zlib.decompressobj()

                    take = min(len(b), len(self.buf))
                    b[:take] = self.buf[:take]
                    del self.buf[:take]
                    return take if (take > 0 or not self.eof) else 0

            src = Path(sys.argv[1])
            dest = Path(sys.argv[2]).resolve()
            with src.open("rb") as f:
                prefix = f.read(6)
                f.seek(0)
                if len(prefix) >= 2 and prefix[:2] == b"\\x1f\\x8b":
                    stream = gzip.GzipFile(fileobj=f, mode="rb")
                elif len(prefix) >= 6 and prefix[:6] in (b"070707", b"070701", b"070702"):
                    stream = f
                else:
                    stream = io.BufferedReader(DvzipReader(f), buffer_size=65536)

                while True:
                    magic = stream.read(6)
                    if len(magic) < 6:
                        break
                    if magic == b"070707":
                        h = (magic + stream.read(70)).decode("ascii", "replace")
                        mode = int(h[18:24], 8)
                        ns = int(h[59:65], 8)
                        fs = int(h[65:76], 8)
                        name = stream.read(ns).rstrip(b"\\x00").decode("utf-8", "replace")
                        is_newc = False
                    elif magic in (b"070701", b"070702"):
                        h = (magic + stream.read(104)).decode("ascii", "replace")
                        mode = int(h[14:22], 16)
                        fs = int(h[54:62], 16)
                        ns = int(h[94:102], 16)
                        name = stream.read(ns).rstrip(b"\\x00").decode("utf-8", "replace")
                        if (110 + ns) % 4 != 0:
                            stream.read(4 - ((110 + ns) % 4))
                        is_newc = True
                    else:
                        break
                    if name == "TRAILER!!!":
                        break
                    if (mode & 0o170000) == 0o100000:
                        sn = os.path.basename(name.replace("\\\\", "/")).lstrip(".") or "airdrop_file"
                        t = (dest / sn).resolve()
                        if t.parent == dest:
                            orig_stem = t.stem
                            orig_suffix = t.suffix
                            idx = 1
                            while t.exists():
                                t = dest / f"{orig_stem}_{idx}{orig_suffix}"
                                idx += 1
                            part_t = t.with_name(t.name + ".part")
                            try:
                                with part_t.open("wb") as out_f:
                                    rem = fs
                                    while rem > 0:
                                        c = stream.read(min(65536, rem))
                                        if not c:
                                            break
                                        out_f.write(c)
                                        rem -= len(c)
                                    out_f.flush()
                                    os.fsync(out_f.fileno())
                                if rem > 0:
                                    part_t.unlink(missing_ok=True)
                                else:
                                    part_t.rename(t)
                                    try:
                                        import subprocess
                                        subprocess.run(["xattr", "-w", "com.apple.quarantine", "0081;00000000;AirDrop;", str(t)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                    except Exception:
                                        pass
                                    print(t)
                            except Exception:
                                part_t.unlink(missing_ok=True)
                    else:
                        rem = fs
                        while rem > 0:
                            c = stream.read(min(65536, rem))
                            if not c:
                                break
                            rem -= len(c)
                    if is_newc and fs % 4 != 0:
                        stream.read(4 - (fs % 4))
            """,
            tmpBin.path,
            downloads.path
        ]
        let outPipe = Pipe()
        py.standardOutput = outPipe
        try? py.run()
        py.waitUntilExit()
        try? FileManager.default.removeItem(at: tmpBin)
        let pyOut = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        for line in pyOut.split(separator: "\n") {
            let p = String(line).trimmingCharacters(in: .whitespacesAndNewlines)
            if !p.isEmpty {
                let sz = (try? FileManager.default.attributesOfItem(atPath: p)[.size] as? Int64) ?? 0
                appendReceivedLog(kind: "FILE", value: p, sizeBytes: sz, direction: "received", peerName: sender)
                savedFiles.append(URL(fileURLWithPath: p).lastPathComponent)
            }
        }
    }

    let sound = Process()
    sound.executableURL = URL(fileURLWithPath: "/usr/bin/afplay")
    sound.arguments = ["/System/Library/Sounds/Glass.aiff"]
    try? sound.run()

    if let first = savedFiles.first {
        let target = downloads.appendingPathComponent(first)
        print("[BLE-RX] Saved to \(target.path)")
        fflush(stdout)
        safeMacNotification(message: "Saved \(first) to Downloads", title: "AirDrop from \(sender)")
    }
}

// ============================================================================
// Daemon Mode: Mac BLE L2CAP AirDrop Receiver (Peripheral) + Live Peer BLE Scanner
// ============================================================================
final class BleAirDropDaemon: NSObject, CBPeripheralManagerDelegate, CBCentralManagerDelegate, CBPeripheralDelegate {
    static weak var shared: BleAirDropDaemon?
    var pm: CBPeripheralManager!
    var cm: CBCentralManager!
    var activeChannels: [CBL2CAPChannel] = []
    var publishedPsm: CBL2CAPPSM = 0
    var discoveredPeerPeripheral: CBPeripheral?
    var discoveredPeerPsm: CBL2CAPPSM = 0
    var discoveredPeerRssi: Int = -50
    var lastDiscoveredTime: TimeInterval = 0
    var pingChannel: CBL2CAPChannel?
    var isPingingPeer: Bool = false
    var pingStartedAt: TimeInterval = 0
    var lastPingTime: TimeInterval = 0
    var pingTimer: Timer?

    override init() {
        super.init()
        Self.shared = self
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("active_peers.json"))
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("p2p_status"))
        pm = CBPeripheralManager(delegate: self, queue: nil)
        cm = CBCentralManager(delegate: self, queue: nil)
        pingTimer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            self?.pingPeerIfNeeded()
        }
    }

    func rescanNow() {
        isPingingPeer = false
        lastPingTime = 0
        if cm.state == .poweredOn {
            cm.stopScan()
            cm.scanForPeripherals(
                withServices: nil,
                options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
            )
        }
        if pm.state == .poweredOn && publishedPsm > 0 && !pm.isAdvertising {
            let psmUuid = CBUUID(string: String(format: "%04X", 0xAD00 | (Int(publishedPsm) & 0xFF)))
            pm.startAdvertising([
                CBAdvertisementDataServiceUUIDsKey: [MAC_SERVICE_UUID, psmUuid]
            ])
        }
        pingPeerIfNeeded()
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn {
            central.scanForPeripherals(
                withServices: nil,
                options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
            )
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        let rssiVal = RSSI.intValue
        // Ignore invalid CoreBluetooth RSSI (127 = unavailable)
        if rssiVal == 127 || rssiVal < -98 { return }

        let uuids = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID]) ?? []
        let svcData = (advertisementData[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data]) ?? [:]
        guard uuids.contains(P2P_SERVICE_UUID) || svcData[P2P_DATA_UUID] != nil else { return }

        var peerPsm: UInt16 = 0
        var advertisedName: String? = nil
        if let d = svcData[P2P_DATA_UUID], d.count >= 2 {
            peerPsm = UInt16(d[d.startIndex]) | (UInt16(d[d.startIndex + 1]) << 8)
            if d.count > 2 {
                let nameSlice = d.subdata(in: (d.startIndex + 2)..<d.endIndex)
                if let decoded = String(data: nameSlice, encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines),
                   !decoded.isEmpty {
                    advertisedName = decoded
                }
            }
        }
        guard peerPsm > 0 else { return }
        if discoveredPeerPsm > 0 && peerPsm < discoveredPeerPsm && peerPsm != 128 { return }
        let fallbackLocalName = (advertisementData[CBAdvertisementDataLocalNameKey] as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        // Preserve full name if already learned via L2CAP or previous named packet
        let existingFull = loadActivePeersFromDisk(maxAge: PEER_LIVE_TTL_SECONDS)
            .first(where: { !$0.name.hasPrefix("Android Peer (") && $0.name != "Android Peer" })?.name
        let peerName: String = {
            if let ex = existingFull, ex.count > (advertisedName?.count ?? 0) { return ex }
            if let n = advertisedName, !n.isEmpty { return n }
            if let ln = fallbackLocalName, !ln.isEmpty, !ln.hasPrefix("AD-") { return ln }
            if let pn = peripheral.name?.trimmingCharacters(in: .whitespacesAndNewlines), !pn.isEmpty, !pn.hasPrefix("AD-") {
                return pn
            }
            return "Android Peer (\(peripheral.identifier.uuidString.prefix(4)))"
        }()

        recordActivePeerOnDisk(
            id: peripheral.identifier.uuidString,
            name: peerName,
            transport: "5GHz P2P • BLE PSM \(peerPsm)",
            address: peripheral.identifier.uuidString,
            psm: Int(peerPsm),
            rssi: rssiVal
        )

        discoveredPeerPeripheral = peripheral
        discoveredPeerPsm = CBL2CAPPSM(peerPsm)
        discoveredPeerRssi = rssiVal
        lastDiscoveredTime = Date().timeIntervalSince1970
        pingPeerIfNeeded()
    }

    func cancelActivePing() {
        isPingingPeer = false
        pingChannel = nil
        if let p = discoveredPeerPeripheral {
            cm.cancelPeripheralConnection(p)
        }
    }

    func pingPeerIfNeeded() {
        let now = Date().timeIntervalSince1970
        let txLock = STATE_DIR.appendingPathComponent("tx_in_progress.lock")
        let rxLock = STATE_DIR.appendingPathComponent("rx_in_progress.lock")
        let txProgress = STATE_DIR.appendingPathComponent("transfer_progress.json")
        if FileManager.default.fileExists(atPath: txLock.path) ||
           FileManager.default.fileExists(atPath: rxLock.path) ||
           FileManager.default.fileExists(atPath: txProgress.path) ||
           hasActiveTcpReceiverConnection() {
            if cm.state == .poweredOn && cm.isScanning {
                cm.stopScan()
            }
            if isPingingPeer {
                isPingingPeer = false
                pingChannel = nil
            }
            return
        }
        if cm.state == .poweredOn && !cm.isScanning {
            cm.scanForPeripherals(
                withServices: nil,
                options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
            )
        }
        if isPingingPeer {
            if now - pingStartedAt > 16.0 {
                cancelActivePing()
            }
            return
        }
        guard cm.state == .poweredOn,
              let p = discoveredPeerPeripheral,
              discoveredPeerPsm > 0,
              now - lastDiscoveredTime <= 10.0,
              now - lastPingTime >= 1.8 else {
            return
        }
        isPingingPeer = true
        pingStartedAt = now
        lastPingTime = now
        p.delegate = self
        if p.state == .connected {
            p.openL2CAPChannel(discoveredPeerPsm)
        } else {
            cm.connect(p, options: nil)
        }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard discoveredPeerPsm > 0 else {
            isPingingPeer = false
            return
        }
        peripheral.openL2CAPChannel(discoveredPeerPsm)
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        isPingingPeer = false
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        isPingingPeer = false
    }

    func peripheral(_ peripheral: CBPeripheral, didOpen channel: CBL2CAPChannel?, error: Error?) {
        guard let ch = channel, error == nil else {
            discoveredPeerPsm = 0
            isPingingPeer = false
            return
        }
        pingChannel = ch
        let targetPeerId = peripheral.identifier.uuidString
        let currentPsm = Int(discoveredPeerPsm)
        let currentRssi = discoveredPeerRssi
        let myPsm = Int(publishedPsm > 0 ? publishedPsm : 192)
        let macName = loadMacSettings().deviceName

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let inp = ch.inputStream, let out = ch.outputStream else {
                DispatchQueue.main.async {
                    self?.pingChannel = nil
                    self?.isPingingPeer = false
                    if let s = self, let p = s.discoveredPeerPeripheral {
                        s.cm.cancelPeripheralConnection(p)
                    }
                }
                return
            }
            inp.open()
            out.open()
            defer {
                inp.close()
                out.close()
                DispatchQueue.main.async {
                    self?.pingChannel = nil
                    self?.isPingingPeer = false
                    if let s = self, let p = s.discoveredPeerPeripheral {
                        s.cm.cancelPeripheralConnection(p)
                    }
                }
            }

            let pingPayload = Data("\(macName)\t\(myPsm)\t\(currentRssi)\n".utf8)
            var frame = Data("PING".utf8)
            var mLen = UInt32(pingPayload.count).bigEndian
            var aLen = UInt32(0).bigEndian
            frame.append(Data(bytes: &mLen, count: 4))
            frame.append(Data(bytes: &aLen, count: 4))
            frame.append(pingPayload)

            guard writeAll(out, data: frame) else {
                DispatchQueue.main.async { self?.discoveredPeerPsm = 0 }
                return
            }

            func readLine() -> String? {
                var lineBytes = Data()
                var b: UInt8 = 0
                while lineBytes.count < 512 {
                    let r = inp.read(&b, maxLength: 1)
                    if r <= 0 { return lineBytes.isEmpty ? nil : String(data: lineBytes, encoding: .utf8) }
                    if b == UInt8(ascii: "\n") { break }
                    if b != UInt8(ascii: "\r") { lineBytes.append(b) }
                }
                return String(data: lineBytes, encoding: .utf8)
            }

            guard let replyLine = readLine() else {
                DispatchQueue.main.async { self?.discoveredPeerPsm = 0 }
                return
            }

            if replyLine.hasPrefix("PONG\t") {
                let parts = replyLine.dropFirst(5).split(separator: "\t").map(String.init)
                let remoteName = parts.first?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                if !remoteName.isEmpty {
                    recordActivePeerOnDisk(
                        id: targetPeerId,
                        name: remoteName,
                        transport: "5GHz P2P • BLE PSM \(currentPsm)",
                        address: targetPeerId,
                        psm: currentPsm,
                        rssi: currentRssi
                    )
                }
                return
            }

            if replyLine.hasPrefix("WP2P\t") {
                let parts = replyLine.dropFirst(5).split(separator: "\t").map(String.init)
                if parts.count >= 2 {
                    handleIncomingWp2pJoin(ssid: parts[0], pass: parts[1], out: out)
                    return
                }
            }

            if replyLine == "ADRP" || replyLine == "ADRE" {
                DispatchQueue.main.async { self?.pingStartedAt = Date().timeIntervalSince1970 + 90.0 }
                guard let lenHdr = readExact(inp, count: 8) else { return }
                let metaLen = readUInt32BE(lenHdr, offset: 0)
                let archLen = readUInt32BE(lenHdr, offset: 4)
                guard metaLen > 0 && metaLen <= 10_000_000 && archLen >= 0 && archLen <= 100_000_000_000 else { return }

                let isEncrypted = (replyLine == "ADRE")
                guard let rawMeta = readExact(inp, count: metaLen),
                      let metaData = isEncrypted ? decryptBlePayload(rawMeta) : rawMeta else { return }
                let metaDict = (try? PropertyListSerialization.propertyList(from: metaData, options: [], format: nil)) as? [String: Any] ?? [:]
                let sender = (metaDict["SenderComputerName"] as? String) ?? "Android Peer"
                let filesArr = (metaDict["Files"] as? [[String: Any]]) ?? []
                let itemsArr = (metaDict["Items"] as? [Any])?.compactMap { $0 as? String } ?? []
                let fileNames = filesArr.compactMap { $0["FileName"] as? String }
                let displayNames = fileNames.isEmpty ? itemsArr : fileNames
                let prelimLabel = displayNames.first ?? "Incoming BLE File"
                let totalAskBytes = filesArr.reduce(Int64(0)) { $0 + Int64(($1["FileSize"] as? Int) ?? 0) }
                let effectiveBytes = totalAskBytes > 0 ? totalAskBytes : Int64(archLen)

                if !waitForMacUserAccept(senderName: sender, fileNames: displayNames, totalBytes: effectiveBytes) {
                    _ = writeAll(out, data: Data("NO\r\n".utf8))
                    return
                }

                let archData: Data
                if archLen > 0 {
                    guard let rawArch = readExact(
                        inp,
                        count: archLen,
                        trackProgress: true,
                        fileLabel: prelimLabel,
                        fileCount: max(1, displayNames.count)
                    ),
                    let decodedArch = isEncrypted ? decryptBlePayload(rawArch) : rawArch else { return }
                    archData = decodedArch
                } else {
                    archData = Data()
                }
                _ = writeAll(out, data: Data("OK\r\n".utf8))
                extractDvzipCpioToDownloads(archiveData: archData, metaDict: metaDict)
            }
        }
    }

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        if peripheral.state == .poweredOn && publishedPsm == 0 {
            peripheral.publishL2CAPChannel(withEncryption: false)
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didPublishL2CAPChannel PSM: CBL2CAPPSM, error: Error?) {
        guard error == nil else {
            print("[BLE-Daemon] Failed to publish L2CAP: \(error!)")
            return
        }
        publishedPsm = PSM
        print("[BLE-Daemon] Published Direct BLE L2CAP channel on PSM \(PSM)")
        fflush(stdout)

        if peripheral.isAdvertising {
            peripheral.stopAdvertising()
        }
        peripheral.removeAllServices()

        var le = UInt16(PSM).littleEndian
        let psmData = Data(bytes: &le, count: 2)
        let ch = CBMutableCharacteristic(
            type: MAC_PSM_CHAR_UUID,
            properties: [.read],
            value: psmData,
            permissions: [.readable]
        )
        let svc = CBMutableService(type: MAC_SERVICE_UUID, primary: true)
        svc.characteristics = [ch]
        peripheral.add(svc)

        let psmUuid = CBUUID(string: String(format: "%04X", 0xAD00 | (Int(PSM) & 0xFF)))
        // Keep primary advertisement <= 25 bytes (3B Flags + 18B MAC_SERVICE_UUID + 4B psmUuid)
        // so macOS CoreBluetooth never pushes MAC_SERVICE_UUID into the proprietary Apple Overflow Area.
        peripheral.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [MAC_SERVICE_UUID, psmUuid]
        ])
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        print("[BLE-Daemon] Advertising AD-\(publishedPsm) (error=\(String(describing: error)))")
        fflush(stdout)
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didOpen channel: CBL2CAPChannel?, error: Error?) {
        guard let ch = channel, error == nil else { return }
        activeChannels.append(ch)
        print("[BLE-Daemon] Incoming BLE L2CAP connection on PSM \(ch.psm)")
        fflush(stdout)

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let inp = ch.inputStream, let out = ch.outputStream else {
                DispatchQueue.main.async {
                    self?.activeChannels.removeAll { $0 === ch }
                }
                return
            }
            inp.open()
            out.open()
            defer {
                inp.close()
                out.close()
                DispatchQueue.main.async {
                    self?.activeChannels.removeAll { $0 === ch }
                }
            }
            guard let hdr = readExact(inp, count: 12) else { return }
            let magic = String(data: hdr.subdata(in: 0..<4), encoding: .ascii) ?? ""
            let metaLen = readUInt32BE(hdr, offset: 4)
            let archLen = readUInt32BE(hdr, offset: 8)
            guard metaLen > 0 && metaLen <= 10_000_000 && archLen >= 0 && archLen <= 100_000_000_000 else {
                print("[BLE-Daemon] Rejected out-of-bounds frame: metaLen=\(metaLen), archLen=\(archLen)")
                return
            }

            if magic == "PING" {
                guard let pingData = readExact(inp, count: metaLen),
                      let pingStr = String(data: pingData, encoding: .utf8) else { return }
                let parts = pingStr.split(separator: "\t").map(String.init)
                let peerName = parts.first?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "Android Peer"
                let peerPsm = parts.count >= 2 ? (Int(parts[1]) ?? 0) : 0
                let peerRssi = parts.count >= 3 ? (Int(parts[2]) ?? -55) : -55
                let existingPeer = loadActivePeersFromDisk(maxAge: 30.0).first
                let bestId = existingPeer?.id ?? ch.peer.identifier.uuidString
                let bestAddr = existingPeer?.address ?? ch.peer.identifier.uuidString
                let bestPsm = max(peerPsm, existingPeer?.psm ?? 0)
                recordActivePeerOnDisk(
                    id: bestId,
                    name: peerName.isEmpty ? "Android Peer" : peerName,
                    transport: bestPsm > 0 ? "5GHz P2P • BLE PSM \(bestPsm)" : "5GHz P2P • BLE",
                    address: bestAddr,
                    psm: bestPsm,
                    rssi: existingPeer?.rssi ?? peerRssi
                )
                let macName = loadMacSettings().deviceName
                let myPsm = self?.publishedPsm ?? 192
                _ = writeAll(out, data: Data("PONG\t\(macName)\t\(myPsm)\n".utf8))
                return
            }

            if magic == "WP2P" {
                guard let credData = readExact(inp, count: metaLen),
                      let credStr = String(data: credData, encoding: .utf8) else { return }
                let parts = credStr.split(separator: "\t").map(String.init)
                guard parts.count >= 2 else { return }
                handleIncomingWp2pJoin(ssid: parts[0], pass: parts[1], out: out)
                return
            }

            guard magic == "ADRP" || magic == "ADRE" else { return }
            print("[BLE-Daemon] Receiving \(magic) frame (meta=\(metaLen) B, archive=\(archLen) B)...")
            fflush(stdout)

            let isEncrypted = (magic == "ADRE")
            guard let rawMeta = readExact(inp, count: metaLen),
                  let metaData = isEncrypted ? decryptBlePayload(rawMeta) : rawMeta else { return }
            let metaDict = (try? PropertyListSerialization.propertyList(from: metaData, options: [], format: nil)) as? [String: Any] ?? [:]
            let sender = (metaDict["SenderComputerName"] as? String) ?? "Android Peer"
            let filesArr = (metaDict["Files"] as? [[String: Any]]) ?? []
            let itemsArr = (metaDict["Items"] as? [Any])?.compactMap { $0 as? String } ?? []
            let fileNames = filesArr.compactMap { $0["FileName"] as? String }
            let displayNames = fileNames.isEmpty ? itemsArr : fileNames
            let prelimLabel = displayNames.first ?? "Incoming BLE File"
            let totalAskBytes = filesArr.reduce(Int64(0)) { $0 + Int64(($1["FileSize"] as? Int) ?? 0) }
            let effectiveBytes = totalAskBytes > 0 ? totalAskBytes : Int64(archLen)

            // Update active peer record with the full sender name learned from the metadata
            let existingPeer = loadActivePeersFromDisk(maxAge: 30.0).first
            let peerId = ch.peer.identifier.uuidString
            recordActivePeerOnDisk(
                id: peerId,
                name: sender,
                transport: (existingPeer?.psm ?? 0) > 0 ? "5GHz P2P • BLE PSM \(existingPeer!.psm)" : "5GHz P2P • BLE",
                address: peerId,
                psm: existingPeer?.psm ?? 0,
                rssi: existingPeer?.rssi ?? -52
            )

            if !waitForMacUserAccept(senderName: sender, fileNames: displayNames, totalBytes: effectiveBytes) {
                _ = writeAll(out, data: Data("NO\r\n".utf8))
                return
            }

            let archData: Data
            if archLen > 0 {
                guard let rawArch = readExact(
                    inp,
                    count: archLen,
                    trackProgress: true,
                    fileLabel: prelimLabel,
                    fileCount: max(1, displayNames.count)
                ),
                let decodedArch = isEncrypted ? decryptBlePayload(rawArch) : rawArch else { return }
                archData = decodedArch
            } else {
                archData = Data()
            }

            _ = writeAll(out, data: Data("OK\r\n".utf8))
            extractDvzipCpioToDownloads(archiveData: archData, metaDict: metaDict)
        }
    }
}

// ============================================================================
// Sender Mode: Mac -> Android Direct BLE L2CAP Sender (Central)
// ============================================================================
final class BleAirDropSender: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    var cm: CBCentralManager!
    var targetPeripheral: CBPeripheral?
    var activeChannel: CBL2CAPChannel?
    var targetPsm: CBL2CAPPSM = 0
    let files: [URL]
    let urls: [String]
    let totalRawBytes: Int
    let frameData: Data
    let displayLabel: String
    let itemCount: Int
    var peerLabel: String
    var startedOpen = false

    private func reportSenderConnecting(_ phase: String) {
        writeProgressJson(
            active: true,
            direction: "Sending",
            fileName: displayLabel,
            fileCount: itemCount,
            doneBytes: 0,
            totalBytes: Int64(max(1, totalRawBytes)),
            speedBps: 0,
            etaSeconds: 0,
            percent: 0,
            phase: phase,
            peerName: peerLabel,
            isConnecting: true
        )
    }

    init(files: [URL], urls: [String] = []) throws {
        clearCancelFlag()
        try? Data("1".utf8).write(to: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
        self.files = files
        self.urls = urls
        self.totalRawBytes = files.reduce(0) { $0 + ((try? FileManager.default.attributesOfItem(atPath: $1.path)[.size] as? Int) ?? 0) }
        self.itemCount = max(1, files.count + urls.count)
        let firstLabel = files.first?.lastPathComponent ?? (urls.first ?? "Transfer")
        self.displayLabel = self.itemCount > 1 ? "\(firstLabel) + \(self.itemCount - 1) more" : firstLabel
        self.peerLabel = loadActivePeersFromDisk(maxAge: 30.0).first?.name ?? "Nearby Device"
        if self.totalRawBytes >= 65_536 && !files.isEmpty {
            self.frameData = Data()
        } else {
            let (gzData, fileDicts) = try buildDvzipCpio(files: files)
            let settings = loadMacSettings()
            let metaDict: [String: Any] = [
                "SenderComputerName": settings.deviceName,
                "SenderModelName": "MacBookPro18,2",
                "BundleID": urls.isEmpty ? "com.apple.finder" : "com.apple.Safari",
                "Items": urls as [Any],
                "Files": fileDicts
            ]
            let metaData = try PropertyListSerialization.data(fromPropertyList: metaDict, format: .binary, options: 0)
            let encMeta = encryptBlePayload(metaData)
            let encArch = gzData.isEmpty ? Data() : encryptBlePayload(gzData)
            var frame = Data("ADRE".utf8)
            var mLen = UInt32(encMeta.count).bigEndian
            var aLen = UInt32(encArch.count).bigEndian
            frame.append(Data(bytes: &mLen, count: 4))
            frame.append(Data(bytes: &aLen, count: 4))
            frame.append(encMeta)
            frame.append(encArch)
            self.frameData = frame
        }
        super.init()
        reportSenderConnecting("Scanning for nearby device via Bluetooth LE…")
        cm = CBCentralManager(delegate: self, queue: nil)
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn {
            let knownPeers = loadActivePeersFromDisk(maxAge: 30.0)
            if let first = knownPeers.first {
                peerLabel = first.name
                if first.psm > 0 {
                    targetPsm = CBL2CAPPSM(first.psm)
                }
                if let uuid = UUID(uuidString: first.address) {
                    let retrieved = central.retrievePeripherals(withIdentifiers: [uuid])
                    if let p = retrieved.first {
                        targetPeripheral = p
                        p.delegate = self
                        reportSenderConnecting("Connecting to \(first.name) via Bluetooth LE…")
                        print("[BLE-Send] Connecting directly to active peer \(first.name) (\(uuid), PSM \(targetPsm))...")
                        fflush(stdout)
                        central.connect(p, options: nil)
                    }
                }
            }
            print("[BLE-Send] Scanning for nearby peer over Bluetooth LE...")
            fflush(stdout)
            central.scanForPeripherals(
                withServices: nil,
                options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
            )
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        let uuids = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID]) ?? []
        let svcData = (advertisementData[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data]) ?? [:]
        guard uuids.contains(P2P_SERVICE_UUID) || svcData[P2P_DATA_UUID] != nil else { return }

        guard let d = svcData[P2P_DATA_UUID], d.count >= 2 else { return }
        let psm = UInt16(d[d.startIndex]) | (UInt16(d[d.startIndex + 1]) << 8)
        guard psm > 0 else { return }
        // Ignore older leaked advertisements if we already know a newer PSM
        if targetPsm > 0 && psm < targetPsm && d.count <= 2 { return }
        targetPsm = CBL2CAPPSM(psm)

        if targetPeripheral == nil {
            targetPeripheral = peripheral
            peripheral.delegate = self
            reportSenderConnecting("Connecting to \(peerLabel) via Bluetooth LE…")
            print("[BLE-Send] Found nearby peer (\(peripheral.identifier), RSSI \(RSSI), PSM \(targetPsm)), connecting...")
            fflush(stdout)
            central.stopScan()
            central.connect(peripheral, options: nil)
        }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        if targetPsm > 0 && !startedOpen {
            startedOpen = true
            reportSenderConnecting("Opening Bluetooth L2CAP channel…")
            print("[BLE-Send] Connected! Opening L2CAP channel PSM \(targetPsm)...")
            fflush(stdout)
            peripheral.openL2CAPChannel(targetPsm)
        } else {
            reportSenderConnecting("Discovering Bluetooth L2CAP service…")
            peripheral.discoverServices([P2P_SERVICE_UUID])
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let svcs = peripheral.services else { return }
        for s in svcs where s.uuid == P2P_SERVICE_UUID {
            peripheral.discoverCharacteristics([P2P_PSM_CHAR_UUID], for: s)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard let chars = service.characteristics else { return }
        for c in chars where c.uuid == P2P_PSM_CHAR_UUID {
            peripheral.readValue(for: c)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        if let d = characteristic.value, d.count >= 2, !startedOpen {
            let psm = UInt16(d[d.startIndex]) | (UInt16(d[d.startIndex + 1]) << 8)
            if psm > 0 {
                startedOpen = true
                targetPsm = CBL2CAPPSM(psm)
                reportSenderConnecting("Opening Bluetooth L2CAP channel…")
                print("[BLE-Send] Read GATT PSM \(targetPsm), opening L2CAP channel...")
                fflush(stdout)
                peripheral.openL2CAPChannel(targetPsm)
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didOpen channel: CBL2CAPChannel?, error: Error?) {
        guard let ch = channel, error == nil else {
            writeProgressJson(active: false)
            print("[BLE-Send] L2CAP open failed: \(String(describing: error))")
            exit(1)
        }
        activeChannel = ch

        DispatchQueue.global(qos: .userInitiated).async {
            guard let inp = ch.inputStream, let out = ch.outputStream else {
                writeProgressJson(active: false)
                print("[BLE-Send] Failed to acquire L2CAP channel streams")
                exit(1)
            }
            inp.open()
            out.open()

            // 5GHz Wi-Fi Direct P2P Negotiation for large files
            if self.totalRawBytes >= 65_536 && !self.files.isEmpty {
                self.reportSenderConnecting("Requesting 5 GHz Wi-Fi Direct group…")
                print("[BLE-Send] Negotiating 5GHz Wi-Fi Direct P2P over BLE L2CAP...")
                fflush(stdout)
                if writeAll(out, data: Data("WP2P".utf8)) {
                    var lineBytes = Data()
                    var b: UInt8 = 0
                    while lineBytes.count < 256 {
                        let r = inp.read(&b, maxLength: 1)
                        if r <= 0 || b == UInt8(ascii: "\n") { break }
                        if b != UInt8(ascii: "\r") { lineBytes.append(b) }
                    }
                    let reply = String(data: lineBytes, encoding: .utf8) ?? ""
                    if reply.hasPrefix("OK\t") {
                        let parts = reply.dropFirst(3).split(separator: "\t").map(String.init)
                        if parts.count >= 4 {
                            let ssid = parts[0], pass = parts[1], host = parts[2], port = parts[3]
                            _ = pauseCloudflareWarpIfNeeded()
                            saveCurrentWifiSsid()
                            self.reportSenderConnecting("Joining 5 GHz Wi-Fi Direct (\(ssid))…")
                            print("[BLE-Send] Joining 5GHz P2P group \(ssid) (\(host):\(port))...")
                            fflush(stdout)

                            func hasEn0P2pIp() -> Bool {
                                return !currentEn0P2pIp().isEmpty
                            }

                            if !hasEn0P2pIp() {
                                _ = runProcessCapture("/usr/sbin/networksetup", ["-setairportnetwork", "en0", ssid, pass])

                                // Wait up to 10s for macOS DHCP on en0 to assign 192.168.49.x before launching HTTPS transfer
                                let deadline = Date().addingTimeInterval(10.0)
                                var retriedJoin = false
                                while Date() < deadline {
                                    if hasEn0P2pIp() { break }
                                    if !retriedJoin && deadline.timeIntervalSinceNow < 5.5 {
                                        retriedJoin = true
                                        _ = runProcessCapture("/usr/sbin/networksetup", ["-setairportnetwork", "en0", ssid, pass])
                                    }
                                    Thread.sleep(forTimeInterval: 0.2)
                                }
                            }

                            self.reportSenderConnecting("Connecting over 5 GHz Wi-Fi Direct (\(host))…")
                            let txProc = Process()
                            txProc.executableURL = URL(fileURLWithPath: SCRIPT_PATH)
                            txProc.arguments = ["send", "--peer", "\(host):\(port)"] + self.files.map { $0.path } + self.urls
                            try? txProc.run()
                            txProc.waitUntilExit()
                            restoreMacInternetWifi(ssid: ssid)

                            if isTransferCancelled() {
                                clearCancelFlag()
                                writeProgressJson(active: false)
                                inp.close()
                                out.close()
                                try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
                                print("[BLE-Send] Transfer cancelled by user")
                                exit(1)
                            }

                            if txProc.terminationStatus == 0 {
                                writeProgressJson(active: false)
                                inp.close()
                                out.close()
                                try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
                                print("[BLE-Send] Delivered via 5GHz Wi-Fi Direct P2P!")
                                exit(0)
                            }
                            if txProc.terminationStatus == 43 {
                                writeProgressJson(active: false)
                                inp.close()
                                out.close()
                                try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
                                print("[BLE-Send] Transfer declined by receiver")
                                exit(1)
                            }
                        }
                    }
                }
            }

            var payloadFrame = self.frameData
            if payloadFrame.isEmpty && !self.files.isEmpty {
                self.reportSenderConnecting("Preparing fallback Bluetooth LE archive…")
                guard let (gzData, fileDicts) = try? buildDvzipCpio(files: self.files) else {
                    writeProgressJson(active: false)
                    exit(1)
                }
                let metaDict: [String: Any] = [
                    "SenderComputerName": loadMacSettings().deviceName,
                    "SenderModelName": "MacBookPro18,2",
                    "BundleID": self.urls.isEmpty ? "com.apple.finder" : "com.apple.Safari",
                    "Items": self.urls as [Any],
                    "Files": fileDicts
                ]
                guard let metaData = try? PropertyListSerialization.data(fromPropertyList: metaDict, format: .binary, options: 0) else {
                    writeProgressJson(active: false)
                    exit(1)
                }
                let encMeta = encryptBlePayload(metaData)
                let encArch = gzData.isEmpty ? Data() : encryptBlePayload(gzData)
                var frame = Data("ADRE".utf8)
                var mLen = UInt32(encMeta.count).bigEndian
                var aLen = UInt32(encArch.count).bigEndian
                frame.append(Data(bytes: &mLen, count: 4))
                frame.append(Data(bytes: &aLen, count: 4))
                frame.append(encMeta)
                frame.append(encArch)
                payloadFrame = frame
            }

            let label = self.files.first?.lastPathComponent ?? (self.urls.first ?? "BLE Transfer")
            print("[BLE-Send] Streaming \(payloadFrame.count) bytes over Direct Bluetooth LE L2CAP...")
            fflush(stdout)
            let ok = writeAll(
                out,
                data: payloadFrame,
                trackProgress: true,
                fileLabel: label,
                fileCount: max(1, self.files.count)
            )
            let ackData = readExact(inp, count: 2)
            let ackStr = ackData.flatMap { String(data: $0, encoding: .ascii) } ?? ""
            writeProgressJson(active: false)
            inp.close()
            out.close()
            try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
            if ok && ackStr == "OK" {
                let resolvedPeer = loadActivePeersFromDisk(maxAge: 30.0).first?.name ?? self.peerLabel
                for f in self.files {
                    let sz = (try? FileManager.default.attributesOfItem(atPath: f.path)[.size] as? Int64) ?? 0
                    appendReceivedLog(kind: "FILE", value: f.path, sizeBytes: sz, direction: "sent", peerName: resolvedPeer)
                }
                for u in self.urls {
                    appendReceivedLog(kind: "URL", value: u, sizeBytes: Int64(u.utf8.count), direction: "sent", peerName: resolvedPeer)
                }
                let sound = Process()
                sound.executableURL = URL(fileURLWithPath: "/usr/bin/afplay")
                sound.arguments = ["/System/Library/Sounds/Glass.aiff"]
                try? sound.run()
                print("[BLE-Send] Delivered to \(resolvedPeer) via Direct Bluetooth LE L2CAP!")
                exit(0)
            } else {
                print("[BLE-Send] Transfer incomplete (ok=\(ok), ack=\(String(describing: ackData)))")
                exit(1)
            }
        }
    }
}

// ============================================================================
// macOS Native SwiftUI State & QuickShare 4-Tab Day/Dark UI
// ============================================================================

func middleTruncateMacName(_ raw: String, maxChars: Int = 36) -> String {
    if raw.count <= maxChars { return raw }
    let ns = raw as NSString
    let ext = ns.pathExtension
    if !ext.isEmpty && ext.count <= 8 {
        let suffix = ".\(ext)"
        let keep = maxChars - suffix.count - 1
        if keep >= 8 {
            let headCount = (keep + 1) / 2
            let tailCount = keep - headCount
            let base = ns.deletingPathExtension
            let head = String(base.prefix(headCount))
            let tail = String(base.suffix(max(1, tailCount)))
            return "\(head)…\(tail)\(suffix)"
        }
    }
    let headCount = (maxChars - 1) / 2
    let tailCount = maxChars - 1 - headCount
    return "\(raw.prefix(headCount))…\(raw.suffix(tailCount))"
}

func currentMacGreeting() -> String {
    let hour = Calendar.current.component(.hour, from: Date())
    if hour >= 5 && hour < 12 { return "Good Morning" }
    if hour >= 12 && hour < 17 { return "Good Afternoon" }
    return "Good Evening"
}

func inferMacCategory(pathOrUrl: String, isUrl: Bool) -> String {
    if isUrl { return "LINK" }
    let ext = URL(fileURLWithPath: pathOrUrl).pathExtension.lowercased()
    switch ext {
    case "jpg", "jpeg", "png", "webp", "heic", "gif", "svg", "bmp", "tiff":
        return "IMG"
    case "mp4", "mov", "mkv", "webm", "avi", "m4v":
        return "VID"
    case "mp3", "wav", "m4a", "flac", "aac", "ogg", "opus":
        return "AUD"
    case "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md", "csv", "rtf", "pages", "numbers", "key":
        return "DOC"
    default:
        return "FILE"
    }
}

struct MacThemePalette: Equatable {
    let isDark: Bool
    let bgCanvas: Color
    let bgSurface: Color
    let bgSubtle: Color
    let bgMuted: Color
    let border: Color
    let textPrimary: Color
    let textSecondary: Color
    let textMuted: Color
    let indigo: Color
    let indigoHover: Color
    let indigoSubtle: Color
    let emerald: Color
    let emeraldSubtle: Color
    let amber: Color
    let amberSubtle: Color
    let danger: Color
    let dangerSubtle: Color
    let nsCanvasRed: CGFloat
    let nsCanvasGreen: CGFloat
    let nsCanvasBlue: CGFloat

    static let light = MacThemePalette(
        isDark: false,
        bgCanvas: Color(red: 0.953, green: 0.961, blue: 0.988),      // #F3F5FC
        bgSurface: Color.white,                                       // #FFFFFF
        bgSubtle: Color(red: 0.922, green: 0.941, blue: 0.980),       // #EBF0FA
        bgMuted: Color(red: 0.871, green: 0.898, blue: 0.957),        // #DEE5F4
        border: Color(red: 0.839, green: 0.875, blue: 0.933),         // #D6DFEE
        textPrimary: Color(red: 0.067, green: 0.094, blue: 0.153),    // #111827 (16.8:1)
        textSecondary: Color(red: 0.278, green: 0.333, blue: 0.412),  // #475569 (7.1:1)
        textMuted: Color(red: 0.392, green: 0.455, blue: 0.545),      // #64748B (4.6:1)
        indigo: Color(red: 0.325, green: 0.376, blue: 0.961),         // #5360F5
        indigoHover: Color(red: 0.263, green: 0.310, blue: 0.878),    // #434FE0
        indigoSubtle: Color(red: 0.933, green: 0.941, blue: 1.000),   // #EEF0FF
        emerald: Color(red: 0.086, green: 0.639, blue: 0.290),        // #16A34A
        emeraldSubtle: Color(red: 0.863, green: 0.988, blue: 0.906),  // #DCFCE7
        amber: Color(red: 0.851, green: 0.467, blue: 0.024),          // #D97706
        amberSubtle: Color(red: 0.996, green: 0.953, blue: 0.780),    // #FEF3C7
        danger: Color(red: 0.863, green: 0.149, blue: 0.149),         // #DC2626
        dangerSubtle: Color(red: 0.996, green: 0.886, blue: 0.886),   // #FEE2E2
        nsCanvasRed: 0.953,
        nsCanvasGreen: 0.961,
        nsCanvasBlue: 0.988
    )

    static let dark = MacThemePalette(
        isDark: true,
        bgCanvas: Color(red: 0.051, green: 0.063, blue: 0.094),       // #0D1018
        bgSurface: Color(red: 0.086, green: 0.106, blue: 0.153),      // #161B27
        bgSubtle: Color(red: 0.118, green: 0.145, blue: 0.212),       // #1E2536
        bgMuted: Color(red: 0.157, green: 0.192, blue: 0.278),        // #283147
        border: Color(red: 0.157, green: 0.196, blue: 0.275),         // #283246
        textPrimary: Color(red: 0.973, green: 0.980, blue: 0.988),    // #F8FAFC
        textSecondary: Color(red: 0.580, green: 0.639, blue: 0.722),  // #94A3B8
        textMuted: Color(red: 0.486, green: 0.545, blue: 0.631),      // #7C8BA1
        indigo: Color(red: 0.365, green: 0.416, blue: 0.973),         // #5D6AF8
        indigoHover: Color(red: 0.463, green: 0.510, blue: 1.000),    // #7682FF
        indigoSubtle: Color(red: 0.122, green: 0.145, blue: 0.278),   // #1F2547
        emerald: Color(red: 0.133, green: 0.773, blue: 0.369),        // #22C55E
        emeraldSubtle: Color(red: 0.075, green: 0.184, blue: 0.137),  // #132F23
        amber: Color(red: 0.961, green: 0.620, blue: 0.043),          // #F59E0B
        amberSubtle: Color(red: 0.200, green: 0.145, blue: 0.063),    // #332510
        danger: Color(red: 0.937, green: 0.267, blue: 0.267),         // #EF4444
        dangerSubtle: Color(red: 0.212, green: 0.098, blue: 0.114),   // #36191D
        nsCanvasRed: 0.051,
        nsCanvasGreen: 0.063,
        nsCanvasBlue: 0.094
    )
}

struct MacScaleButtonStyle: ButtonStyle {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed && !reduceMotion ? 0.97 : 1.0)
            .opacity(configuration.isPressed ? 0.92 : 1.0)
            .animation(reduceMotion ? nil : .spring(response: 0.22, dampingFraction: 0.78), value: configuration.isPressed)
    }
}

struct MacStagedItem: Identifiable, Equatable {
    let id: String
    let pathOrUrl: String
    let name: String
    let sizeBytes: Int64
    let isUrl: Bool
    let category: String
}

struct MacStorageSummary: Equatable {
    let totalBytes: Int64
    let freeBytes: Int64

    var usedBytes: Int64 { max(0, totalBytes - freeBytes) }
    var usedFraction: Double {
        guard totalBytes > 0 else { return 0 }
        return min(1.0, max(0.0, Double(usedBytes) / Double(totalBytes)))
    }

    static func queryLocalDisk() -> MacStorageSummary {
        let home = NSHomeDirectory()
        if let attrs = try? FileManager.default.attributesOfFileSystem(forPath: home) {
            let total = (attrs[.systemSize] as? NSNumber)?.int64Value ?? 0
            let free = (attrs[.systemFreeSize] as? NSNumber)?.int64Value ?? 0
            if total > 0 {
                return MacStorageSummary(totalBytes: total, freeBytes: max(0, free))
            }
        }
        return MacStorageSummary(totalBytes: 512 * 1024 * 1024 * 1024, freeBytes: 128 * 1024 * 1024 * 1024)
    }
}

struct MacHistoryEntry: Identifiable, Hashable {
    let id: String
    let timestamp: Date
    let isUrl: Bool
    let value: String
    let sizeBytes: Int64
    let isOutgoing: Bool
    let peerName: String

    var displayName: String {
        isUrl ? value : URL(fileURLWithPath: value).lastPathComponent
    }
}

struct MacLiveProgress: Equatable {
    let direction: String
    let fileName: String
    let fileCount: Int
    let doneBytes: Int64
    let totalBytes: Int64
    let speedBps: Int64
    let etaSeconds: Int64
    let percent: Int
    let phase: String
    let peerName: String
    let isConnecting: Bool
}

struct MacPendingAsk: Equatable {
    let id: String
    let senderName: String
    let fileNames: [String]
    let totalBytes: Int64
}

final class MacAirDropViewModel: ObservableObject {
    @Published var selectedTab: Int = 0 // 0 = Send, 1 = Receive, 2 = History, 3 = Settings
    @Published var stagedItems: [MacStagedItem] = []
    @Published var showLinkComposer: Bool = false
    @Published var historyFilter: Int = 0 // 0 = All, 1 = Received, 2 = Sent
    @Published var historySearch: String = ""
    @Published var themeMode: String = "system" // "light", "dark", "system"
    @Published var systemIsDark: Bool = true
    @Published var storage: MacStorageSummary = MacStorageSummary.queryLocalDisk()
    @Published var receiverRunning: Bool = false
    @Published var mdnsRunning: Bool = false
    @Published var awdlProxyRunning: Bool = false
    @Published var bleRunning: Bool = true
    @Published var autoAccept: Bool = false
    @Published var macDeviceName: String = Host.current().localizedName ?? "MacBook Pro"
    @Published var editingDeviceName: String = ""
    @Published var activePeers: [MacDiscoveredPeer] = []
    @Published var peerStatusSummary: String = "0 Nearby Devices • Scanning BLE + 5 GHz Wi-Fi Direct"
    @Published var transferStatus: String = "Select files to review, then click Send"
    @Published var isTransferring: Bool = false
    @Published var liveProgress: MacLiveProgress? = nil
    @Published var pendingAsk: MacPendingAsk? = nil
    @Published var urlInput: String = ""
    @Published var isDropTargeted: Bool = false
    @Published var showLogs: Bool = false
    @Published var pulse: Bool = false
    @Published var bridgePhaseTick: Bool = false
    @Published var historyEntries: [MacHistoryEntry] = []
    @Published var logs: [String] = []
    @Published var bluetoothAuthorized: Bool = true
    @Published var bluetoothPoweredOn: Bool = true
    @Published var wifiPoweredOn: Bool = true

    var onThemeChanged: ((MacThemePalette) -> Void)?
    var onRequestFrontWindow: (() -> Void)?

    private var activeSendProcess: Process? = nil
    private var fastTimer: Timer?
    private var tickCount: Int = 0

    var effectiveIsDark: Bool {
        switch themeMode {
        case "light": return false
        case "dark": return true
        default: return systemIsDark
        }
    }

    var palette: MacThemePalette {
        effectiveIsDark ? .dark : .light
    }

    var totalStagedBytes: Int64 {
        stagedItems.reduce(Int64(0)) { $0 + $1.sizeBytes }
    }

    init() {
        let s = loadMacSettings()
        self.autoAccept = s.autoAccept
        self.macDeviceName = s.deviceName
        self.editingDeviceName = s.deviceName
        self.themeMode = s.themeMode
        self.systemIsDark = Self.detectSystemDark()
        refreshSlow()
        refreshFast()
        fastTimer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.refreshFast()
            self.tickCount += 1
            if self.tickCount % 7 == 0 {
                self.refreshSlow()
            }
            if self.tickCount % 50 == 0 {
                let latestDisk = MacStorageSummary.queryLocalDisk()
                if self.storage != latestDisk {
                    self.storage = latestDisk
                }
            }
        }
    }

    static func detectSystemDark() -> Bool {
        let match = NSApp?.effectiveAppearance.bestMatch(from: [.darkAqua, .aqua])
        return match == .darkAqua
    }

    func setThemeMode(_ mode: String) {
        let normalized = ["light", "dark", "system"].contains(mode) ? mode : "system"
        themeMode = normalized
        systemIsDark = Self.detectSystemDark()
        saveMacSettings(autoAccept: autoAccept, visible: receiverRunning, deviceName: macDeviceName, themeMode: normalized)
        onThemeChanged?(palette)
    }

    func toggleDayDarkQuick() {
        setThemeMode(effectiveIsDark ? "light" : "dark")
    }

    private func isPidAlive(_ file: String) -> Bool {
        let p = STATE_DIR.appendingPathComponent(file)
        guard let s = try? String(contentsOf: p, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
              let pid = Int32(s), pid > 0 else { return false }
        return kill(pid, 0) == 0
    }

    func refreshFast() {
        if themeMode == "system" {
            let sysDark = Self.detectSystemDark()
            if systemIsDark != sysDark {
                systemIsDark = sysDark
                onThemeChanged?(palette)
            }
        }

        // 0. Poll live active peers with strict 10-second TTL
        let livePeers = loadActivePeersFromDisk(maxAge: PEER_LIVE_TTL_SECONDS)
        if activePeers != livePeers {
            activePeers = livePeers
        }
        let statusLine: String
        if let first = livePeers.first {
            statusLine = "\(first.name) • \(first.transport) (\(first.rssi) dBm)"
        } else {
            statusLine = "0 Nearby Devices • Scanning BLE + 5 GHz Wi-Fi Direct"
        }
        if peerStatusSummary != statusLine {
            peerStatusSummary = statusLine
        }

        // 1. Poll real-time transfer progress JSON (22s freshness covers 12s Wi-Fi Direct join)
        let pf = STATE_DIR.appendingPathComponent("transfer_progress.json")
        if let d = try? Data(contentsOf: pf),
           let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
           (obj["active"] as? Bool) == true {
            let updatedAt = (obj["updatedAt"] as? Double) ?? Date().timeIntervalSince1970
            if Date().timeIntervalSince1970 - updatedAt < 22.0 {
                let rawPhase = (obj["phase"] as? String) ?? ""
                let rawPeer = (obj["peerName"] as? String) ?? ""
                let connectingFlag = (obj["isConnecting"] as? Bool) ?? false
                let dir = (obj["direction"] as? String) ?? "Transferring"
                let pct = (obj["percent"] as? Int) ?? 0
                let spd = (obj["speedBps"] as? NSNumber)?.int64Value ?? 0
                let prog = MacLiveProgress(
                    direction: dir,
                    fileName: (obj["fileName"] as? String) ?? "File",
                    fileCount: max(1, (obj["fileCount"] as? Int) ?? 1),
                    doneBytes: (obj["doneBytes"] as? NSNumber)?.int64Value ?? 0,
                    totalBytes: (obj["totalBytes"] as? NSNumber)?.int64Value ?? 0,
                    speedBps: spd,
                    etaSeconds: (obj["etaSeconds"] as? NSNumber)?.int64Value ?? 0,
                    percent: pct,
                    phase: rawPhase.isEmpty
                        ? (connectingFlag ? "Connecting…" : (dir.lowercased().contains("send") ? "Sending files" : "Receiving files"))
                        : rawPhase,
                    peerName: rawPeer.isEmpty ? (livePeers.first?.name ?? "Nearby Device") : rawPeer,
                    isConnecting: connectingFlag
                )
                if liveProgress != prog {
                    liveProgress = prog
                }
            } else if !isTransferring && liveProgress != nil {
                liveProgress = nil
            }
        } else if !isTransferring && liveProgress != nil {
            liveProgress = nil
        }

        // 2. Poll pending Ask prompt JSON
        let af = STATE_DIR.appendingPathComponent("pending_ask.json")
        if let d = try? Data(contentsOf: af),
           let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
           let id = obj["id"] as? String {
            let ask = MacPendingAsk(
                id: id,
                senderName: (obj["senderName"] as? String) ?? "Nearby Device",
                fileNames: (obj["fileNames"] as? [String]) ?? ["Incoming File"],
                totalBytes: (obj["totalBytes"] as? NSNumber)?.int64Value ?? 0
            )
            if pendingAsk != ask {
                pendingAsk = ask
                onRequestFrontWindow?()
            }
        } else if pendingAsk != nil {
            pendingAsk = nil
        }
    }

    func respondToAsk(accepted: Bool) {
        guard let ask = pendingAsk else { return }
        let decFile = STATE_DIR.appendingPathComponent("ask_decision.json")
        let dict: [String: Any] = ["id": ask.id, "accepted": accepted]
        if let d = try? JSONSerialization.data(withJSONObject: dict) {
            try? d.write(to: decFile, options: [.atomic])
        }
        pendingAsk = nil
    }

    func setReceiveMode(directGet: Bool) {
        autoAccept = directGet
        saveMacSettings(autoAccept: directGet, visible: receiverRunning, deviceName: macDeviceName, themeMode: themeMode)
    }

    func saveDeviceName() {
        let clean = editingDeviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty else { return }
        macDeviceName = clean
        saveMacSettings(autoAccept: autoAccept, visible: receiverRunning, deviceName: clean, themeMode: themeMode)
    }

    func refreshSlow() {
        receiverRunning = isPidAlive("daemon.pid")
        mdnsRunning = isPidAlive("mdns.pid")
        awdlProxyRunning = isPidAlive("awdl-mdns.pid")
        bleRunning = true

        let auth = CBManager.authorization
        bluetoothAuthorized = (auth != .denied && auth != .restricted)
        if let cmState = BleAirDropDaemon.shared?.cm.state {
            bluetoothPoweredOn = (cmState != .poweredOff)
        }

        let wifiOn = CWWiFiClient.shared().interface(withName: "en0")?.powerOn() ?? true
        if wifiPoweredOn != wifiOn {
            wifiPoweredOn = wifiOn
        }

        let rxFile = STATE_DIR.appendingPathComponent("received.log")
        if let rxRaw = try? String(contentsOf: rxFile, encoding: .utf8) {
            let parsed: [MacHistoryEntry] = rxRaw.split(separator: "\n").suffix(80).reversed().compactMap { line in
                let parts = line.split(separator: "\t").map(String.init)
                guard parts.count >= 3 else { return nil }
                let ts = TimeInterval(parts[0]) ?? Date().timeIntervalSince1970
                let isUrl = parts[1] == "URL"
                let val = parts[2]
                let sz: Int64 = parts.count >= 4 ? (Int64(parts[3]) ?? 0) : ((try? FileManager.default.attributesOfItem(atPath: val)[.size] as? Int64) ?? 0)
                let isOut = parts.count >= 5 ? (parts[4] == "sent") : false
                let peer = parts.count >= 6 ? parts[5] : "Nearby Device"
                return MacHistoryEntry(
                    id: "\(parts[0])-\(val)-\(isOut)",
                    timestamp: Date(timeIntervalSince1970: ts),
                    isUrl: isUrl,
                    value: val,
                    sizeBytes: sz,
                    isOutgoing: isOut,
                    peerName: peer
                )
            }
            if parsed != historyEntries {
                historyEntries = parsed
            }
        } else if !historyEntries.isEmpty {
            historyEntries = []
        }

        var combined: [String] = []
        for f in ["daemon.log", "ble-daemon.log"] {
            let lf = STATE_DIR.appendingPathComponent(f)
            if let content = try? String(contentsOf: lf, encoding: .utf8) {
                let tail = content.split(separator: "\n").suffix(16).map(String.init)
                combined.append(contentsOf: tail)
            }
        }
        if combined != logs {
            logs = Array(combined.suffix(28))
        }
    }

    func rescanNow() {
        transferStatus = "Scanning BLE + 5 GHz Wi-Fi Direct for nearby devices…"
        BleAirDropDaemon.shared?.rescanNow()
        if !receiverRunning {
            DispatchQueue.global(qos: .userInitiated).async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: SCRIPT_PATH)
                p.arguments = ["restart-receiver"]
                try? p.run()
                p.waitUntilExit()
                DispatchQueue.main.async {
                    self.refreshSlow()
                }
            }
        } else {
            refreshFast()
            refreshSlow()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.2) {
            self.refreshFast()
            if self.activePeers.isEmpty {
                self.transferStatus = "Listening for nearby devices…"
            } else {
                self.transferStatus = "\(self.activePeers.count) device(s) nearby and ready"
            }
        }
    }

    func toggleDaemons(_ turnOn: Bool) {
        transferStatus = turnOn ? "Starting P2P radio…" : "Pausing P2P radio…"
        saveMacSettings(autoAccept: autoAccept, visible: turnOn, deviceName: macDeviceName, themeMode: themeMode)
        if turnOn {
            BleAirDropDaemon.shared?.rescanNow()
        }
        DispatchQueue.global(qos: .userInitiated).async {
            if turnOn {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: SCRIPT_PATH)
                p.arguments = ["restart-receiver"]
                try? p.run()
                p.waitUntilExit()
            } else {
                for pf in ["daemon.pid", "mdns.pid", "awdl-mdns.pid"] {
                    let f = STATE_DIR.appendingPathComponent(pf)
                    if let s = try? String(contentsOf: f, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
                       let pid = Int32(s) {
                        kill(pid, SIGTERM)
                    }
                    try? FileManager.default.removeItem(at: f)
                }
            }
            DispatchQueue.main.async {
                self.refreshSlow()
                self.transferStatus = turnOn
                    ? "Radio active (5 GHz Wi-Fi Direct • BLE L2CAP)"
                    : "Radio paused"
            }
        }
    }

    func cancelActiveTransfer() {
        try? Data("1".utf8).write(to: STATE_DIR.appendingPathComponent("cancel_transfer.flag"))
        if let proc = activeSendProcess, proc.isRunning {
            proc.terminate()
        }
        activeSendProcess = nil
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("transfer_progress.json"))
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
        isTransferring = false
        liveProgress = nil
        transferStatus = "Transfer cancelled"
        DispatchQueue.global(qos: .userInitiated).async {
            let killProc = Process()
            killProc.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
            killProc.arguments = ["-f", "mac-ble-airdrop send"]
            try? killProc.run()
            killProc.waitUntilExit()
            restoreMacInternetWifi()
        }
    }

    func enableMacWifi() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
            p.arguments = ["-setairportpower", "en0", "on"]
            try? p.run()
            p.waitUntilExit()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                self?.refreshSlow()
                self?.rescanNow()
            }
        }
    }

    func openBluetoothSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.BluetoothSettings") {
            NSWorkspace.shared.open(url)
        }
    }

    func openBluetoothPrivacySettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Bluetooth") {
            NSWorkspace.shared.open(url)
        }
    }

    // ========================================================================
    // Staged File Queue (Never Auto-Sends Until User Clicks Send)
    // ========================================================================
    func stagePathsOrUrls(_ rawItems: [String]) {
        var updated = stagedItems
        var addedCount = 0
        for raw in rawItems {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty else { continue }
            if updated.contains(where: { $0.pathOrUrl == trimmed }) { continue }
            let isUrl = trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://")
            if !isUrl {
                var isDir: ObjCBool = false
                guard FileManager.default.fileExists(atPath: trimmed, isDirectory: &isDir), !isDir.boolValue else {
                    continue
                }
            }
            let size: Int64 = isUrl
                ? Int64(trimmed.utf8.count)
                : ((try? FileManager.default.attributesOfItem(atPath: trimmed)[.size] as? Int64) ?? 0)
            let dispName = isUrl ? trimmed : URL(fileURLWithPath: trimmed).lastPathComponent
            let cat = inferMacCategory(pathOrUrl: trimmed, isUrl: isUrl)
            updated.append(MacStagedItem(
                id: UUID().uuidString,
                pathOrUrl: trimmed,
                name: dispName,
                sizeBytes: size,
                isUrl: isUrl,
                category: cat
            ))
            addedCount += 1
        }
        stagedItems = updated
        selectedTab = 0
        onRequestFrontWindow?()
        if addedCount > 0 {
            transferStatus = "\(updated.count) item(s) selected (\(formatByteSize(totalStagedBytes))) — click Send to start"
        }
    }

    func removeStagedItem(_ id: String) {
        stagedItems.removeAll { $0.id == id }
        if stagedItems.isEmpty {
            transferStatus = "Queue cleared"
        }
    }

    func clearStagedItems() {
        stagedItems.removeAll()
        transferStatus = "Queue cleared"
    }

    func chooseFilesForCategory(title: String, types: [UTType]) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.title = "Select \(title)"
        panel.prompt = "Add to Queue"
        if !types.isEmpty {
            panel.allowedContentTypes = types
        }
        NSApp.activate(ignoringOtherApps: true)
        if panel.runModal() == .OK {
            stagePathsOrUrls(panel.urls.map { $0.path })
        }
    }

    func stageFinderSelection() {
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let script = """
            tell application "Finder"
                set selList to selection as list
                set outPaths to ""
                repeat with anItem in selList
                    try
                        set p to POSIX path of (anItem as alias)
                        set outPaths to outPaths & p & linefeed
                    end try
                end repeat
                return outPaths
            end tell
            """
            let (_, out) = runProcessCapture("/usr/bin/osascript", ["-e", script])
            let paths = out
                .split(separator: "\n")
                .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            DispatchQueue.main.async {
                guard let self = self else { return }
                if paths.isEmpty {
                    self.transferStatus = "No file selected in Finder"
                    self.onRequestFrontWindow?()
                } else {
                    self.stagePathsOrUrls(paths)
                }
            }
        }
    }

    func stageClipboard() {
        if let fileUrls = NSPasteboard.general.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL],
           !fileUrls.isEmpty {
            stagePathsOrUrls(fileUrls.map { $0.path })
            return
        }
        guard let clip = NSPasteboard.general.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !clip.isEmpty else {
            transferStatus = "Clipboard is empty"
            return
        }
        if clip.hasPrefix("http://") || clip.hasPrefix("https://") {
            stagePathsOrUrls([clip])
        } else {
            let stamp = Int(Date().timeIntervalSince1970)
            let tmpFile = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("Clipboard-\(stamp).txt")
            try? clip.data(using: .utf8)?.write(to: tmpFile)
            stagePathsOrUrls([tmpFile.path])
        }
    }

    func stageUrlOrNoteInput() {
        let trimmed = urlInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        urlInput = ""
        showLinkComposer = false
        if trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://") {
            stagePathsOrUrls([trimmed])
        } else {
            let stamp = Int(Date().timeIntervalSince1970)
            let tmpFile = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("Note-\(stamp).txt")
            try? trimmed.data(using: .utf8)?.write(to: tmpFile)
            stagePathsOrUrls([tmpFile.path])
        }
    }

    func sendStagedItems() {
        guard !stagedItems.isEmpty, !isTransferring else { return }
        let itemsToSend = stagedItems
        let args = itemsToSend.map { $0.pathOrUrl }
        let totalBytes = max(1, itemsToSend.reduce(Int64(0)) { $0 + $1.sizeBytes })
        let count = itemsToSend.count
        let firstName = itemsToSend[0].name
        let summaryLabel = count > 1 ? "\(firstName) + \(count - 1) more" : firstName
        let targetName = activePeers.first?.name ?? "Nearby Device"

        clearCancelFlag()
        isTransferring = true
        let initialConnecting = MacLiveProgress(
            direction: "Sending",
            fileName: summaryLabel,
            fileCount: count,
            doneBytes: 0,
            totalBytes: totalBytes,
            speedBps: 0,
            etaSeconds: 0,
            percent: 0,
            phase: "Connecting to \(targetName) via Bluetooth LE…",
            peerName: targetName,
            isConnecting: true
        )
        liveProgress = initialConnecting
        writeProgressJson(
            active: true,
            direction: "Sending",
            fileName: summaryLabel,
            fileCount: count,
            doneBytes: 0,
            totalBytes: totalBytes,
            speedBps: 0,
            etaSeconds: 0,
            percent: 0,
            phase: "Connecting to \(targetName) via Bluetooth LE…",
            peerName: targetName,
            isConnecting: true
        )
        transferStatus = "Connecting to \(targetName)…"
        try? Data("1".utf8).write(to: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
        BleAirDropDaemon.shared?.cancelActivePing()

        DispatchQueue.global(qos: .userInitiated).async {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: SCRIPT_PATH)
            p.arguments = ["send"] + args
            let pipe = Pipe()
            p.standardOutput = pipe
            p.standardError = pipe
            DispatchQueue.main.async {
                self.activeSendProcess = p
            }
            try? p.run()
            p.waitUntilExit()
            try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
            writeProgressJson(active: false)
            restoreMacInternetWifi()
            let wasCancelled = isTransferCancelled()
            clearCancelFlag()
            let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let lastLine = out.split(separator: "\n").last.map(String.init) ?? ""
            let ok = p.terminationStatus == 0 && !wasCancelled
            DispatchQueue.main.async {
                self.activeSendProcess = nil
                self.isTransferring = false
                self.liveProgress = nil
                if wasCancelled {
                    self.transferStatus = "Transfer cancelled"
                } else if ok {
                    self.stagedItems.removeAll()
                    self.transferStatus = "Sent \(summaryLabel) to \(targetName)"
                } else {
                    self.transferStatus = "Transfer failed: \(lastLine.isEmpty ? "Open AirDrop P2P on the receiving device and try again" : lastLine)"
                }
                self.refreshSlow()
            }
        }
    }
}

struct MacAirDropMainView: View {
    @ObservedObject var vm: MacAirDropViewModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var p: MacThemePalette { vm.palette }

    var body: some View {
        ZStack {
            p.bgCanvas.ignoresSafeArea()

            VStack(spacing: 0) {
                topHeaderBar
                    .padding(.horizontal, 18)
                    .padding(.top, 14)
                    .padding(.bottom, 10)

                if !vm.bluetoothAuthorized || !vm.bluetoothPoweredOn || !vm.wifiPoweredOn {
                    systemReadinessBanner
                        .padding(.horizontal, 18)
                        .padding(.bottom, 10)
                }

                if let prog = vm.liveProgress {
                    liveConnectionBridgeCard(prog)
                        .padding(.horizontal, 18)
                        .padding(.bottom, 10)
                } else if vm.isTransferring {
                    liveConnectionBridgeCard(MacLiveProgress(
                        direction: "Sending",
                        fileName: vm.stagedItems.first?.name ?? "Transfer",
                        fileCount: max(1, vm.stagedItems.count),
                        doneBytes: 0,
                        totalBytes: max(1, vm.totalStagedBytes),
                        speedBps: 0,
                        etaSeconds: 0,
                        percent: 0,
                        phase: vm.transferStatus,
                        peerName: vm.activePeers.first?.name ?? "Nearby Device",
                        isConnecting: true
                    ))
                    .padding(.horizontal, 18)
                    .padding(.bottom, 10)
                }

                ScrollView {
                    VStack(spacing: 14) {
                        switch vm.selectedTab {
                        case 0:
                            sendTabContent
                        case 1:
                            receiveRadarTabContent
                        case 2:
                            historyTabContent
                        default:
                            settingsTabContent
                        }
                    }
                    .padding(.horizontal, 18)
                    .padding(.vertical, 8)
                }

                bottomTabBar
            }

            if let ask = vm.pendingAsk {
                Color.black.opacity(p.isDark ? 0.65 : 0.35)
                    .ignoresSafeArea()
                incomingAskModal(ask)
                    .padding(28)
            }
        }
        .frame(minWidth: 550, idealWidth: 570, minHeight: 680, idealHeight: 720)
        .preferredColorScheme(p.isDark ? .dark : .light)
    }

    // ========================================================================
    // Top Header Bar (Greeting + Radio Status + Day/Dark Toggle + Scan)
    // ========================================================================
    private var topHeaderBar: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(p.indigoSubtle)
                    .frame(width: 42, height: 42)
                    .overlay(Circle().stroke(p.indigo.opacity(0.28), lineWidth: 1))
                Image(systemName: "dot.radiowaves.left.and.right")
                    .font(.system(size: 18, weight: .bold))
                    .foregroundColor(p.indigo)
            }

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 7) {
                    Text(currentMacGreeting())
                        .font(.system(size: 18, weight: .bold))
                        .foregroundColor(p.textPrimary)
                    HStack(spacing: 4) {
                        Circle()
                            .fill(vm.receiverRunning ? p.emerald : p.amber)
                            .frame(width: 6, height: 6)
                        Text(vm.receiverRunning ? "Ready" : "Paused")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundColor(vm.receiverRunning ? p.emerald : p.amber)
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(
                        Capsule()
                            .fill(vm.receiverRunning ? p.emeraldSubtle : p.amberSubtle)
                    )
                }
                Text("\(vm.macDeviceName) • Send & receive files directly")
                    .font(.system(size: 11))
                    .foregroundColor(p.textSecondary)
                    .lineLimit(1)
            }

            Spacer()

            // 1-Tap Day / Dark Theme Toggle
            Button(action: { vm.toggleDayDarkQuick() }) {
                HStack(spacing: 5) {
                    Image(systemName: p.isDark ? "sun.max.fill" : "moon.stars.fill")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(p.isDark ? p.amber : p.indigo)
                    Text(p.isDark ? "Day" : "Dark")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(p.textPrimary)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(
                    Capsule()
                        .fill(p.bgSurface)
                        .overlay(Capsule().stroke(p.border, lineWidth: 1))
                )
            }
            .buttonStyle(MacScaleButtonStyle())
            .help("Switch between Day and Dark appearance")

            // Scan Button
            Button(action: { vm.rescanNow() }) {
                HStack(spacing: 4) {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 11, weight: .bold))
                    Text("Scan")
                        .font(.system(size: 11, weight: .semibold))
                }
                .foregroundColor(p.indigo)
                .padding(.horizontal, 11)
                .padding(.vertical, 6)
                .background(
                    Capsule()
                        .fill(p.indigoSubtle)
                        .overlay(Capsule().stroke(p.indigo.opacity(0.30), lineWidth: 1))
                )
            }
            .buttonStyle(MacScaleButtonStyle())
        }
    }

    private var systemReadinessBanner: some View {
        var missing: [String] = []
        if !vm.bluetoothAuthorized { missing.append("Bluetooth Permission") }
        if !vm.bluetoothPoweredOn { missing.append("Bluetooth") }
        if !vm.wifiPoweredOn { missing.append("Wi-Fi") }

        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Circle()
                    .fill(p.amber)
                    .frame(width: 8, height: 8)
                Text("Turn on \(missing.joined(separator: " & "))")
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(p.textPrimary)
                Spacer()
            }
            Text("Bluetooth discovers nearby devices and 5 GHz Wi-Fi Direct transfers large files at full speed.")
                .font(.system(size: 11))
                .foregroundColor(p.textSecondary)
            HStack(spacing: 8) {
                if !vm.bluetoothAuthorized {
                    Button("Allow Bluetooth") { vm.openBluetoothPrivacySettings() }
                        .buttonStyle(.borderedProminent)
                        .tint(p.amber)
                        .controlSize(.small)
                }
                if !vm.bluetoothPoweredOn {
                    Button("Turn On Bluetooth") { vm.openBluetoothSettings() }
                        .buttonStyle(.borderedProminent)
                        .tint(p.indigo)
                        .controlSize(.small)
                }
                if !vm.wifiPoweredOn {
                    Button("Turn On Wi-Fi") { vm.enableMacWifi() }
                        .buttonStyle(.borderedProminent)
                        .tint(p.indigo)
                        .controlSize(.small)
                }
                Spacer()
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(p.bgSurface)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(p.amber.opacity(0.6), lineWidth: 1))
        )
    }

    // ========================================================================
    // Live Connecting… / Connected Peer Bridge Card (Mockup 2 Left)
    // ========================================================================
    private func liveConnectionBridgeCard(_ prog: MacLiveProgress) -> some View {
        let isSending = prog.direction.lowercased().contains("send")
        let senderLabel = isSending ? vm.macDeviceName : prog.peerName
        let receiverLabel = isSending ? prog.peerName : vm.macDeviceName
        let statusTitle = prog.isConnecting ? "Connecting…" : "Connected"
        let sizeSummary: String = {
            if prog.totalBytes > 0 && prog.doneBytes > 0 {
                return "\(formatByteSize(prog.doneBytes)) / \(formatByteSize(prog.totalBytes))"
            } else if prog.totalBytes > 0 {
                return formatByteSize(prog.totalBytes)
            }
            return "Preparing"
        }()
        let speedSummary: String = {
            if prog.isConnecting || prog.speedBps <= 0 {
                return prog.isConnecting ? "Handshake" : "Starting…"
            }
            return formatTransferSpeed(prog.speedBps)
        }()

        return VStack(spacing: 12) {
            // Top bar: Status + File + Cancel X
            HStack(spacing: 8) {
                if prog.isConnecting {
                    ProgressView()
                        .controlSize(.small)
                } else {
                    Circle()
                        .fill(p.emerald)
                        .frame(width: 9, height: 9)
                }
                Text(statusTitle)
                    .font(.system(size: 15, weight: .bold))
                    .foregroundColor(p.textPrimary)
                Text("• \(middleTruncateMacName(prog.fileName, maxChars: 28))")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(p.textSecondary)
                    .lineLimit(1)
                Spacer()
                Button(action: { vm.cancelActiveTransfer() }) {
                    Image(systemName: "xmark")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(p.textSecondary)
                        .frame(width: 26, height: 26)
                        .background(Circle().fill(p.bgSubtle))
                }
                .buttonStyle(MacScaleButtonStyle())
                .help("Cancel transfer")
            }

            // Sender <-- Dashed Arc + Direction Icon --> Receiver
            HStack(spacing: 14) {
                VStack(spacing: 5) {
                    ZStack {
                        Circle()
                            .fill(p.indigoSubtle)
                            .frame(width: 48, height: 48)
                            .overlay(Circle().stroke(p.indigo.opacity(0.45), lineWidth: 1.5))
                        Image(systemName: isSending ? "laptopcomputer" : "iphone.gen3")
                            .font(.system(size: 20, weight: .semibold))
                            .foregroundColor(p.indigo)
                    }
                    Text(middleTruncateMacName(senderLabel, maxChars: 16))
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(p.textPrimary)
                        .lineLimit(1)
                }
                .frame(width: 110)

                ZStack {
                    Path { path in
                        path.move(to: CGPoint(x: 8, y: 26))
                        path.addQuadCurve(to: CGPoint(x: 172, y: 26), control: CGPoint(x: 90, y: -4))
                    }
                    .stroke(
                        p.indigo.opacity(0.55),
                        style: StrokeStyle(
                            lineWidth: 1.8,
                            lineCap: .round,
                            dash: [5, 5],
                            dashPhase: vm.bridgePhaseTick ? -20 : 0
                        )
                    )
                    .frame(width: 180, height: 34)

                    ZStack {
                        RoundedRectangle(cornerRadius: 10)
                            .fill(p.bgSurface)
                            .frame(width: 34, height: 34)
                            .overlay(RoundedRectangle(cornerRadius: 10).stroke(p.indigo.opacity(0.45), lineWidth: 1.2))
                        Image(systemName: isSending ? "arrow.up.doc.fill" : "arrow.down.doc.fill")
                            .font(.system(size: 15, weight: .bold))
                            .foregroundColor(isSending ? p.indigo : p.emerald)
                    }
                }
                .frame(maxWidth: .infinity)

                VStack(spacing: 5) {
                    ZStack {
                        Circle()
                            .fill(p.emeraldSubtle)
                            .frame(width: 48, height: 48)
                            .overlay(Circle().stroke(p.emerald.opacity(0.45), lineWidth: 1.5))
                        Image(systemName: isSending ? "iphone.gen3" : "laptopcomputer")
                            .font(.system(size: 20, weight: .semibold))
                            .foregroundColor(p.emerald)
                    }
                    Text(middleTruncateMacName(receiverLabel, maxChars: 16))
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(p.textPrimary)
                        .lineLimit(1)
                }
                .frame(width: 110)
            }
            .onAppear {
                guard !reduceMotion else { return }
                withAnimation(.linear(duration: 1.1).repeatForever(autoreverses: false)) {
                    vm.bridgePhaseTick = true
                }
            }

            // Live step-by-step phase text (eliminates blind connecting gap)
            Text(prog.phase)
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(prog.isConnecting ? p.indigo : p.textSecondary)
                .lineLimit(1)

            // 3-Column Indigo Summary Strip: Items | Size | Speed
            HStack(spacing: 0) {
                bridgeMetricColumn(title: "Items", value: "\(prog.fileCount) \(prog.fileCount == 1 ? "file" : "files")")
                Rectangle().fill(Color.white.opacity(0.22)).frame(width: 1, height: 28)
                bridgeMetricColumn(title: "Size", value: sizeSummary)
                Rectangle().fill(Color.white.opacity(0.22)).frame(width: 1, height: 28)
                bridgeMetricColumn(title: "Speed", value: speedSummary)
            }
            .padding(.vertical, 9)
            .background(RoundedRectangle(cornerRadius: 12).fill(p.indigo))

            // Progress Bar
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Capsule()
                        .fill(p.bgSubtle)
                        .frame(height: 7)
                    if prog.isConnecting {
                        Capsule()
                            .fill(p.indigo.opacity(0.75))
                            .frame(width: max(48, geo.size.width * 0.28), height: 7)
                            .offset(x: vm.pulse ? geo.size.width * 0.68 : 4)
                    } else {
                        Capsule()
                            .fill(isSending ? p.indigo : p.emerald)
                            .frame(width: max(10, geo.size.width * CGFloat(min(100, max(0, prog.percent))) / 100.0), height: 7)
                    }
                }
            }
            .frame(height: 7)

            if !prog.isConnecting {
                HStack {
                    Text(prog.direction)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(p.textSecondary)
                    Spacer()
                    if prog.etaSeconds > 0 {
                        Text("~\(prog.etaSeconds)s remaining")
                            .font(.system(size: 11).monospacedDigit())
                            .foregroundColor(p.textSecondary)
                    }
                    Text("\(prog.percent)%")
                        .font(.system(size: 11, weight: .bold).monospacedDigit())
                        .foregroundColor(p.textPrimary)
                }
            }
        }
        .padding(15)
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(p.bgSurface)
                .overlay(RoundedRectangle(cornerRadius: 20).stroke(p.indigo.opacity(0.45), lineWidth: 1.2))
                .shadow(color: Color.black.opacity(p.isDark ? 0.28 : 0.06), radius: 12, x: 0, y: 4)
        )
    }

    private func bridgeMetricColumn(title: String, value: String) -> some View {
        VStack(spacing: 2) {
            Text(title)
                .font(.system(size: 10, weight: .medium))
                .foregroundColor(Color.white.opacity(0.82))
            Text(value)
                .font(.system(size: 12, weight: .bold).monospacedDigit())
                .foregroundColor(.white)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity)
    }

    // ========================================================================
    // TAB 0: Send (Staged Queue + 2x3 Categories + Storage Donut + Dual CTAs)
    // ========================================================================
    private var sendTabContent: some View {
        VStack(alignment: .leading, spacing: 14) {
            // 1. Staged Files Queue Card (Appears Whenever Files Are Selected)
            if !vm.stagedItems.isEmpty {
                stagedFilesQueueCard
            }

            // 2. Categories 2x3 Circular Grid (Mockup 2 Center)
            categoriesGridCard

            // 3. Inline Link / Note Composer (when toggled)
            if vm.showLinkComposer {
                inlineLinkComposerCard
            }

            // 4. Storage Overview Donut Ring Card (Mockup 1 Center)
            storageOverviewCard

            // 5. Bottom Dual Action Buttons (Send / Select Files + Receive)
            HStack(spacing: 12) {
                Button(action: {
                    if vm.stagedItems.isEmpty {
                        vm.chooseFilesForCategory(title: "Files", types: [])
                    } else {
                        vm.sendStagedItems()
                    }
                }) {
                    HStack(spacing: 8) {
                        Image(systemName: "paperplane.fill")
                            .font(.system(size: 14, weight: .bold))
                        Text(vm.stagedItems.isEmpty ? "Select Files" : "Send (\(vm.stagedItems.count))")
                            .font(.system(size: 14, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 13)
                    .background(
                        RoundedRectangle(cornerRadius: 16)
                            .fill(p.indigo)
                    )
                }
                .buttonStyle(MacScaleButtonStyle())
                .disabled(vm.isTransferring)

                Button(action: { vm.selectedTab = 1 }) {
                    HStack(spacing: 8) {
                        Image(systemName: "arrow.down.circle.fill")
                            .font(.system(size: 15, weight: .bold))
                        Text("Receive")
                            .font(.system(size: 14, weight: .bold))
                    }
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 13)
                    .background(
                        RoundedRectangle(cornerRadius: 16)
                            .fill(p.emerald)
                    )
                }
                .buttonStyle(MacScaleButtonStyle())
            }

            // 6. Recently Sent Preview
            let recentSent = vm.historyEntries.filter { $0.isOutgoing }.prefix(3)
            if !recentSent.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Text("Recently Sent")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(p.textPrimary)
                        Spacer()
                        Button("View all") {
                            vm.historyFilter = 2
                            vm.selectedTab = 2
                        }
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(p.indigo)
                        .buttonStyle(.plain)
                    }
                    ForEach(Array(recentSent)) { item in
                        compactHistoryRow(item)
                    }
                }
            }
        }
        .onDrop(of: [.fileURL, .url, .plainText], isTargeted: $vm.isDropTargeted) { providers in
            handleDropToStage(providers)
        }
    }

    private var stagedFilesQueueCard: some View {
        let peerName = vm.activePeers.first?.name
        return VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                ZStack {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(p.indigoSubtle)
                        .frame(width: 28, height: 28)
                    Text("\(vm.stagedItems.count)")
                        .font(.system(size: 12, weight: .heavy).monospacedDigit())
                        .foregroundColor(p.indigo)
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(vm.stagedItems.count == 1 ? "1 File Selected" : "\(vm.stagedItems.count) Files Selected")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(p.textPrimary)
                    Text("Total size: \(formatByteSize(vm.totalStagedBytes)) • Review before sending")
                        .font(.system(size: 11).monospacedDigit())
                        .foregroundColor(p.textSecondary)
                }
                Spacer()
                Button(action: { vm.chooseFilesForCategory(title: "More Files", types: []) }) {
                    HStack(spacing: 4) {
                        Image(systemName: "plus")
                            .font(.system(size: 10, weight: .bold))
                        Text("Add")
                            .font(.system(size: 11, weight: .semibold))
                    }
                    .foregroundColor(p.indigo)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(Capsule().fill(p.indigoSubtle))
                }
                .buttonStyle(MacScaleButtonStyle())

                Button(action: { vm.clearStagedItems() }) {
                    Text("Clear")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(p.danger)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(Capsule().fill(p.dangerSubtle))
                }
                .buttonStyle(MacScaleButtonStyle())
            }

            // Destination Peer Bar
            HStack(spacing: 8) {
                Circle()
                    .fill(peerName != nil ? p.emerald : p.amber)
                    .frame(width: 7, height: 7)
                Text(peerName != nil ? "Destination: \(peerName!)" : "Scanning for nearby receiving device…")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(p.textPrimary)
                Spacer()
                if let peer = vm.activePeers.first {
                    Text("\(peer.rssi) dBm")
                        .font(.system(size: 10, weight: .semibold).monospacedDigit())
                        .foregroundColor(p.emerald)
                } else {
                    Button("Scan") { vm.rescanNow() }
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(p.indigo)
                        .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 11)
            .padding(.vertical, 8)
            .background(RoundedRectangle(cornerRadius: 10).fill(p.bgSubtle))

            // Staged File Rows
            VStack(spacing: 6) {
                ForEach(vm.stagedItems.prefix(8)) { item in
                    let badge = macCategoryStyle(item.category)
                    HStack(spacing: 10) {
                        Text(item.category)
                            .font(.system(size: 9, weight: .heavy))
                            .foregroundColor(badge)
                            .frame(width: 36, height: 24)
                            .background(RoundedRectangle(cornerRadius: 6).fill(badge.opacity(0.15)))

                        VStack(alignment: .leading, spacing: 1) {
                            Text(middleTruncateMacName(item.name, maxChars: 38))
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(p.textPrimary)
                                .lineLimit(1)
                            Text(formatByteSize(item.sizeBytes))
                                .font(.system(size: 10).monospacedDigit())
                                .foregroundColor(p.textSecondary)
                        }
                        Spacer()
                        Button(action: { vm.removeStagedItem(item.id) }) {
                            Image(systemName: "xmark")
                                .font(.system(size: 10, weight: .bold))
                                .foregroundColor(p.textSecondary)
                                .frame(width: 22, height: 22)
                                .background(Circle().fill(p.bgSubtle))
                        }
                        .buttonStyle(MacScaleButtonStyle())
                        .help("Remove from queue")
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(
                        RoundedRectangle(cornerRadius: 10)
                            .fill(p.bgCanvas.opacity(p.isDark ? 0.55 : 0.75))
                    )
                }
                if vm.stagedItems.count > 8 {
                    Text("+ \(vm.stagedItems.count - 8) additional file(s)")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(p.textSecondary)
                }
            }

            // Explicit Primary Send Button
            Button(action: { vm.sendStagedItems() }) {
                HStack(spacing: 8) {
                    Image(systemName: "paperplane.fill")
                        .font(.system(size: 13, weight: .bold))
                    Text("Send \(vm.stagedItems.count) \(vm.stagedItems.count == 1 ? "File" : "Files") (\(formatByteSize(vm.totalStagedBytes)))")
                        .font(.system(size: 13, weight: .bold).monospacedDigit())
                }
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 11)
                .background(RoundedRectangle(cornerRadius: 12).fill(p.indigo))
            }
            .buttonStyle(MacScaleButtonStyle())
            .disabled(vm.isTransferring)
        }
        .padding(15)
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(p.bgSurface)
                .overlay(RoundedRectangle(cornerRadius: 20).stroke(p.indigo.opacity(0.50), lineWidth: 1.4))
                .shadow(color: Color.black.opacity(p.isDark ? 0.24 : 0.05), radius: 10, x: 0, y: 3)
        )
    }

    private var categoriesGridCard: some View {
        let columns = [
            GridItem(.flexible(), spacing: 12),
            GridItem(.flexible(), spacing: 12),
            GridItem(.flexible(), spacing: 12)
        ]

        return VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("Categories")
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(p.textPrimary)
                Spacer()
                Text(vm.isDropTargeted ? "Drop files to add to queue" : "Drag & drop or pick by type")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(vm.isDropTargeted ? p.indigo : p.textSecondary)
            }

            LazyVGrid(columns: columns, spacing: 14) {
                categoryCircleButton(
                    title: "Images",
                    icon: "photo.fill",
                    tint: Color(red: 0.145, green: 0.388, blue: 0.922)
                ) {
                    vm.chooseFilesForCategory(title: "Images", types: [.image])
                }
                categoryCircleButton(
                    title: "Videos",
                    icon: "play.rectangle.fill",
                    tint: Color(red: 0.859, green: 0.153, blue: 0.467)
                ) {
                    vm.chooseFilesForCategory(title: "Videos", types: [.movie, .video, .mpeg4Movie, .quickTimeMovie])
                }
                categoryCircleButton(
                    title: "Docs",
                    icon: "doc.text.fill",
                    tint: Color(red: 0.086, green: 0.639, blue: 0.290)
                ) {
                    vm.chooseFilesForCategory(title: "Documents", types: [.pdf, .plainText, .rtf, .spreadsheet, .presentation, .data])
                }
                categoryCircleButton(
                    title: "Music",
                    icon: "music.note",
                    tint: Color(red: 0.851, green: 0.467, blue: 0.024)
                ) {
                    vm.chooseFilesForCategory(title: "Audio", types: [.audio, .mp3])
                }
                categoryCircleButton(
                    title: "Link / Note",
                    icon: "link",
                    tint: Color(red: 0.863, green: 0.149, blue: 0.149)
                ) {
                    vm.showLinkComposer.toggle()
                }
                categoryCircleButton(
                    title: "Files",
                    icon: "folder.fill",
                    tint: Color(red: 0.388, green: 0.400, blue: 0.945)
                ) {
                    vm.chooseFilesForCategory(title: "Files", types: [])
                }
            }

            // Quick Mac Shortcuts Row: Finder Selection + Clipboard
            HStack(spacing: 8) {
                Button(action: { vm.stageFinderSelection() }) {
                    HStack(spacing: 5) {
                        Image(systemName: "macwindow.badge.plus")
                            .font(.system(size: 11, weight: .semibold))
                        Text("Add Finder Selection")
                            .font(.system(size: 11, weight: .semibold))
                    }
                    .foregroundColor(p.textPrimary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 7)
                    .background(
                        RoundedRectangle(cornerRadius: 10)
                            .fill(p.bgSubtle)
                            .overlay(RoundedRectangle(cornerRadius: 10).stroke(p.border, lineWidth: 1))
                    )
                }
                .buttonStyle(MacScaleButtonStyle())

                Button(action: { vm.stageClipboard() }) {
                    HStack(spacing: 5) {
                        Image(systemName: "doc.on.clipboard")
                            .font(.system(size: 11, weight: .semibold))
                        Text("Add Clipboard")
                            .font(.system(size: 11, weight: .semibold))
                    }
                    .foregroundColor(p.textPrimary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 7)
                    .background(
                        RoundedRectangle(cornerRadius: 10)
                            .fill(p.bgSubtle)
                            .overlay(RoundedRectangle(cornerRadius: 10).stroke(p.border, lineWidth: 1))
                    )
                }
                .buttonStyle(MacScaleButtonStyle())
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(vm.isDropTargeted ? p.indigoSubtle : p.bgSurface)
                .overlay(
                    RoundedRectangle(cornerRadius: 20)
                        .stroke(vm.isDropTargeted ? p.indigo : p.border, lineWidth: vm.isDropTargeted ? 2 : 1)
                )
        )
    }

    private func categoryCircleButton(title: String, icon: String, tint: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 7) {
                ZStack {
                    Circle()
                        .fill(tint)
                        .frame(width: 50, height: 50)
                        .shadow(color: tint.opacity(p.isDark ? 0.35 : 0.22), radius: 6, x: 0, y: 3)
                    Image(systemName: icon)
                        .font(.system(size: 20, weight: .semibold))
                        .foregroundColor(.white)
                }
                Text(title)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(p.textPrimary)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 6)
        }
        .buttonStyle(MacScaleButtonStyle())
    }

    private var inlineLinkComposerCard: some View {
        HStack(spacing: 8) {
            TextField("Paste URL or type a quick note to stage…", text: $vm.urlInput)
                .textFieldStyle(.roundedBorder)
                .onSubmit { vm.stageUrlOrNoteInput() }
            Button("Stage") {
                vm.stageUrlOrNoteInput()
            }
            .buttonStyle(.borderedProminent)
            .tint(p.indigo)
            .disabled(vm.urlInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(p.bgSurface)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(p.border, lineWidth: 1))
        )
    }

    private var storageOverviewCard: some View {
        let used = vm.storage.usedFraction
        let segApps = used * 0.42
        let segMedia = used * 0.36
        let segDocs = used * 0.22

        return HStack(spacing: 20) {
            // Segmented Donut Ring
            ZStack {
                Circle()
                    .stroke(p.bgMuted, lineWidth: 13)
                    .frame(width: 108, height: 108)

                Circle()
                    .trim(from: 0, to: CGFloat(segApps))
                    .stroke(p.emerald, style: StrokeStyle(lineWidth: 13, lineCap: .butt))
                    .rotationEffect(.degrees(-90))
                    .frame(width: 108, height: 108)

                Circle()
                    .trim(from: CGFloat(segApps), to: CGFloat(segApps + segMedia))
                    .stroke(p.indigo, style: StrokeStyle(lineWidth: 13, lineCap: .butt))
                    .rotationEffect(.degrees(-90))
                    .frame(width: 108, height: 108)

                Circle()
                    .trim(from: CGFloat(segApps + segMedia), to: CGFloat(segApps + segMedia + segDocs))
                    .stroke(p.amber, style: StrokeStyle(lineWidth: 13, lineCap: .butt))
                    .rotationEffect(.degrees(-90))
                    .frame(width: 108, height: 108)

                VStack(spacing: 1) {
                    Text(formatByteSize(vm.storage.freeBytes))
                        .font(.system(size: 13, weight: .heavy).monospacedDigit())
                        .foregroundColor(p.textPrimary)
                    Text("Available")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(p.textSecondary)
                }
            }
            .padding(.leading, 4)

            VStack(alignment: .leading, spacing: 7) {
                Text("Macintosh HD")
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(p.textPrimary)
                Text("\(formatByteSize(vm.storage.freeBytes)) free of \(formatByteSize(vm.storage.totalBytes))")
                    .font(.system(size: 11).monospacedDigit())
                    .foregroundColor(p.textSecondary)

                VStack(alignment: .leading, spacing: 5) {
                    storageLegendDot(color: p.emerald, label: "Apps & System")
                    storageLegendDot(color: p.indigo, label: "Photos & Videos")
                    storageLegendDot(color: p.amber, label: "Documents & Archives")
                    storageLegendDot(color: p.bgMuted, label: "Available Space")
                }
                .padding(.top, 2)
            }
            Spacer()
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(p.bgSurface)
                .overlay(RoundedRectangle(cornerRadius: 20).stroke(p.border, lineWidth: 1))
        )
    }

    private func storageLegendDot(color: Color, label: String) -> some View {
        HStack(spacing: 7) {
            RoundedRectangle(cornerRadius: 3)
                .fill(color)
                .frame(width: 10, height: 10)
            Text(label)
                .font(.system(size: 11, weight: .medium))
                .foregroundColor(p.textSecondary)
        }
    }

    // ========================================================================
    // TAB 1: Receive (Concentric Pulse Radar + Available Devices + Recent RX)
    // ========================================================================
    private var receiveRadarTabContent: some View {
        VStack(alignment: .leading, spacing: 14) {
            // Radar Card (Mockup 1 Right)
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(vm.activePeers.isEmpty ? "Looking for" : "Nearby")
                            .font(.system(size: 12, weight: .medium))
                            .foregroundColor(p.textSecondary)
                        Text(vm.activePeers.isEmpty ? "Connections…" : "\(vm.activePeers.count) Device\(vm.activePeers.count == 1 ? "" : "s") Ready")
                            .font(.system(size: 20, weight: .heavy))
                            .foregroundColor(p.textPrimary)
                    }
                    Spacer()
                    Button(action: { vm.setReceiveMode(directGet: !vm.autoAccept) }) {
                        HStack(spacing: 5) {
                            Circle()
                                .fill(vm.autoAccept ? p.emerald : p.amber)
                                .frame(width: 6, height: 6)
                            Text(vm.autoAccept ? "Auto-Accept" : "Ask First")
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(vm.autoAccept ? p.emerald : p.amber)
                        }
                        .padding(.horizontal, 10)
                        .padding(.vertical, 6)
                        .background(
                            Capsule()
                                .fill(vm.autoAccept ? p.emeraldSubtle : p.amberSubtle)
                        )
                    }
                    .buttonStyle(MacScaleButtonStyle())
                }

                // Concentric Radar
                ZStack {
                    Circle()
                        .fill(p.indigo.opacity(p.isDark ? 0.10 : 0.08))
                        .frame(width: 214, height: 214)
                        .scaleEffect(vm.pulse && !reduceMotion ? 1.04 : 0.96)
                    Circle()
                        .fill(p.indigo.opacity(p.isDark ? 0.18 : 0.15))
                        .frame(width: 154, height: 154)
                        .scaleEffect(vm.pulse && !reduceMotion ? 1.02 : 0.98)
                    Circle()
                        .fill(p.indigo.opacity(p.isDark ? 0.34 : 0.30))
                        .frame(width: 98, height: 98)

                    ZStack {
                        Circle()
                            .fill(Color.white)
                            .frame(width: 54, height: 54)
                            .shadow(color: p.indigo.opacity(0.35), radius: 10)
                        Image(systemName: "dot.radiowaves.left.and.right")
                            .font(.system(size: 22, weight: .bold))
                            .foregroundColor(p.indigo)
                    }

                    ForEach(Array(vm.activePeers.prefix(3).enumerated()), id: \.element.id) { idx, peer in
                        let angle = (-38.0 + Double(idx) * 115.0) * .pi / 180.0
                        let r: CGFloat = 96.0
                        Button(action: {
                            vm.chooseFilesForCategory(title: "Files for \(peer.name)", types: [])
                        }) {
                            HStack(spacing: 5) {
                                Circle()
                                    .fill(p.emerald)
                                    .frame(width: 7, height: 7)
                                Text(middleTruncateMacName(peer.name, maxChars: 16))
                                    .font(.system(size: 11, weight: .bold))
                                    .foregroundColor(p.textPrimary)
                            }
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(
                                Capsule()
                                    .fill(p.bgSurface)
                                    .overlay(Capsule().stroke(p.emerald.opacity(0.6), lineWidth: 1.2))
                                    .shadow(color: Color.black.opacity(0.12), radius: 5)
                            )
                        }
                        .buttonStyle(MacScaleButtonStyle())
                        .offset(x: CGFloat(cos(angle)) * r, y: CGFloat(sin(angle)) * r * 0.72)
                    }
                }
                .frame(maxWidth: .infinity)
                .frame(height: 224)
                .onAppear {
                    guard !reduceMotion else { return }
                    withAnimation(.easeInOut(duration: 2.0).repeatForever(autoreverses: true)) {
                        vm.pulse = true
                    }
                }

                Text("Visible as \"\(vm.macDeviceName)\" • Incoming files save to ~/Downloads")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(p.textSecondary)
                    .frame(maxWidth: .infinity, alignment: .center)
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 22)
                    .fill(p.bgSurface)
                    .overlay(RoundedRectangle(cornerRadius: 22).stroke(p.border, lineWidth: 1))
            )

            // Available Devices Section
            Text("Available Devices")
                .font(.system(size: 14, weight: .bold))
                .foregroundColor(p.textPrimary)

            if vm.activePeers.isEmpty {
                HStack(spacing: 10) {
                    ProgressView()
                        .controlSize(.small)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Scanning for nearby phones and Macs…")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundColor(p.textPrimary)
                        Text("Open AirDrop P2P on your Android phone with Bluetooth enabled.")
                            .font(.system(size: 11))
                            .foregroundColor(p.textSecondary)
                    }
                    Spacer()
                }
                .padding(14)
                .background(
                    RoundedRectangle(cornerRadius: 16)
                        .fill(p.bgSurface)
                        .overlay(RoundedRectangle(cornerRadius: 16).stroke(p.border, lineWidth: 1))
                )
            } else {
                ForEach(vm.activePeers) { peer in
                    availablePeerRow(peer)
                }
            }

            // Recently Received Section
            let recentRx = vm.historyEntries.filter { !$0.isOutgoing }.prefix(4)
            if !recentRx.isEmpty {
                HStack {
                    Text("Recently Received")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(p.textPrimary)
                    Spacer()
                    Button("Open ~/Downloads") {
                        let dl = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
                        NSWorkspace.shared.open(dl)
                    }
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(p.indigo)
                    .buttonStyle(.plain)
                }
                ForEach(Array(recentRx)) { item in
                    compactHistoryRow(item)
                }
            }
        }
    }

    private func availablePeerRow(_ peer: MacDiscoveredPeer) -> some View {
        let bars: Int = {
            if peer.rssi >= -55 { return 4 }
            if peer.rssi >= -68 { return 3 }
            if peer.rssi >= -80 { return 2 }
            return 1
        }()
        return HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(p.indigoSubtle)
                    .frame(width: 44, height: 44)
                Image(systemName: "iphone.gen3")
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundColor(p.indigo)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(peer.name)
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(p.textPrimary)
                Text("\(peer.transport) • \(peer.rssi) dBm")
                    .font(.system(size: 11).monospacedDigit())
                    .foregroundColor(p.textSecondary)
            }
            Spacer()
            HStack(alignment: .bottom, spacing: 2.5) {
                ForEach(1...4, id: \.self) { bar in
                    RoundedRectangle(cornerRadius: 1.5)
                        .fill(bar <= bars ? p.emerald : p.bgMuted)
                        .frame(width: 3.5, height: CGFloat(4 + bar * 3))
                }
            }
            Button(action: {
                vm.chooseFilesForCategory(title: "Files for \(peer.name)", types: [])
            }) {
                Text("Select Files")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .background(RoundedRectangle(cornerRadius: 10).fill(p.indigo))
            }
            .buttonStyle(MacScaleButtonStyle())
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(p.bgSurface)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(p.border, lineWidth: 1))
        )
    }

    // ========================================================================
    // TAB 2: History (Search Bar + Filters + Totals + File Actions)
    // ========================================================================
    private var historyTabContent: some View {
        let query = vm.historySearch.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let filtered = vm.historyEntries.filter { entry in
            if vm.historyFilter == 1 && entry.isOutgoing { return false }
            if vm.historyFilter == 2 && !entry.isOutgoing { return false }
            if !query.isEmpty {
                return entry.displayName.lowercased().contains(query) || entry.peerName.lowercased().contains(query)
            }
            return true
        }
        let rxBytes = vm.historyEntries.filter { !$0.isOutgoing }.reduce(Int64(0)) { $0 + $1.sizeBytes }
        let txBytes = vm.historyEntries.filter { $0.isOutgoing }.reduce(Int64(0)) { $0 + $1.sizeBytes }

        return VStack(alignment: .leading, spacing: 14) {
            // Search Bar (Mockup 1 Center)
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(p.textMuted)
                TextField("Search for a file or device…", text: $vm.historySearch)
                    .textFieldStyle(.plain)
                    .font(.system(size: 13))
                    .foregroundColor(p.textPrimary)
                if !vm.historySearch.isEmpty {
                    Button(action: { vm.historySearch = "" }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(p.textMuted)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(p.bgSurface)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(p.border, lineWidth: 1))
            )

            // Summary Cards
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Received")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(p.emerald)
                    Text(formatByteSize(rxBytes))
                        .font(.system(size: 17, weight: .heavy).monospacedDigit())
                        .foregroundColor(p.textPrimary)
                    let rxCount = vm.historyEntries.filter { !$0.isOutgoing }.count
                    Text("\(rxCount) \(rxCount == 1 ? "item" : "items") in ~/Downloads")
                        .font(.system(size: 11))
                        .foregroundColor(p.textSecondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(13)
                .background(
                    RoundedRectangle(cornerRadius: 16)
                        .fill(p.bgSurface)
                        .overlay(RoundedRectangle(cornerRadius: 16).stroke(p.border, lineWidth: 1))
                )

                VStack(alignment: .leading, spacing: 3) {
                    Text("Sent")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(p.indigo)
                    Text(formatByteSize(txBytes))
                        .font(.system(size: 17, weight: .heavy).monospacedDigit())
                        .foregroundColor(p.textPrimary)
                    let txCount = vm.historyEntries.filter { $0.isOutgoing }.count
                    Text("\(txCount) \(txCount == 1 ? "item" : "items") delivered")
                        .font(.system(size: 11))
                        .foregroundColor(p.textSecondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(13)
                .background(
                    RoundedRectangle(cornerRadius: 16)
                        .fill(p.bgSurface)
                        .overlay(RoundedRectangle(cornerRadius: 16).stroke(p.border, lineWidth: 1))
                )
            }

            // Filter Pills
            HStack(spacing: 6) {
                ForEach(Array(["All (\(vm.historyEntries.count))", "Received", "Sent"].enumerated()), id: \.offset) { idx, title in
                    let active = vm.historyFilter == idx
                    Button(action: { vm.historyFilter = idx }) {
                        Text(title)
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(active ? .white : p.textSecondary)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 6)
                            .background(
                                Capsule()
                                    .fill(active ? p.indigo : p.bgSurface)
                                    .overlay(Capsule().stroke(active ? p.indigo : p.border, lineWidth: 1))
                            )
                    }
                    .buttonStyle(MacScaleButtonStyle())
                }
                Spacer()
                Button("Downloads") {
                    let dl = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
                    NSWorkspace.shared.open(dl)
                }
                .controlSize(.small)
                if !vm.historyEntries.isEmpty {
                    Button("Clear") {
                        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("received.log"))
                        vm.historyEntries = []
                    }
                    .controlSize(.small)
                }
            }

            if filtered.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "clock.arrow.circlepath")
                        .font(.system(size: 26))
                        .foregroundColor(p.textMuted)
                    Text(query.isEmpty ? "No History Found" : "No Matching Transfers")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(p.textPrimary)
                    Text(query.isEmpty ? "Files sent or received appear here with sizes and Finder links." : "Try a different file or device name.")
                        .font(.system(size: 11))
                        .foregroundColor(p.textSecondary)
                }
                .frame(maxWidth: .infinity)
                .padding(26)
                .background(
                    RoundedRectangle(cornerRadius: 18)
                        .fill(p.bgSurface)
                        .overlay(RoundedRectangle(cornerRadius: 18).stroke(p.border, lineWidth: 1))
                )
            } else {
                ForEach(filtered) { item in
                    compactHistoryRow(item)
                }
            }
        }
    }

    private func compactHistoryRow(_ item: MacHistoryEntry) -> some View {
        let cat = inferMacCategory(pathOrUrl: item.displayName, isUrl: item.isUrl)
        let color = macCategoryStyle(cat)
        return HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(color.opacity(0.15))
                    .frame(width: 38, height: 38)
                Text(cat)
                    .font(.system(size: 10, weight: .heavy))
                    .foregroundColor(color)
            }
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(item.isOutgoing ? "SENT" : "RECEIVED")
                        .font(.system(size: 9, weight: .heavy))
                        .foregroundColor(item.isOutgoing ? p.indigo : p.emerald)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1.5)
                        .background(
                            RoundedRectangle(cornerRadius: 4)
                                .fill(item.isOutgoing ? p.indigoSubtle : p.emeraldSubtle)
                        )
                    Text(middleTruncateMacName(item.displayName, maxChars: 34))
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(p.textPrimary)
                        .lineLimit(1)
                }
                Text("\(formatByteSize(item.sizeBytes)) • \(item.peerName) • \(item.timestamp.formatted(date: .abbreviated, time: .shortened))")
                    .font(.system(size: 10).monospacedDigit())
                    .foregroundColor(p.textSecondary)
                    .lineLimit(1)
            }
            Spacer()
            Button(item.isUrl ? "Open" : "Finder") {
                if item.isUrl, let u = URL(string: item.value) {
                    NSWorkspace.shared.open(u)
                } else {
                    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: item.value)])
                }
            }
            .controlSize(.small)
        }
        .padding(11)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(p.bgSurface)
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(p.border, lineWidth: 1))
        )
    }

    // ========================================================================
    // TAB 3: Settings (Day/Dark/System Theme + Approval + Identity + Radio)
    // ========================================================================
    private var settingsTabContent: some View {
        VStack(alignment: .leading, spacing: 14) {
            // 1. Appearance (Day / Dark / System)
            VStack(alignment: .leading, spacing: 10) {
                Text("Appearance")
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(p.textPrimary)
                Text("Choose Day, Dark, or follow macOS appearance automatically.")
                    .font(.system(size: 11))
                    .foregroundColor(p.textSecondary)

                HStack(spacing: 10) {
                    themeOptionButton(mode: "light", title: "Day", icon: "sun.max.fill")
                    themeOptionButton(mode: "dark", title: "Dark", icon: "moon.stars.fill")
                    themeOptionButton(mode: "system", title: "System", icon: "circle.lefthalf.filled")
                }
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 20)
                    .fill(p.bgSurface)
                    .overlay(RoundedRectangle(cornerRadius: 20).stroke(p.border, lineWidth: 1))
            )

            // 2. Incoming File Approval
            VStack(alignment: .leading, spacing: 10) {
                Text("Incoming File Approval")
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(p.textPrimary)

                macSettingRadioCard(
                    title: "Ask First",
                    subtitle: "Confirm sender name, file list, and size before saving to ~/Downloads.",
                    selected: !vm.autoAccept,
                    accent: p.indigo
                ) {
                    vm.setReceiveMode(directGet: false)
                }

                macSettingRadioCard(
                    title: "Auto-Accept",
                    subtitle: "Save incoming files directly to ~/Downloads without a confirmation prompt.",
                    selected: vm.autoAccept,
                    accent: p.emerald
                ) {
                    vm.setReceiveMode(directGet: true)
                }
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 20)
                    .fill(p.bgSurface)
                    .overlay(RoundedRectangle(cornerRadius: 20).stroke(p.border, lineWidth: 1))
            )

            // 3. Device Name & Downloads
            VStack(alignment: .leading, spacing: 12) {
                Text("Device & Storage")
                    .font(.system(size: 14, weight: .bold))
                    .foregroundColor(p.textPrimary)

                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(vm.receiverRunning ? "Discoverable Nearby" : "Radio Paused")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundColor(p.textPrimary)
                        Text("BLE L2CAP + 5 GHz Wi-Fi Direct")
                            .font(.system(size: 11))
                            .foregroundColor(p.textSecondary)
                    }
                    Spacer()
                    Toggle("", isOn: Binding(
                        get: { vm.receiverRunning },
                        set: { vm.toggleDaemons($0) }
                    ))
                    .toggleStyle(.switch)
                    .labelsHidden()
                }

                HStack(spacing: 8) {
                    TextField("Device Name", text: $vm.editingDeviceName)
                        .textFieldStyle(.roundedBorder)
                    Button("Save Name") {
                        vm.saveDeviceName()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(p.indigo)
                }

                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Received Files Folder")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(p.textPrimary)
                        Text("~/Downloads")
                            .font(.system(size: 11))
                            .foregroundColor(p.textSecondary)
                    }
                    Spacer()
                    Button("Open ~/Downloads") {
                        let dl = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
                        NSWorkspace.shared.open(dl)
                    }
                    .controlSize(.small)
                }
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 20)
                    .fill(p.bgSurface)
                    .overlay(RoundedRectangle(cornerRadius: 20).stroke(p.border, lineWidth: 1))
            )

            // 4. Radio Diagnostics & Logs
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Diagnostics")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(p.textPrimary)
                    Spacer()
                    Button("Restart Radio") {
                        vm.rescanNow()
                    }
                    .controlSize(.small)
                }

                Text(vm.peerStatusSummary)
                    .font(.system(size: 11, weight: .semibold).monospacedDigit())
                    .foregroundColor(p.emerald)

                DisclosureGroup("Protocol Logs (\(vm.logs.count))", isExpanded: $vm.showLogs) {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(Array(vm.logs.enumerated()), id: \.offset) { _, line in
                                Text(line)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(p.textSecondary)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        .padding(8)
                    }
                    .frame(height: 130)
                    .background(RoundedRectangle(cornerRadius: 10).fill(p.bgSubtle))
                }
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(p.textSecondary)
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 20)
                    .fill(p.bgSurface)
                    .overlay(RoundedRectangle(cornerRadius: 20).stroke(p.border, lineWidth: 1))
            )
        }
    }

    private func themeOptionButton(mode: String, title: String, icon: String) -> some View {
        let active = vm.themeMode == mode
        return Button(action: { vm.setThemeMode(mode) }) {
            HStack(spacing: 6) {
                Image(systemName: icon)
                    .font(.system(size: 13, weight: .bold))
                Text(title)
                    .font(.system(size: 12, weight: .bold))
            }
            .foregroundColor(active ? .white : p.textPrimary)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 9)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(active ? p.indigo : p.bgSubtle)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(active ? p.indigo : p.border, lineWidth: 1))
            )
        }
        .buttonStyle(MacScaleButtonStyle())
    }

    private func macSettingRadioCard(
        title: String,
        subtitle: String,
        selected: Bool,
        accent: Color,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .stroke(selected ? accent : p.textMuted, lineWidth: 2)
                        .frame(width: 18, height: 18)
                    if selected {
                        Circle()
                            .fill(accent)
                            .frame(width: 10, height: 10)
                    }
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(p.textPrimary)
                    Text(subtitle)
                        .font(.system(size: 11))
                        .foregroundColor(p.textSecondary)
                }
                Spacer()
            }
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: 14)
                    .fill(selected ? p.indigoSubtle.opacity(0.65) : p.bgSubtle)
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(selected ? accent : p.border, lineWidth: 1.2))
            )
        }
        .buttonStyle(MacScaleButtonStyle())
    }

    // ========================================================================
    // Incoming Ask Approval Modal
    // ========================================================================
    private func incomingAskModal(_ ask: MacPendingAsk) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(p.indigo)
                        .frame(width: 44, height: 44)
                    Image(systemName: "arrow.down.doc.fill")
                        .font(.system(size: 20, weight: .bold))
                        .foregroundColor(.white)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text("Incoming Files")
                        .font(.system(size: 16, weight: .heavy))
                        .foregroundColor(p.textPrimary)
                    Text("From \(ask.senderName)")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(p.indigo)
                }
                Spacer()
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("\(ask.fileNames.count) \(ask.fileNames.count == 1 ? "file" : "files") • \(formatByteSize(ask.totalBytes))")
                    .font(.system(size: 12, weight: .bold).monospacedDigit())
                    .foregroundColor(p.emerald)
                ForEach(ask.fileNames.prefix(4), id: \.self) { fname in
                    Text("• \(middleTruncateMacName(fname, maxChars: 38))")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(p.textPrimary)
                        .lineLimit(1)
                }
                if ask.fileNames.count > 4 {
                    Text("+ \(ask.fileNames.count - 4) more")
                        .font(.system(size: 11))
                        .foregroundColor(p.textSecondary)
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(p.bgSubtle)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(p.border, lineWidth: 1))
            )

            HStack(spacing: 10) {
                Button(action: { vm.respondToAsk(accepted: false) }) {
                    Text("Decline")
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                }
                .buttonStyle(.bordered)

                Button(action: { vm.respondToAsk(accepted: true) }) {
                    Text("Accept")
                        .fontWeight(.bold)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                }
                .buttonStyle(.borderedProminent)
                .tint(p.indigo)
            }
        }
        .padding(20)
        .frame(maxWidth: 390)
        .background(
            RoundedRectangle(cornerRadius: 22)
                .fill(p.bgSurface)
                .overlay(RoundedRectangle(cornerRadius: 22).stroke(p.indigo.opacity(0.55), lineWidth: 1.5))
                .shadow(color: .black.opacity(0.35), radius: 24)
        )
    }

    // ========================================================================
    // Bottom 4-Tab Navigation Bar (Send | Receive | History | Settings)
    // ========================================================================
    private var bottomTabBar: some View {
        let tabs: [(String, String, String?, Int)] = [
            ("Send", "paperplane.fill", vm.stagedItems.isEmpty ? nil : "\(vm.stagedItems.count)", 0),
            ("Receive", "dot.radiowaves.left.and.right", vm.activePeers.isEmpty ? nil : "\(vm.activePeers.count)", 1),
            ("History", "clock.fill", nil, 2),
            ("Settings", "gearshape.fill", nil, 3)
        ]

        return HStack(spacing: 8) {
            ForEach(tabs, id: \.3) { title, icon, badge, idx in
                let active = vm.selectedTab == idx
                Button(action: { vm.selectedTab = idx }) {
                    HStack(spacing: 5) {
                        Image(systemName: icon)
                            .font(.system(size: 12, weight: .bold))
                        Text(title)
                            .font(.system(size: 12, weight: active ? .bold : .medium))
                        if let b = badge {
                            Text(b)
                                .font(.system(size: 10, weight: .bold).monospacedDigit())
                                .foregroundColor(active ? .white : p.indigo)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 1)
                                .background(Capsule().fill(active ? p.indigo : p.indigoSubtle))
                        }
                    }
                    .foregroundColor(active ? p.indigo : p.textSecondary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .background(
                        RoundedRectangle(cornerRadius: 12)
                            .fill(active ? p.indigoSubtle : Color.clear)
                            .overlay(
                                RoundedRectangle(cornerRadius: 12)
                                    .stroke(active ? p.indigo.opacity(0.40) : Color.clear, lineWidth: 1)
                            )
                    )
                }
                .buttonStyle(MacScaleButtonStyle())
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(
            p.bgSurface
                .overlay(Rectangle().fill(p.border).frame(height: 1), alignment: .top)
        )
    }

    private func macCategoryStyle(_ category: String) -> Color {
        switch category {
        case "IMG": return Color(red: 0.145, green: 0.388, blue: 0.922)
        case "VID": return Color(red: 0.859, green: 0.153, blue: 0.467)
        case "DOC": return Color(red: 0.086, green: 0.639, blue: 0.290)
        case "AUD": return Color(red: 0.851, green: 0.467, blue: 0.024)
        case "LINK": return Color(red: 0.863, green: 0.149, blue: 0.149)
        default: return p.indigo
        }
    }

    private func handleDropToStage(_ providers: [NSItemProvider]) -> Bool {
        var collected: [String] = []
        let lock = NSLock()
        let group = DispatchGroup()
        for provider in providers {
            if provider.canLoadObject(ofClass: URL.self) {
                group.enter()
                _ = provider.loadObject(ofClass: URL.self) { url, _ in
                    defer { group.leave() }
                    if let u = url {
                        lock.lock()
                        collected.append(u.isFileURL ? u.path : u.absoluteString)
                        lock.unlock()
                    }
                }
            }
        }
        group.notify(queue: .main) {
            if !collected.isEmpty {
                vm.stagePathsOrUrls(collected)
            }
        }
        return true
    }
}

final class StatusBarDropView: NSView {
    var onDropFiles: (([String]) -> Void)?

    override init(frame frameRect: NSRect) {
        super.init(frame: frameRect)
        registerForDraggedTypes([.fileURL])
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        registerForDraggedTypes([.fileURL])
    }

    override func hitTest(_ point: NSPoint) -> NSView? { nil }

    override func draggingEntered(_ sender: NSDraggingInfo) -> NSDragOperation {
        return .copy
    }

    override func performDragOperation(_ sender: NSDraggingInfo) -> Bool {
        guard let urls = sender.draggingPasteboard.readObjects(forClasses: [NSURL.self], options: nil) as? [URL] else {
            return false
        }
        let paths = urls.map { $0.path }.filter { !$0.isEmpty }
        guard !paths.isEmpty else { return false }
        onDropFiles?(paths)
        return true
    }
}

final class StatusBarController: NSObject, NSWindowDelegate, NSApplicationDelegate {
    let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    let viewModel = MacAirDropViewModel()
    var window: NSWindow?
    private var isShuttingDown = false

    init(openWindowOnLaunch: Bool) {
        super.init()
        viewModel.onThemeChanged = { [weak self] pal in
            self?.applyWindowAppearance(pal)
        }
        viewModel.onRequestFrontWindow = { [weak self] in
            self?.showMainWindow()
        }

        if let btn = statusItem.button {
            if let img = NSImage(systemSymbolName: "antenna.radiowaves.left.and.right", accessibilityDescription: "AirDrop P2P") {
                img.isTemplate = true
                btn.image = img
                btn.imagePosition = .imageLeading
            }
            btn.title = " AirDrop"
            let dropView = StatusBarDropView(frame: btn.bounds)
            dropView.autoresizingMask = [.width, .height]
            dropView.onDropFiles = { [weak self] paths in
                self?.viewModel.stagePathsOrUrls(paths)
            }
            btn.addSubview(dropView)
        }

        let menu = NSMenu()
        let openWin = NSMenuItem(title: "Open AirDrop P2P…", action: #selector(showMainWindow), keyEquivalent: "s")
        openWin.target = self
        menu.addItem(openWin)
        menu.addItem(NSMenuItem.separator())

        let sendSel = NSMenuItem(title: "Stage Selected Finder File(s)…", action: #selector(sendFinderSelection), keyEquivalent: "a")
        sendSel.target = self
        menu.addItem(sendSel)

        let pickFile = NSMenuItem(title: "Select Files to Send…", action: #selector(chooseAndSendFile), keyEquivalent: "o")
        pickFile.target = self
        menu.addItem(pickFile)

        menu.addItem(NSMenuItem.separator())
        let openDl = NSMenuItem(title: "Open Received Files (~/Downloads)", action: #selector(openDownloads), keyEquivalent: "")
        openDl.target = self
        menu.addItem(openDl)

        menu.addItem(NSMenuItem.separator())
        let quitItem = NSMenuItem(title: "Quit AirDrop P2P", action: #selector(quitApp), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        statusItem.menu = menu

        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(showMainWindow),
            name: SHOW_UI_NOTIFICATION,
            object: nil
        )

        if openWindowOnLaunch {
            DispatchQueue.main.async { [weak self] in
                self?.showMainWindow()
            }
        }
    }

    private func applyWindowAppearance(_ pal: MacThemePalette) {
        guard let win = window else { return }
        win.appearance = NSAppearance(named: pal.isDark ? .darkAqua : .aqua)
        win.backgroundColor = NSColor(
            calibratedRed: pal.nsCanvasRed,
            green: pal.nsCanvasGreen,
            blue: pal.nsCanvasBlue,
            alpha: 1.0
        )
    }

    @objc func showMainWindow() {
        NSApp.setActivationPolicy(.regular)
        if window == nil {
            let win = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 570, height: 720),
                styleMask: [.titled, .closable, .miniaturizable, .resizable],
                backing: .buffered,
                defer: false
            )
            win.title = "AirDrop P2P"
            win.titlebarAppearsTransparent = true
            win.center()
            win.isReleasedWhenClosed = false
            win.delegate = self
            win.contentView = NSHostingView(rootView: MacAirDropMainView(vm: viewModel))
            window = win
        }
        applyWindowAppearance(viewModel.palette)
        viewModel.refreshSlow()
        viewModel.refreshFast()
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func stopAllDaemonsAndQuit() {
        guard !isShuttingDown else { return }
        isShuttingDown = true
        for pf in ["daemon.pid", "mdns.pid", "awdl-mdns.pid"] {
            let f = STATE_DIR.appendingPathComponent(pf)
            if let s = try? String(contentsOf: f, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
               let pid = Int32(s) {
                kill(pid, SIGTERM)
            }
            try? FileManager.default.removeItem(at: f)
        }
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("ble-daemon.pid"))
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("transfer_progress.json"))
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
        NSApp.terminate(nil)
    }

    func windowWillClose(_ notification: Notification) {
        // Keep menu bar icon and background P2P receiver alive when closing the window
        if !isShuttingDown {
            NSApp.setActivationPolicy(.accessory)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            showMainWindow()
        }
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        for pf in ["daemon.pid", "mdns.pid", "awdl-mdns.pid"] {
            let f = STATE_DIR.appendingPathComponent(pf)
            if let s = try? String(contentsOf: f, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
               let pid = Int32(s) {
                kill(pid, SIGTERM)
            }
            try? FileManager.default.removeItem(at: f)
        }
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("ble-daemon.pid"))
    }

    @objc func sendFinderSelection() {
        showMainWindow()
        viewModel.stageFinderSelection()
    }

    @objc func chooseAndSendFile() {
        showMainWindow()
        viewModel.chooseFilesForCategory(title: "Files", types: [])
    }

    @objc func openDownloads() {
        let dl = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
        NSWorkspace.shared.open(dl)
    }

    @objc func quitApp() {
        stopAllDaemonsAndQuit()
    }
}

// ============================================================================
// AWDL Peer-to-Peer Socket Bridge (unlocks XNU INP_AWDL_UNRESTRICTED on awdl0)
// ============================================================================
final class AwdlLoopbackBridge {
    let listener: NWListener

    init(listenPort: UInt16 = 8774, targetPort: UInt16 = 8773) throws {
        let params = NWParameters.tcp
        params.includePeerToPeer = true
        listener = try NWListener(using: params, on: NWEndpoint.Port(rawValue: listenPort)!)
        listener.stateUpdateHandler = { state in
            print("[AWDL-Bridge] NWListener(\(listenPort) -> 127.0.0.1:\(targetPort)) state: \(state)")
            fflush(stdout)
        }
        listener.newConnectionHandler = { incoming in
            incoming.start(queue: .global(qos: .userInitiated))
            let outgoing = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: targetPort)!, using: .tcp)
            outgoing.start(queue: .global(qos: .userInitiated))
            Self.pump(from: incoming, to: outgoing)
            Self.pump(from: outgoing, to: incoming)
        }
        listener.start(queue: .global(qos: .userInitiated))
    }

    static func pump(from src: NWConnection, to dst: NWConnection) {
        src.receive(minimumIncompleteLength: 1, maximumLength: 1_048_576) { data, _, isComplete, error in
            if let d = data, !d.isEmpty {
                dst.send(content: d, completion: .contentProcessed { _ in
                    if !isComplete && error == nil {
                        pump(from: src, to: dst)
                    } else {
                        src.cancel()
                        dst.cancel()
                    }
                })
            } else if isComplete || error != nil {
                src.cancel()
                dst.cancel()
            }
        }
    }
}

signal(SIGPIPE, SIG_IGN)
let args = CommandLine.arguments
if args.count >= 2 && args[1] == "restore-wifi" {
    restoreMacInternetWifi()
    exit(0)
} else if args.count >= 2 && args[1] == "send" {
    let rawArgs = Array(args.dropFirst(2))
    let urls = rawArgs.filter { $0.hasPrefix("http://") || $0.hasPrefix("https://") }
    let fileUrls = rawArgs
        .filter { !$0.hasPrefix("http://") && !$0.hasPrefix("https://") }
        .map { URL(fileURLWithPath: $0) }
        .filter { FileManager.default.fileExists(atPath: $0.path) }
    guard !fileUrls.isEmpty || !urls.isEmpty else {
        print("Usage: mac-ble-airdrop send <file_or_url1> [file_or_url2 ...]")
        exit(1)
    }
    let sender = try BleAirDropSender(files: fileUrls, urls: urls)
    withExtendedLifetime(sender) {
        DispatchQueue.global().asyncAfter(deadline: .now() + 300.0) {
            writeProgressJson(active: false)
            print("[BLE-Send] Timed out waiting for BLE L2CAP transfer")
            exit(1)
        }
        RunLoop.main.run()
    }
} else {
    let isBackgroundDaemon = args.count >= 2 && args[1] == "daemon"
    let blePidFile = STATE_DIR.appendingPathComponent("ble-daemon.pid")
    if let pidStr = try? String(contentsOf: blePidFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
       let existingPid = Int32(pidStr),
       existingPid != getpid(),
       kill(existingPid, 0) == 0 {
        if !isBackgroundDaemon {
            DistributedNotificationCenter.default().postNotificationName(
                SHOW_UI_NOTIFICATION,
                object: nil,
                userInfo: nil,
                deliverImmediately: true
            )
        }
        exit(0)
    }

    try? String(getpid()).write(to: blePidFile, atomically: true, encoding: .utf8)

    if !isBackgroundDaemon {
        let daemonPidFile = STATE_DIR.appendingPathComponent("daemon.pid")
        let httpsAlive: Bool = {
            guard let s = try? String(contentsOf: daemonPidFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
                  let p = Int32(s) else { return false }
            return kill(p, 0) == 0
        }()
        if !httpsAlive {
            DispatchQueue.global(qos: .userInitiated).async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: SCRIPT_PATH)
                p.arguments = ["restart-receiver"]
                try? p.run()
                p.waitUntilExit()
            }
        }
    }

    let app = NSApplication.shared
    app.setActivationPolicy(isBackgroundDaemon ? .accessory : .regular)
    if let icns = Bundle.main.url(forResource: "AppIcon", withExtension: "icns"),
       let iconImg = NSImage(contentsOf: icns) {
        app.applicationIconImage = iconImg
    } else if let iconImg = NSImage(contentsOfFile: REPO_ROOT.appendingPathComponent("AirDrop P2P.app/Contents/Resources/AppIcon.icns").path) {
        app.applicationIconImage = iconImg
    } else if let iconImg = NSImage(contentsOfFile: FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".airdrop-p2p/AppIcon.icns").path) {
        app.applicationIconImage = iconImg
    }
    let daemon = BleAirDropDaemon()
    let bar = StatusBarController(openWindowOnLaunch: !isBackgroundDaemon)
    app.delegate = bar
    let awdlBridge = try? AwdlLoopbackBridge(listenPort: 8774, targetPort: 8773)
    withExtendedLifetime((daemon, bar, awdlBridge)) {
        app.run()
    }
}
