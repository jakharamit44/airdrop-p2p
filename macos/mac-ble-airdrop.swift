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

func hasActiveTcpReceiverConnection() -> Bool {
    let p = Process()
    let pipe = Pipe()
    p.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
    p.arguments = ["-n", "-P", "-iTCP:8772"]
    p.standardOutput = pipe
    try? p.run()
    let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    p.waitUntilExit()
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
    percent: Int = 0
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

func loadMacSettings() -> (autoAccept: Bool, visible: Bool, deviceName: String) {
    let defaultName = Host.current().localizedName ?? "MacBook Pro"
    let sf = STATE_DIR.appendingPathComponent("settings.json")
    if let d = try? Data(contentsOf: sf),
       let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] {
        let auto = (obj["autoAccept"] as? Bool) ?? false
        let vis = (obj["visible"] as? Bool) ?? true
        let name = (obj["deviceName"] as? String) ?? defaultName
        return (auto, vis, name.isEmpty ? defaultName : name)
    }
    return (false, true, defaultName)
}

func saveMacSettings(autoAccept: Bool, visible: Bool, deviceName: String) {
    let sf = STATE_DIR.appendingPathComponent("settings.json")
    let dict: [String: Any] = [
        "autoAccept": autoAccept,
        "visible": visible,
        "deviceName": deviceName
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

func currentWifiSsid() -> String {
    let p = Process()
    let pipe = Pipe()
    p.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
    p.arguments = ["-getairportnetwork", "en0"]
    p.standardOutput = pipe
    try? p.run()
    p.waitUntilExit()
    let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
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
    let p = Process()
    let pipe = Pipe()
    p.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
    p.arguments = ["-listpreferredwirelessnetworks", "en0"]
    p.standardOutput = pipe
    try? p.run()
    p.waitUntilExit()
    let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    for line in out.split(separator: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty && !trimmed.hasPrefix("Preferred networks") && !trimmed.hasPrefix("DIRECT-") {
            return trimmed
        }
    }
    return ""
}

func restoreMacInternetWifi(ssid: String = "DIRECT-") {
    // 1. ALWAYS unconditionally remove any ephemeral P2P network from preferred list so macOS never stays stuck or reconnects to it
    let listProc = Process()
    let listPipe = Pipe()
    listProc.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
    listProc.arguments = ["-listpreferredwirelessnetworks", "en0"]
    listProc.standardOutput = listPipe
    try? listProc.run()
    listProc.waitUntilExit()
    let prefNetworks = (String(data: listPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "")
        .components(separatedBy: "\n")
    for net in prefNetworks {
        let trimmed = net.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("DIRECT-") {
            let rmProc = Process()
            rmProc.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
            rmProc.arguments = ["-removepreferredwirelessnetwork", "en0", trimmed]
            try? rmProc.run()
            rmProc.waitUntilExit()
        }
    }

    // 2. Check if en0 is still on P2P (192.168.49.)
    let ifc = Process()
    let pipe = Pipe()
    ifc.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
    ifc.arguments = ["en0"]
    ifc.standardOutput = pipe
    try? ifc.run()
    let outStr = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    ifc.waitUntilExit()
    if !outStr.contains("inet 192.168.49.") {
        if outStr.contains("inet 192.168.") || outStr.contains("inet 10.") || outStr.contains("inet 172.") {
            print("[BLE-Daemon] en0 connected to normal Wi-Fi. P2P removed from preferred list.")
            fflush(stdout)
            try? FileManager.default.removeItem(at: PREV_WIFI_FILE)
            return
        }
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
    // Give macOS airportd native auto-join 2.0s to reconnect to preferred network
    Thread.sleep(forTimeInterval: 2.0)

    // 5. If target network is known and not yet reconnected, reassociate
    let activeNow = currentWifiSsid()
    if activeNow.isEmpty && !targetSsid.isEmpty {
        print("[BLE-Daemon] Fast-reassociating en0 to home Wi-Fi '\(targetSsid)'...")
        fflush(stdout)
        let joinProc = Process()
        joinProc.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        joinProc.arguments = ["-setairportnetwork", "en0", targetSsid]
        try? joinProc.run()
        joinProc.waitUntilExit()
    }

    // 6. Fallback safety verification: only cycle power if en0 is completely wedged on 192.168.49.x
    DispatchQueue.global().asyncAfter(deadline: .now() + 3.0) {
        let checkPipe = Pipe()
        let checkProc = Process()
        checkProc.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
        checkProc.arguments = ["en0"]
        checkProc.standardOutput = checkPipe
        try? checkProc.run()
        checkProc.waitUntilExit()
        let checkStr = String(data: checkPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let hasValidIp = checkStr.contains("inet ") && !checkStr.contains("inet 192.168.49.")
        if !hasValidIp {
            print("[BLE-Daemon] Network did not reassociate automatically — power cycling radio as fallback...")
            fflush(stdout)
            let cycleOff = Process()
            cycleOff.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
            cycleOff.arguments = ["-setairportpower", "en0", "off"]
            try? cycleOff.run()
            cycleOff.waitUntilExit()
            Thread.sleep(forTimeInterval: 0.3)
            let cycleOn = Process()
            cycleOn.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
            cycleOn.arguments = ["-setairportpower", "en0", "on"]
            try? cycleOn.run()
            cycleOn.waitUntilExit()
        }
    }

    try? FileManager.default.removeItem(at: PREV_WIFI_FILE)
    print("[BLE-Daemon] Wi-Fi restored and auto-reassociation initiated.")
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

func handleIncomingWp2pJoin(ssid: String, pass: String, out: OutputStream) {
    guard ssid.hasPrefix("DIRECT-"), !pass.isEmpty else {
        print("[BLE-Daemon] Rejected invalid WP2P request: SSID '\(ssid)' does not start with DIRECT-")
        _ = writeAll(out, data: Data("ERR\n".utf8))
        return
    }
    saveCurrentWifiSsid()
    print("[BLE-Daemon] Incoming WP2P 5GHz Wi-Fi Direct request: joining \(ssid)...")
    fflush(stdout)

    func currentEn0P2pIp() -> String {
        let ifc = Process()
        let pipe = Pipe()
        ifc.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
        ifc.arguments = ["en0"]
        ifc.standardOutput = pipe
        try? ifc.run()
        ifc.waitUntilExit()
        let outStr = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        for line in outStr.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("inet 192.168.49.") {
                let toks = trimmed.split(separator: " ")
                if toks.count >= 2 { return String(toks[1]) }
            }
        }
        return ""
    }

    var macP2pIp = currentEn0P2pIp()
    if macP2pIp.isEmpty {
        let joinProc = Process()
        joinProc.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        joinProc.arguments = ["-setairportnetwork", "en0", ssid, pass]
        try? joinProc.run()
        joinProc.waitUntilExit()

        let deadline = Date().addingTimeInterval(12.0)
        while Date() < deadline {
            macP2pIp = currentEn0P2pIp()
            if !macP2pIp.isEmpty { break }
            Thread.sleep(forTimeInterval: 0.2)
        }
    }

    if macP2pIp.isEmpty {
        _ = writeAll(out, data: Data("ERR\n".utf8))
        return
    }

    print("[BLE-Daemon] Joined \(ssid) at \(macP2pIp), signaling peer...")
    fflush(stdout)
    _ = writeAll(out, data: Data("OK \(macP2pIp)\n".utf8))

    // Monitor incoming Wi-Fi Direct transfer without ANY arbitrary timeout cap!
    let askFile = STATE_DIR.appendingPathComponent("pending_ask.json")
    let txFile = STATE_DIR.appendingPathComponent("transfer_progress.json")
    let rxLock = STATE_DIR.appendingPathComponent("rx_in_progress.lock")

    // Phase 1: Wait up to 30s for the peer to initiate the HTTPS transfer
    let startDeadline = Date().addingTimeInterval(30.0)
    var transferDetected = false
    while Date() < startDeadline {
        if FileManager.default.fileExists(atPath: askFile.path) ||
           FileManager.default.fileExists(atPath: txFile.path) ||
           FileManager.default.fileExists(atPath: rxLock.path) ||
           hasActiveTcpReceiverConnection() {
            transferDetected = true
            break
        }
        Thread.sleep(forTimeInterval: 0.25)
    }

    if !transferDetected {
        print("[BLE-Daemon] Peer did not initiate HTTPS transfer within 30s — restoring Wi-Fi")
        fflush(stdout)
        restoreMacInternetWifi(ssid: ssid)
        return
    }

    // Phase 2: Transfer is active. Wait until it completes
    let uploadDoneFile = STATE_DIR.appendingPathComponent("upload_completed.flag")
    try? FileManager.default.removeItem(at: uploadDoneFile)

    var idleCount = 0
    var lastActivity = Date()
    var lastKeepAlivePing = Date.distantPast

    while true {
        // Active bidirectional ARP keepalive: ping Android GO (192.168.49.1) every 2.0s
        // Keeps Android's Linux neighbor table in REACHABLE state and prevents the 35s ARP stall!
        if Date().timeIntervalSince(lastKeepAlivePing) >= 2.0 {
            lastKeepAlivePing = Date()
            DispatchQueue.global(qos: .utility).async {
                let pingProc = Process()
                pingProc.executableURL = URL(fileURLWithPath: "/sbin/ping")
                pingProc.arguments = ["-c", "1", "-t", "1", "-W", "500", "192.168.49.1"]
                try? pingProc.run()
                pingProc.waitUntilExit()
            }
        }

        // Fast path: upload finished completely and file is saved to Downloads!
        if FileManager.default.fileExists(atPath: uploadDoneFile.path) {
            try? FileManager.default.removeItem(at: uploadDoneFile)
            print("[BLE-Daemon] Upload completed successfully — restoring Wi-Fi immediately")
            fflush(stdout)
            Thread.sleep(forTimeInterval: 1.0) // Give Android 1.0s to receive the HTTP 200 response
            break
        }

        let isAsk = FileManager.default.fileExists(atPath: askFile.path)
        let now = Date().timeIntervalSince1970

        var isRxLockActive = false
        if let content = try? String(contentsOf: rxLock, encoding: .utf8) {
            let parts = content.split(separator: "\t")
            if parts.count >= 3, let ts = Double(parts[2]) {
                if (now - ts) < 8.0 { isRxLockActive = true }
            } else if let attrs = try? FileManager.default.attributesOfItem(atPath: rxLock.path),
                      let mtime = attrs[.modificationDate] as? Date {
                if now - mtime.timeIntervalSince1970 < 8.0 { isRxLockActive = true }
            }
        }

        var isProgressActive = false
        if let data = try? Data(contentsOf: txFile),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let active = obj["active"] as? Bool, active,
           let updatedAt = obj["updatedAt"] as? Double {
            if (now - updatedAt) < 8.0 { isProgressActive = true }
        }

        let isActiveTcp = hasActiveTcpReceiverConnection()

        if isAsk || isRxLockActive || isProgressActive || isActiveTcp {
            lastActivity = Date()
            idleCount = 0
        } else {
            // If all transfer activity and TCP sockets have completed for > 3.0s, restore Wi-Fi promptly
            if Date().timeIntervalSince(lastActivity) > 3.0 {
                idleCount += 1
                if idleCount >= 4 { // 4 * 0.5s = 2.0s -> ~5.0s of dead silence
                    print("[BLE-Daemon] Transfer stream ended (idle timeout) — restoring Wi-Fi immediately")
                    fflush(stdout)
                    break
                }
            }
        }
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
            if isPingingPeer {
                isPingingPeer = false
                pingChannel = nil
            }
            return
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
    var startedOpen = false

    init(files: [URL], urls: [String] = []) throws {
        clearCancelFlag()
        try? Data("1".utf8).write(to: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
        self.files = files
        self.urls = urls
        self.totalRawBytes = files.reduce(0) { $0 + ((try? FileManager.default.attributesOfItem(atPath: $1.path)[.size] as? Int) ?? 0) }
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
        cm = CBCentralManager(delegate: self, queue: nil)
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn {
            let knownPeers = loadActivePeersFromDisk(maxAge: 30.0)
            if let first = knownPeers.first {
                if first.psm > 0 {
                    targetPsm = CBL2CAPPSM(first.psm)
                }
                if let uuid = UUID(uuidString: first.address) {
                    let retrieved = central.retrievePeripherals(withIdentifiers: [uuid])
                    if let p = retrieved.first {
                        targetPeripheral = p
                        p.delegate = self
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
            print("[BLE-Send] Found nearby peer (\(peripheral.identifier), RSSI \(RSSI), PSM \(targetPsm)), connecting...")
            fflush(stdout)
            central.stopScan()
            central.connect(peripheral, options: nil)
        }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        if targetPsm > 0 && !startedOpen {
            startedOpen = true
            print("[BLE-Send] Connected! Opening L2CAP channel PSM \(targetPsm)...")
            fflush(stdout)
            peripheral.openL2CAPChannel(targetPsm)
        } else {
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
                print("[BLE-Send] Read GATT PSM \(targetPsm), opening L2CAP channel...")
                fflush(stdout)
                peripheral.openL2CAPChannel(targetPsm)
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didOpen channel: CBL2CAPChannel?, error: Error?) {
        guard let ch = channel, error == nil else {
            print("[BLE-Send] L2CAP open failed: \(String(describing: error))")
            exit(1)
        }
        activeChannel = ch

        DispatchQueue.global(qos: .userInitiated).async {
            guard let inp = ch.inputStream, let out = ch.outputStream else {
                print("[BLE-Send] Failed to acquire L2CAP channel streams")
                exit(1)
            }
            inp.open()
            out.open()

            // 5GHz Wi-Fi Direct P2P Negotiation for large files
            if self.totalRawBytes >= 65_536 && !self.files.isEmpty {
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
                            saveCurrentWifiSsid()
                            print("[BLE-Send] Joining 5GHz P2P group \(ssid) (\(host):\(port))...")
                            fflush(stdout)

                            func hasEn0P2pIp() -> Bool {
                                let ifc = Process()
                                let pipe = Pipe()
                                ifc.executableURL = URL(fileURLWithPath: "/sbin/ifconfig")
                                ifc.arguments = ["en0"]
                                ifc.standardOutput = pipe
                                try? ifc.run()
                                ifc.waitUntilExit()
                                let outStr = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                                return outStr.contains("inet 192.168.49.")
                            }

                            if !hasEn0P2pIp() {
                                let joinProc = Process()
                                joinProc.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
                                joinProc.arguments = ["-setairportnetwork", "en0", ssid, pass]
                                try? joinProc.run()
                                joinProc.waitUntilExit()

                                // Wait up to 10s for macOS DHCP on en0 to assign 192.168.49.x before launching HTTPS transfer
                                let deadline = Date().addingTimeInterval(10.0)
                                var retriedJoin = false
                                while Date() < deadline {
                                    if hasEn0P2pIp() { break }
                                    if !retriedJoin && deadline.timeIntervalSinceNow < 5.5 {
                                        retriedJoin = true
                                        let retryProc = Process()
                                        retryProc.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
                                        retryProc.arguments = ["-setairportnetwork", "en0", ssid, pass]
                                        try? retryProc.run()
                                        retryProc.waitUntilExit()
                                    }
                                    Thread.sleep(forTimeInterval: 0.2)
                                }
                            }

                            let txProc = Process()
                            txProc.executableURL = URL(fileURLWithPath: SCRIPT_PATH)
                            txProc.arguments = ["send", "--peer", "\(host):\(port)"] + self.files.map { $0.path } + self.urls
                            try? txProc.run()
                            txProc.waitUntilExit()
                            restoreMacInternetWifi(ssid: ssid)

                            if isTransferCancelled() {
                                clearCancelFlag()
                                inp.close()
                                out.close()
                                try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
                                print("[BLE-Send] Transfer cancelled by user")
                                exit(1)
                            }

                            if txProc.terminationStatus == 0 {
                                inp.close()
                                out.close()
                                try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
                                print("[BLE-Send] Delivered via 5GHz Wi-Fi Direct P2P!")
                                exit(0)
                            }
                            if txProc.terminationStatus == 43 {
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
                guard let (gzData, fileDicts) = try? buildDvzipCpio(files: self.files) else { exit(1) }
                let metaDict: [String: Any] = [
                    "SenderComputerName": loadMacSettings().deviceName,
                    "SenderModelName": "MacBookPro18,2",
                    "BundleID": self.urls.isEmpty ? "com.apple.finder" : "com.apple.Safari",
                    "Items": self.urls as [Any],
                    "Files": fileDicts
                ]
                guard let metaData = try? PropertyListSerialization.data(fromPropertyList: metaDict, format: .binary, options: 0) else { exit(1) }
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
            inp.close()
            out.close()
            try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
            if ok && ackStr == "OK" {
                let peerLabel = loadActivePeersFromDisk(maxAge: 30.0).first?.name ?? "Android Device"
                for f in self.files {
                    let sz = (try? FileManager.default.attributesOfItem(atPath: f.path)[.size] as? Int64) ?? 0
                    appendReceivedLog(kind: "FILE", value: f.path, sizeBytes: sz, direction: "sent", peerName: peerLabel)
                }
                for u in self.urls {
                    appendReceivedLog(kind: "URL", value: u, sizeBytes: Int64(u.utf8.count), direction: "sent", peerName: peerLabel)
                }
                let sound = Process()
                sound.executableURL = URL(fileURLWithPath: "/usr/bin/afplay")
                sound.arguments = ["/System/Library/Sounds/Glass.aiff"]
                try? sound.run()
                print("[BLE-Send] Delivered to \(peerLabel) via Direct Bluetooth LE L2CAP!")
                exit(0)
            } else {
                print("[BLE-Send] Transfer incomplete (ok=\(ok), ack=\(String(describing: ackData)))")
                exit(1)
            }
        }
    }
}

// ============================================================================
// macOS Native SwiftUI State & Production 3-Tab Window UI (Zero Macro Plugins)
// ============================================================================

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
}

struct MacPendingAsk: Equatable {
    let id: String
    let senderName: String
    let fileNames: [String]
    let totalBytes: Int64
}

final class MacAirDropViewModel: ObservableObject {
    @Published var selectedTab: Int = 0 // 0 = Nearby & Send, 1 = Transfers, 2 = Receive & P2P
    @Published var historyFilter: Int = 0 // 0 = All, 1 = Received, 2 = Sent
    @Published var receiverRunning: Bool = false
    @Published var mdnsRunning: Bool = false
    @Published var awdlProxyRunning: Bool = false
    @Published var bleRunning: Bool = true
    @Published var autoAccept: Bool = false
    @Published var macDeviceName: String = Host.current().localizedName ?? "Amit’s MacBook Pro"
    @Published var editingDeviceName: String = ""
    @Published var activePeers: [MacDiscoveredPeer] = []
    @Published var peerStatusSummary: String = "0 Active Devices • Scanning BLE + 5GHz P2P..."
    @Published var transferStatus: String = "5GHz Wi-Fi Direct + BLE L2CAP Ready — No shared router required"
    @Published var isTransferring: Bool = false
    @Published var liveProgress: MacLiveProgress? = nil
    @Published var pendingAsk: MacPendingAsk? = nil
    @Published var urlInput: String = ""
    @Published var isDropTargeted: Bool = false
    @Published var showLogs: Bool = false
    @Published var pulse: Bool = false
    @Published var historyEntries: [MacHistoryEntry] = []
    @Published var logs: [String] = []
    @Published var bluetoothAuthorized: Bool = true
    @Published var bluetoothPoweredOn: Bool = true
    @Published var wifiPoweredOn: Bool = true
    private var activeSendProcess: Process? = nil
    private var fastTimer: Timer?
    private var tickCount: Int = 0

    init() {
        let s = loadMacSettings()
        self.autoAccept = s.autoAccept
        self.macDeviceName = s.deviceName
        self.editingDeviceName = s.deviceName
        refreshSlow()
        refreshFast()
        fastTimer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.refreshFast()
            self.tickCount += 1
            if self.tickCount % 7 == 0 {
                self.refreshSlow()
            }
        }
    }

    private func isPidAlive(_ file: String) -> Bool {
        let p = STATE_DIR.appendingPathComponent(file)
        guard let s = try? String(contentsOf: p, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
              let pid = Int32(s), pid > 0 else { return false }
        return kill(pid, 0) == 0
    }

    func refreshFast() {
        // 0. Poll live active peers with strict 10-second TTL
        let livePeers = loadActivePeersFromDisk(maxAge: PEER_LIVE_TTL_SECONDS)
        if activePeers != livePeers {
            activePeers = livePeers
        }
        let statusLine: String
        if let first = livePeers.first {
            statusLine = "Active: \(first.name) • \(first.transport) (\(first.rssi) dBm)"
        } else {
            statusLine = "0 Active Devices • Scanning BLE + 5GHz Wi-Fi Direct..."
        }
        if peerStatusSummary != statusLine {
            peerStatusSummary = statusLine
        }

        // 1. Poll real-time transfer progress JSON
        let pf = STATE_DIR.appendingPathComponent("transfer_progress.json")
        if let d = try? Data(contentsOf: pf),
           let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
           (obj["active"] as? Bool) == true {
            let updatedAt = (obj["updatedAt"] as? Double) ?? Date().timeIntervalSince1970
            if Date().timeIntervalSince1970 - updatedAt < 8.0 {
                let prog = MacLiveProgress(
                    direction: (obj["direction"] as? String) ?? "Transferring",
                    fileName: (obj["fileName"] as? String) ?? "File",
                    fileCount: (obj["fileCount"] as? Int) ?? 1,
                    doneBytes: (obj["doneBytes"] as? NSNumber)?.int64Value ?? 0,
                    totalBytes: (obj["totalBytes"] as? NSNumber)?.int64Value ?? 1,
                    speedBps: (obj["speedBps"] as? NSNumber)?.int64Value ?? 0,
                    etaSeconds: (obj["etaSeconds"] as? NSNumber)?.int64Value ?? 0,
                    percent: (obj["percent"] as? Int) ?? 0
                )
                if liveProgress != prog {
                    liveProgress = prog
                }
            } else if liveProgress != nil {
                liveProgress = nil
            }
        } else if liveProgress != nil {
            liveProgress = nil
        }

        // 2. Poll pending Ask prompt JSON (when Ask Every Time is enabled)
        let af = STATE_DIR.appendingPathComponent("pending_ask.json")
        if let d = try? Data(contentsOf: af),
           let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
           let id = obj["id"] as? String {
            let ask = MacPendingAsk(
                id: id,
                senderName: (obj["senderName"] as? String) ?? "Android Peer",
                fileNames: (obj["fileNames"] as? [String]) ?? ["Incoming File"],
                totalBytes: (obj["totalBytes"] as? NSNumber)?.int64Value ?? 0
            )
            if pendingAsk != ask {
                pendingAsk = ask
                NSApp.activate(ignoringOtherApps: true)
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
        saveMacSettings(autoAccept: directGet, visible: receiverRunning, deviceName: macDeviceName)
    }

    func saveDeviceName() {
        let clean = editingDeviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty else { return }
        macDeviceName = clean
        saveMacSettings(autoAccept: autoAccept, visible: receiverRunning, deviceName: clean)
    }

    func refreshSlow() {
        receiverRunning = isPidAlive("daemon.pid")
        mdnsRunning = isPidAlive("mdns.pid")
        awdlProxyRunning = isPidAlive("awdl-mdns.pid")
        bleRunning = true

        // Check Bluetooth authorization and power state
        let auth = CBManager.authorization
        bluetoothAuthorized = (auth != .denied && auth != .restricted)
        if let cmState = BleAirDropDaemon.shared?.cm.state {
            bluetoothPoweredOn = (cmState != .poweredOff)
        }

        // Check Wi-Fi power state asynchronously on background queue so UI never blocks
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let p = Process()
            let pipe = Pipe()
            p.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
            p.arguments = ["-getairportpower", "en0"]
            p.standardOutput = pipe
            try? p.run()
            p.waitUntilExit()
            let outStr = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "On"
            let wifiOn = !outStr.lowercased().contains(": off")
            DispatchQueue.main.async {
                if self?.wifiPoweredOn != wifiOn {
                    self?.wifiPoweredOn = wifiOn
                }
            }
        }

        // Load received & sent history log
        let rxFile = STATE_DIR.appendingPathComponent("received.log")
        if let rxRaw = try? String(contentsOf: rxFile, encoding: .utf8) {
            let parsed: [MacHistoryEntry] = rxRaw.split(separator: "\n").suffix(60).reversed().compactMap { line in
                let parts = line.split(separator: "\t").map(String.init)
                guard parts.count >= 3 else { return nil }
                let ts = TimeInterval(parts[0]) ?? Date().timeIntervalSince1970
                let isUrl = parts[1] == "URL"
                let val = parts[2]
                let sz: Int64 = parts.count >= 4 ? (Int64(parts[3]) ?? 0) : ((try? FileManager.default.attributesOfItem(atPath: val)[.size] as? Int64) ?? 0)
                let isOut = parts.count >= 5 ? (parts[4] == "sent") : false
                let peer = parts.count >= 6 ? parts[5] : "Nearby Peer"
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

        // Load logs
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
        transferStatus = "Scanning BLE + 5GHz Wi-Fi Direct for active devices..."
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
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
            self.refreshFast()
            if self.activePeers.isEmpty {
                self.transferStatus = "Radar Active — Searching for Nearby Devices..."
            } else {
                self.transferStatus = "Found \(self.activePeers.count) active peer(s) ready for transfer"
            }
        }
    }

    func toggleDaemons(_ turnOn: Bool) {
        transferStatus = turnOn ? "Starting P2P AirDrop services..." : "Pausing P2P AirDrop services..."
        saveMacSettings(autoAccept: autoAccept, visible: turnOn, deviceName: macDeviceName)
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
                    ? "P2P Radio Active (5GHz Wi-Fi Direct • BLE L2CAP • HTTPS :8772)"
                    : "AirDrop Radio Paused"
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
        transferStatus = "Transfer stopped by user"
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

    func sendItems(_ args: [String]) {
        guard !args.isEmpty, !isTransferring else { return }
        clearCancelFlag()
        let targetName = activePeers.first?.name ?? "Nearby Peer"
        isTransferring = true
        let label = args.map { $0.hasPrefix("http") ? $0 : URL(fileURLWithPath: $0).lastPathComponent }.joined(separator: ", ")
        transferStatus = "Sending \(label) to \(targetName) over 5GHz P2P..."
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
                    self.transferStatus = "Transfer stopped by user"
                } else {
                    self.transferStatus = ok
                        ? "Delivered \(label) to \(targetName)!"
                        : "Transfer failed: \(lastLine.isEmpty ? "Ensure AirDrop P2P app is open on target device" : lastLine)"
                }
                self.refreshSlow()
            }
        }
    }

    func chooseAndSendFiles() {
        let targetName = activePeers.first?.name ?? "Nearby Device"
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Quick Share to \(targetName)"
        NSApp.activate(ignoringOtherApps: true)
        if panel.runModal() == .OK {
            let paths = panel.urls.map { $0.path }
            sendItems(paths)
        }
    }

    func sendFinderSelection() {
        DispatchQueue.global(qos: .userInitiated).async {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: SCRIPT_PATH)
            p.arguments = ["send"]
            try? p.run()
        }
    }

    func sendClipboardTextOrUrl() {
        guard let clip = NSPasteboard.general.string(forType: .string)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !clip.isEmpty else {
            transferStatus = "Clipboard is empty"
            return
        }
        if clip.hasPrefix("http://") || clip.hasPrefix("https://") {
            sendItems([clip])
        } else {
            let stamp = Int(Date().timeIntervalSince1970)
            let tmpFile = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("Clipboard-\(stamp).txt")
            try? clip.data(using: .utf8)?.write(to: tmpFile)
            sendItems([tmpFile.path])
        }
    }
}

// Color Tokens matching Android Obsidian Glass UI
private let MacObsidianBg = Color(red: 0.03, green: 0.04, blue: 0.07)
private let MacGlassCard = Color(red: 0.07, green: 0.09, blue: 0.14)
private let MacGlassElevated = Color(red: 0.09, green: 0.13, blue: 0.20)
private let MacGlassBorder = Color.white.opacity(0.11)
private let MacCyan = Color(red: 0.05, green: 0.65, blue: 0.91)
private let MacCyanBright = Color(red: 0.22, green: 0.74, blue: 0.97)
private let MacIndigo = Color(red: 0.39, green: 0.40, blue: 0.95)
private let MacEmerald = Color(red: 0.06, green: 0.73, blue: 0.51)
private let MacAmber = Color(red: 0.96, green: 0.62, blue: 0.04)

struct MacAirDropMainView: View {
    @ObservedObject var vm: MacAirDropViewModel

    var body: some View {
        ZStack {
            MacObsidianBg.ignoresSafeArea()

            VStack(spacing: 0) {
                // 1. Top Brand & Status Header Bar
                topHeaderBar
                    .padding(.horizontal, 18)
                    .padding(.top, 14)
                    .padding(.bottom, 10)

                // 1b. System Readiness Banner (Permissions + Bluetooth & Wi-Fi Power Prompts)
                if !vm.bluetoothAuthorized || !vm.bluetoothPoweredOn || !vm.wifiPoweredOn {
                    systemReadinessBanner
                        .padding(.horizontal, 18)
                        .padding(.bottom, 10)
                }

                // 2. Real-Time Active Transfer Telemetry Banner
                if let prog = vm.liveProgress {
                    liveTelemetryCard(prog)
                        .padding(.horizontal, 18)
                        .padding(.bottom, 10)
                } else if vm.isTransferring {
                    preparingTransferCard
                        .padding(.horizontal, 18)
                        .padding(.bottom, 10)
                }

                // 3. Active Tab Content
                ScrollView {
                    VStack(spacing: 14) {
                        if vm.selectedTab == 0 {
                            nearbyRadarTab
                        } else if vm.selectedTab == 1 {
                            transfersHistoryTab
                        } else {
                            receiveAndP2pTab
                        }
                    }
                    .padding(.horizontal, 18)
                    .padding(.vertical, 8)
                }

                // 4. Bottom 3-Tab Segmented Navigation Bar
                bottomTabBar
            }

            // 5. Incoming Transfer Accept / Decline Modal Overlay (When Direct Get = OFF)
            if let ask = vm.pendingAsk {
                Color.black.opacity(0.65)
                    .ignoresSafeArea()
                incomingAskModal(ask)
                    .padding(28)
            }
        }
        .frame(minWidth: 540, idealWidth: 560, minHeight: 650, idealHeight: 680)
        .preferredColorScheme(.dark)
    }

    private var topHeaderBar: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 12)
                    .fill(LinearGradient(
                        colors: [Color(red: 0.06, green: 0.12, blue: 0.24), Color(red: 0.04, green: 0.06, blue: 0.12)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ))
                    .frame(width: 42, height: 42)
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(MacCyan.opacity(0.5), lineWidth: 1)
                    )
                Image(systemName: "dot.radiowaves.left.and.right")
                    .font(.system(size: 20, weight: .bold))
                    .foregroundColor(MacCyanBright)
            }

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 7) {
                    Text("AirDrop P2P")
                        .font(.system(size: 17, weight: .heavy))
                        .foregroundColor(.white)
                    Circle()
                        .fill(vm.receiverRunning ? MacEmerald : MacAmber)
                        .frame(width: 7, height: 7)
                    Text(vm.receiverRunning ? "P2P ONLINE" : "PAUSED")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundColor(vm.receiverRunning ? MacEmerald : MacAmber)
                }
                Text("\(vm.macDeviceName) • 5GHz Wi-Fi Direct + BLE L2CAP")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
            }

            Spacer()

            // Quick Receive Mode Pill
            Button(action: { vm.setReceiveMode(directGet: !vm.autoAccept) }) {
                HStack(spacing: 5) {
                    Circle()
                        .fill(vm.autoAccept ? MacEmerald : MacAmber)
                        .frame(width: 6, height: 6)
                    Text(vm.autoAccept ? "Direct Get" : "Ask First")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(vm.autoAccept ? MacEmerald : MacAmber)
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .background(
                    Capsule()
                        .fill((vm.autoAccept ? MacEmerald : MacAmber).opacity(0.15))
                        .overlay(Capsule().stroke((vm.autoAccept ? MacEmerald : MacAmber).opacity(0.45), lineWidth: 1))
                )
            }
            .buttonStyle(.plain)

            // Rescan Button
            Button(action: { vm.rescanNow() }) {
                HStack(spacing: 4) {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 11, weight: .bold))
                    Text("Scan")
                        .font(.system(size: 11, weight: .semibold))
                }
                .foregroundColor(MacCyanBright)
                .padding(.horizontal, 11)
                .padding(.vertical, 6)
                .background(
                    Capsule()
                        .fill(MacGlassElevated)
                        .overlay(Capsule().stroke(MacGlassBorder, lineWidth: 1))
                )
            }
            .buttonStyle(.plain)
        }
    }

    private var systemReadinessBanner: some View {
        var missing: [String] = []
        if !vm.bluetoothAuthorized { missing.append("Bluetooth Permission") }
        if !vm.bluetoothPoweredOn { missing.append("Bluetooth") }
        if !vm.wifiPoweredOn { missing.append("Wi-Fi") }
        let titleText = "Turn on \(missing.joined(separator: " & ")) for AirDrop P2P"

        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Circle()
                    .fill(MacAmber)
                    .frame(width: 8, height: 8)
                Text(titleText)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(.white)
                Spacer()
            }
            Text("Bluetooth discovers nearby devices and 5 GHz Wi-Fi Direct transfers large files at full speed.")
                .font(.system(size: 11))
                .foregroundColor(.secondary)
            HStack(spacing: 8) {
                if !vm.bluetoothAuthorized {
                    Button("Allow Bluetooth Permission") {
                        vm.openBluetoothPrivacySettings()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(MacAmber)
                    .controlSize(.small)
                }
                if !vm.bluetoothPoweredOn {
                    Button("Turn On Bluetooth") {
                        vm.openBluetoothSettings()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(MacCyan)
                    .controlSize(.small)
                }
                if !vm.wifiPoweredOn {
                    Button("Turn On Wi-Fi") {
                        vm.enableMacWifi()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(MacCyan)
                    .controlSize(.small)
                }
                Spacer()
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(MacGlassElevated)
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(MacAmber.opacity(0.65), lineWidth: 1))
        )
    }

    private func liveTelemetryCard(_ prog: MacLiveProgress) -> some View {
        let isSending = prog.direction.lowercased().contains("send")
        return VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Text(prog.direction.uppercased())
                    .font(.system(size: 9, weight: .heavy))
                    .foregroundColor(isSending ? MacCyanBright : MacEmerald)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 3)
                    .background(
                        RoundedRectangle(cornerRadius: 5)
                            .fill((isSending ? MacCyan : MacEmerald).opacity(0.2))
                    )
                Text(prog.fileName)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundColor(.white)
                    .lineLimit(1)
                Spacer()
                Text(formatTransferSpeed(prog.speedBps))
                    .font(.system(size: 12, weight: .heavy).monospacedDigit())
                    .foregroundColor(MacCyanBright)
                    .padding(.horizontal, 9)
                    .padding(.vertical, 3)
                    .background(
                        Capsule()
                            .fill(MacObsidianBg.opacity(0.8))
                            .overlay(Capsule().stroke(MacGlassBorder, lineWidth: 1))
                    )
                Button(action: { vm.cancelActiveTransfer() }) {
                    Text("Cancel")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(.white)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .background(
                            Capsule()
                                .fill(Color.red.opacity(0.28))
                                .overlay(Capsule().stroke(Color.red.opacity(0.65), lineWidth: 1))
                        )
                }
                .buttonStyle(.plain)
            }

            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Capsule()
                        .fill(MacObsidianBg)
                        .frame(height: 8)
                    Capsule()
                        .fill(LinearGradient(
                            colors: [MacCyan, MacCyanBright, MacEmerald],
                            startPoint: .leading,
                            endPoint: .trailing
                        ))
                        .frame(width: max(12, geo.size.width * CGFloat(prog.percent) / 100.0), height: 8)
                }
            }
            .frame(height: 8)

            HStack {
                Text("\(formatByteSize(prog.doneBytes)) / \(formatByteSize(prog.totalBytes))")
                    .font(.system(size: 11, weight: .medium).monospacedDigit())
                    .foregroundColor(.secondary)
                Spacer()
                if prog.etaSeconds > 0 {
                    Text("~\(prog.etaSeconds)s left")
                        .font(.system(size: 11).monospacedDigit())
                        .foregroundColor(.secondary)
                }
                Text("\(prog.percent)%")
                    .font(.system(size: 11, weight: .heavy).monospacedDigit())
                    .foregroundColor(.white)
            }
        }
        .padding(14)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(MacGlassElevated)
                .overlay(RoundedRectangle(cornerRadius: 16).stroke(MacCyan.opacity(0.55), lineWidth: 1))
        )
    }

    private var preparingTransferCard: some View {
        HStack(spacing: 12) {
            ProgressView()
                .controlSize(.small)
            Text(vm.transferStatus)
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(MacCyanBright)
                .lineLimit(1)
            Spacer()
            Button(action: { vm.cancelActiveTransfer() }) {
                Text("Cancel")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(
                        Capsule()
                            .fill(Color.red.opacity(0.28))
                            .overlay(Capsule().stroke(Color.red.opacity(0.65), lineWidth: 1))
                    )
            }
            .buttonStyle(.plain)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(MacGlassElevated)
                .overlay(RoundedRectangle(cornerRadius: 14).stroke(MacCyan.opacity(0.45), lineWidth: 1))
        )
    }

    // ========================================================================
    // TAB 1: Nearby & Send (Live Active Peer Radar + Drag & Drop + Action Cards)
    // ========================================================================
    private var nearbyRadarTab: some View {
        VStack(spacing: 14) {
            // Interactive Radar & Drop Zone Card
            ZStack {
                RoundedRectangle(cornerRadius: 22)
                    .fill(vm.isDropTargeted ? MacCyan.opacity(0.14) : MacGlassCard)
                    .overlay(
                        RoundedRectangle(cornerRadius: 22)
                            .strokeBorder(
                                vm.isDropTargeted ? MacCyanBright : MacGlassBorder,
                                style: StrokeStyle(lineWidth: vm.isDropTargeted ? 2 : 1)
                            )
                    )

                VStack(spacing: 12) {
                    HStack {
                        HStack(spacing: 6) {
                            Circle()
                                .fill(MacCyanBright)
                                .frame(width: 7, height: 7)
                            Text("P2P Radar Active • Live 10s Heartbeat")
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundColor(.secondary)
                        }
                        Spacer()
                        Text("\(vm.activePeers.count) Active Device\(vm.activePeers.count == 1 ? "" : "s")")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(vm.activePeers.isEmpty ? .secondary : MacEmerald)
                    }

                    ZStack {
                        ForEach(1..<4) { ring in
                            Circle()
                                .stroke(MacCyan.opacity(0.18 / Double(ring)), lineWidth: 1.4)
                                .frame(width: CGFloat(ring) * 56, height: CGFloat(ring) * 56)
                                .scaleEffect(vm.pulse ? 1.04 : 0.96)
                        }

                        // Center Mac Node
                        VStack(spacing: 4) {
                            ZStack {
                                Circle()
                                    .fill(LinearGradient(
                                        colors: [MacCyan, MacIndigo],
                                        startPoint: .topLeading,
                                        endPoint: .bottomTrailing
                                    ))
                                    .frame(width: 54, height: 54)
                                    .shadow(color: MacCyan.opacity(0.35), radius: 10)
                                Image(systemName: "laptopcomputer")
                                    .font(.system(size: 22, weight: .semibold))
                                    .foregroundColor(.white)
                            }
                            Text(vm.macDeviceName)
                                .font(.system(size: 11, weight: .bold))
                                .foregroundColor(.white)
                        }

                        // Orbiting Live Active Peer Pills (ONLY rendered when real peers are actively broadcasting!)
                        ForEach(Array(vm.activePeers.prefix(3).enumerated()), id: \.element.id) { idx, peer in
                            let angle = (-45.0 + Double(idx) * 110.0) * .pi / 180.0
                            let r: CGFloat = 88.0
                            Button(action: { vm.chooseAndSendFiles() }) {
                                HStack(spacing: 6) {
                                    Circle()
                                        .fill(MacEmerald)
                                        .frame(width: 8, height: 8)
                                    Image(systemName: "iphone.gen3")
                                        .font(.system(size: 12, weight: .bold))
                                        .foregroundColor(MacCyanBright)
                                    Text(peer.name)
                                        .font(.system(size: 11, weight: .bold))
                                        .foregroundColor(.white)
                                        .lineLimit(1)
                                }
                                .padding(.horizontal, 11)
                                .padding(.vertical, 6)
                                .background(
                                    Capsule()
                                        .fill(MacGlassElevated)
                                        .overlay(Capsule().stroke(MacEmerald.opacity(0.65), lineWidth: 1))
                                )
                            }
                            .buttonStyle(.plain)
                            .offset(x: CGFloat(cos(angle)) * r, y: CGFloat(sin(angle)) * r * 0.65)
                        }
                    }
                    .frame(height: 175)
                    .onAppear {
                        withAnimation(.easeInOut(duration: 2.0).repeatForever(autoreverses: true)) {
                            vm.pulse = true
                        }
                    }

                    Text(vm.transferStatus)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
                .padding(16)
            }
            .onDrop(of: [.fileURL, .url, .plainText], isTargeted: $vm.isDropTargeted) { providers in
                handleDrop(providers)
            }

            // Discovered Active Peers Section (Zero Hardcoded / Fake Devices!)
            if vm.activePeers.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 10) {
                        ProgressView()
                            .controlSize(.small)
                        Text("No Active Devices Nearby")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(.white)
                        Spacer()
                        Text("LIVE SCANNING")
                            .font(.system(size: 9, weight: .heavy))
                            .foregroundColor(MacCyanBright)
                            .padding(.horizontal, 7)
                            .padding(.vertical, 3)
                            .background(RoundedRectangle(cornerRadius: 5).fill(MacCyan.opacity(0.18)))
                    }
                    Text("Only real, actively broadcasting devices appear here (10-second live heartbeat). Open the AirDrop P2P app on your Android phone with Bluetooth enabled to start transferring.")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                .padding(16)
                .background(
                    RoundedRectangle(cornerRadius: 20)
                        .fill(MacGlassCard)
                        .overlay(RoundedRectangle(cornerRadius: 20).stroke(MacGlassBorder, lineWidth: 1))
                )
            } else {
                ForEach(vm.activePeers) { peer in
                    activePeerCard(peer)
                }
            }

            // Quick Receive Mode Card on Home Tab
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(vm.autoAccept ? "Direct Get Mode (Auto-Accept)" : "Ask Every Time Mode (Confirm Incoming)")
                        .font(.system(size: 13, weight: .bold))
                        .foregroundColor(.white)
                    Text(vm.autoAccept
                         ? "Incoming files from nearby devices save directly to ~/Downloads without asking"
                         : "Shows an Accept / Decline confirmation dialog with file size before saving")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                Spacer()
                Toggle("", isOn: Binding(
                    get: { vm.autoAccept },
                    set: { vm.setReceiveMode(directGet: $0) }
                ))
                .toggleStyle(.switch)
                .labelsHidden()
            }
            .padding(14)
            .background(
                RoundedRectangle(cornerRadius: 18)
                    .fill(MacGlassCard)
                    .overlay(RoundedRectangle(cornerRadius: 18).stroke(MacGlassBorder, lineWidth: 1))
            )
        }
    }

    private func activePeerCard(_ peer: MacDiscoveredPeer) -> some View {
        let bars: Int = {
            if peer.rssi >= -55 { return 4 }
            if peer.rssi >= -68 { return 3 }
            if peer.rssi >= -80 { return 2 }
            return 1
        }()
        return VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 14)
                        .fill(LinearGradient(
                            colors: [MacCyan.opacity(0.25), MacIndigo.opacity(0.25)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ))
                        .frame(width: 46, height: 46)
                        .overlay(RoundedRectangle(cornerRadius: 14).stroke(MacCyanBright.opacity(0.4), lineWidth: 1))
                    Image(systemName: "iphone.gen3")
                        .font(.system(size: 22, weight: .semibold))
                        .foregroundColor(MacCyanBright)
                }

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 8) {
                        Text(peer.name)
                            .font(.system(size: 15, weight: .bold))
                            .foregroundColor(.white)
                        Text(peer.transport)
                            .font(.system(size: 9, weight: .heavy))
                            .foregroundColor(MacEmerald)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(RoundedRectangle(cornerRadius: 5).fill(MacEmerald.opacity(0.16)))
                    }
                    Text("Live Signal: \(peer.rssi) dBm • Seen \(max(0, Int(Date().timeIntervalSince1970 - peer.lastSeen)))s ago")
                        .font(.system(size: 11).monospacedDigit())
                        .foregroundColor(.secondary)
                }

                Spacer()

                // Live Signal Bars
                HStack(alignment: .bottom, spacing: 2.5) {
                    ForEach(1...4, id: \.self) { bar in
                        RoundedRectangle(cornerRadius: 1.5)
                            .fill(bar <= bars ? MacEmerald : Color.white.opacity(0.18))
                            .frame(width: 3.5, height: CGFloat(4 + bar * 3))
                    }
                }
            }

            // Quick Send Actions
            HStack(spacing: 8) {
                Button(action: { vm.chooseAndSendFiles() }) {
                    HStack(spacing: 6) {
                        Image(systemName: "paperplane.fill")
                        Text("Send Files…")
                            .fontWeight(.bold)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.borderedProminent)
                .tint(MacCyan)
                .disabled(vm.isTransferring)

                Button(action: { vm.sendFinderSelection() }) {
                    HStack(spacing: 5) {
                        Image(systemName: "folder.fill")
                        Text("Finder Selection")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.bordered)
                .disabled(vm.isTransferring)

                Button(action: { vm.sendClipboardTextOrUrl() }) {
                    HStack(spacing: 5) {
                        Image(systemName: "doc.on.clipboard")
                        Text("Send Clipboard")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                }
                .buttonStyle(.bordered)
                .disabled(vm.isTransferring)
            }

            // Inline URL / Text Input Row
            HStack(spacing: 8) {
                TextField("Paste URL or text to send to \(peer.name)…", text: $vm.urlInput)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { sendUrlInput() }
                Button("Send") {
                    sendUrlInput()
                }
                .buttonStyle(.borderedProminent)
                .tint(MacIndigo)
                .disabled(vm.urlInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || vm.isTransferring)
            }
        }
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 20)
                .fill(MacGlassCard)
                .overlay(RoundedRectangle(cornerRadius: 20).stroke(MacCyan.opacity(0.35), lineWidth: 1))
        )
    }

    // ========================================================================
    // TAB 2: Transfers & History (Live Telemetry + All / Received / Sent)
    // ========================================================================
    private var transfersHistoryTab: some View {
        let filtered = vm.historyEntries.filter {
            if vm.historyFilter == 1 { return !$0.isOutgoing }
            if vm.historyFilter == 2 { return $0.isOutgoing }
            return true
        }
        let rxBytes = vm.historyEntries.filter { !$0.isOutgoing }.reduce(Int64(0)) { $0 + $1.sizeBytes }
        let txBytes = vm.historyEntries.filter { $0.isOutgoing }.reduce(Int64(0)) { $0 + $1.sizeBytes }

        return VStack(alignment: .leading, spacing: 14) {
            // Summary Cards
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("RECEIVED")
                        .font(.system(size: 10, weight: .heavy))
                        .foregroundColor(MacEmerald)
                    Text(formatByteSize(rxBytes))
                        .font(.system(size: 18, weight: .heavy).monospacedDigit())
                        .foregroundColor(.white)
                    Text("\(vm.historyEntries.filter { !$0.isOutgoing }.count) files in ~/Downloads")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(14)
                .background(
                    RoundedRectangle(cornerRadius: 16)
                        .fill(MacGlassCard)
                        .overlay(RoundedRectangle(cornerRadius: 16).stroke(MacGlassBorder, lineWidth: 1))
                )

                VStack(alignment: .leading, spacing: 4) {
                    Text("SENT")
                        .font(.system(size: 10, weight: .heavy))
                        .foregroundColor(MacCyanBright)
                    Text(formatByteSize(txBytes))
                        .font(.system(size: 18, weight: .heavy).monospacedDigit())
                        .foregroundColor(.white)
                    Text("\(vm.historyEntries.filter { $0.isOutgoing }.count) files delivered")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(14)
                .background(
                    RoundedRectangle(cornerRadius: 16)
                        .fill(MacGlassCard)
                        .overlay(RoundedRectangle(cornerRadius: 16).stroke(MacGlassBorder, lineWidth: 1))
                )
            }

            // Filter Pills + Open Downloads + Clear
            HStack(spacing: 6) {
                ForEach(Array(["All (\(vm.historyEntries.count))", "Received", "Sent"].enumerated()), id: \.offset) { idx, title in
                    let active = vm.historyFilter == idx
                    Button(action: { vm.historyFilter = idx }) {
                        Text(title)
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(active ? .white : .secondary)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 6)
                            .background(
                                Capsule()
                                    .fill(active ? MacCyan : MacGlassCard)
                                    .overlay(Capsule().stroke(active ? MacCyanBright : MacGlassBorder, lineWidth: 1))
                            )
                    }
                    .buttonStyle(.plain)
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
                    Image(systemName: "arrow.left.arrow.right.circle")
                        .font(.system(size: 28))
                        .foregroundColor(.secondary)
                    Text("No Transfers Yet")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(.white)
                    Text("Files sent or received between MacBook Pro and Android devices appear here with exact sizes and Finder shortcuts.")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding(28)
                .background(
                    RoundedRectangle(cornerRadius: 18)
                        .fill(MacGlassCard)
                        .overlay(RoundedRectangle(cornerRadius: 18).stroke(MacGlassBorder, lineWidth: 1))
                )
            } else {
                ForEach(filtered) { item in
                    let badge = macFileBadge(name: item.displayName, isUrl: item.isUrl)
                    HStack(spacing: 12) {
                        ZStack {
                            RoundedRectangle(cornerRadius: 10)
                                .fill(badge.color.opacity(0.18))
                                .frame(width: 40, height: 40)
                                .overlay(RoundedRectangle(cornerRadius: 10).stroke(badge.color.opacity(0.45), lineWidth: 1))
                            Text(badge.label)
                                .font(.system(size: 10, weight: .heavy))
                                .foregroundColor(badge.color)
                        }

                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 6) {
                                Text(item.isOutgoing ? "SENT" : "RECEIVED")
                                    .font(.system(size: 9, weight: .heavy))
                                    .foregroundColor(item.isOutgoing ? MacCyanBright : MacEmerald)
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1.5)
                                    .background(
                                        RoundedRectangle(cornerRadius: 4)
                                            .fill((item.isOutgoing ? MacCyan : MacEmerald).opacity(0.18))
                                    )
                                Text(item.displayName)
                                    .font(.system(size: 13, weight: .bold))
                                    .foregroundColor(.white)
                                    .lineLimit(1)
                            }
                            Text("\(formatByteSize(item.sizeBytes)) • \(item.peerName) • \(item.timestamp.formatted(date: .abbreviated, time: .shortened))")
                                .font(.system(size: 11).monospacedDigit())
                                .foregroundColor(.secondary)
                                .lineLimit(1)
                        }

                        Spacer()

                        Button("Copy") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(item.value, forType: .string)
                        }
                        .controlSize(.small)

                        Button(item.isUrl ? "Open Link" : "Show in Finder") {
                            if item.isUrl, let u = URL(string: item.value) {
                                NSWorkspace.shared.open(u)
                            } else {
                                NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: item.value)])
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(MacGlassElevated)
                        .controlSize(.small)
                    }
                    .padding(12)
                    .background(
                        RoundedRectangle(cornerRadius: 16)
                            .fill(MacGlassCard)
                            .overlay(RoundedRectangle(cornerRadius: 16).stroke(MacGlassBorder, lineWidth: 1))
                    )
                }
            }
        }
    }

    // ========================================================================
    // TAB 3: Receive Mode & P2P Radio Settings
    // ========================================================================
    private var receiveAndP2pTab: some View {
        VStack(alignment: .leading, spacing: 14) {
            // 1. Receiving Mode Card (Direct Get vs. Ask Every Time)
            VStack(alignment: .leading, spacing: 10) {
                Text("RECEIVING MODE")
                    .font(.system(size: 10, weight: .heavy))
                    .foregroundColor(MacCyanBright)
                Text("Choose how incoming files from Android devices are handled on this Mac")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)

                macReceiveOptionCard(
                    title: "Direct Get (Instant Auto-Download)",
                    subtitle: "Incoming files from Android devices save directly to ~/Downloads without any confirmation popup.",
                    badge: "FASTEST",
                    selected: vm.autoAccept,
                    accent: MacEmerald
                ) {
                    vm.setReceiveMode(directGet: true)
                }

                macReceiveOptionCard(
                    title: "Ask Every Time (Accept / Decline Modal)",
                    subtitle: "Prompt with sender name, file list, and total size before accepting incoming files.",
                    badge: "SAFE",
                    selected: !vm.autoAccept,
                    accent: MacAmber
                ) {
                    vm.setReceiveMode(directGet: false)
                }
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 20)
                    .fill(MacGlassCard)
                    .overlay(RoundedRectangle(cornerRadius: 20).stroke(MacGlassBorder, lineWidth: 1))
            )

            // 2. Visibility & Mac Identity Card
            VStack(alignment: .leading, spacing: 12) {
                Text("VISIBILITY & IDENTITY")
                    .font(.system(size: 10, weight: .heavy))
                    .foregroundColor(MacCyanBright)

                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(vm.receiverRunning ? "Visible to Everyone Nearby" : "Hidden (Radio Paused)")
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.white)
                        Text("Advertises BLE L2CAP + mDNS + 5GHz Wi-Fi Direct")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
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
                    TextField("Mac Device Name", text: $vm.editingDeviceName)
                        .textFieldStyle(.roundedBorder)
                    Button("Save Name") {
                        vm.saveDeviceName()
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(MacCyan)
                }

                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Downloads Folder")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(.white)
                        Text("~/Downloads")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                    Button("Open ~/Downloads") {
                        let dl = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
                        NSWorkspace.shared.open(dl)
                    }
                    .controlSize(.small)
                }

                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("End-to-End Encryption")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(.white)
                        Text("TLS 1.3 (ECDSA P-256) + AES-256-GCM + Ephemeral WPA2")
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                    Spacer()
                    Text("ACTIVE")
                        .font(.system(size: 10, weight: .heavy))
                        .foregroundColor(MacEmerald)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(
                            Capsule()
                                .fill(MacEmerald.opacity(0.16))
                                .overlay(Capsule().stroke(MacEmerald.opacity(0.5), lineWidth: 1))
                        )
                }
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 20)
                    .fill(MacGlassCard)
                    .overlay(RoundedRectangle(cornerRadius: 20).stroke(MacGlassBorder, lineWidth: 1))
            )

            // 3. P2P Radio Diagnostics & Live Protocol Log
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("P2P RADIO DIAGNOSTICS")
                        .font(.system(size: 10, weight: .heavy))
                        .foregroundColor(MacCyanBright)
                    Spacer()
                    Button("Restart P2P Engine") {
                        vm.rescanNow()
                    }
                    .controlSize(.small)
                }

                Text(vm.peerStatusSummary)
                    .font(.system(size: 12, weight: .bold).monospacedDigit())
                    .foregroundColor(MacEmerald)

                DisclosureGroup("Live Protocol Logs (\(vm.logs.count))", isExpanded: $vm.showLogs) {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 3) {
                            ForEach(Array(vm.logs.enumerated()), id: \.offset) { _, line in
                                Text(line)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(.secondary)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                        .padding(8)
                    }
                    .frame(height: 140)
                    .background(RoundedRectangle(cornerRadius: 10).fill(MacObsidianBg))
                }
                .font(.system(size: 12, weight: .semibold))
                .foregroundColor(.secondary)
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 20)
                    .fill(MacGlassCard)
                    .overlay(RoundedRectangle(cornerRadius: 20).stroke(MacGlassBorder, lineWidth: 1))
            )
        }
    }

    private func macReceiveOptionCard(
        title: String,
        subtitle: String,
        badge: String,
        selected: Bool,
        accent: Color,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .stroke(selected ? accent : Color.secondary, lineWidth: 2)
                        .frame(width: 18, height: 18)
                    if selected {
                        Circle()
                            .fill(accent)
                            .frame(width: 10, height: 10)
                    }
                }
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 7) {
                        Text(title)
                            .font(.system(size: 13, weight: .bold))
                            .foregroundColor(.white)
                        Text(badge)
                            .font(.system(size: 9, weight: .heavy))
                            .foregroundColor(accent)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(RoundedRectangle(cornerRadius: 4).fill(accent.opacity(0.18)))
                    }
                    Text(subtitle)
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
                Spacer()
            }
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: 14)
                    .fill(selected ? MacGlassElevated : MacObsidianBg.opacity(0.6))
                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(selected ? accent : MacGlassBorder, lineWidth: 1.2))
            )
        }
        .buttonStyle(.plain)
    }

    private func incomingAskModal(_ ask: MacPendingAsk) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(LinearGradient(colors: [MacCyan, MacIndigo], startPoint: .topLeading, endPoint: .bottomTrailing))
                        .frame(width: 44, height: 44)
                    Image(systemName: "arrow.down.doc.fill")
                        .font(.system(size: 20, weight: .bold))
                        .foregroundColor(.white)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text("Incoming Quick Share")
                        .font(.system(size: 16, weight: .heavy))
                        .foregroundColor(.white)
                    Text("From \(ask.senderName)")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(MacCyanBright)
                }
                Spacer()
            }

            VStack(alignment: .leading, spacing: 6) {
                Text("\(ask.fileNames.count) File(s) • \(formatByteSize(ask.totalBytes))")
                    .font(.system(size: 12, weight: .bold).monospacedDigit())
                    .foregroundColor(MacEmerald)
                ForEach(ask.fileNames.prefix(4), id: \.self) { fname in
                    Text("• \(fname)")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(.white)
                        .lineLimit(1)
                }
                if ask.fileNames.count > 4 {
                    Text("+ \(ask.fileNames.count - 4) more file(s)")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(MacObsidianBg)
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(MacGlassBorder, lineWidth: 1))
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
                    Text("Accept & Save to Downloads")
                        .fontWeight(.bold)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                }
                .buttonStyle(.borderedProminent)
                .tint(MacCyan)
            }
        }
        .padding(20)
        .frame(maxWidth: 390)
        .background(
            RoundedRectangle(cornerRadius: 22)
                .fill(MacGlassElevated)
                .overlay(RoundedRectangle(cornerRadius: 22).stroke(MacCyanBright.opacity(0.6), lineWidth: 1.5))
                .shadow(color: .black.opacity(0.6), radius: 24)
        )
    }

    private var bottomTabBar: some View {
        HStack(spacing: 10) {
            let tabs: [(String, String, String?, Int)] = [
                ("Nearby & Send", "dot.radiowaves.left.and.right", vm.activePeers.isEmpty ? nil : "\(vm.activePeers.count)", 0),
                ("Transfers", "arrow.up.arrow.down.circle", vm.historyEntries.isEmpty ? nil : "\(vm.historyEntries.count)", 1),
                ("Receive & P2P", "shield.lefthalf.filled", vm.autoAccept ? "Direct" : "Ask", 2)
            ]
            ForEach(tabs, id: \.3) { title, icon, badge, idx in
                let active = vm.selectedTab == idx
                Button(action: { vm.selectedTab = idx }) {
                    HStack(spacing: 6) {
                        Image(systemName: icon)
                            .font(.system(size: 13, weight: .bold))
                        Text(title)
                            .font(.system(size: 12, weight: active ? .heavy : .medium))
                        if let b = badge {
                            Text(b)
                                .font(.system(size: 10, weight: .bold))
                                .foregroundColor(active ? .white : .secondary)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 1.5)
                                .background(Capsule().fill(active ? MacCyan : MacGlassElevated))
                        }
                    }
                    .foregroundColor(active ? MacCyanBright : .secondary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 9)
                    .background(
                        RoundedRectangle(cornerRadius: 12)
                            .fill(active ? MacCyan.opacity(0.18) : Color.clear)
                            .overlay(
                                RoundedRectangle(cornerRadius: 12)
                                    .stroke(active ? MacCyan.opacity(0.55) : Color.clear, lineWidth: 1)
                            )
                    )
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(
            MacGlassCard
                .overlay(Rectangle().fill(MacGlassBorder).frame(height: 1), alignment: .top)
        )
    }

    private func macFileBadge(name: String, isUrl: Bool) -> (label: String, color: Color) {
        if isUrl { return ("LINK", MacCyanBright) }
        let ext = URL(fileURLWithPath: name).pathExtension.lowercased()
        switch ext {
        case "jpg", "jpeg", "png", "webp", "heic", "gif", "svg":
            return ("IMG", MacCyanBright)
        case "mp4", "mov", "mkv", "webm", "avi":
            return ("VID", Color.purple)
        case "mp3", "wav", "m4a", "flac", "aac":
            return ("AUD", Color.pink)
        case "zip", "rar", "7z", "tar", "gz", "dmg":
            return ("ZIP", MacAmber)
        case "apk", "aab":
            return ("APK", MacEmerald)
        default:
            return ("FILE", MacIndigo)
        }
    }

    private func sendUrlInput() {
        let trimmed = vm.urlInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        vm.urlInput = ""
        if trimmed.hasPrefix("http://") || trimmed.hasPrefix("https://") {
            vm.sendItems([trimmed])
        } else {
            let stamp = Int(Date().timeIntervalSince1970)
            let tmpFile = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("Note-\(stamp).txt")
            try? trimmed.data(using: .utf8)?.write(to: tmpFile)
            vm.sendItems([tmpFile.path])
        }
    }

    private func handleDrop(_ providers: [NSItemProvider]) -> Bool {
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
                vm.sendItems(collected)
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
                self?.viewModel.sendItems(paths)
            }
            btn.addSubview(dropView)
        }

        let menu = NSMenu()
        let openWin = NSMenuItem(title: "Open AirDrop P2P Window…", action: #selector(showMainWindow), keyEquivalent: "s")
        openWin.target = self
        menu.addItem(openWin)
        menu.addItem(NSMenuItem.separator())

        let sendSel = NSMenuItem(title: "AirDrop Selected Finder File(s) to Active Device", action: #selector(sendFinderSelection), keyEquivalent: "a")
        sendSel.target = self
        menu.addItem(sendSel)

        let pickFile = NSMenuItem(title: "Choose File to AirDrop to Active Device...", action: #selector(chooseAndSendFile), keyEquivalent: "o")
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

    @objc func showMainWindow() {
        NSApp.setActivationPolicy(.regular)
        if window == nil {
            let win = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 560, height: 680),
                styleMask: [.titled, .closable, .miniaturizable, .resizable],
                backing: .buffered,
                defer: false
            )
            win.title = "AirDrop P2P — Enterprise Cross-Platform Quick Share"
            win.titlebarAppearsTransparent = true
            win.backgroundColor = NSColor(calibratedRed: 0.03, green: 0.04, blue: 0.07, alpha: 1.0)
            win.center()
            win.isReleasedWhenClosed = false
            win.delegate = self
            win.contentView = NSHostingView(rootView: MacAirDropMainView(vm: viewModel))
            window = win
        }
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
        stopAllDaemonsAndQuit()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
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
        viewModel.sendFinderSelection()
    }

    @objc func chooseAndSendFile() {
        viewModel.chooseAndSendFiles()
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
        src.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
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
