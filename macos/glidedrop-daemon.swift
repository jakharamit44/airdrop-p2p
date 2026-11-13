import Foundation
import CoreBluetooth
import AppKit
import SwiftUI
import Network
import UniformTypeIdentifiers
import CryptoKit
import CoreWLAN
import CoreLocation
import Darwin
import SystemConfiguration

private let p2pSessionTokenLock = NSLock()
private let P2P_SESSION_TOKEN_TTL: TimeInterval = 300.0
private let MAX_P2P_SESSION_TOKENS = 4

func normalizeSha256Fingerprint(_ raw: String) -> String {
    return raw
        .replacingOccurrences(of: ":", with: "")
        .replacingOccurrences(of: "-", with: "")
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .lowercased()
}

func isValidSha256Fingerprint(_ raw: String?) -> Bool {
    guard let raw = raw else { return false }
    let hex = normalizeSha256Fingerprint(raw)
    guard hex.count == 64 else { return false }
    return hex.unicodeScalars.allSatisfy {
        ($0.value >= 48 && $0.value <= 57) || ($0.value >= 97 && $0.value <= 102)
    }
}

func registerP2pSessionToken(_ token: String, stateDir: URL = STATE_DIR, ttl: TimeInterval = P2P_SESSION_TOKEN_TTL) {
    let clean = token.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    guard clean.count == 64,
          clean.unicodeScalars.allSatisfy({ ($0.value >= 48 && $0.value <= 57) || ($0.value >= 97 && $0.value <= 102) }) else {
        return
    }
    p2pSessionTokenLock.lock()
    defer { p2pSessionTokenLock.unlock() }
    try? FileManager.default.createDirectory(at: stateDir, withIntermediateDirectories: true)
    let tokenFile = stateDir.appendingPathComponent("p2p_session_token.json")
    let now = Date().timeIntervalSince1970
    var activeTokens: [[String: Any]] = []
    if let existingData = try? Data(contentsOf: tokenFile),
       let existingObj = try? JSONSerialization.jsonObject(with: existingData) as? [String: Any],
       let rawList = existingObj["tokens"] as? [[String: Any]] {
        for item in rawList {
            guard let t = item["token"] as? String,
                  let exp = item["expires_at"] as? Double,
                  exp > now,
                  t != clean else { continue }
            activeTokens.append(item)
        }
    }
    activeTokens.append([
        "token": clean,
        "created_at": now,
        "expires_at": now + max(1.0, ttl)
    ])
    if activeTokens.count > MAX_P2P_SESSION_TOKENS {
        activeTokens = Array(activeTokens.suffix(MAX_P2P_SESSION_TOKENS))
    }
    let payload: [String: Any] = ["tokens": activeTokens]
    guard let jsonData = try? JSONSerialization.data(withJSONObject: payload, options: []) else { return }
    let tmpFile = stateDir.appendingPathComponent("p2p_session_token.json.tmp.\(UUID().uuidString)")
    if FileManager.default.createFile(atPath: tmpFile.path, contents: jsonData, attributes: [.posixPermissions: 0o600]) {
        _ = chmod(tmpFile.path, 0o600)
        if Darwin.rename(tmpFile.path, tokenFile.path) != 0 {
            try? FileManager.default.removeItem(at: tmpFile)
        }
    }
}

func clearP2pSessionTokens(stateDir: URL = STATE_DIR) {
    p2pSessionTokenLock.lock()
    defer { p2pSessionTokenLock.unlock() }
    try? FileManager.default.removeItem(at: stateDir.appendingPathComponent("p2p_session_token.json"))
}

func revokeP2pSessionToken(_ token: String, stateDir: URL = STATE_DIR) {
    let clean = token.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    guard !clean.isEmpty else { return }
    p2pSessionTokenLock.lock()
    defer { p2pSessionTokenLock.unlock() }
    let tokenFile = stateDir.appendingPathComponent("p2p_session_token.json")
    guard let existingData = try? Data(contentsOf: tokenFile),
          let existingObj = try? JSONSerialization.jsonObject(with: existingData) as? [String: Any],
          let rawList = existingObj["tokens"] as? [[String: Any]] else {
        return
    }
    let now = Date().timeIntervalSince1970
    let remaining = rawList.filter { item in
        guard let t = (item["token"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
              let exp = item["expires_at"] as? Double else { return false }
        return exp > now && t != clean
    }
    if remaining.isEmpty {
        try? FileManager.default.removeItem(at: tokenFile)
        return
    }
    guard let jsonData = try? JSONSerialization.data(withJSONObject: ["tokens": remaining], options: []) else { return }
    let tmpFile = stateDir.appendingPathComponent("p2p_session_token.json.tmp.\(UUID().uuidString)")
    if FileManager.default.createFile(atPath: tmpFile.path, contents: jsonData, attributes: [.posixPermissions: 0o600]) {
        _ = chmod(tmpFile.path, 0o600)
        if Darwin.rename(tmpFile.path, tokenFile.path) != 0 {
            try? FileManager.default.removeItem(at: tmpFile)
        }
    }
}

// No compiled-in ports: every listener binds to port 0 and the OS-assigned value is
// published via port files in STATE_DIR or exchanged inside the encrypted handshake.

func parseIpv4Address(_ ip: String) -> UInt32? {
    let clean = ip.trimmingCharacters(in: .whitespacesAndNewlines)
    var addr = in_addr()
    guard clean.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 else {
        return nil
    }
    return UInt32(bigEndian: addr.s_addr)
}

func formatIpv4Address(_ value: UInt32) -> String {
    var netOrder = in_addr(s_addr: value.bigEndian)
    var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
    guard inet_ntop(AF_INET, &netOrder, &buf, socklen_t(INET_ADDRSTRLEN)) != nil else {
        return ""
    }
    return String(cString: buf)
}

func deriveIpv4Cidr(ip: String, prefixLen: Int = 24) -> String? {
    guard prefixLen > 0, prefixLen <= 32, let ipInt = parseIpv4Address(ip) else { return nil }
    let mask: UInt32 = (0xFFFF_FFFF << UInt32(32 - prefixLen))
    let netStr = formatIpv4Address(ipInt & mask)
    return netStr.isEmpty ? nil : "\(netStr)/\(prefixLen)"
}

func prefixLengthFromIpv4Netmask(_ maskIp: String) -> Int? {
    guard let maskInt = parseIpv4Address(maskIp), maskInt != 0 else { return nil }
    var leading = 0
    for shift in stride(from: 31, through: 0, by: -1) {
        if (maskInt & (1 << UInt32(shift))) != 0 {
            leading += 1
        } else {
            let remMask: UInt32 = (1 << UInt32(shift + 1)) - 1
            if (maskInt & remMask) != 0 { return nil }
            break
        }
    }
    return leading > 0 ? leading : nil
}

func parseIpv4Cidr(_ cidr: String) -> (network: UInt32, mask: UInt32)? {
    let parts = cidr.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "/")
    guard parts.count == 2,
          let ipInt = parseIpv4Address(String(parts[0])),
          let prefix = Int(parts[1]),
          prefix > 0 && prefix <= 32 else {
        return nil
    }
    let mask: UInt32 = (0xFFFF_FFFF << UInt32(32 - prefix))
    return (ipInt & mask, mask)
}

func cidrContains(cidr: String, ip: String) -> Bool {
    guard let parsed = parseIpv4Cidr(cidr),
          let ipInt = parseIpv4Address(ip) else {
        return false
    }
    return (ipInt & parsed.mask) == parsed.network
}

func isRfc1918Ipv4(_ ip: String) -> Bool {
    guard let v = parseIpv4Address(ip) else { return false }
    if (v & 0xFF00_0000) == 0x0A00_0000 { return true }       // 10.0.0.0/8
    if (v & 0xFFF0_0000) == 0xAC10_0000 { return true }       // 172.16.0.0/12
    if (v & 0xFFFF_0000) == 0xC0A8_0000 { return true }       // 192.168.0.0/16
    return false
}

func isCgnatIpv4(_ ip: String) -> Bool {
    guard let v = parseIpv4Address(ip) else { return false }
    return (v & 0xFFC0_0000) == 0x6440_0000                   // 100.64.0.0/10
}

func isValidP2pGatewayIp(_ ip: String) -> Bool {
    let clean = ip.trimmingCharacters(in: .whitespacesAndNewlines)
    if clean.isEmpty { return false }
    if let v = parseIpv4Address(clean) {
        if (v & 0xFF00_0000) == 0 { return false }            // 0.0.0.0/8
        if (v & 0xFF00_0000) == 0x7F00_0000 { return false }  // 127.0.0.0/8 loopback
        if (v & 0xF000_0000) == 0xE000_0000 { return false }  // multicast/reserved
        if isRfc1918Ipv4(clean) { return true }
        if (v & 0xFFFF_0000) == 0xA9FE_0000 { return true }   // 169.254.0.0/16 link-local
        return false
    }
    var addr6 = in6_addr()
    let zoneStripped = clean.split(separator: "%", maxSplits: 1).first.map(String.init) ?? clean
    guard zoneStripped.withCString({ inet_pton(AF_INET6, $0, &addr6) }) == 1 else {
        return false
    }
    let b0 = withUnsafeBytes(of: addr6) { $0[0] }
    let b1 = withUnsafeBytes(of: addr6) { $0[1] }
    if b0 == 0xFE && (b1 & 0xC0) == 0x80 { return true }      // fe80::/10 link-local
    if (b0 & 0xFE) == 0xFC { return true }                    // fc00::/7 ULA
    return false
}

func isNormalWifiIpv4(_ ip: String, activeP2pCidr: String? = nil, rawWifiSsid: String? = nil) -> Bool {
    if let ssid = rawWifiSsid, ssid.hasPrefix("DIRECT-") { return false }
    guard let v = parseIpv4Address(ip) else { return false }
    if (v & 0xFF00_0000) == 0 || v == 0xFFFF_FFFF { return false }
    if (v & 0xFF00_0000) == 0x7F00_0000 { return false }      // loopback 127.0.0.0/8
    if (v & 0xFFFF_0000) == 0xA9FE_0000 { return false }      // link-local 169.254.0.0/16
    if (v & 0xF000_0000) == 0xE000_0000 { return false }      // multicast / reserved
    if let cidr = activeP2pCidr, !cidr.isEmpty, cidrContains(cidr: cidr, ip: ip) { return false }
    return true
}

struct ActiveP2pSession: Codable, Equatable {
    let ssid: String
    let interfaceName: String
    let gatewayIp: String
    let cidr: String
    let httpsPort: Int
    let proxyPort: Int
    let macRxPort: Int
    let udpKeepalivePort: Int
    let updatedAt: Double

    enum CodingKeys: String, CodingKey {
        case ssid, interfaceName, gatewayIp, cidr, httpsPort, proxyPort, macRxPort, udpKeepalivePort, updatedAt
    }

    init(
        ssid: String,
        interfaceName: String,
        gatewayIp: String,
        cidr: String,
        httpsPort: Int,
        proxyPort: Int,
        macRxPort: Int,
        udpKeepalivePort: Int,
        updatedAt: Double
    ) {
        self.ssid = ssid
        self.interfaceName = interfaceName
        self.gatewayIp = gatewayIp
        self.cidr = cidr
        self.httpsPort = httpsPort
        self.proxyPort = proxyPort
        self.macRxPort = macRxPort
        self.udpKeepalivePort = udpKeepalivePort
        self.updatedAt = updatedAt
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.ssid = try c.decode(String.self, forKey: .ssid)
        self.interfaceName = try c.decode(String.self, forKey: .interfaceName)
        self.gatewayIp = try c.decode(String.self, forKey: .gatewayIp)
        self.cidr = try c.decode(String.self, forKey: .cidr)
        self.httpsPort = try c.decode(Int.self, forKey: .httpsPort)
        self.proxyPort = try c.decode(Int.self, forKey: .proxyPort)
        self.macRxPort = try c.decodeIfPresent(Int.self, forKey: .macRxPort) ?? 0
        self.udpKeepalivePort = try c.decodeIfPresent(Int.self, forKey: .udpKeepalivePort) ?? 0
        self.updatedAt = try c.decode(Double.self, forKey: .updatedAt)
    }
}

@discardableResult
func writeAtomicPrivateFile(data: Data, to target: URL) -> Bool {
    let tmp = target.deletingLastPathComponent().appendingPathComponent("\(target.lastPathComponent).tmp.\(UUID().uuidString)")
    if FileManager.default.createFile(atPath: tmp.path, contents: data, attributes: [.posixPermissions: 0o600]) {
        _ = chmod(tmp.path, 0o600)
        if Darwin.rename(tmp.path, target.path) == 0 { return true }
        try? FileManager.default.removeItem(at: tmp)
    }
    return false
}

func hasValidP2pProvenance(ssid: String, interfaceName: String, gatewayIp: String, cidr: String, httpsPort: Int) -> Bool {
    return ssid.hasPrefix("DIRECT-") && ssid.utf8.count <= 32 &&
        interfaceName.range(of: "^[A-Za-z][A-Za-z0-9]{0,31}$", options: .regularExpression) != nil &&
        isRfc1918Ipv4(gatewayIp) && cidrContains(cidr: cidr, ip: gatewayIp) &&
        (1...65535).contains(httpsPort)
}

@discardableResult
func writeActiveP2pSession(
    ssid: String,
    interfaceName: String,
    gatewayIp: String,
    cidr: String,
    httpsPort: Int,
    proxyPort: Int,
    macRxPort: Int = readPortFile("mac_rx_port") ?? 0,
    udpKeepalivePort: Int = readPortFile("awdl_bridge_port") ?? 0,
    stateDir: URL = STATE_DIR,
    now: Double = Date().timeIntervalSince1970
) -> Bool {
    guard now.isFinite,
          hasValidP2pProvenance(ssid: ssid, interfaceName: interfaceName, gatewayIp: gatewayIp, cidr: cidr, httpsPort: httpsPort) else { return false }
    try? FileManager.default.createDirectory(at: stateDir, withIntermediateDirectories: true)
    let session = ActiveP2pSession(
        ssid: ssid,
        interfaceName: interfaceName,
        gatewayIp: gatewayIp,
        cidr: cidr,
        httpsPort: httpsPort,
        proxyPort: (1...65535).contains(proxyPort) ? proxyPort : 0,
        macRxPort: (1...65535).contains(macRxPort) ? macRxPort : 0,
        udpKeepalivePort: (1...65535).contains(udpKeepalivePort) ? udpKeepalivePort : 0,
        updatedAt: now
    )
    guard let data = try? JSONEncoder().encode(session) else { return false }
    return writeAtomicPrivateFile(data: data, to: stateDir.appendingPathComponent("active_p2p_session.json"))
}

func loadActiveP2pSession(
    stateDir: URL = STATE_DIR,
    maxAge: TimeInterval = 1800.0,
    now: Double = Date().timeIntervalSince1970
) -> ActiveP2pSession? {
    let file = stateDir.appendingPathComponent("active_p2p_session.json")
    guard let data = try? Data(contentsOf: file),
          let session = try? JSONDecoder().decode(ActiveP2pSession.self, from: data),
          now.isFinite, session.updatedAt.isFinite,
          (0...max(0, maxAge)).contains(now - session.updatedAt),
          hasValidP2pProvenance(ssid: session.ssid, interfaceName: session.interfaceName,
                                gatewayIp: session.gatewayIp, cidr: session.cidr, httpsPort: session.httpsPort) else {
        return nil
    }
    return session
}

@discardableResult
func writeWp2pAuthorization(
    senderName: String, ssid: String, token: String, peerIp: String,
    stateDir: URL = STATE_DIR, now: Double = Date().timeIntervalSince1970
) -> Bool {
    guard token.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
          let session = loadActiveP2pSession(stateDir: stateDir, now: now),
          session.ssid == ssid, session.gatewayIp == peerIp else { return false }
    let payload: [String: Any] = [
        "senderName": senderName, "ssid": ssid, "token": token,
        "peerIp": peerIp, "authorizedAt": now
    ]
    guard let data = try? JSONSerialization.data(withJSONObject: payload) else { return false }
    return writeAtomicPrivateFile(data: data, to: stateDir.appendingPathComponent("wp2p_authorized_session.json"))
}

func clearActiveP2pSession(stateDir: URL = STATE_DIR) {
    try? FileManager.default.removeItem(at: stateDir.appendingPathComponent("active_p2p_session.json"))
}

func writeOutgoingP2pToken(
    _ token: String,
    host: String,
    port: Int,
    stateDir: URL = STATE_DIR,
    ttl: TimeInterval = P2P_SESSION_TOKEN_TTL
) {
    let clean = token.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    guard clean.count == 64,
          clean.unicodeScalars.allSatisfy({ ($0.value >= 48 && $0.value <= 57) || ($0.value >= 97 && $0.value <= 102) }) else {
        return
    }
    try? FileManager.default.createDirectory(at: stateDir, withIntermediateDirectories: true)
    let now = Date().timeIntervalSince1970
    let payload: [String: Any] = [
        "token": clean,
        "host": host,
        "port": port,
        "created_at": now,
        "expires_at": now + max(1.0, ttl)
    ]
    guard let data = try? JSONSerialization.data(withJSONObject: payload, options: []) else { return }
    writeAtomicPrivateFile(data: data, to: stateDir.appendingPathComponent("p2p_outgoing_token.json"))
}

func clearOutgoingP2pToken(stateDir: URL = STATE_DIR) {
    try? FileManager.default.removeItem(at: stateDir.appendingPathComponent("p2p_outgoing_token.json"))
}

/// Reads an OS-assigned port published by a listener. Returns nil when it is missing or invalid; there is no fallback value.
func readPortFile(_ name: String, stateDir: URL = STATE_DIR) -> Int? {
    let file = stateDir.appendingPathComponent(name)
    guard let raw = try? String(contentsOf: file, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
          let val = Int(raw), val >= 1 && val <= 65535 else {
        return nil
    }
    return val
}

func writeAwdlBridgePortFile(port: Int, stateDir: URL = STATE_DIR) {
    guard (1...65535).contains(port) else { return }
    try? FileManager.default.createDirectory(at: stateDir, withIntermediateDirectories: true)
    guard let data = "\(port)\n".data(using: .utf8) else { return }
    writeAtomicPrivateFile(data: data, to: stateDir.appendingPathComponent("awdl_bridge_port"))
}

func isAllowedAwdlInterfaceNames(_ names: [String]) -> Bool {
    return names.contains { $0 == "awdl0" || $0.hasPrefix("awdl") }
}

func isAllowedAwdlEndpoint(_ endpoint: NWEndpoint?) -> Bool {
    guard let ep = endpoint else { return true }
    switch ep {
    case .hostPort(let host, _):
        switch host {
        case .ipv4(_):
            return false
        case .ipv6(let addr):
            if !addr.isLinkLocal { return false }
            if let ifName = addr.interface?.name, !ifName.hasPrefix("awdl") {
                return false
            }
            return true
        case .name(_, let iface):
            if let ifName = iface?.name, !ifName.hasPrefix("awdl") {
                return false
            }
            return true
        @unknown default:
            return true
        }
    default:
        return true
    }
}

func readFinderProxySockPath(stateDir: URL = STATE_DIR) -> String {
    let file = stateDir.appendingPathComponent("finder_proxy_sock")
    if let raw = try? String(contentsOf: file, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
       !raw.isEmpty {
        return raw
    }
    return stateDir.appendingPathComponent("finder_proxy.sock").path
}

func ensureLocalMacTlsCertFiles() {
    let certPath = STATE_DIR.appendingPathComponent("cert.pem")
    let keyPath = STATE_DIR.appendingPathComponent("key.pem")
    if !FileManager.default.fileExists(atPath: certPath.path) || !FileManager.default.fileExists(atPath: keyPath.path) {
        try? FileManager.default.createDirectory(at: STATE_DIR, withIntermediateDirectories: true)
        _ = runProcessCapture("/usr/bin/openssl", [
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-keyout", keyPath.path, "-out", certPath.path,
            "-days", "3650", "-nodes", "-subj", "/CN=glidedrop"
        ])
    }
}

func getLocalMacTlsCertFingerprint() -> String {
    let certPath = STATE_DIR.appendingPathComponent("cert.pem")
    let keyPath = STATE_DIR.appendingPathComponent("key.pem")
    if !FileManager.default.fileExists(atPath: certPath.path) || !FileManager.default.fileExists(atPath: keyPath.path) {
        ensureLocalMacTlsCertFiles()
    }
    guard let pemStr = try? String(contentsOf: certPath, encoding: .utf8) else { return "" }
    let lines = pemStr.components(separatedBy: .newlines)
    let b64 = lines.filter { !$0.hasPrefix("-----") && !$0.isEmpty }.joined()
    guard let der = Data(base64Encoded: b64, options: .ignoreUnknownCharacters), !der.isEmpty else { return "" }
    let digest = SHA256.hash(data: der)
    return digest.map { String(format: "%02x", $0) }.joined()
}

func readBleStreamLine(
    _ inp: InputStream,
    maxLen: Int = 4096,
    timeout: TimeInterval = 25.0,
    checkCancel: Bool = false,
    onTimeout: (() -> Void)? = nil
) -> String? {
    func readSync(shouldStop: @escaping () -> Bool) -> String? {
        var lineBytes = Data()
        var b: UInt8 = 0
        while lineBytes.count < maxLen {
            if shouldStop() { return nil }
            let r = inp.read(&b, maxLength: 1)
            if r > 0 {
                if b == UInt8(ascii: "\n") { break }
                if b != UInt8(ascii: "\r") { lineBytes.append(b) }
            } else if r == 0 {
                let status = inp.streamStatus
                if status == .error || status == .closed {
                    return nil
                }
                if status == .atEnd {
                    return lineBytes.isEmpty ? nil : String(data: lineBytes, encoding: .utf8)
                }
                Thread.sleep(forTimeInterval: 0.01)
            } else {
                return nil
            }
        }
        return String(data: lineBytes, encoding: .utf8)
    }

    if timeout <= 0 && !checkCancel {
        return readSync { false }
    }

    let lock = NSLock()
    var aborted = false
    var result: String? = nil
    let sem = DispatchSemaphore(value: 0)
    DispatchQueue.global(qos: .userInitiated).async {
        let line = readSync {
            lock.lock()
            let stop = aborted
            lock.unlock()
            return stop
        }
        lock.lock()
        if !aborted { result = line }
        lock.unlock()
        sem.signal()
    }

    let deadline = timeout > 0 ? Date().addingTimeInterval(timeout) : Date.distantFuture
    while true {
        if checkCancel && isTransferCancelled() {
            lock.lock()
            aborted = true
            lock.unlock()
            onTimeout?()
            return nil
        }
        let remaining = deadline.timeIntervalSinceNow
        if remaining <= 0 {
            lock.lock()
            aborted = true
            lock.unlock()
            onTimeout?()
            return nil
        }
        let step = min(0.2, remaining)
        if sem.wait(timeout: .now() + step) == .success {
            lock.lock()
            let res = result
            lock.unlock()
            return res
        }
    }
}

func deriveSessionKey(sharedSecret: SharedSecret) -> SymmetricKey {
    let raw = sharedSecret.withUnsafeBytes { Data($0) }
    var hasher = SHA256()
    hasher.update(data: raw)
    hasher.update(data: Data("GlideDrop-v2-SessionKey".utf8))
    let keyBytes = hasher.finalize()
    return SymmetricKey(data: keyBytes)
}

// MARK: - W2P2 protocol v3 (HKDF-SHA256, key/fingerprint/session-bound)

/// W2P2 wire version. v3 requests are `W2P2\t3\t<initiatorPub>\t<initiatorTlsFp>\t<sessionIdHex>`;
/// v3 replies are `OK\t<responderPub>\t<responderTlsFp>[\t<encryptedCreds>]`.
/// Older peers (no version field, or 1/2) are refused with `UPDATE` so the security
/// properties are never silently downgraded.
let W2P2_PROTOCOL_VERSION = 3
let W2P2_SESSION_ID_BYTES = 16

struct W2p2Request {
    let version: Int
    let pubB64: String
    let tlsFingerprint: String
    let sessionId: Data?
}

/// Parses the tab-separated body of a W2P2 request (everything after the magic).
func parseW2p2Request(_ body: String) -> W2p2Request {
    let parts = body.split(separator: "\t").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    if parts.count >= 4, let v = Int(parts[0]), v >= 3 {
        return W2p2Request(version: v, pubB64: parts[1], tlsFingerprint: parts[2], sessionId: dataFromHex(parts[3]))
    }
    if parts.count >= 3, parts[0] == "2" || parts[0] == "1" {
        return W2p2Request(version: Int(parts[0]) ?? 1, pubB64: parts[1], tlsFingerprint: parts[2], sessionId: nil)
    }
    if parts.count >= 2 {
        return W2p2Request(version: 1, pubB64: parts[0], tlsFingerprint: parts[1], sessionId: nil)
    }
    return W2p2Request(version: 1, pubB64: parts.first ?? "", tlsFingerprint: "", sessionId: nil)
}

func dataFromHex(_ hex: String) -> Data? {
    let chars = Array(hex.lowercased())
    guard !chars.isEmpty, chars.count % 2 == 0 else { return nil }
    var out = Data(capacity: chars.count / 2)
    var i = 0
    while i < chars.count {
        guard let hi = chars[i].hexDigitValue, let lo = chars[i + 1].hexDigitValue else { return nil }
        out.append(UInt8(hi << 4 | lo))
        i += 2
    }
    return out
}

func randomW2p2SessionId() -> Data {
    var bytes = [UInt8](repeating: 0, count: W2P2_SESSION_ID_BYTES)
    for i in 0..<bytes.count { bytes[i] = UInt8.random(in: 0...255) }
    return Data(bytes)
}

func w2p2HexString(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

private func w2p2LengthPrefixed(_ data: Data) -> Data {
    var out = Data()
    var n = UInt32(data.count).bigEndian
    withUnsafeBytes(of: &n) { out.append(contentsOf: $0) }
    out.append(data)
    return out
}

/// HKDF `info` = "GlideDrop-v3/<label>" 0x00 || lp(initiatorPub) || lp(responderPub) || lp(initiatorFp) || lp(responderFp)
func w2p2HkdfInfo(label: String, initiatorPubDer: Data, responderPubDer: Data, initiatorFp: Data, responderFp: Data) -> Data {
    var info = Data("GlideDrop-v3/\(label)".utf8)
    info.append(0)
    info.append(w2p2LengthPrefixed(initiatorPubDer))
    info.append(w2p2LengthPrefixed(responderPubDer))
    info.append(w2p2LengthPrefixed(initiatorFp))
    info.append(w2p2LengthPrefixed(responderFp))
    return info
}

struct W2p2SessionMaterial {
    let sessionKey: SymmetricKey
    let token: String
    /// Six decimal digits, formatted "123 456".
    let verificationCode: String
}

/// Formats a 32-bit value as a six digit code split in two groups of three.
func formatW2p2VerificationCode(_ value: UInt32) -> String {
    let six = String(format: "%06u", value % 1_000_000)
    return "\(six.prefix(3)) \(six.suffix(3))"
}

/// Derives AES key, bearer token and verification code with distinct HKDF labels.
/// Returns nil when a fingerprint is malformed.
func deriveW2p2SessionMaterial(
    sharedSecret: SharedSecret,
    sessionId: Data,
    initiatorPubDer: Data,
    responderPubDer: Data,
    initiatorFingerprint: String,
    responderFingerprint: String
) -> W2p2SessionMaterial? {
    guard let iFp = dataFromHex(normalizeSha256Fingerprint(initiatorFingerprint)), iFp.count == 32,
          let rFp = dataFromHex(normalizeSha256Fingerprint(responderFingerprint)), rFp.count == 32,
          !sessionId.isEmpty else { return nil }
    func derive(_ label: String, _ count: Int) -> Data {
        let info = w2p2HkdfInfo(label: label, initiatorPubDer: initiatorPubDer, responderPubDer: responderPubDer, initiatorFp: iFp, responderFp: rFp)
        let key = sharedSecret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: sessionId, sharedInfo: info, outputByteCount: count)
        return key.withUnsafeBytes { Data($0) }
    }
    let aes = derive("aes-key", 32)
    let tok = derive("bearer-token", 32)
    let code = derive("verify-code", 4)
    let codeValue = code.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    return W2p2SessionMaterial(
        sessionKey: SymmetricKey(data: aes),
        token: w2p2HexString(tok),
        verificationCode: formatW2p2VerificationCode(codeValue)
    )
}

/// True when a peer reply asks for a newer protocol (`NO\tUPDATE\t3` / `ERR\tUPDATE\t3`).
func isW2p2UpdateRequiredReply(_ line: String) -> Bool {
    let parts = line.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "\t").map(String.init)
    return parts.count >= 2 && (parts[0] == "NO" || parts[0] == "ERR") && parts[1] == "UPDATE"
}

func deriveBleFrameKey(sharedSecret: SharedSecret) -> SymmetricKey {
    let raw = sharedSecret.withUnsafeBytes { Data($0) }
    var hasher = SHA256()
    hasher.update(data: raw)
    hasher.update(data: Data("GlideDrop-v2-BleFrameKey".utf8))
    let keyBytes = hasher.finalize()
    return SymmetricKey(data: keyBytes)
}

func deriveSessionToken(sharedSecret: SharedSecret) -> String {
    let raw = sharedSecret.withUnsafeBytes { Data($0) }
    var hasher = SHA256()
    hasher.update(data: raw)
    hasher.update(data: Data("GlideDrop-v2-BearerToken".utf8))
    let digest = hasher.finalize()
    return digest.map { String(format: "%02x", $0) }.joined()
}

func decryptAesGcm(packet: Data, using key: SymmetricKey) -> Data? {
    guard packet.count >= 28,
          let box = try? AES.GCM.SealedBox(combined: packet),
          let opened = try? AES.GCM.open(box, using: key) else { return nil }
    return opened
}

func encryptBlePayload(_ plain: Data, key: SymmetricKey) -> Data {
    guard let sealed = try? AES.GCM.seal(plain, using: key),
          let combined = sealed.combined else {
        fatalError("[BLE-Security] BLE encryption failed - refusing to transmit unencrypted payload")
    }
    return combined
}

func decryptBlePayload(_ packet: Data, key: SymmetricKey) -> Data? {
    return decryptAesGcm(packet: packet, using: key)
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
let SHOW_UI_NOTIFICATION = Notification.Name("io.github.jakharamit44.glidedrop.showWindow")

func resolveRepoRoot() -> URL {
    if let env = ProcessInfo.processInfo.environment["GLIDEDROP_HOME"],
       (FileManager.default.fileExists(atPath: "\(env)/macos/glidedrop.sh") || FileManager.default.fileExists(atPath: "\(env)/glidedrop.sh")) {
        return URL(fileURLWithPath: env)
    }
    // 1. If running inside GlideDrop.app bundle, check Resources
    if let res = Bundle.main.resourceURL,
       (FileManager.default.fileExists(atPath: res.appendingPathComponent("glidedrop.sh").path) ||
        FileManager.default.fileExists(atPath: res.appendingPathComponent("macos/glidedrop.sh").path)) {
        return res
    }
    // 2. Check enclosing directory
    let enclosing = Bundle.main.bundleURL.deletingLastPathComponent()
    if FileManager.default.fileExists(atPath: enclosing.appendingPathComponent("macos/glidedrop.sh").path) ||
       FileManager.default.fileExists(atPath: enclosing.appendingPathComponent("glidedrop.sh").path) {
        return enclosing
    }
    // 3. Argument 0 walking
    var url = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent()
    for _ in 0..<6 {
        if FileManager.default.fileExists(atPath: url.appendingPathComponent("macos/glidedrop.sh").path) ||
           FileManager.default.fileExists(atPath: url.appendingPathComponent("glidedrop.sh").path) {
            return url
        }
        url.deleteLastPathComponent()
    }
    let pwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
    if FileManager.default.fileExists(atPath: pwd.appendingPathComponent("macos/glidedrop.sh").path) {
        return pwd
    }
    return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".glidedrop")
}

let REPO_ROOT = resolveRepoRoot()
let STATE_DIR: URL = {
    if let env = ProcessInfo.processInfo.environment["GLIDEDROP_STATE_DIR"], !env.isEmpty {
        let u = URL(fileURLWithPath: env)
        try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
        return u
    }
    let u = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".glidedrop")
    try? FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
    return u
}()
let SCRIPT_PATH: String = {
    if let p = Bundle.main.path(forResource: "glidedrop", ofType: "sh"), FileManager.default.fileExists(atPath: p) {
        return p
    }
    if let res = Bundle.main.resourceURL?.appendingPathComponent("glidedrop.sh").path, FileManager.default.fileExists(atPath: res) {
        return res
    }
    let p0 = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".glidedrop/glidedrop.sh").path
    if FileManager.default.fileExists(atPath: p0) { return p0 }
    let p1 = REPO_ROOT.appendingPathComponent("macos/glidedrop.sh").path
    if FileManager.default.fileExists(atPath: p1) { return p1 }
    let p2 = REPO_ROOT.appendingPathComponent("glidedrop.sh").path
    if FileManager.default.fileExists(atPath: p2) { return p2 }
    return p1
}()

func currentMacLanIp() -> String {
    var ifaddr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else { return "" }
    defer { freeifaddrs(ifaddr) }
    let wifiIface = getWifiInterfaceName()
    let activeCidr = loadActiveP2pSession()?.cidr
    let rawSsid = currentRawWifiSsid()

    func extractValidLanIpv4(_ ptr: UnsafeMutablePointer<ifaddrs>, rawWifiSsid: String? = nil) -> String? {
        guard let sa = ptr.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) else { return nil }
        var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(sa, socklen_t(sa.pointee.sa_len), &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST) == 0 else {
            return nil
        }
        let ip = String(cString: hostname)
        guard isNormalWifiIpv4(ip, activeP2pCidr: activeCidr, rawWifiSsid: rawWifiSsid), !isCgnatIpv4(ip) else {
            return nil
        }
        return ip
    }

    // Pass 1: prefer active Wi-Fi interface over secondary USB/Docker/virtual en* interfaces
    for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
        let flags = Int32(ptr.pointee.ifa_flags)
        guard (flags & (IFF_UP|IFF_RUNNING|IFF_LOOPBACK)) == (IFF_UP|IFF_RUNNING) else { continue }
        if String(cString: ptr.pointee.ifa_name) == wifiIface,
           let ip = extractValidLanIpv4(ptr, rawWifiSsid: rawSsid) {
            return ip
        }
    }

    // Pass 2: fallback to other active physical en* Ethernet interfaces
    for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
        let flags = Int32(ptr.pointee.ifa_flags)
        guard (flags & (IFF_UP|IFF_RUNNING|IFF_LOOPBACK)) == (IFF_UP|IFF_RUNNING) else { continue }
        let name = String(cString: ptr.pointee.ifa_name)
        if name != wifiIface && name.hasPrefix("en"),
           let ip = extractValidLanIpv4(ptr) {
            return ip
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
    if isTransferCancelled() {
        let rxLock = STATE_DIR.appendingPathComponent("rx_in_progress.lock")
        try? FileManager.default.removeItem(at: rxLock)
        return false
    }
    let rxLock = STATE_DIR.appendingPathComponent("rx_in_progress.lock")
    guard FileManager.default.fileExists(atPath: rxLock.path) else { return false }
    let now = Date().timeIntervalSince1970
    var isActive = false
    if let attrs = try? FileManager.default.attributesOfItem(atPath: rxLock.path),
       let mtime = attrs[.modificationDate] as? Date {
        if now - mtime.timeIntervalSince1970 < 30.0 { isActive = true }
    }
    if !isActive, let content = try? String(contentsOf: rxLock, encoding: .utf8) {
        let parts = content.split(separator: "\t")
        if parts.count >= 3, let ts = Double(parts[2]) {
            if (now - ts) < 30.0 { isActive = true }
        }
    }
    if !isActive {
        // Lock file is stale (> 30s old) - remove to prevent false positives and unblock radio operations
        try? FileManager.default.removeItem(at: rxLock)
        return false
    }
    return true
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
        let exIsFallback = exName.hasPrefix("Android Peer (") || exName == "Android Peer"
        if !exIsFallback && incomingIsFallback {
            // Ignore unnamed zombie BLE advertisements when a named peer is already live
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

func isStreamAborted(_ stream: InputStream?) -> Bool {
    guard let st = stream?.streamStatus else { return false }
    return st == .atEnd || st == .closed || st == .error
}

func waitForMacUserAccept(
    senderName: String,
    fileNames: [String],
    totalBytes: Int64,
    forcePrompt: Bool = false,
    isRemoteAborted: (() -> Bool)? = nil
) -> Bool {
    let settings = loadMacSettings()
    if settings.autoAccept && !forcePrompt { return true }

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
        if isTransferCancelled() {
            writeProgressJson(active: false)
            return false
        }
        if isRemoteAborted?() == true {
            print("[BLE-Daemon] Incoming request cancelled by \(senderName) before acceptance")
            fflush(stdout)
            writeProgressJson(active: false)
            return false
        }
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
    let flag = STATE_DIR.appendingPathComponent("cancel_transfer.flag")
    guard let s = try? String(contentsOf: flag, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
          let ts = Double(s) else {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: flag.path),
              let mtime = attrs[.modificationDate] as? Date else { return false }
        return Date().timeIntervalSince(mtime) < 10.0
    }
    return Date().timeIntervalSince1970 - ts < 10.0
}

func clearCancelFlag() {
    try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("cancel_transfer.flag"))
}

let TX_LOCK_TTL_SECONDS: TimeInterval = 180.0
let MAX_ENCRYPTED_BLE_ARCHIVE_BYTES = 30_000_000
let BLE_RAW_PRECHECK_MAX_BYTES: Int64 = 120_000_000
let BLE_AUTO_FALLBACK_MAX_RAW_BYTES: Int64 = 5_000_000
let MAX_BLE_META_BYTES = 1_048_576

func shouldAllowBleAutoFallback(fileCount: Int, totalRawBytes: Int64, txExitCode: Int32? = nil) -> Bool {
    if let code = txExitCode, (43...47).contains(code) {
        return false
    }
    if fileCount > 0 && totalRawBytes > BLE_AUTO_FALLBACK_MAX_RAW_BYTES {
        return false
    }
    return true
}

func shouldRetryP2pTx(fileCount: Int, totalRawBytes: Int64, txExitCode: Int32, elapsed: TimeInterval, cancelled: Bool) -> Bool {
    return txExitCode != 0 && !(43...47).contains(txExitCode) && !cancelled && elapsed < 15.0 &&
        !shouldAllowBleAutoFallback(fileCount: fileCount, totalRawBytes: totalRawBytes, txExitCode: txExitCode)
}

struct BleSenderActivityDeadline {
    let startedAt: TimeInterval
    private var lastActivityAt: TimeInterval?

    init(startedAt: TimeInterval = Date().timeIntervalSince1970) {
        self.startedAt = startedAt
    }

    mutating func hasTimedOut(transferStarted: Bool, progressUpdatedAt: TimeInterval?, now: TimeInterval) -> Bool {
        guard transferStarted else { return now - startedAt >= 300.0 }
        // Opening L2CAP ends the startup deadline; only inactivity can expire a live send.
        let previousActivity = lastActivityAt ?? now
        if let updatedAt = progressUpdatedAt, updatedAt.isFinite, updatedAt >= startedAt, updatedAt <= now {
            lastActivityAt = max(previousActivity, updatedAt)
        } else {
            lastActivityAt = previousActivity
        }
        return now - (lastActivityAt ?? now) >= 300.0
    }
}

func senderProgressUpdatedAt(stateDir: URL = STATE_DIR) -> TimeInterval? {
    guard let data = try? Data(contentsOf: stateDir.appendingPathComponent("transfer_progress.json")),
          let progress = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          progress["active"] as? Bool == true, progress["direction"] as? String == "Sending" else { return nil }
    return progress["updatedAt"] as? Double
}

func writeTxInProgressLock(timestamp: TimeInterval = Date().timeIntervalSince1970) {
    let txLock = STATE_DIR.appendingPathComponent("tx_in_progress.lock")
    try? String(timestamp).write(to: txLock, atomically: true, encoding: .utf8)
}

func hasActiveTxInProgressLock(now: TimeInterval = Date().timeIntervalSince1970) -> Bool {
    let txLock = STATE_DIR.appendingPathComponent("tx_in_progress.lock")
    guard FileManager.default.fileExists(atPath: txLock.path) else { return false }
    var isFresh = false
    if let raw = try? String(contentsOf: txLock, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
       let ts = Double(raw) {
        isFresh = (now - ts) < TX_LOCK_TTL_SECONDS
    } else if let attrs = try? FileManager.default.attributesOfItem(atPath: txLock.path),
              let mtime = attrs[.modificationDate] as? Date {
        isFresh = (now - mtime.timeIntervalSince1970) < TX_LOCK_TTL_SECONDS
    }
    if !isFresh {
        try? FileManager.default.removeItem(at: txLock)
        return false
    }
    return true
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
/// networks and activates its fail-closed base firewall (`catch all policy Deny`), dropping offline P2P subnet traffic.
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

/// Enforces the WARP pause at most once per `interval` during P2P join/transfer wait loops
/// because Always-On Zero Trust profiles can auto-reconnect WARP immediately on SSID change.
func keepCloudflareWarpPausedPeriodically(lastChecked: inout Date, interval: TimeInterval = 2.5) {
    let now = Date()
    if now.timeIntervalSince(lastChecked) >= interval {
        lastChecked = now
        keepCloudflareWarpPausedIfFlagged()
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

private var _cachedWifiInterface: String? = nil

func getWifiInterfaceName() -> String {
    if let cached = _cachedWifiInterface, !cached.isEmpty {
        return cached
    }
    if let name = CWWiFiClient.shared().interface()?.interfaceName, !name.isEmpty {
        _cachedWifiInterface = name
        return name
    }
    if let names = CWWiFiClient.shared().interfaceNames(), let first = names.first, !first.isEmpty {
        _cachedWifiInterface = first
        return first
    }
    let (_, out) = runProcessCapture("/usr/sbin/networksetup", ["-listallhardwareports"])
    let lines = out.components(separatedBy: "\n")
    var isWifiPort = false
    for line in lines {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("Hardware Port:") {
            let portName = trimmed.replacingOccurrences(of: "Hardware Port:", with: "").trimmingCharacters(in: .whitespaces).lowercased()
            isWifiPort = portName.contains("wi-fi") || portName.contains("wifi") || portName.contains("airport") || portName.contains("wlan")
        } else if isWifiPort && trimmed.hasPrefix("Device:") {
            let dev = trimmed.replacingOccurrences(of: "Device:", with: "").trimmingCharacters(in: .whitespaces)
            if !dev.isEmpty {
                _cachedWifiInterface = dev
                return dev
            }
        }
    }
    // Do not permanently cache fallback "en0" when lookup fails
    return "en0"
}

func parseAirportNetworkSsid(_ output: String) -> String {
    guard output.contains("Current Wi-Fi Network: ") else { return "" }
    let name = output.components(separatedBy: "Current Wi-Fi Network: ").last?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    if name.isEmpty || name.contains("not associated") {
        return ""
    }
    return name
}

func currentRawWifiSsid(on iface: String = getWifiInterfaceName()) -> String {
    if let ssid = CWWiFiClient.shared().interface(withName: iface)?.ssid(), !ssid.isEmpty {
        return ssid
    }
    let (_, out) = runProcessCapture("/usr/sbin/networksetup", ["-getairportnetwork", iface])
    return parseAirportNetworkSsid(out)
}

func currentWifiRouterIp(on iface: String = getWifiInterfaceName()) -> String? {
    let cleanIface = iface.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !cleanIface.isEmpty else { return nil }

    func validRouterCandidate(_ raw: String?) -> String? {
        guard let raw = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty,
              let v = parseIpv4Address(raw) else { return nil }
        if (v & 0xFF00_0000) == 0 || v == 0xFFFF_FFFF { return nil }
        if (v & 0xFF00_0000) == 0x7F00_0000 { return nil }
        if (v & 0xF000_0000) == 0xE000_0000 { return nil }
        return raw
    }

    if let store = SCDynamicStoreCreate(nil, "GlideDrop" as CFString, nil, nil),
       let dict = SCDynamicStoreCopyValue(store, "State:/Network/Interface/\(cleanIface)/IPv4" as CFString) as? [String: Any],
       let router = validRouterCandidate(dict["Router"] as? String) {
        return router
    }

    let (rc, ipconfigOut) = runProcessCapture("/usr/sbin/ipconfig", ["getoption", cleanIface, "router"])
    if rc == 0, let router = validRouterCandidate(ipconfigOut) {
        return router
    }

    let (routeRc, routeOut) = runProcessCapture("/sbin/route", ["-n", "get", "default"])
    if routeRc == 0 {
        var routeIface: String?
        var routeGateway: String?
        for line in routeOut.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.hasPrefix("interface:") {
                routeIface = trimmed.replacingOccurrences(of: "interface:", with: "").trimmingCharacters(in: .whitespacesAndNewlines)
            } else if trimmed.hasPrefix("gateway:") {
                routeGateway = trimmed.replacingOccurrences(of: "gateway:", with: "").trimmingCharacters(in: .whitespacesAndNewlines)
            }
        }
        if routeIface == cleanIface, let router = validRouterCandidate(routeGateway) {
            return router
        }
    }

    return nil
}

func currentWifiSsid() -> String {
    let name = currentRawWifiSsid()
    if name.hasPrefix("DIRECT-") {
        return ""
    }
    return name
}

/// True when the interface still reports the expected SSID, or when macOS redacts the SSID
/// (no Location authorization) so the name cannot contradict the interface-state association.
func wifiSsidConsistent(on iface: String, expected: String) -> Bool {
    let current = currentRawWifiSsid(on: iface)
    return current.isEmpty || current == expected
}

private var locationAuthManager: CLLocationManager?

func isLocationAuthorizedForWifiNames() -> Bool {
    let status = CLLocationManager().authorizationStatus
    return status == .authorizedAlways || status == .authorized
}

/// Requests Location authorization (required for macOS to reveal SSID/BSSID) before the first join.
/// Returns true when authorized. If denied or undetermined after the wait, logs where to enable it;
/// the join still proceeds because association is confirmed from interface state.
@discardableResult
func requestLocationAuthorizationForWifi(timeout: TimeInterval = 8.0) -> Bool {
    if isLocationAuthorizedForWifiNames() { return true }
    DispatchQueue.main.async {
        if locationAuthManager == nil { locationAuthManager = CLLocationManager() }
        locationAuthManager?.requestWhenInUseAuthorization()
        locationAuthManager?.startUpdatingLocation()
    }
    if !Thread.isMainThread {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if isLocationAuthorizedForWifiNames() { return true }
            if CLLocationManager().authorizationStatus != .notDetermined { break }
            Thread.sleep(forTimeInterval: 0.2)
        }
    }
    if isLocationAuthorizedForWifiNames() { return true }
    print("[BLE-Daemon] Location access is not granted, so macOS hides Wi-Fi names. Enable it in System Settings > Privacy & Security > Location Services > GlideDrop. Continuing with interface-state association.")
    fflush(stdout)
    return false
}

func saveCurrentWifiSsid() {
    requestLocationAuthorizationForWifi()
    // Record only from reliable data (a readable, non-P2P current association). Never guess from the
    // preferred list; if the name is hidden, restore falls back to re-enabling auto-join.
    let ssid = currentWifiSsid()
    if ssid.isEmpty {
        if !currentRawWifiSsid().hasPrefix("DIRECT-") { try? FileManager.default.removeItem(at: PREV_WIFI_FILE) }
        print("[BLE-Daemon] Home Wi-Fi name unavailable; will restore by re-enabling auto-join.")
        fflush(stdout)
    } else {
        try? ssid.write(to: PREV_WIFI_FILE, atomically: true, encoding: .utf8)
        print("[BLE-Daemon] Preserved home Wi-Fi network: '\(ssid)'")
        fflush(stdout)
    }
}

func topPreferredWifiNetwork() -> String {
    let iface = getWifiInterfaceName()
    let (_, out) = runProcessCapture("/usr/sbin/networksetup", ["-listpreferredwirelessnetworks", iface])
    for line in out.split(separator: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty && !trimmed.hasPrefix("Preferred networks") && !trimmed.hasPrefix("DIRECT-") {
            return trimmed
        }
    }
    return ""
}

private var _cachedWifiServiceName: String?

func getWifiServiceName() -> String {
    if let cached = _cachedWifiServiceName { return cached }
    let iface = getWifiInterfaceName()
    let (_, out) = runProcessCapture("/usr/sbin/networksetup", ["-listnetworkserviceorder"])
    let lines = out.components(separatedBy: "\n")
    var lastService = ""
    for line in lines {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        let clean = trimmed.trimmingCharacters(in: CharacterSet(charactersIn: "* \t"))
        if clean.hasPrefix("(") && clean.contains(")") {
            if let closeParen = clean.firstIndex(of: ")") {
                let name = String(clean[clean.index(after: closeParen)...]).trimmingCharacters(in: .whitespaces)
                if !name.isEmpty {
                    lastService = name
                }
            }
        } else if trimmed.contains("Device: \(iface)") {
            if !lastService.isEmpty {
                _cachedWifiServiceName = lastService
                return lastService
            }
        }
    }
    return "Wi-Fi"
}

let PREV_PROXY_FILE = STATE_DIR.appendingPathComponent("prev_proxy_settings.json")

struct ProxyEndpointConfig: Codable {
    let enabled: Bool
    let server: String
    let port: Int
    let authenticated: Bool
}

struct AppliedProxyTarget: Codable {
    let host: String
    let port: Int
    let cidr: String
}

struct SavedProxySettings: Codable {
    let service: String
    let socks: ProxyEndpointConfig
    let http: ProxyEndpointConfig
    let https: ProxyEndpointConfig
    let bypassDomains: [String]
    let appliedTarget: AppliedProxyTarget?
}

func parseProxyOutput(_ output: String) -> ProxyEndpointConfig {
    var enabled = false
    var server = ""
    var port = 0
    var authenticated = false
    for line in output.components(separatedBy: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        let lower = trimmed.lowercased()
        if lower.hasPrefix("enabled:") {
            let val = trimmed.components(separatedBy: ":").last?.trimmingCharacters(in: .whitespaces).lowercased() ?? ""
            enabled = (val == "yes")
        } else if lower.hasPrefix("server:") {
            server = trimmed.components(separatedBy: ":").dropFirst().joined(separator: ":").trimmingCharacters(in: .whitespaces)
        } else if lower.hasPrefix("port:") {
            if let p = Int(trimmed.components(separatedBy: ":").last?.trimmingCharacters(in: .whitespaces) ?? "") {
                port = p
            }
        } else if lower.hasPrefix("authenticated proxy enabled:") {
            let val = trimmed.components(separatedBy: ":").last?.trimmingCharacters(in: .whitespaces) ?? ""
            authenticated = (val == "1" || val.lowercased() == "yes")
        }
    }
    return ProxyEndpointConfig(enabled: enabled, server: server, port: port, authenticated: authenticated)
}

func parseBypassDomainsOutput(_ output: String) -> [String] {
    var domains: [String] = []
    for line in output.components(separatedBy: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty || trimmed.contains("aren't any bypass domains") {
            continue
        }
        domains.append(trimmed)
    }
    return domains
}

private var proxyEnabledInCurrentProcess = false
private let activeChildTxLock = NSLock()
private var activeChildTxProcess: Process?

func withProxyStateFileLock<T>(_ body: () -> T) -> T {
    let lockPath = STATE_DIR.appendingPathComponent("proxy_state.lock").path
    let fd = open(lockPath, O_CREAT | O_RDWR, 0o600)
    if fd >= 0 {
        flock(fd, LOCK_EX)
        defer {
            flock(fd, LOCK_UN)
            close(fd)
        }
        return body()
    }
    return body()
}

func isTcpPortReachable(host: String, port: Int, timeoutMs: Int = 200) -> Bool {
    guard !host.isEmpty, port > 0, port <= 65535 else { return false }
    var hints = addrinfo()
    hints.ai_family = AF_UNSPEC
    hints.ai_socktype = SOCK_STREAM
    hints.ai_flags = AI_NUMERICHOST
    var res: UnsafeMutablePointer<addrinfo>?
    let portStr = String(port)
    if getaddrinfo(host, portStr, &hints, &res) != 0 {
        hints.ai_flags = 0
        guard getaddrinfo(host, portStr, &hints, &res) == 0 else {
            return false
        }
    }
    guard let firstInfo = res else { return false }
    defer { freeaddrinfo(firstInfo) }

    var ptr: UnsafeMutablePointer<addrinfo>? = firstInfo
    while let info = ptr {
        let sock = socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
        if sock >= 0 {
            let flags = fcntl(sock, F_GETFL, 0)
            if flags >= 0 && fcntl(sock, F_SETFL, flags | O_NONBLOCK) >= 0 {
                let connRes = connect(sock, info.pointee.ai_addr, info.pointee.ai_addrlen)
                if connRes == 0 {
                    close(sock)
                    return true
                }
                if errno == EINPROGRESS {
                    var pollFd = pollfd(fd: sock, events: Int16(POLLOUT), revents: 0)
                    var pollRes: Int32 = -1
                    repeat {
                        pollRes = poll(&pollFd, 1, Int32(timeoutMs))
                    } while pollRes < 0 && errno == EINTR
                    if pollRes > 0 && (pollFd.revents & Int16(POLLOUT)) != 0 && (pollFd.revents & Int16(POLLERR | POLLNVAL)) == 0 {
                        var err: Int32 = 0
                        var errLen = socklen_t(MemoryLayout<Int32>.size)
                        if getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &errLen) == 0 && err == 0 {
                            close(sock)
                            return true
                        }
                    }
                }
            }
            close(sock)
        }
        ptr = info.pointee.ai_next
    }
    return false
}

func shouldClearFallbackP2pProxy(
    _ cfg: ProxyEndpointConfig,
    session: ActiveP2pSession?,
    currentRouterIp: String? = nil
) -> Bool {
    if let s = session, !cfg.server.isEmpty {
        if cfg.server == s.gatewayIp || (!s.cidr.isEmpty && cidrContains(cidr: s.cidr, ip: cfg.server)) {
            return true
        }
    }
    if let router = currentRouterIp?.trimmingCharacters(in: .whitespacesAndNewlines),
       !router.isEmpty,
       !cfg.server.isEmpty {
        if cfg.server == router {
            return true
        }
        if let routerCidr = deriveIpv4Cidr(ip: router), cidrContains(cidr: routerCidr, ip: cfg.server) {
            return true
        }
    }
    if cfg.enabled && (cfg.server == "127.0.0.1" || cfg.server == "::1") {
        let trackedPort = session?.proxyPort ?? 0
        if trackedPort > 0 && cfg.port == trackedPort {
            return true
        }
    }
    return false
}

func enableMacInternetProxy(host: String, port: Int, cidr: String? = nil) {
    let cleanHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !cleanHost.isEmpty, port >= 1 && port <= 65535 else {
        print("[BLE-Daemon] Cellular internet sharing disabled or invalid endpoint (\(cleanHost):\(port)) — skipping macOS system proxy")
        fflush(stdout)
        return
    }
    let activeSession = loadActiveP2pSession()
    let sessionCidr = (cidr?.isEmpty == false ? cidr! : nil)
        ?? (activeSession?.cidr.isEmpty == false ? activeSession?.cidr : nil)
        ?? deriveIpv4Cidr(ip: cleanHost)
        ?? ""
    let isLoopback = (cleanHost == "127.0.0.1" || cleanHost == "::1")
    if !isLoopback {
        guard isValidP2pGatewayIp(cleanHost) else {
            print("[BLE-Daemon] Non-P2P host \(cleanHost) — skipping macOS system proxy")
            fflush(stdout)
            return
        }
        if currentWifiP2pIp(matchingGateway: cleanHost, matchingCidr: sessionCidr.isEmpty ? nil : sessionCidr).isEmpty {
            print("[BLE-Daemon] No active P2P Wi-Fi Direct IP matching \(sessionCidr) — skipping proxy setup for \(cleanHost):\(port)")
            fflush(stdout)
            return
        }
    }

    guard isTcpPortReachable(host: cleanHost, port: port, timeoutMs: 500) else {
        print("[BLE-Daemon] Peer proxy \(cleanHost):\(port) unreachable or disabled — skipping macOS system proxy")
        fflush(stdout)
        return
    }

    withProxyStateFileLock {
        proxyEnabledInCurrentProcess = true
        let service = getWifiServiceName()

        // 1. Snapshot previous proxy settings if not already snapshotted
        if !FileManager.default.fileExists(atPath: PREV_PROXY_FILE.path) {
            let (_, socksOut) = runProcessCapture("/usr/sbin/networksetup", ["-getsocksfirewallproxy", service])
            let (_, httpOut) = runProcessCapture("/usr/sbin/networksetup", ["-getwebproxy", service])
            let (_, httpsOut) = runProcessCapture("/usr/sbin/networksetup", ["-getsecurewebproxy", service])
            let (_, bypassOut) = runProcessCapture("/usr/sbin/networksetup", ["-getproxybypassdomains", service])

            let saved = SavedProxySettings(
                service: service,
                socks: parseProxyOutput(socksOut),
                http: parseProxyOutput(httpOut),
                https: parseProxyOutput(httpsOut),
                bypassDomains: parseBypassDomainsOutput(bypassOut),
                appliedTarget: AppliedProxyTarget(host: cleanHost, port: port, cidr: sessionCidr)
            )
            if let data = try? JSONEncoder().encode(saved) {
                try? data.write(to: PREV_PROXY_FILE, options: .atomic)
                print("[BLE-Daemon] Snapshotted existing proxy settings for \(service) to \(PREV_PROXY_FILE.lastPathComponent)")
                fflush(stdout)
            }
        }

        // 2. Configure proxy bypass domains: preserve user's existing bypass domains alongside P2P / local bypasses
        var bypassList: [String] = []
        for entry in [sessionCidr, "localhost", "127.0.0.1", "::1", "*.local", "169.254/16"] {
            if !entry.isEmpty && !bypassList.contains(entry) {
                bypassList.append(entry)
            }
        }
        if let savedData = try? Data(contentsOf: PREV_PROXY_FILE),
           let savedObj = try? JSONDecoder().decode(SavedProxySettings.self, from: savedData) {
            for d in savedObj.bypassDomains {
                if !bypassList.contains(d) && !d.isEmpty {
                    bypassList.append(d)
                }
            }
        }
        var bypassArgs = ["-setproxybypassdomains", service]
        bypassArgs.append(contentsOf: bypassList)
        _ = runProcessCapture("/usr/sbin/networksetup", bypassArgs)

        // 3. Configure SOCKS5 proxy
        _ = runProcessCapture("/usr/sbin/networksetup", ["-setsocksfirewallproxy", service, cleanHost, String(port)])
        _ = runProcessCapture("/usr/sbin/networksetup", ["-setsocksfirewallproxystate", service, "on"])

        // 4. Configure Web (HTTP) proxy
        _ = runProcessCapture("/usr/sbin/networksetup", ["-setwebproxy", service, cleanHost, String(port)])
        _ = runProcessCapture("/usr/sbin/networksetup", ["-setwebproxystate", service, "on"])

        // 5. Configure Secure Web (HTTPS) proxy
        _ = runProcessCapture("/usr/sbin/networksetup", ["-setsecurewebproxy", service, cleanHost, String(port)])
        _ = runProcessCapture("/usr/sbin/networksetup", ["-setsecurewebproxystate", service, "on"])

        print("[BLE-Daemon] Dual-Protocol embedded proxy active for \(service) -> \(cleanHost):\(port) (SOCKS5 + HTTP CONNECT/Forward)")
        fflush(stdout)
    }
}

func disableMacInternetProxy() {
    withProxyStateFileLock {
        defer { proxyEnabledInCurrentProcess = false }
        let defaultService = getWifiServiceName()
        var targetService = defaultService
        let activeSession = loadActiveP2pSession()

        if FileManager.default.fileExists(atPath: PREV_PROXY_FILE.path) {
            if let data = try? Data(contentsOf: PREV_PROXY_FILE),
               let saved = try? JSONDecoder().decode(SavedProxySettings.self, from: data) {
                targetService = saved.service.isEmpty ? defaultService : saved.service

                // Restore SOCKS5
                if saved.socks.enabled && !saved.socks.server.isEmpty && saved.socks.port > 0 {
                    _ = runProcessCapture("/usr/sbin/networksetup", ["-setsocksfirewallproxy", targetService, saved.socks.server, String(saved.socks.port)])
                    _ = runProcessCapture("/usr/sbin/networksetup", ["-setsocksfirewallproxystate", targetService, "on"])
                } else {
                    _ = runProcessCapture("/usr/sbin/networksetup", ["-setsocksfirewallproxy", targetService, "", "0"])
                    _ = runProcessCapture("/usr/sbin/networksetup", ["-setsocksfirewallproxystate", targetService, "off"])
                }

                // Restore Web Proxy
                if saved.http.enabled && !saved.http.server.isEmpty && saved.http.port > 0 {
                    _ = runProcessCapture("/usr/sbin/networksetup", ["-setwebproxy", targetService, saved.http.server, String(saved.http.port)])
                    _ = runProcessCapture("/usr/sbin/networksetup", ["-setwebproxystate", targetService, "on"])
                } else {
                    _ = runProcessCapture("/usr/sbin/networksetup", ["-setwebproxy", targetService, "", "0"])
                    _ = runProcessCapture("/usr/sbin/networksetup", ["-setwebproxystate", targetService, "off"])
                }

                // Restore Secure Web Proxy
                if saved.https.enabled && !saved.https.server.isEmpty && saved.https.port > 0 {
                    _ = runProcessCapture("/usr/sbin/networksetup", ["-setsecurewebproxy", targetService, saved.https.server, String(saved.https.port)])
                    _ = runProcessCapture("/usr/sbin/networksetup", ["-setsecurewebproxystate", targetService, "on"])
                } else {
                    _ = runProcessCapture("/usr/sbin/networksetup", ["-setsecurewebproxy", targetService, "", "0"])
                    _ = runProcessCapture("/usr/sbin/networksetup", ["-setsecurewebproxystate", targetService, "off"])
                }

                // Restore bypass domains
                if !saved.bypassDomains.isEmpty {
                    var args = ["-setproxybypassdomains", targetService]
                    args.append(contentsOf: saved.bypassDomains)
                    _ = runProcessCapture("/usr/sbin/networksetup", args)
                } else {
                    _ = runProcessCapture("/usr/sbin/networksetup", ["-setproxybypassdomains", targetService, "Empty"])
                }
                print("[BLE-Daemon] Restored original proxy settings on \(targetService)")
                fflush(stdout)
            }
            try? FileManager.default.removeItem(at: PREV_PROXY_FILE)
        } else {
            // Fallback: If no snapshot file exists, only clear stale tracked/P2P proxy state (never unrelated local proxies)
            let fallbackRouterIp: String? = currentRawWifiSsid().hasPrefix("DIRECT-") ? currentWifiRouterIp(on: getWifiInterfaceName()) : nil
            let (_, socksOut) = runProcessCapture("/usr/sbin/networksetup", ["-getsocksfirewallproxy", targetService])
            let socksCfg = parseProxyOutput(socksOut)
            if shouldClearFallbackP2pProxy(socksCfg, session: activeSession, currentRouterIp: fallbackRouterIp) {
                _ = runProcessCapture("/usr/sbin/networksetup", ["-setsocksfirewallproxy", targetService, "", "0"])
                _ = runProcessCapture("/usr/sbin/networksetup", ["-setsocksfirewallproxystate", targetService, "off"])
            }

            let (_, httpOut) = runProcessCapture("/usr/sbin/networksetup", ["-getwebproxy", targetService])
            let httpCfg = parseProxyOutput(httpOut)
            if shouldClearFallbackP2pProxy(httpCfg, session: activeSession, currentRouterIp: fallbackRouterIp) {
                _ = runProcessCapture("/usr/sbin/networksetup", ["-setwebproxy", targetService, "", "0"])
                _ = runProcessCapture("/usr/sbin/networksetup", ["-setwebproxystate", targetService, "off"])
            }

            let (_, httpsOut) = runProcessCapture("/usr/sbin/networksetup", ["-getsecurewebproxy", targetService])
            let httpsCfg = parseProxyOutput(httpsOut)
            if shouldClearFallbackP2pProxy(httpsCfg, session: activeSession, currentRouterIp: fallbackRouterIp) {
                _ = runProcessCapture("/usr/sbin/networksetup", ["-setsecurewebproxy", targetService, "", "0"])
                _ = runProcessCapture("/usr/sbin/networksetup", ["-setsecurewebproxystate", targetService, "off"])
            }
        }
    }
}

func restoreMacInternetWifi(ssid: String = "DIRECT-") {
    let activeSession = loadActiveP2pSession()
    disableMacInternetProxy()
    try? FileManager.default.removeItem(at: LAN_FALLBACK_FILE)
    try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("pinned_peer_tls_fingerprint.txt"))
    clearP2pSessionTokens()
    clearOutgoingP2pToken()

    let iface = getWifiInterfaceName()
    // 1. ALWAYS unconditionally remove any ephemeral P2P network from preferred list so macOS never stays stuck or reconnects to it
    let (_, prefOut) = runProcessCapture("/usr/sbin/networksetup", ["-listpreferredwirelessnetworks", iface])
    for net in prefOut.components(separatedBy: "\n") {
        let trimmed = net.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("DIRECT-") {
            _ = runProcessCapture("/usr/sbin/networksetup", ["-removepreferredwirelessnetwork", iface, trimmed])
        }
    }
    if ssid.hasPrefix("DIRECT-") { forgetWifiDirectProfile(iface: iface, ssid: ssid) }

    func wifiHasNormalIpv4() -> Bool {
        let rawSsid = currentRawWifiSsid()
        if rawSsid.hasPrefix("DIRECT-") { return false }
        let sessionCidr = activeSession?.cidr ?? loadActiveP2pSession()?.cidr
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else { return false }
        defer { freeifaddrs(ifaddr) }
        for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let flags = Int32(ptr.pointee.ifa_flags)
            if (flags & (IFF_UP|IFF_RUNNING|IFF_LOOPBACK)) == (IFF_UP|IFF_RUNNING) {
                let name = String(cString: ptr.pointee.ifa_name)
                if name == iface {
                    guard let sa = ptr.pointee.ifa_addr else { continue }
                    if sa.pointee.sa_family == UInt8(AF_INET) {
                        var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                        if getnameinfo(sa, socklen_t(sa.pointee.sa_len), &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST) == 0 {
                            let ip = String(cString: hostname)
                            if isNormalWifiIpv4(ip, activeP2pCidr: sessionCidr, rawWifiSsid: rawSsid) {
                                return true
                            }
                        }
                    }
                }
            }
        }
        return false
    }

    // 2. Check if iface is already back on normal Wi-Fi or was never on P2P
    let curSsid = currentRawWifiSsid()
    let onP2p = curSsid.hasPrefix("DIRECT-") || !currentWifiP2pIp(matchingGateway: activeSession?.gatewayIp, matchingCidr: activeSession?.cidr).isEmpty
    let savedSsid = (try? String(contentsOf: PREV_WIFI_FILE, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    if !onP2p && (wifiHasNormalIpv4() || savedSsid.isEmpty) {
        print("[BLE-Daemon] \(iface) already on normal Wi-Fi ('\(curSsid)'). P2P cleanup completed.")
        fflush(stdout)
        try? FileManager.default.removeItem(at: PREV_WIFI_FILE)
        clearActiveP2pSession()
        resumeCloudflareWarpIfNeeded()
        return
    }

    if wifiHasNormalIpv4() && !onP2p {
        print("[BLE-Daemon] \(iface) connected to normal Wi-Fi. P2P removed from preferred list.")
        fflush(stdout)
        try? FileManager.default.removeItem(at: PREV_WIFI_FILE)
        clearActiveP2pSession()
        resumeCloudflareWarpIfNeeded()
        return
    }

    print("[BLE-Daemon] Restoring Mac Internet Wi-Fi (disconnecting P2P on \(iface))...")
    fflush(stdout)

    // 3. Resolve target home network to restore
    // Only a network recorded from reliable data is restored by name; never guess from the preferred list.
    let targetSsid = (!savedSsid.isEmpty && !savedSsid.hasPrefix("DIRECT-")) ? savedSsid : ""

    // 4. Disassociate iface using CoreWLAN to cleanly detach from P2P when still on P2P
    if onP2p {
        if let cwIface = CWWiFiClient.shared().interface(withName: iface) ?? CWWiFiClient.shared().interface() {
            cwIface.disassociate()
        }
        Thread.sleep(forTimeInterval: 0.5)
    }

    // 5. If target network is known and not yet reconnected, reassociate
    let activeNow = currentWifiSsid()
    if activeNow.isEmpty && !wifiHasNormalIpv4() {
        if !targetSsid.isEmpty {
            print("[BLE-Daemon] Fast-reassociating \(iface) to home Wi-Fi '\(targetSsid)'...")
            fflush(stdout)
            _ = runProcessCapture("/usr/sbin/networksetup", ["-setairportnetwork", iface, targetSsid])
        } else {
            // Home network unknown: let macOS auto-join its own preferred network by cycling Wi-Fi power.
            print("[BLE-Daemon] Home Wi-Fi unknown; re-enabling auto-join on \(iface).")
            fflush(stdout)
            _ = runProcessCapture("/usr/sbin/networksetup", ["-setairportpower", iface, "off"])
            Thread.sleep(forTimeInterval: 0.5)
            _ = runProcessCapture("/usr/sbin/networksetup", ["-setairportpower", iface, "on"])
        }
    }

    // 6. Wait synchronously up to 3.0s for iface to obtain normal Wi-Fi IPv4 before resuming WARP
    let waitDeadline = Date().addingTimeInterval(3.0)
    while Date() < waitDeadline {
        if wifiHasNormalIpv4() { break }
        Thread.sleep(forTimeInterval: 0.25)
    }

    try? FileManager.default.removeItem(at: PREV_WIFI_FILE)
    clearActiveP2pSession()
    resumeCloudflareWarpIfNeeded()
    print("[BLE-Daemon] Wi-Fi restored and auto-reassociation completed.")
    fflush(stdout)
}

func hasPendingWifiRestoreState(
    wifiP2pIp: String,
    wifiSsid: String,
    hasPrevProxy: Bool,
    hasPrevWifi: Bool,
    hasWarpPaused: Bool
) -> Bool {
    return !wifiP2pIp.isEmpty ||
        wifiSsid.hasPrefix("DIRECT-") ||
        hasPrevProxy ||
        hasPrevWifi ||
        hasWarpPaused
}

func needsMacInternetWifiRestore() -> Bool {
    if FileManager.default.fileExists(atPath: PREV_PROXY_FILE.path) ||
        FileManager.default.fileExists(atPath: PREV_WIFI_FILE.path) ||
        FileManager.default.fileExists(atPath: WARP_PAUSED_FILE.path) ||
        !currentWifiP2pIp().isEmpty {
        return true
    }
    return hasPendingWifiRestoreState(
        wifiP2pIp: "",
        wifiSsid: currentRawWifiSsid(),
        hasPrevProxy: false,
        hasPrevWifi: false,
        hasWarpPaused: false
    )
}

func readExact(
    _ stream: InputStream,
    count: Int,
    trackProgress: Bool = false,
    fileLabel: String = "Incoming File",
    fileCount: Int = 1,
    timeout: TimeInterval? = nil,
    checkCancel: Bool = false,
    onWaitTick: (() -> Void)? = nil,
    onTimeout: (() -> Void)? = nil
) -> Data? {
    guard count >= 0 else { return nil }
    if count == 0 { return Data() }

    func readSync(shouldStop: @escaping () -> Bool) -> Data? {
        var data = Data(count: count)
        var offset = 0
        let startTime = Date()
        var lastEmit = Date.distantPast
        while offset < count {
            if shouldStop() {
                if trackProgress { writeProgressJson(active: false) }
                return nil
            }
            if (trackProgress || checkCancel) && isTransferCancelled() {
                if trackProgress { writeProgressJson(active: false) }
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
                let status = stream.streamStatus
                if status == .atEnd || status == .error || status == .closed {
                    if trackProgress { writeProgressJson(active: false) }
                    return nil
                }
                Thread.sleep(forTimeInterval: 0.01)
            } else {
                if trackProgress { writeProgressJson(active: false) }
                return nil
            }
        }
        if trackProgress { writeProgressJson(active: false) }
        return data
    }

    guard let timeout = timeout, timeout > 0 else {
        return readSync { false }
    }

    let lock = NSLock()
    var aborted = false
    var result: Data? = nil
    let sem = DispatchSemaphore(value: 0)
    DispatchQueue.global(qos: .userInitiated).async {
        let d = readSync {
            lock.lock()
            let stop = aborted
            lock.unlock()
            return stop
        }
        lock.lock()
        if !aborted { result = d }
        lock.unlock()
        sem.signal()
    }

    let deadline = Date().addingTimeInterval(timeout)
    var lastTick = Date()
    while true {
        if (trackProgress || checkCancel) && isTransferCancelled() {
            lock.lock()
            aborted = true
            lock.unlock()
            if trackProgress { writeProgressJson(active: false) }
            onTimeout?()
            return nil
        }
        let remaining = deadline.timeIntervalSinceNow
        if remaining <= 0 {
            lock.lock()
            aborted = true
            lock.unlock()
            if trackProgress { writeProgressJson(active: false) }
            onTimeout?()
            return nil
        }
        let step = min(0.2, remaining)
        if sem.wait(timeout: .now() + step) == .success {
            lock.lock()
            let d = result
            lock.unlock()
            return d
        }
        if let tickCb = onWaitTick, Date().timeIntervalSince(lastTick) >= 2.0 {
            lastTick = Date()
            tickCb()
        }
    }
}

func writeAll(
    _ stream: OutputStream,
    data: Data,
    trackProgress: Bool = false,
    fileLabel: String = "Sending File",
    fileCount: Int = 1,
    peerName: String = "",
    clearProgressOnSuccess: Bool = false
) -> Bool {
    var offset = 0
    let total = data.count
    var idleLoops = 0
    var lastLoggedPct = -10
    let startTime = Date()
    var lastEmit = Date.distantPast
    var lastLockTouch = Date()
    while offset < total {
        if trackProgress && isTransferCancelled() {
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
                if now.timeIntervalSince(lastLockTouch) >= 15.0 {
                    lastLockTouch = now
                    writeTxInProgressLock(timestamp: now.timeIntervalSince1970)
                }
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
                        percent: min(99, pct),
                        peerName: peerName
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
    if trackProgress && clearProgressOnSuccess {
        writeProgressJson(active: false)
    }
    return true
}

private let wp2pJoinLock = NSLock()
private var wp2pJoinActive = false

func beginWp2pJoin() -> Bool {
    wp2pJoinLock.lock()
    defer { wp2pJoinLock.unlock() }
    guard !wp2pJoinActive else { return false }
    wp2pJoinActive = true
    return true
}

func finishWp2pJoin() {
    wp2pJoinLock.lock()
    defer { wp2pJoinLock.unlock() }
    wp2pJoinActive = false
}

struct ParsedWp2pJoinPayload: Equatable {
    let ssid: String
    let pass: String
    let goIp: String
    let proxyPort: Int
    let httpsPort: Int
    let isV2: Bool
}

func parseWp2pJoinCredentials(_ decStr: String) -> ParsedWp2pJoinPayload? {
    let parts = decStr.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
    guard parts.count >= 2 else { return nil }
    let ssid = parts[0]
    let pass = parts[1]
    guard !ssid.isEmpty, !pass.isEmpty else { return nil }
    let isV2 = parts.count >= 4
    let rawGo = parts.count >= 3 ? parts[2].trimmingCharacters(in: .whitespacesAndNewlines) : ""
    let goIp = isValidP2pGatewayIp(rawGo) ? rawGo : ""
    let rawProxy = parts.count >= 4 ? (Int(parts[3].trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0) : 0
    let proxyPort = (1...65535).contains(rawProxy) ? rawProxy : 0
    // Peer's runtime-assigned HTTPS port (5th field). Older peers omit it; 0 means "not supplied".
    let rawHttps = parts.count >= 5 ? (Int(parts[4].trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0) : 0
    let httpsPort = (1...65535).contains(rawHttps) ? rawHttps : 0
    return ParsedWp2pJoinPayload(ssid: ssid, pass: pass, goIp: goIp, proxyPort: proxyPort, httpsPort: httpsPort, isV2: isV2)
}

func formatWp2pJoinReply(macIp: String, isV2: Bool, macRxPort: Int, udpKeepalivePort: Int) -> String {
    if isV2 {
        return "OK \(macIp)\t\(macRxPort)\t\(udpKeepalivePort)\n"
    }
    return "OK \(macIp)\n"
}

func matchWifiP2pInterfaceAddress(
    ip: String,
    netmask: String?,
    actualSsid: String,
    requestedSsid: String? = nil,
    matchingGateway: String? = nil,
    matchingCidr: String? = nil,
    activeSession: ActiveP2pSession? = nil
) -> (ip: String, cidr: String)? {
    // Subnet overlap (including a previous session's subnet) is not association evidence.
    // A readable SSID must be a DIRECT-* name equal to the requested one. When macOS redacts the
    // SSID (no Location authorization) the name is not evidence either way, so association is
    // decided from interface state instead: the OS netmask must put the advertised group-owner
    // address on the same subnet as the interface address, and an explicit gateway is mandatory.
    let ssidReadable = !actualSsid.isEmpty
    if ssidReadable {
        guard actualSsid.hasPrefix("DIRECT-"), requestedSsid == nil || actualSsid == requestedSsid else { return nil }
    } else {
        guard let g = matchingGateway, !g.isEmpty else { return nil }
    }
    guard isRfc1918Ipv4(ip),
          let netmask = netmask,
          let prefix = prefixLengthFromIpv4Netmask(netmask),
          let actualCidr = deriveIpv4Cidr(ip: ip, prefixLen: prefix) else { return nil }
    let session = activeSession?.ssid == actualSsid ? activeSession : nil
    let gateway = matchingGateway ?? session?.gatewayIp
    if let gateway = gateway {
        guard isRfc1918Ipv4(gateway), ip != gateway,
              cidrContains(cidr: actualCidr, ip: gateway) else { return nil }
    } else if let cidr = matchingCidr {
        guard cidrContains(cidr: cidr, ip: ip) else { return nil }
    }
    return (ip, actualCidr)
}

func currentWifiP2pAddressAndCidr(matchingGateway: String? = nil, matchingCidr: String? = nil, matchingSsid: String? = nil, on interfaceName: String? = nil) -> (ip: String, cidr: String, ssid: String, interfaceName: String)? {
    var ifaddr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else { return nil }
    defer { freeifaddrs(ifaddr) }
    let wifiIface = interfaceName ?? getWifiInterfaceName()
    let activeSession = loadActiveP2pSession()
    let actualSsid = currentRawWifiSsid(on: wifiIface)
    let requestedSsid = matchingSsid ?? activeSession?.ssid
    let ssidReadable = !actualSsid.isEmpty
    if ssidReadable {
        guard actualSsid.hasPrefix("DIRECT-"), requestedSsid == nil || actualSsid == requestedSsid else { return nil }
    } else {
        // Redacted SSID: require a target gateway and confirm the DHCP router (route interface)
        // equals the advertised group-owner address before treating the interface as joined.
        let sessionGateway = (activeSession != nil && activeSession?.ssid == requestedSsid) ? activeSession?.gatewayIp : nil
        guard let gateway = matchingGateway ?? sessionGateway, !gateway.isEmpty,
              currentWifiRouterIp(on: wifiIface) == gateway else { return nil }
    }
    let effectiveGateway: String? = matchingGateway ?? (ssidReadable ? nil : ((activeSession?.ssid == requestedSsid) ? activeSession?.gatewayIp : nil))
    let reportedSsid = ssidReadable ? actualSsid : (requestedSsid ?? "")

    for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
        let flags = Int32(ptr.pointee.ifa_flags)
        guard (flags & (IFF_UP|IFF_RUNNING|IFF_LOOPBACK)) == (IFF_UP|IFF_RUNNING) else { continue }
        let name = String(cString: ptr.pointee.ifa_name)
        guard name == wifiIface,
              let sa = ptr.pointee.ifa_addr,
              sa.pointee.sa_family == UInt8(AF_INET) else { continue }
        var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(sa, socklen_t(sa.pointee.sa_len), &hostname, socklen_t(hostname.count), nil, 0, NI_NUMERICHOST) == 0 else {
            continue
        }
        let ip = String(cString: hostname)
        var netmaskStr: String? = nil
        if let maskSa = ptr.pointee.ifa_netmask, maskSa.pointee.sa_family == UInt8(AF_INET) {
            var maskBuf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(maskSa, socklen_t(maskSa.pointee.sa_len), &maskBuf, socklen_t(maskBuf.count), nil, 0, NI_NUMERICHOST) == 0 {
                netmaskStr = String(cString: maskBuf)
            }
        }
        if let matched = matchWifiP2pInterfaceAddress(
            ip: ip,
            netmask: netmaskStr,
            actualSsid: actualSsid,
            requestedSsid: requestedSsid,
            matchingGateway: effectiveGateway,
            matchingCidr: matchingCidr,
            activeSession: activeSession
        ) {
            // Reject an association change while the interface snapshot was being read.
            guard currentRawWifiSsid(on: wifiIface) == actualSsid else { return nil }
            return (matched.ip, matched.cidr, reportedSsid, wifiIface)
        }
    }
    return nil
}

func currentWifiP2pIp(matchingGateway: String? = nil, matchingCidr: String? = nil) -> String {
    return currentWifiP2pAddressAndCidr(matchingGateway: matchingGateway, matchingCidr: matchingCidr)?.ip ?? ""
}

/// Optional BSSID / channel hints for the group owner, taken from the encrypted credentials.
/// Used only to recognise the SoftAP when the OS redacts scan-result names.
struct WifiJoinHints {
    var bssid: String? = nil
    var channelHint: Int? = nil
}

struct WifiScanCandidate {
    let ssid: String?
    let bssid: String?
    let channel: Int
    let rssi: Int
}

/// Picks the index of the scan result to join. Order: readable exact name, then BSSID hint, then
/// channel hint among results whose name is hidden. Never picks an unrelated named network.
func selectWifiJoinCandidate(_ candidates: [WifiScanCandidate], ssid: String, hints: WifiJoinHints) -> Int? {
    func best(_ idxs: [Int]) -> Int? { idxs.max(by: { candidates[$0].rssi < candidates[$1].rssi }) }
    let all = Array(candidates.indices)
    if let i = best(all.filter { candidates[$0].ssid == ssid }) { return i }
    if let hint = hints.bssid?.lowercased(), !hint.isEmpty,
       let i = best(all.filter { candidates[$0].bssid?.lowercased() == hint }) { return i }
    if let ch = hints.channelHint, ch > 0 {
        return best(all.filter { (candidates[$0].ssid ?? "").isEmpty && candidates[$0].channel == ch })
    }
    return nil
}

/// Parses an Android `PENDING\t<retryAfterMs>` W2P2 reply. Returns the clamped retry delay in
/// milliseconds, or nil when the line is not a PENDING reply (OK, NO, BUSY, ERR keep their meaning).
func parseW2p2PendingRetryMs(_ line: String) -> Int? {
    let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed == "PENDING" || trimmed.hasPrefix("PENDING\t") || trimmed.hasPrefix("PENDING ") else { return nil }
    let fields = trimmed.split(whereSeparator: { $0 == "\t" || $0 == " " })
    let raw = fields.count >= 2 ? (Int(fields[1]) ?? 2000) : 2000
    return min(max(raw, 250), 5000)
}

/// Stage at which a Mac-to-Android Wi-Fi Direct send failed, with an action the user can take.
enum WifiDirectStage: String {
    case bluetoothConnect = "Bluetooth connect"
    case handshake = "handshake"
    case groupCreation = "group creation"
    case association = "association"
    case addressAssignment = "address assignment"
    case tlsPin = "TLS pin"
    case token = "token"

    var userAction: String {
        switch self {
        case .bluetoothConnect: return "Keep the phone unlocked and nearby with GlideDrop open, then try again."
        case .handshake: return "Open GlideDrop on the phone, accept the request, and try again."
        case .groupCreation: return "Make sure Wi-Fi is on and Wi-Fi Direct is allowed on the phone, then try again."
        case .association: return "Make sure Mac Wi-Fi is on. If a Location prompt appeared, allow it in System Settings > Privacy & Security > Location Services > GlideDrop, then try again."
        case .addressAssignment: return "Move the phone closer to the Mac and try again."
        case .tlsPin: return "The phone's certificate did not match. Retry; if it repeats, re-pair the devices."
        case .token: return "The phone rejected the session token. Retry the transfer."
        }
    }
}

enum WifiJoinFailure {
    case wifiOff
    case notFound
    case rejected
}

/// Most recent failure reason from joinWifiDirectNetwork (single sender per process).
var lastWifiJoinFailure: WifiJoinFailure? = nil

/// Delay before the next join attempt: exponential backoff from 1.5 s capped at 6 s.
func wifiJoinBackoff(attempt: Int) -> TimeInterval {
    min(6.0, 1.5 * pow(1.5, Double(max(0, attempt - 1))))
}

/// Removes the saved profile and stored password for a (per-session) Wi-Fi Direct name. Best effort.
func forgetWifiDirectProfile(iface: String, ssid: String) {
    guard ssid.hasPrefix("DIRECT-") else { return }
    _ = runProcessCapture("/usr/sbin/networksetup", ["-removepreferredwirelessnetwork", iface, ssid])
    _ = runProcessCapture("/usr/bin/security", ["delete-generic-password", "-a", ssid, "-D", "AirPort network password"])
}

/// Attempts one association pass to an ephemeral Wi-Fi Direct SoftAP. Returns true if the OS
/// accepted the join request (even though DHCP may still take a moment to assign a P2P IP).
func joinWifiDirectNetwork(iface: String, ssid: String, pass: String, logPrefix: String, attempt: Int = 1,
                           hints: WifiJoinHints = WifiJoinHints()) -> Bool {
    if let cwIface = CWWiFiClient.shared().interface(withName: iface) ?? CWWiFiClient.shared().interface() {
        if !cwIface.powerOn() {
            lastWifiJoinFailure = .wifiOff
            print("\(logPrefix) Wi-Fi interface \(iface) is powered off; cannot join \(ssid)")
            fflush(stdout)
            return false
        }
        // 1. Fast directed scan by name (works when the name is readable); otherwise run a full sweep and
        // match on BSSID / channelHint from the encrypted credentials, since the OS may redact SSIDs.
        var matchedNet: CWNetwork? = nil
        if let fastNets = try? cwIface.scanForNetworks(withName: ssid),
           let best = fastNets.max(by: { $0.rssiValue < $1.rssiValue }) {
            matchedNet = best
        } else {
            let wildNets: [CWNetwork]
            if let hiddenSweep = try? cwIface.scanForNetworks(withName: nil, includeHidden: true) {
                wildNets = Array(hiddenSweep)
            } else {
                wildNets = Array((try? cwIface.scanForNetworks(withName: nil)) ?? [])
            }
            let candidates = wildNets.map {
                WifiScanCandidate(ssid: $0.ssid, bssid: $0.bssid, channel: $0.wlanChannel?.channelNumber ?? 0, rssi: $0.rssiValue)
            }
            if let idx = selectWifiJoinCandidate(candidates, ssid: ssid, hints: hints) {
                matchedNet = wildNets[idx]
            } else {
                print("\(logPrefix) CoreWLAN full-channel sweep scanned \(wildNets.count) BSS(s), 0 matching \(ssid) (attempt \(attempt))")
                fflush(stdout)
            }
        }
        if let targetNet = matchedNet {
            do {
                try cwIface.associate(to: targetNet, password: pass)
                print("\(logPrefix) CoreWLAN associated to \(ssid) (ch \(targetNet.wlanChannel?.channelNumber ?? 0), rssi \(targetNet.rssiValue))")
                fflush(stdout)
                return true
            } catch {
                let nsErr = error as NSError
                print("\(logPrefix) CoreWLAN associate failed for \(ssid) (attempt \(attempt)): \(error.localizedDescription) [domain=\(nsErr.domain) code=\(nsErr.code) userInfo=\(nsErr.userInfo)]")
                fflush(stdout)
                lastWifiJoinFailure = .rejected
            }
        }
    }

    // Fallback to networksetup after the CoreWLAN sweep refreshed airportd's scan cache
    let (joinRc, joinOut) = runProcessCapture("/usr/sbin/networksetup", ["-setairportnetwork", iface, ssid, pass])
    let cleanJoinOut = joinOut.trimmingCharacters(in: .whitespacesAndNewlines)
    let lowerOut = cleanJoinOut.lowercased()
    let notFound = lowerOut.contains("could not find") || lowerOut.contains("failed") || lowerOut.contains("error")
    if joinRc == 0 && !notFound {
        if !cleanJoinOut.isEmpty {
            print("\(logPrefix) networksetup join \(ssid) on \(iface) (attempt \(attempt)): \(cleanJoinOut)")
            fflush(stdout)
        }
        return true
    }
    print("\(logPrefix) networksetup join \(ssid) on \(iface) (attempt \(attempt)) rc=\(joinRc)\(cleanJoinOut.isEmpty ? "" : ": \(cleanJoinOut)")")
    fflush(stdout)
    if lastWifiJoinFailure != .rejected { lastWifiJoinFailure = .notFound }
    return false
}

/// Joins an ephemeral Wi-Fi Direct SoftAP and waits for DHCP to assign an IP matching the group,
/// retrying join attempts when freshly started SoftAP beacons are not yet visible to macOS.
func associateWifiDirectWithRetry(
    iface: String,
    ssid: String,
    pass: String,
    matchingGateway: String?,
    timeout: TimeInterval = 25.0,
    logPrefix: String,
    lastWarpCheck: inout Date,
    isAborted: (() -> Bool)? = nil,
    hints: WifiJoinHints = WifiJoinHints(),
    maxAttempts: Int = 8,
    onTick: () -> Void
) -> (ip: String, cidr: String, ssid: String, interfaceName: String)? {
    guard !isTransferCancelled(), isAborted?() != true else { return nil }
    if let existing = currentWifiP2pAddressAndCidr(matchingGateway: matchingGateway, matchingSsid: ssid, on: iface), !existing.ip.isEmpty {
        return existing
    }
    lastWifiJoinFailure = nil
    // Clear any stale profile/password for this name before joining, and again if the join fails.
    forgetWifiDirectProfile(iface: iface, ssid: ssid)
    var joinedOk = false
    defer { if !joinedOk { forgetWifiDirectProfile(iface: iface, ssid: ssid) } }

    let deadline = Date().addingTimeInterval(timeout)
    var lastProgressTouch = Date()
    var lastJoinAttemptAt = Date.distantPast
    var attempt = 0
    var joinAccepted = false

    while Date() < deadline {
        if isTransferCancelled() || (isAborted?() == true) { return nil }
        keepCloudflareWarpPausedPeriodically(lastChecked: &lastWarpCheck)
        if let resolved = currentWifiP2pAddressAndCidr(matchingGateway: matchingGateway, matchingSsid: ssid, on: iface), !resolved.ip.isEmpty {
            joinedOk = true
            return resolved
        }

        let retryCooldown: TimeInterval = joinAccepted ? 5.0 : wifiJoinBackoff(attempt: attempt)
        if Date().timeIntervalSince(lastJoinAttemptAt) >= retryCooldown {
            if attempt >= maxAttempts { break }
            attempt += 1
            lastJoinAttemptAt = Date()
            joinAccepted = joinWifiDirectNetwork(iface: iface, ssid: ssid, pass: pass, logPrefix: logPrefix, attempt: attempt, hints: hints)
            keepCloudflareWarpPausedPeriodically(lastChecked: &lastWarpCheck, interval: 0.5)
            if let resolved = currentWifiP2pAddressAndCidr(matchingGateway: matchingGateway, matchingSsid: ssid, on: iface), !resolved.ip.isEmpty {
                joinedOk = true
                return resolved
            }
            // Unrecoverable: Wi-Fi is off, so further attempts cannot succeed. Stop now.
            if lastWifiJoinFailure == .wifiOff { break }
        }

        if Date().timeIntervalSince(lastProgressTouch) >= 2.0 {
            lastProgressTouch = Date()
            onTick()
        }
        Thread.sleep(forTimeInterval: 0.2)
    }

    guard !isTransferCancelled(), isAborted?() != true else { return nil }
    let finalResult = currentWifiP2pAddressAndCidr(matchingGateway: matchingGateway, matchingSsid: ssid, on: iface)
    if let r = finalResult, !r.ip.isEmpty { joinedOk = true }
    return finalResult
}

/// Stage that failed after associateWifiDirectWithRetry returned nil or an address-less result.
func wifiJoinFailureStage() -> WifiDirectStage {
    // The OS accepted a join request but never produced an address: address assignment.
    // Otherwise the SoftAP was never found, was refused, or Wi-Fi is off: association.
    lastWifiJoinFailure == nil ? .addressAssignment : .association
}

func logWifiDirectStageFailure(_ stage: WifiDirectStage, logPrefix: String) {
    print("\(logPrefix) Wi-Fi Direct failed at stage '\(stage.rawValue)'. Action: \(stage.userAction)")
    fflush(stdout)
}

func handleIncomingWp2pJoin(
    ssid: String,
    pass: String,
    out: OutputStream,
    goIp: String = "",
    proxyPort: Int = 0,
    httpsPort: Int = 0,
    isV2Join: Bool = false,
    peerName: String? = nil,
    sessionToken: String? = nil,
    peerTlsFingerprint: String,
    inp: InputStream? = nil,
    isRemoteDisconnected: (() -> Bool)? = nil,
    pauseWarp: () -> Bool = pauseCloudflareWarpIfNeeded,
    verificationCode: String? = nil
) {
    let suppliedGoIp = isValidP2pGatewayIp(goIp) ? goIp.trimmingCharacters(in: .whitespacesAndNewlines) : ""
    let effectiveProxyPort = (1...65535).contains(proxyPort) ? proxyPort : 0
    let macRxPort = readPortFile("mac_rx_port") ?? 0
    let udpKeepalivePort = readPortFile("awdl_bridge_port") ?? 0
    let isRemoteAbortedNow: () -> Bool = {
        isStreamAborted(inp) || (isRemoteDisconnected?() ?? false)
    }

    func revokeCurrentSessionToken() {
        if let tok = sessionToken {
            revokeP2pSessionToken(tok)
        }
    }
    guard beginWp2pJoin() else {
        // A concurrent request has no approval and must not borrow or clean up the owner's session.
        _ = writeAll(out, data: Data("ERR\n".utf8))
        return
    }
    defer {
        revokeCurrentSessionToken()
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("pinned_peer_tls_fingerprint.txt"))
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("wp2p_authorized_session.json"))
        finishWp2pJoin()
    }
    guard isValidSha256Fingerprint(peerTlsFingerprint),
          ssid.hasPrefix("DIRECT-"), ssid.utf8.count <= 32, !pass.isEmpty else {
        print("[BLE-Daemon] Rejected invalid WP2P request: SSID '\(ssid)' does not start with DIRECT-")
        revokeCurrentSessionToken()
        _ = writeAll(out, data: Data("ERR\n".utf8))
        return
    }
    guard (1...65535).contains(httpsPort), (1...65535).contains(macRxPort), (1...65535).contains(udpKeepalivePort) else {
        print("[BLE-Daemon] Rejected WP2P request for \(ssid): missing runtime-assigned port (peer httpsPort=\(httpsPort), mac rx=\(macRxPort), keepalive=\(udpKeepalivePort)). Update GlideDrop on both devices.")
        fflush(stdout)
        revokeCurrentSessionToken()
        _ = writeAll(out, data: Data("ERR\n".utf8))
        return
    }
    if isV2Join && suppliedGoIp.isEmpty {
        print("[BLE-Daemon] Rejected v2 WP2P request for \(ssid): missing valid GO IP")
        revokeCurrentSessionToken()
        _ = writeAll(out, data: Data("ERR\n".utf8))
        return
    }

    let incomingPeerName = peerName ?? (loadActivePeersFromDisk(maxAge: 30.0).first?.name ?? "Nearby Device")
    clearCancelFlag()

    // Gate incoming WP2P join behind mandatory explicit user confirmation even when autoAccept is enabled
    if !waitForMacUserAccept(senderName: incomingPeerName, fileNames: ["5 GHz Wi-Fi Direct Connection (\(ssid))" + (verificationCode.map { " • Verification code \($0)" } ?? "")], totalBytes: 0, forcePrompt: true, isRemoteAborted: isRemoteAbortedNow) {
        print("[BLE-Daemon] User declined or sender cancelled incoming WP2P connection request from \(incomingPeerName)")
        revokeCurrentSessionToken()
        _ = writeAll(out, data: Data("ERR\n".utf8))
        return
    }

    let authSessionFile = STATE_DIR.appendingPathComponent("wp2p_authorized_session.json")
    try? FileManager.default.removeItem(at: authSessionFile)
    clearActiveP2pSession()
    clearOutgoingP2pToken()

    let uploadDoneFile = STATE_DIR.appendingPathComponent("upload_completed.flag")
    try? FileManager.default.removeItem(at: uploadDoneFile)

    // Pause Cloudflare WARP before associating en0 to offline DIRECT-* P2P so WARP's 36s Happy Eyeballs
    // fail-closed firewall never drops P2P subnet traffic mid-transfer.
    guard pauseWarp() else {
        print("[BLE-Daemon] WARP switch locked — refusing LAN transport; peer may use encrypted BLE fallback")
        fflush(stdout)
        _ = writeAll(out, data: Data("ERR\n".utf8))
        return
    }

    saveCurrentWifiSsid()
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
    print("[BLE-Daemon] Incoming WP2P 5GHz Wi-Fi Direct request: joining \(ssid)\(suppliedGoIp.isEmpty ? "" : " (GO \(suppliedGoIp))")...")
    fflush(stdout)

    let wifiIface = getWifiInterfaceName()
    let matchGwArg: String? = suppliedGoIp.isEmpty ? nil : suppliedGoIp
    var lastWarpCheck = Date()
    let resolvedP2p = associateWifiDirectWithRetry(
        iface: wifiIface,
        ssid: ssid,
        pass: pass,
        matchingGateway: matchGwArg,
        timeout: 38.0,
        logPrefix: "[BLE-Daemon]",
        lastWarpCheck: &lastWarpCheck,
        isAborted: isRemoteAbortedNow
    ) {
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
    }

    guard !isTransferCancelled(), !isRemoteAbortedNow(), let joined = resolvedP2p, !joined.ip.isEmpty else {
        logWifiDirectStageFailure(wifiJoinFailureStage(), logPrefix: "[BLE-Daemon]")
        writeProgressJson(active: false)
        restoreMacInternetWifi(ssid: ssid)
        revokeCurrentSessionToken()
        _ = writeAll(out, data: Data("ERR\n".utf8))
        return
    }
    var effectiveGoIp = suppliedGoIp
    if effectiveGoIp.isEmpty {
        let routerDeadline = Date().addingTimeInterval(2.0)
        while Date() < routerDeadline {
            if let discovered = currentWifiRouterIp(on: wifiIface), isValidP2pGatewayIp(discovered) {
                effectiveGoIp = discovered
                break
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
    }
    guard isRfc1918Ipv4(effectiveGoIp), effectiveGoIp != joined.ip,
          cidrContains(cidr: joined.cidr, ip: effectiveGoIp),
          wifiSsidConsistent(on: joined.interfaceName, expected: joined.ssid) else {
        print("[BLE-Daemon] Joined \(ssid) at \(joined.ip) but OS did not report a valid P2P gateway router — failing closed")
        fflush(stdout)
        writeProgressJson(active: false)
        restoreMacInternetWifi(ssid: ssid)
        revokeCurrentSessionToken()
        _ = writeAll(out, data: Data("ERR\n".utf8))
        return
    }
    let macP2pIp = joined.ip
    let sessionCidr = joined.cidr
    guard writeActiveP2pSession(
        ssid: joined.ssid,
        interfaceName: joined.interfaceName,
        gatewayIp: effectiveGoIp,
        cidr: sessionCidr,
        httpsPort: httpsPort,
        proxyPort: effectiveProxyPort,
        macRxPort: macRxPort,
        udpKeepalivePort: udpKeepalivePort
    ), writeAtomicPrivateFile(data: Data(normalizeSha256Fingerprint(peerTlsFingerprint).utf8),
                              to: STATE_DIR.appendingPathComponent("pinned_peer_tls_fingerprint.txt")) else {
        writeProgressJson(active: false)
        restoreMacInternetWifi(ssid: ssid)
        _ = writeAll(out, data: Data("ERR\n".utf8))
        return
    }
    if let tok = sessionToken {
        writeWp2pAuthorization(senderName: incomingPeerName, ssid: joined.ssid, token: tok, peerIp: effectiveGoIp)
        writeOutgoingP2pToken(tok, host: effectiveGoIp, port: httpsPort)
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
    print("[BLE-Daemon] Joined \(ssid) at \(macP2pIp) (cidr=\(sessionCidr)), signaling peer...")
    fflush(stdout)
    if effectiveProxyPort > 0 {
        enableMacInternetProxy(host: effectiveGoIp, port: effectiveProxyPort, cidr: sessionCidr)
    }
    let okReply = formatWp2pJoinReply(macIp: macP2pIp, isV2: isV2Join, macRxPort: macRxPort, udpKeepalivePort: udpKeepalivePort)
    if !writeAll(out, data: Data(okReply.utf8)) {
        print("[BLE-Daemon] Warning: BLE L2CAP reply stream closed while sending \(okReply.trimmingCharacters(in: .whitespacesAndNewlines)); waiting briefly for TCP fallback")
        fflush(stdout)
    }

    let askFile = STATE_DIR.appendingPathComponent("pending_ask.json")
    let txFile = STATE_DIR.appendingPathComponent("transfer_progress.json")

    // Phase 1: Wait up to 30s for the peer to initiate the HTTPS transfer
    let startDeadline = Date().addingTimeInterval(30.0)
    var lastPhase1ProgressTouch = Date()
    var transferDetected = false
    while Date() < startDeadline {
        if isTransferCancelled() {
            print("[BLE-Daemon] Transfer cancelled by user during Phase 1 handshake — restoring Wi-Fi")
            fflush(stdout)
            writeProgressJson(active: false)
            restoreMacInternetWifi(ssid: ssid)
            try? FileManager.default.removeItem(at: authSessionFile)
            return
        }
        keepCloudflareWarpPausedPeriodically(lastChecked: &lastWarpCheck)
        let detected = autoreleasepool { () -> Bool in
            if FileManager.default.fileExists(atPath: askFile.path) ||
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
        if isRemoteAbortedNow() {
            print("[BLE-Daemon] Sender cancelled/disconnected before HTTPS handshake — restoring Wi-Fi")
            fflush(stdout)
            writeProgressJson(active: false)
            restoreMacInternetWifi(ssid: ssid)
            try? FileManager.default.removeItem(at: authSessionFile)
            return
        }
        if Date().timeIntervalSince(lastPhase1ProgressTouch) >= 2.0 {
            lastPhase1ProgressTouch = Date()
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

    // Phase 2: Transfer is active. Keep link alive until completion or peer disconnect/cancel.
    var sawTransferActivity = false
    var lastActivity = Date()
    var lastKeepAlivePing = Date.distantPast
    var uploadCompleted = false

    while true {
        if isTransferCancelled() {
            print("[BLE-Daemon] Transfer cancelled by user during Phase 2 stream — restoring Wi-Fi")
            fflush(stdout)
            break
        }
        let shouldBreak = autoreleasepool { () -> Bool in
            if Date().timeIntervalSince(lastKeepAlivePing) >= 2.0 {
                lastKeepAlivePing = Date()
                DispatchQueue.global(qos: .utility).async {
                    _ = runProcessCapture("/sbin/ping", ["-c", "1", "-t", "1", "-W", "500", effectiveGoIp])
                }
            }

            keepCloudflareWarpPausedPeriodically(lastChecked: &lastWarpCheck)

            if FileManager.default.fileExists(atPath: uploadDoneFile.path) {
                try? FileManager.default.removeItem(at: uploadDoneFile)
                uploadCompleted = true
                print("[BLE-Daemon] Upload completed successfully — restoring Wi-Fi immediately")
                fflush(stdout)
                Thread.sleep(forTimeInterval: 1.0)
                return true
            }

            let isAsk = FileManager.default.fileExists(atPath: askFile.path)
            let now = Date().timeIntervalSince1970

            var isProgressActive = false
            if let data = try? Data(contentsOf: txFile),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let active = obj["active"] as? Bool, active,
               let updatedAt = obj["updatedAt"] as? Double {
                if (now - updatedAt) < 30.0 { isProgressActive = true }
            }

            let isActiveTcp = hasActiveTcpReceiverConnection()

            if isAsk || isProgressActive || isActiveTcp {
                if isProgressActive || isActiveTcp {
                    sawTransferActivity = true
                }
                lastActivity = Date()
            } else {
                let quietFor = Date().timeIntervalSince(lastActivity)
                let idleThreshold: TimeInterval = isRemoteAbortedNow() ? 1.5 : (sawTransferActivity ? 3.5 : 8.0)
                if quietFor >= idleThreshold {
                    print("[BLE-Daemon] Transfer stream ended (quiet=\(String(format: "%.1f", quietFor))s, remoteAborted=\(isRemoteAbortedNow())) — restoring Wi-Fi")
                    fflush(stdout)
                    return true
                }
            }
            return false
        }
        if shouldBreak { break }
        Thread.sleep(forTimeInterval: 0.5)
    }

    if !uploadCompleted {
        writeProgressJson(active: false)
    }
    restoreMacInternetWifi(ssid: ssid)
}

enum DvzipBuildError: Error, LocalizedError {
    case exceedsMaxOutputBytes(limit: Int)
    case unreadableInputFile(URL)
    case gzipFailed(status: Int32)

    var errorDescription: String? {
        switch self {
        case .exceedsMaxOutputBytes(let limit):
            return "Compressed archive exceeded \(limit) byte limit"
        case .unreadableInputFile(let url):
            return "Could not read file: \(url.lastPathComponent)"
        case .gzipFailed(let status):
            return "gzip exited with status \(status)"
        }
    }
}

enum BleFallbackCapError: Error, LocalizedError {
    case exceedsRawPrecheckLimit(totalRawBytes: Int64, limit: Int)
    case exceedsCompressedOrEncryptedLimit(totalRawBytes: Int64, encryptedBytes: Int, limit: Int)
    case metadataExceedsLimit(metaBytes: Int, limit: Int)

    var errorDescription: String? {
        switch self {
        case .exceedsRawPrecheckLimit(let totalRawBytes, _):
            return "5 GHz Wi-Fi Direct failed and payload (\(formatByteSize(totalRawBytes))) exceeds the 30 MB Bluetooth LE fallback limit."
        case .exceedsCompressedOrEncryptedLimit(let totalRawBytes, _, _):
            return "5 GHz Wi-Fi Direct failed and payload (\(formatByteSize(totalRawBytes))) exceeds the 30 MB Bluetooth LE fallback limit."
        case .metadataExceedsLimit(let metaBytes, let limit):
            return "Bluetooth LE metadata (\(metaBytes) B) exceeds \(limit) B limit."
        }
    }
}

func makeOdcCpioHeader(path: String, ino: Int, mode: Int, size: Int64, mtime: Int64) -> Data {
    let nameBytes = Array(path.utf8) + [0]
    let safeSize = max(Int64(0), size)
    let safeMtime = max(Int64(0), mtime)
    let header: String
    if safeSize > 0x1FFFFFFFF {
        header = String(
            format: "070764%016llx%08x%08x%08x%08x%016llx%016llx%08x%08x",
            UInt64(ino), UInt32(mode), UInt32(501), UInt32(20), UInt32(1),
            UInt64(safeMtime), UInt64(safeSize), UInt32(nameBytes.count), UInt32(0)
        )
    } else {
        header = String(
            format: "070707%06o%06o%06o%06o%06o%06o%06o%011llo%06o%011llo",
            UInt32(0), UInt32(ino & 0x3FFFF), UInt32(mode), UInt32(501), UInt32(20), UInt32(1),
            UInt32(0), UInt64(safeMtime), UInt32(nameBytes.count), UInt64(safeSize)
        )
    }
    var d = Data(header.utf8)
    d.append(contentsOf: nameBytes)
    return d
}

func buildDvzipCpio(files: [URL], maxOutputBytes: Int? = nil) throws -> (Data, [[String: Any]]) {
    guard !files.isEmpty else { return (Data(), []) }

    struct PreparedFile {
        let url: URL
        let name: String
        let size: Int64
        let mtime: Int64
    }

    var prepared: [PreparedFile] = []
    var fileDicts: [[String: Any]] = []
    for url in files {
        let name = url.lastPathComponent
        if name.hasPrefix("._") { continue }
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir),
              !isDir.boolValue,
              let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              FileManager.default.isReadableFile(atPath: url.path) else {
            throw DvzipBuildError.unreadableInputFile(url)
        }
        let sz = max(Int64(0), (attrs[.size] as? NSNumber)?.int64Value ?? 0)
        let mtimeDate = (attrs[.modificationDate] as? Date) ?? Date()
        let mtimeSec = max(Int64(0), Int64(mtimeDate.timeIntervalSince1970))
        prepared.append(PreparedFile(url: url, name: name, size: sz, mtime: mtimeSec))
        fileDicts.append([
            "FileName": name,
            "FileType": "public.data",
            "FileSize": sz,
            "FileBomPath": "./\(name)",
            "FileIsDirectory": false,
            "ConvertMediaFormats": false
        ])
    }
    guard !prepared.isEmpty else { return (Data(), []) }

    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/gzip")
    proc.arguments = ["-1", "-c"]
    let inPipe = Pipe()
    let outPipe = Pipe()
    proc.standardInput = inPipe
    proc.standardOutput = outPipe
    proc.standardError = FileHandle.nullDevice
    try proc.run()

    let stateLock = NSLock()
    var abortedForLimit = false
    var writerError: Error? = nil

    func isAborted() -> Bool {
        stateLock.lock()
        let v = abortedForLimit
        stateLock.unlock()
        return v
    }

    let writerGroup = DispatchGroup()
    writerGroup.enter()
    DispatchQueue.global(qos: .userInitiated).async {
        defer { writerGroup.leave() }
        let wh = inPipe.fileHandleForWriting
        defer { try? wh.close() }
        var ino = 1

        func nextOdcHdr(path: String, mode: Int, size: Int64, mtime: Int64) -> Data {
            let d = makeOdcCpioHeader(path: path, ino: ino, mode: mode, size: size, mtime: mtime)
            ino += 1
            return d
        }

        do {
            let nowSec = Int64(Date().timeIntervalSince1970)
            try wh.write(contentsOf: nextOdcHdr(path: ".", mode: 0o040755, size: 0, mtime: nowSec))
            for entry in prepared {
                if isAborted() { return }
                let handle = try FileHandle(forReadingFrom: entry.url)
                defer { try? handle.close() }
                try wh.write(contentsOf: nextOdcHdr(path: "./\(entry.name)", mode: 0o100644, size: entry.size, mtime: entry.mtime))
                var remaining = entry.size
                while remaining > 0 {
                    if isAborted() { return }
                    let toRead = Int(min(Int64(65536), remaining))
                    let chunk = (try handle.read(upToCount: toRead)) ?? Data()
                    if chunk.isEmpty {
                        throw DvzipBuildError.unreadableInputFile(entry.url)
                    }
                    try wh.write(contentsOf: chunk)
                    remaining -= Int64(chunk.count)
                }
            }
            try wh.write(contentsOf: nextOdcHdr(path: "TRAILER!!!", mode: 0, size: 0, mtime: 0))
        } catch {
            if !isAborted() {
                stateLock.lock()
                if writerError == nil { writerError = error }
                stateLock.unlock()
            }
        }
    }

    var gzData = Data()
    let rh = outPipe.fileHandleForReading
    while true {
        let chunk = (try? rh.read(upToCount: 65536)) ?? Data()
        if chunk.isEmpty { break }
        if let maxBytes = maxOutputBytes, gzData.count + chunk.count > maxBytes {
            stateLock.lock()
            abortedForLimit = true
            stateLock.unlock()
            proc.terminate()
            try? rh.close()
            writerGroup.wait()
            proc.waitUntilExit()
            throw DvzipBuildError.exceedsMaxOutputBytes(limit: maxBytes)
        }
        gzData.append(chunk)
    }
    try? rh.close()
    writerGroup.wait()
    proc.waitUntilExit()

    stateLock.lock()
    let capturedWriterErr = writerError
    stateLock.unlock()
    if let err = capturedWriterErr {
        throw err
    }
    if proc.terminationStatus != 0 {
        throw DvzipBuildError.gzipFailed(status: proc.terminationStatus)
    }
    return (gzData, fileDicts)
}

func prepareBleFallbackPayload(
    files: [URL],
    urls: [String],
    totalRawBytes: Int64,
    senderName: String,
    maxEncryptedArchiveBytes: Int = MAX_ENCRYPTED_BLE_ARCHIVE_BYTES,
    rawPrecheckMaxBytes: Int64 = BLE_RAW_PRECHECK_MAX_BYTES
) throws -> (metaData: Data, gzData: Data) {
    if !files.isEmpty && totalRawBytes > rawPrecheckMaxBytes {
        throw BleFallbackCapError.exceedsRawPrecheckLimit(
            totalRawBytes: totalRawBytes,
            limit: maxEncryptedArchiveBytes
        )
    }
    let maxCompressedBytes = max(0, maxEncryptedArchiveBytes - 28)
    let gzData: Data
    let fileDicts: [[String: Any]]
    do {
        (gzData, fileDicts) = try buildDvzipCpio(files: files, maxOutputBytes: maxCompressedBytes)
    } catch DvzipBuildError.exceedsMaxOutputBytes(let limit) {
        throw BleFallbackCapError.exceedsCompressedOrEncryptedLimit(
            totalRawBytes: totalRawBytes,
            encryptedBytes: limit + 28,
            limit: maxEncryptedArchiveBytes
        )
    }

    let metaDict: [String: Any] = [
        "SenderComputerName": senderName,
        "SenderModelName": "MacBookPro18,2",
        "BundleID": urls.isEmpty ? "com.apple.finder" : "com.apple.Safari",
        "Items": urls as [Any],
        "Files": fileDicts
    ]
    let metaData = try PropertyListSerialization.data(fromPropertyList: metaDict, format: .binary, options: 0)
    if metaData.count + 28 > MAX_BLE_META_BYTES {
        throw BleFallbackCapError.metadataExceedsLimit(metaBytes: metaData.count + 28, limit: MAX_BLE_META_BYTES)
    }
    if !gzData.isEmpty && gzData.count + 28 > maxEncryptedArchiveBytes {
        throw BleFallbackCapError.exceedsCompressedOrEncryptedLimit(
            totalRawBytes: totalRawBytes,
            encryptedBytes: gzData.count + 28,
            limit: maxEncryptedArchiveBytes
        )
    }
    return (metaData, gzData)
}

func buildEncryptedBleFallbackFrame(
    metaData: Data,
    gzData: Data,
    totalRawBytes: Int64 = 0,
    sessionKey: SymmetricKey,
    maxEncryptedArchiveBytes: Int = MAX_ENCRYPTED_BLE_ARCHIVE_BYTES
) throws -> Data {
    let encMeta = encryptBlePayload(metaData, key: sessionKey)
    if encMeta.count > MAX_BLE_META_BYTES {
        throw BleFallbackCapError.metadataExceedsLimit(metaBytes: encMeta.count, limit: MAX_BLE_META_BYTES)
    }
    let encArch = gzData.isEmpty ? Data() : encryptBlePayload(gzData, key: sessionKey)
    if encArch.count > maxEncryptedArchiveBytes {
        throw BleFallbackCapError.exceedsCompressedOrEncryptedLimit(
            totalRawBytes: totalRawBytes,
            encryptedBytes: encArch.count,
            limit: maxEncryptedArchiveBytes
        )
    }
    var frame = Data("ADRE".utf8)
    var mLen = UInt32(encMeta.count).bigEndian
    var aLen = UInt32(encArch.count).bigEndian
    frame.append(Data(bytes: &mLen, count: 4))
    frame.append(Data(bytes: &aLen, count: 4))
    frame.append(encMeta)
    frame.append(encArch)
    return frame
}

func buildEncryptedBleFallbackFrame(
    files: [URL],
    urls: [String],
    totalRawBytes: Int64,
    senderName: String,
    sessionKey: SymmetricKey,
    maxEncryptedArchiveBytes: Int = MAX_ENCRYPTED_BLE_ARCHIVE_BYTES,
    rawPrecheckMaxBytes: Int64 = BLE_RAW_PRECHECK_MAX_BYTES
) throws -> Data {
    let prepared = try prepareBleFallbackPayload(
        files: files,
        urls: urls,
        totalRawBytes: totalRawBytes,
        senderName: senderName,
        maxEncryptedArchiveBytes: maxEncryptedArchiveBytes,
        rawPrecheckMaxBytes: rawPrecheckMaxBytes
    )
    return try buildEncryptedBleFallbackFrame(
        metaData: prepared.metaData,
        gzData: prepared.gzData,
        totalRawBytes: totalRawBytes,
        sessionKey: sessionKey,
        maxEncryptedArchiveBytes: maxEncryptedArchiveBytes
    )
}

@discardableResult
func extractDvzipCpioToDownloads(
    archiveData: Data,
    metaDict: [String: Any],
    downloadsDir: URL? = nil,
    maxDecompressedBytes: Int = 100_000_000
) -> Bool {
    let downloads = downloadsDir ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
    let sender = (metaDict["SenderComputerName"] as? String) ?? "Android Peer"

    var handledUrls = 0
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
                safeMacNotification(message: "\(s)\n(Copied to clipboard)", title: "GlideDrop link from \(sender)")
                handledUrls += 1
            }
        }
    }

    var savedFiles: [String] = []
    if !archiveData.isEmpty {
        let tmpBin = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("glidedrop_ble_\(UUID().uuidString).dvzip")
        do {
            try archiveData.write(to: tmpBin)
        } catch {
            return false
        }
        defer { try? FileManager.default.removeItem(at: tmpBin) }
        let py = Process()
        py.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        py.arguments = [
            "-c",
            """
            import gzip, io, os, shutil, struct, sys, zlib
            from pathlib import Path

            MAX_DECOMP = int(sys.argv[3])
            MIN_FREE_HEADROOM = 10_000_000

            class BoundedGzipReader:
                def __init__(self, gz_file, max_out):
                    self.gz = gz_file
                    self.max_out = max_out
                    self.total = 0

                def read(self, n=-1):
                    if n == 0:
                        return b""
                    if n < 0:
                        n = 1_048_576
                    remaining = self.max_out - self.total
                    step = min(n, max(1, remaining + 1))
                    data = self.gz.read(step)
                    self.total += len(data)
                    if self.total > self.max_out:
                        raise ValueError("Decompressed gzip stream exceeds limit")
                    return data

            class DvzipReader(io.RawIOBase):
                def __init__(self, raw, max_out):
                    self.raw = raw
                    self.max_out = max_out
                    self.total_out = 0
                    self.buf = bytearray()
                    self.eof = False
                    self.cur_stored = False
                    self.cur_rem = 0
                    self.decompressor = None

                def _append_out(self, data):
                    if not data:
                        return
                    self.total_out += len(data)
                    if self.total_out > self.max_out:
                        raise ValueError("Decompressed DVZip stream exceeds limit")
                    self.buf.extend(data)

                def _decompress_chunk(self, chunk):
                    remaining = self.max_out - self.total_out
                    cap = min(1_048_576, max(1, remaining + 1))
                    out = self.decompressor.decompress(chunk, max_length=cap)
                    self._append_out(out)
                    while self.decompressor.unconsumed_tail:
                        remaining = self.max_out - self.total_out
                        cap = min(1_048_576, max(1, remaining + 1))
                        out = self.decompressor.decompress(self.decompressor.unconsumed_tail, max_length=cap)
                        if not out and not self.decompressor.unconsumed_tail:
                            break
                        self._append_out(out)
                        if not out and self.decompressor.unconsumed_tail:
                            break

                def _flush_decomp(self):
                    if self.decompressor is None:
                        return
                    remaining = self.max_out - self.total_out
                    cap = min(1_048_576, max(1, remaining + 1))
                    self._append_out(self.decompressor.flush(cap))
                    self.decompressor = None

                def readinto(self, b):
                    while len(self.buf) < len(b) and not self.eof:
                        if self.cur_rem > 0:
                            chunk = self.raw.read(min(65536, self.cur_rem))
                            if not chunk:
                                raise EOFError("Truncated DVZip block")
                            self.cur_rem -= len(chunk)
                            if self.cur_stored:
                                self._append_out(chunk)
                            else:
                                if self.decompressor is None:
                                    self.decompressor = zlib.decompressobj()
                                self._decompress_chunk(chunk)
                                if self.cur_rem == 0:
                                    self._flush_decomp()
                        else:
                            hdr4 = self.raw.read(4)
                            if len(hdr4) == 0:
                                self._flush_decomp()
                                self.eof = True
                                break
                            if len(hdr4) < 4:
                                raise EOFError("Truncated DVZip block header")
                            v = struct.unpack(">I", hdr4)[0]
                            if v == 0:
                                self._flush_decomp()
                                self.eof = True
                                break
                            self.cur_stored = bool(v & 0x80000000)
                            self.cur_rem = v & 0x7FFFFFFF
                            self.decompressor = None if self.cur_stored else zlib.decompressobj()

                    take = min(len(b), len(self.buf))
                    b[:take] = self.buf[:take]
                    del self.buf[:take]
                    return take if (take > 0 or not self.eof) else 0

            def read_exact(stream, n):
                buf = bytearray()
                while len(buf) < n:
                    part = stream.read(n - len(buf))
                    if not part:
                        break
                    buf.extend(part)
                return bytes(buf)

            src = Path(sys.argv[1])
            dest_raw = Path(sys.argv[2])
            if dest_raw.is_symlink():
                raise ValueError("Destination must not be a symlink")
            dest_raw.mkdir(parents=True, exist_ok=True)
            dest = dest_raw.resolve()
            saw_trailer = False
            raw_total_bytes = 0

            with src.open("rb") as f:
                prefix = f.read(6)
                f.seek(0)
                if len(prefix) >= 2 and prefix[:2] == b"\\x1f\\x8b":
                    stream = BoundedGzipReader(gzip.GzipFile(fileobj=f, mode="rb"), MAX_DECOMP)
                elif len(prefix) >= 6 and prefix[:6] in (b"070707", b"070701", b"070702", b"070764"):
                    stream = f
                else:
                    stream = io.BufferedReader(DvzipReader(f, MAX_DECOMP), buffer_size=65536)

                while True:
                    magic = read_exact(stream, 6)
                    if len(magic) == 0:
                        break
                    if len(magic) < 6:
                        raise EOFError("Truncated CPIO magic")
                    if magic == b"070707":
                        rest = read_exact(stream, 70)
                        if len(rest) < 70:
                            raise EOFError("Truncated 070707 header")
                        h = (magic + rest).decode("ascii")
                        mode = int(h[18:24], 8)
                        ns = int(h[59:65], 8)
                        fs = int(h[65:76], 8)
                        is_newc = False
                    elif magic in (b"070701", b"070702"):
                        rest = read_exact(stream, 104)
                        if len(rest) < 104:
                            raise EOFError("Truncated newc header")
                        h = (magic + rest).decode("ascii")
                        mode = int(h[14:22], 16)
                        fs = int(h[54:62], 16)
                        ns = int(h[94:102], 16)
                        is_newc = True
                    elif magic == b"070764":
                        rest = read_exact(stream, 96)
                        if len(rest) < 96:
                            raise EOFError("Truncated 070764 header")
                        h = (magic + rest).decode("ascii")
                        mode = int(h[22:30], 16)
                        fs = int(h[70:86], 16)
                        ns = int(h[86:94], 16)
                        is_newc = False
                    else:
                        raise ValueError(f"Invalid CPIO magic: {magic!r}")

                    if not (1 <= ns <= 4097):
                        raise ValueError(f"Invalid CPIO namesize: {ns}")
                    if fs < 0:
                        raise ValueError(f"Invalid CPIO filesize: {fs}")
                    if stream is f:
                        raw_total_bytes += fs
                        if raw_total_bytes > MAX_DECOMP:
                            raise ValueError(f"Raw CPIO stream exceeds limit: {raw_total_bytes}")

                    name_bytes = read_exact(stream, ns)
                    if len(name_bytes) < ns:
                        raise EOFError("Truncated CPIO entry name")
                    name = name_bytes.rstrip(b"\\x00").decode("utf-8", "replace")
                    if is_newc and (110 + ns) % 4 != 0:
                        pad = 4 - ((110 + ns) % 4)
                        if len(read_exact(stream, pad)) < pad:
                            raise EOFError("Truncated CPIO header padding")
                    if name == "TRAILER!!!":
                        saw_trailer = True
                        break
                    if (mode & 0o170000) == 0o100000:
                        sn = os.path.basename(name.replace("\\\\", "/")).lstrip(".") or "glidedrop_file"
                        t = (dest / sn).resolve()
                        if t.parent != dest:
                            raise ValueError(f"Path traversal rejected: {name}")
                        free_bytes = shutil.disk_usage(dest).free
                        if free_bytes < fs + MIN_FREE_HEADROOM:
                            raise OSError("Insufficient disk space")
                        orig_stem = t.stem
                        orig_suffix = t.suffix
                        idx = 1
                        while t.exists() or t.is_symlink():
                            t = dest / f"{orig_stem}_{idx}{orig_suffix}"
                            idx += 1
                        part_t = t.with_name(t.name + ".part")
                        while part_t.exists() or part_t.is_symlink():
                            if part_t.is_symlink():
                                raise ValueError("Refusing symlink staging file")
                            t = dest / f"{orig_stem}_{idx}{orig_suffix}"
                            part_t = t.with_name(t.name + ".part")
                            idx += 1
                        try:
                            o_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                            fd = os.open(str(part_t), o_flags, 0o644)
                            with os.fdopen(fd, "wb") as out_f:
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
                                raise EOFError(f"Truncated CPIO file data: missing {rem} bytes")
                            if t.is_symlink():
                                raise ValueError("Refusing symlink target")
                            part_t.replace(t)
                            try:
                                import subprocess
                                subprocess.run(["xattr", "-w", "com.apple.quarantine", "0081;00000000;GlideDrop;", str(t)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            except Exception:
                                pass
                            print(t)
                        except Exception:
                            part_t.unlink(missing_ok=True)
                            raise
                    else:
                        rem = fs
                        while rem > 0:
                            c = stream.read(min(65536, rem))
                            if not c:
                                break
                            rem -= len(c)
                        if rem > 0:
                            raise EOFError("Truncated CPIO non-file entry")
                    if is_newc and fs % 4 != 0:
                        dpad = 4 - (fs % 4)
                        if len(read_exact(stream, dpad)) < dpad:
                            raise EOFError("Truncated CPIO data padding")
            if not saw_trailer:
                raise EOFError("Missing CPIO TRAILER!!!")
            """,
            tmpBin.path,
            downloads.path,
            String(maxDecompressedBytes)
        ]
        let outPipe = Pipe()
        py.standardOutput = outPipe
        do {
            try py.run()
        } catch {
            return false
        }
        let rawOutData = outPipe.fileHandleForReading.readDataToEndOfFile()
        py.waitUntilExit()
        guard py.terminationStatus == 0 else {
            return false
        }
        let pyOut = String(data: rawOutData, encoding: .utf8) ?? ""
        for line in pyOut.split(separator: "\n") {
            let p = String(line).trimmingCharacters(in: .whitespacesAndNewlines)
            if !p.isEmpty {
                let sz = (try? FileManager.default.attributesOfItem(atPath: p)[.size] as? Int64) ?? 0
                appendReceivedLog(kind: "FILE", value: p, sizeBytes: sz, direction: "received", peerName: sender)
                savedFiles.append(URL(fileURLWithPath: p).lastPathComponent)
            }
        }
        guard !savedFiles.isEmpty || handledUrls > 0 else {
            return false
        }
    } else if handledUrls == 0 {
        return false
    }

    let sound = Process()
    sound.executableURL = URL(fileURLWithPath: "/usr/bin/afplay")
    sound.arguments = ["/System/Library/Sounds/Glass.aiff"]
    try? sound.run()

    if let first = savedFiles.first {
        let target = downloads.appendingPathComponent(first)
        print("[BLE-RX] Saved to \(target.path)")
        fflush(stdout)
        safeMacNotification(message: "Saved \(first) to Downloads", title: "GlideDrop from \(sender)")
    }
    return true
}

// ============================================================================
// Daemon Mode: Mac BLE L2CAP Receiver (Peripheral) + Live Peer BLE Scanner
// ============================================================================
final class BleGlideDropDaemon: NSObject, CBPeripheralManagerDelegate, CBCentralManagerDelegate, CBPeripheralDelegate {
    static weak var shared: BleGlideDropDaemon?
    var pm: CBPeripheralManager!
    var cm: CBCentralManager!
    var activeChannels: [CBL2CAPChannel] = []
    var publishedPsm: CBL2CAPPSM = 0
    var discoveredPeerPeripheral: CBPeripheral?
    var activePingPeripheral: CBPeripheral?
    var discoveredPeerPsm: CBL2CAPPSM = 0
    var discoveredPeerRssi: Int = -50
    var lastDiscoveredTime: TimeInterval = 0
    var pingChannel: CBL2CAPChannel?
    var isPingingPeer: Bool = false
    var pingStartedAt: TimeInterval = 0
    var lastPingTime: TimeInterval = 0
    var pingTimer: Timer?
    private let pingStateLock = NSLock()
    private var pingPeerDisconnected: Bool = false

    func setPingPeerDisconnected(_ val: Bool) {
        pingStateLock.lock()
        pingPeerDisconnected = val
        pingStateLock.unlock()
    }

    func isPingPeerDisconnected() -> Bool {
        pingStateLock.lock()
        defer { pingStateLock.unlock() }
        return pingPeerDisconnected
    }

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

    func stopAdvertisingAndScanning() {
        if pm?.state == .poweredOn {
            pm?.stopAdvertising()
            print("[BLE-Daemon] Stopped BLE advertising (Incoming radio turned off)")
        }
        if cm?.state == .poweredOn {
            cm?.stopScan()
            print("[BLE-Daemon] Stopped BLE scanning (Incoming radio turned off)")
        }
        cancelActivePing()
        discoveredPeerPeripheral = nil
        discoveredPeerPsm = 0
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("active_peers.json"))
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("p2p_status"))
    }

    func startAdvertisingAndScanning() {
        let settings = loadMacSettings()
        guard settings.visible else { return }
        if cm?.state == .poweredOn {
            cm?.stopScan()
            cm?.scanForPeripherals(
                withServices: nil,
                options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
            )
        }
        if pm?.state == .poweredOn && publishedPsm > 0 && pm?.isAdvertising == false {
            let psmUuid = CBUUID(string: String(format: "%04X", 0xAD00 | (Int(publishedPsm) & 0xFF)))
            pm?.startAdvertising([
                CBAdvertisementDataServiceUUIDsKey: [MAC_SERVICE_UUID, psmUuid]
            ])
            print("[BLE-Daemon] Started BLE advertising on PSM \(publishedPsm)")
        }
    }

    func rescanNow() {
        let settings = loadMacSettings()
        guard settings.visible else {
            stopAdvertisingAndScanning()
            return
        }
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
        let settings = loadMacSettings()
        guard settings.visible else { return }
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
        let settings = loadMacSettings()
        guard settings.visible else { return }

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
        let target = activePingPeripheral ?? discoveredPeerPeripheral
        activePingPeripheral = nil
        if let p = target {
            cm.cancelPeripheralConnection(p)
        }
    }

    func pingPeerIfNeeded() {
        let settings = loadMacSettings()
        guard settings.visible else {
            if cm?.state == .poweredOn && cm?.isScanning == true {
                cm?.stopScan()
            }
            if isPingingPeer {
                cancelActivePing()
            }
            return
        }
        let now = Date().timeIntervalSince1970
        let txProgress = STATE_DIR.appendingPathComponent("transfer_progress.json")
        let hasActiveTxProgress: Bool = {
            guard FileManager.default.fileExists(atPath: txProgress.path) else { return false }
            if let d = try? Data(contentsOf: txProgress),
               let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
               (obj["active"] as? Bool) == true {
                let updatedAt = (obj["updatedAt"] as? Double) ?? now
                if (now - updatedAt) < TX_LOCK_TTL_SECONDS {
                    return true
                }
            } else if let attrs = try? FileManager.default.attributesOfItem(atPath: txProgress.path),
                      let mtime = attrs[.modificationDate] as? Date,
                      (now - mtime.timeIntervalSince1970) < TX_LOCK_TTL_SECONDS {
                return true
            }
            try? FileManager.default.removeItem(at: txProgress)
            return false
        }()
        if hasActiveTxInProgressLock(now: now) ||
           hasActiveTxProgress ||
           hasActiveTcpReceiverConnection() {
            if cm.state == .poweredOn && cm.isScanning {
                cm.stopScan()
            }
            if isPingingPeer {
                isPingingPeer = false
                pingChannel = nil
                activePingPeripheral = nil
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
        activePingPeripheral = p
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
            activePingPeripheral = nil
            return
        }
        peripheral.openL2CAPChannel(discoveredPeerPsm)
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        if activePingPeripheral == nil || activePingPeripheral === peripheral {
            isPingingPeer = false
            activePingPeripheral = nil
        }
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        if activePingPeripheral == nil || activePingPeripheral === peripheral {
            setPingPeerDisconnected(true)
            isPingingPeer = false
            activePingPeripheral = nil
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didOpen channel: CBL2CAPChannel?, error: Error?) {
        guard let ch = channel, error == nil else {
            discoveredPeerPsm = 0
            isPingingPeer = false
            activePingPeripheral = nil
            return
        }
        setPingPeerDisconnected(false)
        pingChannel = ch
        let targetPeerId = peripheral.identifier.uuidString
        let currentPsm = Int(discoveredPeerPsm)
        let currentRssi = discoveredPeerRssi
        let myPsm = Int(publishedPsm > 0 ? publishedPsm : 0)
        if myPsm == 0 {
            print("[BLE-Daemon] Warning: local L2CAP PSM not published yet when sending heartbeat PING")
            fflush(stdout)
        }
        let macName = loadMacSettings().deviceName

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let inp = ch.inputStream, let out = ch.outputStream else {
                DispatchQueue.main.async {
                    self?.pingChannel = nil
                    self?.isPingingPeer = false
                    if self?.activePingPeripheral === peripheral {
                        self?.activePingPeripheral = nil
                    }
                    self?.cm.cancelPeripheralConnection(peripheral)
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
                    if self?.activePingPeripheral === peripheral {
                        self?.activePingPeripheral = nil
                    }
                    self?.cm.cancelPeripheralConnection(peripheral)
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

            var bleSessionKey: SymmetricKey? = nil
            while let replyLine = readBleStreamLine(inp, maxLen: 4096, timeout: 15.0) {
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

                let targetPeerName = loadActivePeersFromDisk(maxAge: 30.0).first(where: { $0.id == targetPeerId })?.name ?? "Android Peer"

                if replyLine.hasPrefix("W2P2\t") {
                    DispatchQueue.main.async { self?.pingStartedAt = Date().timeIntervalSince1970 + 120.0 }
                    let rawParts = replyLine.dropFirst(5).split(separator: "\t").map(String.init)
                    let parts = rawParts.filter { !$0.isEmpty }
                    var androidPubB64 = ""
                    var androidTlsFingerprint = ""
                    if parts.count >= 3 && (parts[0] == "2" || parts[0] == "1") {
                        androidPubB64 = parts[1]
                        androidTlsFingerprint = parts[2]
                    } else if parts.count == 2 && (parts[0] == "2" || parts[0] == "1") {
                        androidPubB64 = parts[1]
                    } else if parts.count >= 2 {
                        androidPubB64 = parts[0]
                        androidTlsFingerprint = parts[1]
                    } else if parts.count == 1 {
                        androidPubB64 = parts[0]
                    }
                    let macTlsFingerprint = getLocalMacTlsCertFingerprint()
                    guard isValidSha256Fingerprint(androidTlsFingerprint),
                          isValidSha256Fingerprint(macTlsFingerprint),
                          !androidPubB64.isEmpty,
                          let androidPubDer = Data(base64Encoded: androidPubB64),
                          let androidPub = try? P256.KeyAgreement.PublicKey(derRepresentation: androidPubDer) else {
                        print("[BLE-Daemon] Rejected W2P2 heartbeat handshake: missing/invalid peer public key or TLS fingerprint")
                        fflush(stdout)
                        _ = writeAll(out, data: Data("NO\n".utf8))
                        return
                    }
                    let normalizedPin = normalizeSha256Fingerprint(androidTlsFingerprint)
                    let macPriv = P256.KeyAgreement.PrivateKey()
                    guard let sharedSecret = try? macPriv.sharedSecretFromKeyAgreement(with: androidPub) else {
                        _ = writeAll(out, data: Data("NO\n".utf8))
                        return
                    }
                    let sessionKey = deriveSessionKey(sharedSecret: sharedSecret)
                    let sessionToken = deriveSessionToken(sharedSecret: sharedSecret)
                    registerP2pSessionToken(sessionToken)
                    let macPubB64 = macPriv.publicKey.derRepresentation.base64EncodedString()
                    let reply = "OK\t\(macPubB64)\t\(macTlsFingerprint)\n"
                    guard writeAll(out, data: Data(reply.utf8)),
                          let joinLine = readBleStreamLine(inp), joinLine.hasPrefix("JOIN\t") else {
                        revokeP2pSessionToken(sessionToken)
                        _ = writeAll(out, data: Data("NO\n".utf8))
                        return
                    }
                    let encB64 = String(joinLine.dropFirst(5)).trimmingCharacters(in: .whitespacesAndNewlines)
                    guard let encData = Data(base64Encoded: encB64),
                          let decData = decryptAesGcm(packet: encData, using: sessionKey),
                          let decStr = String(data: decData, encoding: .utf8) else {
                        revokeP2pSessionToken(sessionToken)
                        _ = writeAll(out, data: Data("NO\n".utf8))
                        return
                    }
                    guard let parsedJoin = parseWp2pJoinCredentials(decStr) else {
                        revokeP2pSessionToken(sessionToken)
                        _ = writeAll(out, data: Data("NO\n".utf8))
                        return
                    }
                    handleIncomingWp2pJoin(
                        ssid: parsedJoin.ssid,
                        pass: parsedJoin.pass,
                        out: out,
                        goIp: parsedJoin.goIp,
                        proxyPort: parsedJoin.proxyPort,
                        httpsPort: parsedJoin.httpsPort,
                        isV2Join: parsedJoin.isV2,
                        peerName: targetPeerName,
                        sessionToken: sessionToken,
                        peerTlsFingerprint: normalizedPin,
                        inp: inp,
                        isRemoteDisconnected: { [weak self] in self?.isPingPeerDisconnected() ?? false }
                    )
                    return
                }

                if replyLine.hasPrefix("WP2P") {
                    print("[BLE-Daemon] Rejected unpinned legacy WP2P downgrade attempt over BLE heartbeat")
                    fflush(stdout)
                    _ = writeAll(out, data: Data("NO\n".utf8))
                    return
                }

                if replyLine.hasPrefix("BLEK\t") {
                    guard bleSessionKey == nil else {
                        _ = writeAll(out, data: Data("NO\n".utf8))
                        return
                    }
                    let androidPubB64 = String(replyLine.dropFirst(5)).trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !androidPubB64.isEmpty,
                          let androidPubDer = Data(base64Encoded: androidPubB64),
                          let androidPub = try? P256.KeyAgreement.PublicKey(derRepresentation: androidPubDer) else {
                        _ = writeAll(out, data: Data("NO\n".utf8))
                        return
                    }
                    let macPriv = P256.KeyAgreement.PrivateKey()
                    guard let sharedSecret = try? macPriv.sharedSecretFromKeyAgreement(with: androidPub) else {
                        _ = writeAll(out, data: Data("NO\n".utf8))
                        return
                    }
                    bleSessionKey = deriveBleFrameKey(sharedSecret: sharedSecret)
                    let macPubB64 = macPriv.publicKey.derRepresentation.base64EncodedString()
                    guard writeAll(out, data: Data("OK\t\(macPubB64)\n".utf8)) else { return }
                    continue
                }

                if replyLine == "ADRP" {
                    print("[BLE-Daemon] Rejected plaintext ADRP BLE frame — ephemeral E2EE required")
                    fflush(stdout)
                    _ = writeAll(out, data: Data("NO\r\n".utf8))
                    return
                }

                if replyLine == "ADRE" {
                    guard let activeBleKey = bleSessionKey else {
                        print("[BLE-Daemon] Rejected ADRE frame without prior BLEK ephemeral ECDH key exchange")
                        fflush(stdout)
                        _ = writeAll(out, data: Data("NO\r\n".utf8))
                        return
                    }
                    DispatchQueue.main.async { self?.pingStartedAt = Date().timeIntervalSince1970 + 90.0 }
                    guard let lenHdr = readExact(inp, count: 8) else { return }
                    let metaLen = readUInt32BE(lenHdr, offset: 0)
                    let archLen = readUInt32BE(lenHdr, offset: 4)
                    guard metaLen > 0 && metaLen <= MAX_BLE_META_BYTES && archLen >= 0 && archLen <= MAX_ENCRYPTED_BLE_ARCHIVE_BYTES else {
                        print("[BLE-Daemon] Rejected out-of-bounds ADRE frame: metaLen=\(metaLen), archLen=\(archLen)")
                        return
                    }

                    guard let rawMeta = readExact(inp, count: metaLen),
                          let metaData = decryptBlePayload(rawMeta, key: activeBleKey) else {
                        print("[BLE-Daemon] Failed to decrypt ADRE metadata with ephemeral ECDH BLE key")
                        _ = writeAll(out, data: Data("NO\r\n".utf8))
                        return
                    }
                    let metaDict = (try? PropertyListSerialization.propertyList(from: metaData, options: [], format: nil)) as? [String: Any] ?? [:]
                    let sender = (metaDict["SenderComputerName"] as? String) ?? "Android Peer"
                    let filesArr = (metaDict["Files"] as? [[String: Any]]) ?? []
                    let itemsArr = (metaDict["Items"] as? [Any])?.compactMap { $0 as? String } ?? []
                    let fileNames = filesArr.compactMap { $0["FileName"] as? String }
                    let displayNames = fileNames.isEmpty ? itemsArr : fileNames
                    let prelimLabel = displayNames.first ?? "Incoming BLE File"
                    let totalAskBytes = filesArr.reduce(Int64(0)) { $0 + Int64(($1["FileSize"] as? Int) ?? 0) }
                    let effectiveBytes = totalAskBytes > 0 ? totalAskBytes : Int64(archLen)

                    let isCentralAdreAborted: () -> Bool = { [weak self] in
                        isStreamAborted(inp) || (self?.isPingPeerDisconnected() ?? false)
                    }
                    if !waitForMacUserAccept(senderName: sender, fileNames: displayNames, totalBytes: effectiveBytes, isRemoteAborted: isCentralAdreAborted) {
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
                        let decodedArch = decryptBlePayload(rawArch, key: activeBleKey) else {
                            _ = writeAll(out, data: Data("NO\r\n".utf8))
                            return
                        }
                        archData = decodedArch
                    } else {
                        archData = Data()
                    }
                    if extractDvzipCpioToDownloads(archiveData: archData, metaDict: metaDict) {
                        _ = writeAll(out, data: Data("OK\r\n".utf8))
                    } else {
                        _ = writeAll(out, data: Data("NO\r\n".utf8))
                    }
                    return
                }
                return
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
        let settings = loadMacSettings()
        if settings.visible {
            // Keep primary advertisement <= 25 bytes (3B Flags + 18B MAC_SERVICE_UUID + 4B psmUuid)
            // so macOS CoreBluetooth never pushes MAC_SERVICE_UUID into the proprietary Apple Overflow Area.
            peripheral.startAdvertising([
                CBAdvertisementDataServiceUUIDsKey: [MAC_SERVICE_UUID, psmUuid]
            ])
        } else {
            print("[BLE-Daemon] Published PSM \(PSM), but radio visibility is OFF.")
        }
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
            var bleSessionKey: SymmetricKey? = nil
            while true {
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
                    let bestPsm = peerPsm > 0 ? peerPsm : (existingPeer?.psm ?? 0)
                    recordActivePeerOnDisk(
                        id: bestId,
                        name: peerName.isEmpty ? "Android Peer" : peerName,
                        transport: bestPsm > 0 ? "5GHz P2P • BLE PSM \(bestPsm)" : "5GHz P2P • BLE",
                        address: bestAddr,
                        psm: bestPsm,
                        rssi: existingPeer?.rssi ?? peerRssi
                    )
                    let macName = loadMacSettings().deviceName
                    let myPsm = self?.publishedPsm ?? 0
                    if myPsm == 0 {
                        print("[BLE-Daemon] Warning: local L2CAP PSM not published yet when answering PING")
                        fflush(stdout)
                    }
                    _ = writeAll(out, data: Data("PONG\t\(macName)\t\(myPsm)\n".utf8))
                    return
                }

                if magic == "W2P2" {
                    guard let reqData = readExact(inp, count: metaLen),
                          let reqStr = String(data: reqData, encoding: .utf8) else { return }
                    let w2p2Req = parseW2p2Request(reqStr)
                    if w2p2Req.version < W2P2_PROTOCOL_VERSION {
                        print("[BLE-Daemon] Rejected W2P2 v\(w2p2Req.version) request: peer must update GlideDrop (protocol v\(W2P2_PROTOCOL_VERSION) required)")
                        fflush(stdout)
                        _ = writeAll(out, data: Data("ERR\tUPDATE\t\(W2P2_PROTOCOL_VERSION)\n".utf8))
                        return
                    }
                    let androidPubB64 = w2p2Req.pubB64
                    let androidTlsFingerprint = w2p2Req.tlsFingerprint
                    let macTlsFingerprint = getLocalMacTlsCertFingerprint()
                    guard isValidSha256Fingerprint(androidTlsFingerprint),
                          isValidSha256Fingerprint(macTlsFingerprint),
                          let w2p2SessionId = w2p2Req.sessionId, w2p2SessionId.count == W2P2_SESSION_ID_BYTES,
                          !androidPubB64.isEmpty,
                          let androidPubDer = Data(base64Encoded: androidPubB64),
                          let androidPub = try? P256.KeyAgreement.PublicKey(derRepresentation: androidPubDer) else {
                        print("[BLE-Daemon] Rejected W2P2 handshake: missing/invalid peer public key, session id or TLS fingerprint")
                        fflush(stdout)
                        _ = writeAll(out, data: Data("ERR\n".utf8))
                        return
                    }
                    let normalizedPin = normalizeSha256Fingerprint(androidTlsFingerprint)

                    let macPriv = P256.KeyAgreement.PrivateKey()
                    guard let sharedSecret = try? macPriv.sharedSecretFromKeyAgreement(with: androidPub),
                          let material = deriveW2p2SessionMaterial(
                            sharedSecret: sharedSecret,
                            sessionId: w2p2SessionId,
                            initiatorPubDer: androidPubDer,
                            responderPubDer: macPriv.publicKey.derRepresentation,
                            initiatorFingerprint: androidTlsFingerprint,
                            responderFingerprint: macTlsFingerprint
                          ) else {
                        _ = writeAll(out, data: Data("ERR\n".utf8))
                        return
                    }
                    let sessionKey = material.sessionKey
                    let sessionToken = material.token
                    let w2p2VerificationCode = material.verificationCode
                    registerP2pSessionToken(sessionToken)
                    let macPubB64 = macPriv.publicKey.derRepresentation.base64EncodedString()
                    let reply = "OK\t\(macPubB64)\t\(macTlsFingerprint)\n"
                    guard writeAll(out, data: Data(reply.utf8)) else {
                        revokeP2pSessionToken(sessionToken)
                        return
                    }

                    guard let joinLine = readBleStreamLine(inp), joinLine.hasPrefix("JOIN\t") else {
                        revokeP2pSessionToken(sessionToken)
                        _ = writeAll(out, data: Data("ERR\n".utf8))
                        return
                    }
                    let encB64 = String(joinLine.dropFirst(5)).trimmingCharacters(in: .whitespacesAndNewlines)
                    guard let encData = Data(base64Encoded: encB64),
                          let decData = decryptAesGcm(packet: encData, using: sessionKey),
                          let decStr = String(data: decData, encoding: .utf8) else {
                        print("[BLE-Daemon] Failed to decrypt encrypted W2P2 credentials with ECDH session key")
                        revokeP2pSessionToken(sessionToken)
                        _ = writeAll(out, data: Data("ERR\n".utf8))
                        return
                    }
                    guard let parsedJoin = parseWp2pJoinCredentials(decStr) else {
                        revokeP2pSessionToken(sessionToken)
                        _ = writeAll(out, data: Data("ERR\n".utf8))
                        return
                    }
                    let activePeer = loadActivePeersFromDisk(maxAge: 30.0).first
                    let pName = activePeer?.name ?? "Android Peer"
                    handleIncomingWp2pJoin(
                        ssid: parsedJoin.ssid,
                        pass: parsedJoin.pass,
                        out: out,
                        goIp: parsedJoin.goIp,
                        proxyPort: parsedJoin.proxyPort,
                        httpsPort: parsedJoin.httpsPort,
                        isV2Join: parsedJoin.isV2,
                        peerName: pName,
                        sessionToken: sessionToken,
                        peerTlsFingerprint: normalizedPin,
                        inp: inp,
                        verificationCode: w2p2VerificationCode
                    )
                    return
                }

                if magic == "WP2P" {
                    print("[BLE-Daemon] Rejected unpinned legacy WP2P downgrade attempt")
                    fflush(stdout)
                    _ = writeAll(out, data: Data("ERR\n".utf8))
                    return
                }

                if magic == "BLEK" {
                    guard bleSessionKey == nil, metaLen > 0, metaLen <= 4096, archLen == 0,
                          let pubData = readExact(inp, count: metaLen),
                          let androidPubB64 = String(data: pubData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                          !androidPubB64.isEmpty,
                          let androidPubDer = Data(base64Encoded: androidPubB64),
                          let androidPub = try? P256.KeyAgreement.PublicKey(derRepresentation: androidPubDer) else {
                        _ = writeAll(out, data: Data("ERR\n".utf8))
                        return
                    }
                    let macPriv = P256.KeyAgreement.PrivateKey()
                    guard let sharedSecret = try? macPriv.sharedSecretFromKeyAgreement(with: androidPub) else {
                        _ = writeAll(out, data: Data("ERR\n".utf8))
                        return
                    }
                    bleSessionKey = deriveBleFrameKey(sharedSecret: sharedSecret)
                    let macPubB64 = macPriv.publicKey.derRepresentation.base64EncodedString()
                    guard writeAll(out, data: Data("OK\t\(macPubB64)\n".utf8)) else { return }
                    continue
                }

                if magic == "ADRP" {
                    print("[BLE-Daemon] Rejected plaintext ADRP BLE frame — ephemeral E2EE required")
                    fflush(stdout)
                    _ = writeAll(out, data: Data("NO\r\n".utf8))
                    return
                }

                guard magic == "ADRE" else { return }
                guard let activeBleKey = bleSessionKey else {
                    print("[BLE-Daemon] Rejected ADRE frame without prior BLEK ephemeral ECDH key exchange")
                    fflush(stdout)
                    _ = writeAll(out, data: Data("NO\r\n".utf8))
                    return
                }
                guard metaLen <= MAX_BLE_META_BYTES && archLen <= MAX_ENCRYPTED_BLE_ARCHIVE_BYTES else {
                    print("[BLE-Daemon] Rejected out-of-bounds ADRE frame: metaLen=\(metaLen), archLen=\(archLen)")
                    _ = writeAll(out, data: Data("NO\r\n".utf8))
                    return
                }
                print("[BLE-Daemon] Receiving ADRE frame (meta=\(metaLen) B, archive=\(archLen) B)...")
                fflush(stdout)

                guard let rawMeta = readExact(inp, count: metaLen),
                      let metaData = decryptBlePayload(rawMeta, key: activeBleKey) else {
                    print("[BLE-Daemon] Failed to decrypt ADRE metadata with ephemeral ECDH BLE key")
                    _ = writeAll(out, data: Data("NO\r\n".utf8))
                    return
                }
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

                if !waitForMacUserAccept(senderName: sender, fileNames: displayNames, totalBytes: effectiveBytes, isRemoteAborted: { isStreamAborted(inp) }) {
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
                    let decodedArch = decryptBlePayload(rawArch, key: activeBleKey) else {
                        _ = writeAll(out, data: Data("NO\r\n".utf8))
                        return
                    }
                    archData = decodedArch
                } else {
                    archData = Data()
                }

                if extractDvzipCpioToDownloads(archiveData: archData, metaDict: metaDict) {
                    _ = writeAll(out, data: Data("OK\r\n".utf8))
                } else {
                    _ = writeAll(out, data: Data("NO\r\n".utf8))
                }
                return
            }
        }
    }
}

// ============================================================================
// Sender Mode: Mac -> Android Direct BLE L2CAP Sender (Central)
// ============================================================================
func runP2pTxProcess(_ process: Process, onTick: () -> Void = {}) -> Int32 {
    activeChildTxLock.lock()
    activeChildTxProcess = process
    activeChildTxLock.unlock()
    defer {
        activeChildTxLock.lock()
        activeChildTxProcess = nil
        activeChildTxLock.unlock()
    }
    do {
        try process.run()
    } catch {
        print("[BLE-Send] Could not launch HTTPS sender: \(error.localizedDescription)")
        return 45
    }
    while process.isRunning {
        if isTransferCancelled() {
            process.terminate()
            break
        }
        onTick()
        Thread.sleep(forTimeInterval: 0.25)
    }
    process.waitUntilExit()
    return isTransferCancelled() ? 44 : process.terminationStatus
}

enum BleConnectSwitchAction: Equatable {
    case keepExisting
    case switchTo(peerId: UUID, psm: UInt16)
}

enum BleConnectDropAction: Equatable {
    case ignoreStaleCallback
    case cancelTransfer
    case restartDiscovery
    case fail(String)
}

enum BleOpenFailAction: Equatable {
    case ignoreStaleCallback
    case refreshGatt
    case restartDiscovery
    case fail(String)
}

struct BleSenderConnectState {
    var targetPeerId: UUID? = nil
    var targetPsm: CBL2CAPPSM = 0
    var startedOpen = false
    var transferStarted = false
    var gattRefreshInProgress = false
    var needsGattRefreshOnOpenFail = false
    var isTerminalFailure = false
    var connectRetryCount = 0
    var l2capRetryCount = 0
    var connectAttemptToken = 0
    var connectStartedAt: Date? = nil
    let maxConnectRetries: Int = 3
    let maxL2capRetries: Int = 2

    func isActivePeer(_ peerId: UUID) -> Bool {
        return !transferStarted && !isTerminalFailure && targetPeerId == peerId
    }

    mutating func beginConnect(peerId: UUID, now: Date = Date()) -> Int {
        targetPeerId = peerId
        connectAttemptToken += 1
        connectStartedAt = now
        return connectAttemptToken
    }

    mutating func evaluateDiscoverSwitch(
        discoveredPeerId: UUID,
        psm: UInt16,
        existingConnected: Bool,
        now: Date = Date()
    ) -> BleConnectSwitchAction {
        guard !transferStarted && !isTerminalFailure else { return .keepExisting }
        if !startedOpen && !gattRefreshInProgress && (targetPeerId == nil || targetPeerId == discoveredPeerId) {
            targetPsm = CBL2CAPPSM(psm)
        }
        if let existingId = targetPeerId,
           existingId != discoveredPeerId,
           !existingConnected,
           !startedOpen,
           let started = connectStartedAt,
           now.timeIntervalSince(started) > 2.5 {
            targetPeerId = nil
            connectAttemptToken += 1
            targetPsm = CBL2CAPPSM(psm)
            return .switchTo(peerId: existingId, psm: psm)
        }
        return .keepExisting
    }

    mutating func onConnectTimeout(peerId: UUID, token: Int, isConnected: Bool, cancelled: Bool) -> BleConnectDropAction {
        guard !transferStarted && !isTerminalFailure else { return .ignoreStaleCallback }
        guard connectAttemptToken == token, targetPeerId == peerId, !isConnected else {
            return .ignoreStaleCallback
        }
        targetPeerId = nil
        connectAttemptToken += 1
        startedOpen = false
        gattRefreshInProgress = false
        connectStartedAt = nil
        if cancelled {
            return .cancelTransfer
        }
        connectRetryCount += 1
        if connectRetryCount <= maxConnectRetries {
            return .restartDiscovery
        }
        return .fail("[BLE-Send] Timed out connecting to nearby device over Bluetooth LE")
    }

    mutating func onDidConnect(peerId: UUID) -> Bool {
        guard isActivePeer(peerId) else { return false }
        connectAttemptToken += 1
        connectStartedAt = nil
        return true
    }

    mutating func onDidDrop(peerId: UUID, cancelled: Bool, failureMessage: String) -> BleConnectDropAction {
        guard !transferStarted && !isTerminalFailure else { return .ignoreStaleCallback }
        guard targetPeerId == peerId else { return .ignoreStaleCallback }
        targetPeerId = nil
        connectAttemptToken += 1
        startedOpen = false
        gattRefreshInProgress = false
        connectStartedAt = nil
        if cancelled {
            return .cancelTransfer
        }
        connectRetryCount += 1
        if connectRetryCount <= maxConnectRetries {
            return .restartDiscovery
        }
        return .fail(failureMessage)
    }

    mutating func onDidModifyServices(peerId: UUID, affectsP2p: Bool) -> Bool {
        guard isActivePeer(peerId), affectsP2p else { return false }
        if startedOpen {
            needsGattRefreshOnOpenFail = true
            return false
        }
        if gattRefreshInProgress {
            return false
        }
        targetPsm = 0
        gattRefreshInProgress = true
        return true
    }

    mutating func onDidOpenFailure(peerId: UUID, isConnected: Bool, cancelled: Bool, errorDesc: String) -> BleOpenFailAction {
        guard isActivePeer(peerId) else { return .ignoreStaleCallback }
        startedOpen = false
        if cancelled {
            return .fail("[BLE-Send] Transfer cancelled by user")
        }
        l2capRetryCount += 1
        if l2capRetryCount <= maxL2capRetries {
            if isConnected && (needsGattRefreshOnOpenFail || l2capRetryCount == 1) {
                needsGattRefreshOnOpenFail = false
                targetPsm = 0
                gattRefreshInProgress = true
                return .refreshGatt
            }
            if connectRetryCount < maxConnectRetries {
                targetPeerId = nil
                connectAttemptToken += 1
                gattRefreshInProgress = false
                needsGattRefreshOnOpenFail = false
                connectRetryCount += 1
                return .restartDiscovery
            }
        }
        return .fail("[BLE-Send] L2CAP open failed: \(errorDesc)")
    }

    mutating func prepareRestartDiscovery() {
        targetPeerId = nil
        targetPsm = 0
        startedOpen = false
        gattRefreshInProgress = false
        needsGattRefreshOnOpenFail = false
        connectStartedAt = nil
    }
}

final class BleGlideDropSender: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    var cm: CBCentralManager!
    var targetPeripheral: CBPeripheral?
    var activeChannel: CBL2CAPChannel?
    let files: [URL]
    let urls: [String]
    let totalRawBytes: Int64
    let preparedBlePayload: (metaData: Data, gzData: Data)?
    let displayLabel: String
    let itemCount: Int
    var peerLabel: String
    var connectState = BleSenderConnectState()

    private func reportSenderConnecting(_ phase: String) {
        writeProgressJson(
            active: true,
            direction: "Sending",
            fileName: displayLabel,
            fileCount: itemCount,
            doneBytes: 0,
            totalBytes: max(Int64(1), totalRawBytes),
            speedBps: 0,
            etaSeconds: 0,
            percent: 0,
            phase: phase,
            peerName: peerLabel,
            isConnecting: true
        )
    }

    private func cleanupAndFail(message: String) -> Never {
        connectState.isTerminalFailure = true
        writeProgressJson(active: false)
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
        if needsMacInternetWifiRestore() {
            restoreMacInternetWifi()
        }
        print(message)
        fflush(stdout)
        exit(1)
    }

    private func beginPeripheralConnect(_ central: CBCentralManager, peripheral: CBPeripheral, phase: String) {
        targetPeripheral = peripheral
        peripheral.delegate = self
        let token = connectState.beginConnect(peerId: peripheral.identifier)
        reportSenderConnecting(phase)
        central.connect(peripheral, options: nil)
        DispatchQueue.main.asyncAfter(deadline: .now() + 8.0) { [weak self] in
            guard let self = self else { return }
            let action = self.connectState.onConnectTimeout(
                peerId: peripheral.identifier,
                token: token,
                isConnected: peripheral.state == .connected,
                cancelled: isTransferCancelled()
            )
            switch action {
            case .ignoreStaleCallback:
                return
            case .cancelTransfer:
                self.targetPeripheral = nil
                central.cancelPeripheralConnection(peripheral)
                clearCancelFlag()
                self.cleanupAndFail(message: "[BLE-Send] Transfer cancelled by user")
            case .restartDiscovery:
                print("[BLE-Send] Connection attempt to \(peripheral.identifier) timed out; restarting discovery...")
                fflush(stdout)
                self.targetPeripheral = nil
                central.cancelPeripheralConnection(peripheral)
                self.restartDiscoveryAfterFailure(central)
            case .fail(let msg):
                self.targetPeripheral = nil
                central.cancelPeripheralConnection(peripheral)
                self.cleanupAndFail(message: msg)
            }
        }
    }

    private func restartDiscoveryAfterFailure(_ central: CBCentralManager) {
        guard !connectState.transferStarted && !connectState.isTerminalFailure else { return }
        targetPeripheral = nil
        connectState.prepareRestartDiscovery()
        guard central.state == .poweredOn else {
            cleanupAndFail(message: "[BLE-Send] Bluetooth LE became unavailable during transfer")
        }
        reportSenderConnecting("Re-scanning for nearby device via Bluetooth LE…")
        central.stopScan()
        central.scanForPeripherals(
            withServices: nil,
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
        )
    }

    init(files: [URL], urls: [String] = []) throws {
        clearCancelFlag()
        writeTxInProgressLock()
        self.files = files
        self.urls = urls
        self.totalRawBytes = files.reduce(Int64(0)) { acc, url in
            let sz = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? NSNumber)?.int64Value ?? 0
            return acc + max(Int64(0), sz)
        }
        self.itemCount = max(1, files.count + urls.count)
        let firstLabel = files.first?.lastPathComponent ?? (urls.first ?? "Transfer")
        self.displayLabel = self.itemCount > 1 ? "\(firstLabel) + \(self.itemCount - 1) more" : firstLabel
        let settings = loadMacSettings()
        self.peerLabel = loadActivePeersFromDisk(maxAge: 30.0).first?.name ?? "Nearby Device"
        if self.totalRawBytes >= 65_536 && !files.isEmpty {
            self.preparedBlePayload = nil
        } else {
            self.preparedBlePayload = try prepareBleFallbackPayload(
                files: files,
                urls: urls,
                totalRawBytes: self.totalRawBytes,
                senderName: settings.deviceName
            )
        }
        super.init()
        reportSenderConnecting("Scanning for nearby device via Bluetooth LE…")
        cm = CBCentralManager(delegate: self, queue: nil)
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            let knownPeers = loadActivePeersFromDisk(maxAge: 30.0)
            if let first = knownPeers.first {
                peerLabel = first.name
                if first.psm > 0 {
                    connectState.targetPsm = CBL2CAPPSM(first.psm)
                }
                if let uuid = UUID(uuidString: first.address) {
                    let retrieved = central.retrievePeripherals(withIdentifiers: [uuid])
                    if let p = retrieved.first {
                        print("[BLE-Send] Connecting directly to active peer \(first.name) (\(uuid), PSM \(connectState.targetPsm))...")
                        fflush(stdout)
                        beginPeripheralConnect(central, peripheral: p, phase: "Connecting to \(first.name) via Bluetooth LE…")
                    }
                }
            }
            print("[BLE-Send] Scanning for nearby peer over Bluetooth LE...")
            fflush(stdout)
            central.scanForPeripherals(
                withServices: nil,
                options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
            )
        case .poweredOff, .unauthorized, .unsupported:
            cleanupAndFail(message: "[BLE-Send] Bluetooth is unavailable (state=\(central.state.rawValue))")
        default:
            break
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        guard !connectState.transferStarted && !connectState.isTerminalFailure else { return }
        let uuids = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID]) ?? []
        let svcData = (advertisementData[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data]) ?? [:]
        guard uuids.contains(P2P_SERVICE_UUID) || svcData[P2P_DATA_UUID] != nil else { return }

        guard let d = svcData[P2P_DATA_UUID], d.count >= 2 else { return }
        let psm = UInt16(d[d.startIndex]) | (UInt16(d[d.startIndex + 1]) << 8)
        guard psm > 0 else { return }
        if d.count > 2 {
            let nameSlice = d.subdata(in: (d.startIndex + 2)..<d.endIndex)
            if let decoded = String(data: nameSlice, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
               !decoded.isEmpty,
               peerLabel == "Nearby Device" {
                peerLabel = decoded
            }
        }

        let switchAction = connectState.evaluateDiscoverSwitch(
            discoveredPeerId: peripheral.identifier,
            psm: psm,
            existingConnected: targetPeripheral?.state == .connected
        )
        if case .switchTo(let staleId, _) = switchAction,
           let existing = targetPeripheral,
           existing.identifier == staleId {
            print("[BLE-Send] Switching from stale peer \(existing.identifier) to live peer \(peripheral.identifier) (PSM \(psm))...")
            fflush(stdout)
            targetPeripheral = nil
            central.cancelPeripheralConnection(existing)
        }

        if targetPeripheral == nil {
            connectState.targetPsm = CBL2CAPPSM(psm)
            print("[BLE-Send] Found nearby peer (\(peripheral.identifier), RSSI \(RSSI), PSM \(connectState.targetPsm)), connecting...")
            fflush(stdout)
            central.stopScan()
            beginPeripheralConnect(central, peripheral: peripheral, phase: "Connecting to \(peerLabel) via Bluetooth LE…")
        }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard connectState.onDidConnect(peerId: peripheral.identifier) else { return }
        if connectState.targetPsm > 0 && !connectState.startedOpen && !connectState.gattRefreshInProgress {
            connectState.startedOpen = true
            reportSenderConnecting("Opening Bluetooth L2CAP channel…")
            print("[BLE-Send] Connected! Opening L2CAP channel PSM \(connectState.targetPsm)...")
            fflush(stdout)
            peripheral.openL2CAPChannel(connectState.targetPsm)
        } else if !connectState.gattRefreshInProgress {
            connectState.gattRefreshInProgress = true
            reportSenderConnecting("Discovering Bluetooth L2CAP service…")
            peripheral.discoverServices([P2P_SERVICE_UUID])
        }
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        let action = connectState.onDidDrop(
            peerId: peripheral.identifier,
            cancelled: isTransferCancelled(),
            failureMessage: "[BLE-Send] Failed to connect to nearby device over Bluetooth LE"
        )
        switch action {
        case .ignoreStaleCallback:
            return
        case .cancelTransfer:
            targetPeripheral = nil
            clearCancelFlag()
            cleanupAndFail(message: "[BLE-Send] Transfer cancelled by user")
        case .restartDiscovery:
            print("[BLE-Send] Failed to connect to \(peripheral.identifier): \(String(describing: error))")
            fflush(stdout)
            targetPeripheral = nil
            restartDiscoveryAfterFailure(central)
        case .fail(let msg):
            targetPeripheral = nil
            cleanupAndFail(message: msg)
        }
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        let action = connectState.onDidDrop(
            peerId: peripheral.identifier,
            cancelled: isTransferCancelled(),
            failureMessage: "[BLE-Send] Bluetooth LE connection dropped before transfer started"
        )
        switch action {
        case .ignoreStaleCallback:
            return
        case .cancelTransfer:
            targetPeripheral = nil
            clearCancelFlag()
            cleanupAndFail(message: "[BLE-Send] Transfer cancelled by user")
        case .restartDiscovery:
            print("[BLE-Send] Disconnected from \(peripheral.identifier) before L2CAP opened: \(String(describing: error))")
            fflush(stdout)
            targetPeripheral = nil
            restartDiscoveryAfterFailure(central)
        case .fail(let msg):
            targetPeripheral = nil
            cleanupAndFail(message: msg)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didModifyServices invalidatedServices: [CBService]) {
        let affectsP2p = invalidatedServices.isEmpty || invalidatedServices.contains(where: { $0.uuid == P2P_SERVICE_UUID })
        guard connectState.onDidModifyServices(peerId: peripheral.identifier, affectsP2p: affectsP2p) else { return }
        print("[BLE-Send] Remote GATT services modified; re-discovering P2P PSM...")
        fflush(stdout)
        peripheral.discoverServices([P2P_SERVICE_UUID])
    }

    private func handleGattDiscoveryFailure(_ peripheral: CBPeripheral, logLine: String, terminalMsg: String) {
        print(logLine)
        fflush(stdout)
        let action = connectState.onDidDrop(
            peerId: peripheral.identifier,
            cancelled: isTransferCancelled(),
            failureMessage: terminalMsg
        )
        switch action {
        case .ignoreStaleCallback:
            return
        case .cancelTransfer:
            targetPeripheral = nil
            cm.cancelPeripheralConnection(peripheral)
            clearCancelFlag()
            cleanupAndFail(message: "[BLE-Send] Transfer cancelled by user")
        case .restartDiscovery:
            targetPeripheral = nil
            cm.cancelPeripheralConnection(peripheral)
            restartDiscoveryAfterFailure(cm)
        case .fail(let msg):
            targetPeripheral = nil
            cm.cancelPeripheralConnection(peripheral)
            cleanupAndFail(message: msg)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard connectState.isActivePeer(peripheral.identifier) else { return }
        guard error == nil, let svcs = peripheral.services, let p2pSvc = svcs.first(where: { $0.uuid == P2P_SERVICE_UUID }) else {
            handleGattDiscoveryFailure(
                peripheral,
                logLine: "[BLE-Send] Service discovery failed: \(String(describing: error))",
                terminalMsg: "[BLE-Send] Peer does not expose GlideDrop GATT service"
            )
            return
        }
        peripheral.discoverCharacteristics([P2P_PSM_CHAR_UUID], for: p2pSvc)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard connectState.isActivePeer(peripheral.identifier) else { return }
        guard error == nil, let chars = service.characteristics, let psmChar = chars.first(where: { $0.uuid == P2P_PSM_CHAR_UUID }) else {
            handleGattDiscoveryFailure(
                peripheral,
                logLine: "[BLE-Send] Characteristic discovery failed: \(String(describing: error))",
                terminalMsg: "[BLE-Send] Peer GATT PSM characteristic unavailable"
            )
            return
        }
        peripheral.readValue(for: psmChar)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard connectState.isActivePeer(peripheral.identifier) else { return }
        guard error == nil, let d = characteristic.value, d.count >= 2 else {
            if !connectState.startedOpen {
                handleGattDiscoveryFailure(
                    peripheral,
                    logLine: "[BLE-Send] Failed to read GATT PSM value: \(String(describing: error))",
                    terminalMsg: "[BLE-Send] Failed to read Bluetooth L2CAP PSM from peer"
                )
            }
            return
        }
        if !connectState.startedOpen {
            let psm = UInt16(d[d.startIndex]) | (UInt16(d[d.startIndex + 1]) << 8)
            if psm > 0 {
                connectState.gattRefreshInProgress = false
                connectState.needsGattRefreshOnOpenFail = false
                connectState.startedOpen = true
                connectState.targetPsm = CBL2CAPPSM(psm)
                reportSenderConnecting("Opening Bluetooth L2CAP channel…")
                print("[BLE-Send] Read GATT PSM \(connectState.targetPsm), opening L2CAP channel...")
                fflush(stdout)
                peripheral.openL2CAPChannel(connectState.targetPsm)
            } else {
                handleGattDiscoveryFailure(
                    peripheral,
                    logLine: "[BLE-Send] Peer returned invalid L2CAP PSM (0)",
                    terminalMsg: "[BLE-Send] Peer returned invalid L2CAP PSM (0)"
                )
            }
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didOpen channel: CBL2CAPChannel?, error: Error?) {
        guard connectState.isActivePeer(peripheral.identifier) else { return }
        guard let ch = channel, error == nil else {
            print("[BLE-Send] L2CAP open failed on PSM \(connectState.targetPsm): \(String(describing: error))")
            fflush(stdout)
            let action = connectState.onDidOpenFailure(
                peerId: peripheral.identifier,
                isConnected: peripheral.state == .connected,
                cancelled: isTransferCancelled(),
                errorDesc: error?.localizedDescription ?? "Unknown error"
            )
            switch action {
            case .ignoreStaleCallback:
                return
            case .refreshGatt:
                reportSenderConnecting("Refreshing Bluetooth L2CAP PSM…")
                print("[BLE-Send] Re-discovering GATT services for fresh PSM...")
                fflush(stdout)
                peripheral.discoverServices([P2P_SERVICE_UUID])
                return
            case .restartDiscovery:
                targetPeripheral = nil
                cm.cancelPeripheralConnection(peripheral)
                restartDiscoveryAfterFailure(cm)
                return
            case .fail(let msg):
                if isTransferCancelled() { clearCancelFlag() }
                targetPeripheral = nil
                cm.cancelPeripheralConnection(peripheral)
                cleanupAndFail(message: msg)
            }
        }
        connectState.transferStarted = true
        activeChannel = ch
        cm.stopScan()

        DispatchQueue.global(qos: .userInitiated).async {
            guard let inp = ch.inputStream, let out = ch.outputStream else {
                self.cleanupAndFail(message: "[BLE-Send] Failed to acquire L2CAP channel streams")
            }
            inp.open()
            out.open()

            func failL2capSession(message: String, clearCancel: Bool = false, exitCode: Int32 = 1) -> Never {
                DispatchQueue.main.async {
                    self.connectState.isTerminalFailure = true
                    self.cm?.cancelPeripheralConnection(peripheral)
                }
                if clearCancel { clearCancelFlag() }
                writeProgressJson(active: false)
                inp.close()
                out.close()
                try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
                clearOutgoingP2pToken()
                if needsMacInternetWifiRestore() {
                    restoreMacInternetWifi()
                } else {
                    clearActiveP2pSession()
                }
                print(message)
                fflush(stdout)
                exit(exitCode)
            }

            var p2pTxExitCode: Int32? = nil
            // 5GHz Wi-Fi Direct P2P Negotiation for large files
            if self.totalRawBytes >= 65_536 && !self.files.isEmpty {
                self.reportSenderConnecting("Negotiating secure 5 GHz Wi-Fi Direct…")
                print("[BLE-Send] Negotiating 5GHz Wi-Fi Direct P2P over BLE L2CAP (ECDH P-256)...")
                fflush(stdout)

                let macCertFingerprint = getLocalMacTlsCertFingerprint()
                guard isValidSha256Fingerprint(macCertFingerprint) else {
                    failL2capSession(message: "[BLE-Send] Local TLS certificate fingerprint unavailable — refusing unpinned P2P handshake")
                }

                let macPriv = P256.KeyAgreement.PrivateKey()
                let macPubB64 = macPriv.publicKey.derRepresentation.base64EncodedString()
                var p2pCreds: (ssid: String, pass: String, host: String, port: String, peerPin: String, proxyPort: Int, sessionToken: String)? = nil
                var w2p2TimedOut = false
                var w2p2ReplyLine: String? = nil
                var w2p2VerificationCode: String? = nil
                let w2p2SessionId = randomW2p2SessionId()
                let w2p2Request = "W2P2\t\(W2P2_PROTOCOL_VERSION)\t\(macPubB64)\t\(macCertFingerprint)\t\(w2p2HexString(w2p2SessionId))\n"

                // Strict v3 ECDH P-256 negotiation with mandatory peer TLS pinning (no unpinned WP2P downgrade)
                try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("pinned_peer_tls_fingerprint.txt"))
                let w2p2WriteOk = writeAll(out, data: Data(w2p2Request.utf8))
                if w2p2WriteOk {
                    // Android may answer `PENDING\t<retryAfterMs>` while its group is still starting.
                    // Wait the advertised time (bounded), resend the same W2P2 request, and read again.
                    // Peers that never send PENDING behave exactly as before.
                    var pendingRetries = 0
                    while true {
                        w2p2ReplyLine = readBleStreamLine(inp, timeout: 25.0, checkCancel: true, onTimeout: {
                            w2p2TimedOut = true
                            DispatchQueue.main.async { self.cm?.cancelPeripheralConnection(peripheral) }
                        })
                        guard let pendingReply = w2p2ReplyLine,
                              let retryAfterMs = parseW2p2PendingRetryMs(pendingReply),
                              pendingRetries < 4, !isTransferCancelled() else { break }
                        pendingRetries += 1
                        print("[BLE-Send] Peer Wi-Fi Direct group still starting; retrying W2P2 in \(retryAfterMs) ms (\(pendingRetries)/4)")
                        fflush(stdout)
                        Thread.sleep(forTimeInterval: Double(retryAfterMs) / 1000.0)
                        if !writeAll(out, data: Data(w2p2Request.utf8)) {
                            w2p2ReplyLine = nil
                            break
                        }
                    }
                    if let reply = w2p2ReplyLine, reply.hasPrefix("OK\t") {
                        // v3 reply: OK <phonePub> <phoneTlsFp> <encryptedCreds>
                        let parts = reply.dropFirst(3).split(separator: "\t").map(String.init)
                        if parts.count >= 3,
                           isValidSha256Fingerprint(parts[1]),
                           let androidPubDer = Data(base64Encoded: parts[0]),
                           let androidPub = try? P256.KeyAgreement.PublicKey(derRepresentation: androidPubDer),
                           let sharedSecret = try? macPriv.sharedSecretFromKeyAgreement(with: androidPub),
                           let encCreds = Data(base64Encoded: parts[2]),
                           let material = deriveW2p2SessionMaterial(
                                sharedSecret: sharedSecret,
                                sessionId: w2p2SessionId,
                                initiatorPubDer: macPriv.publicKey.derRepresentation,
                                responderPubDer: androidPubDer,
                                initiatorFingerprint: macCertFingerprint,
                                responderFingerprint: parts[1]
                           ) {
                            let sessionKey = material.sessionKey
                            let sessionToken = material.token
                            w2p2VerificationCode = material.verificationCode
                            if let decData = decryptAesGcm(packet: encCreds, using: sessionKey),
                               let decStr = String(data: decData, encoding: .utf8) {
                                let credParts = decStr.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
                                // The fingerprint inside the encrypted credentials must equal the one bound into the key derivation.
                                if credParts.count >= 5 && isValidSha256Fingerprint(credParts[4]) &&
                                    normalizeSha256Fingerprint(credParts[4]) == normalizeSha256Fingerprint(parts[1]) {
                                    let rawProxy = credParts.count >= 6 ? (Int(credParts[5].trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0) : 0
                                    let parsedProxyPort = (1...65535).contains(rawProxy) ? rawProxy : 0
                                    p2pCreds = (
                                        credParts[0],
                                        credParts[1],
                                        credParts[2],
                                        credParts[3],
                                        normalizeSha256Fingerprint(credParts[4]),
                                        parsedProxyPort,
                                        sessionToken
                                    )
                                }
                            }
                        }
                    }
                }

                if isTransferCancelled() {
                    failL2capSession(message: "[BLE-Send] Transfer cancelled by user", clearCancel: true, exitCode: 44)
                }
                if !w2p2WriteOk || w2p2ReplyLine == nil {
                    let reason = w2p2TimedOut
                        ? "[BLE-Send] Timed out negotiating 5 GHz Wi-Fi Direct over Bluetooth LE. Failed stage: \(WifiDirectStage.handshake.rawValue). \(WifiDirectStage.handshake.userAction)"
                        : "[BLE-Send] Bluetooth LE connection closed during 5 GHz Wi-Fi Direct handshake. Failed stage: \(WifiDirectStage.bluetoothConnect.rawValue). \(WifiDirectStage.bluetoothConnect.userAction)"
                    failL2capSession(message: reason)
                }

                if let reply = w2p2ReplyLine, isW2p2UpdateRequiredReply(reply) {
                    failL2capSession(message: "[BLE-Send] The phone runs an incompatible GlideDrop version (secure handshake v\(W2P2_PROTOCOL_VERSION) required). Update GlideDrop on the phone and try again.")
                }
                guard let creds = p2pCreds else {
                    failL2capSession(message: "[BLE-Send] Peer rejected secure W2P2 ECDH/TLS pinning handshake — refusing unpinned downgrade. If the phone runs an older GlideDrop build, update it to the matching version.")
                }
                if let code = w2p2VerificationCode {
                    print("[BLE-Send] Verification code \(code) — it must match the code shown on the phone")
                    fflush(stdout)
                    self.reportSenderConnecting("Verification code \(code) (matches phone)…")
                }

                let ssid = creds.ssid, pass = creds.pass, host = creds.host, port = creds.port, peerPin = creds.peerPin
                let proxyPort = creds.proxyPort
                let sessionToken = creds.sessionToken
                guard isValidP2pGatewayIp(host),
                      let targetHttpsPort = Int(port.trimmingCharacters(in: .whitespacesAndNewlines)),
                      (1...65535).contains(targetHttpsPort) else {
                    failL2capSession(message: "[BLE-Send] Peer supplied invalid Wi-Fi Direct endpoint \(host):\(port)")
                }
                guard ssid.hasPrefix("DIRECT-"), ssid.utf8.count <= 32, !pass.isEmpty else {
                    failL2capSession(message: "[BLE-Send] Peer supplied invalid Wi-Fi Direct credentials")
                }
                clearActiveP2pSession()
                clearOutgoingP2pToken()
                let warpCleared = pauseCloudflareWarpIfNeeded()
                if !warpCleared {
                    print("[BLE-Send] WARP switch locked — refusing LAN transport; using encrypted BLE if permitted")
                    fflush(stdout)
                } else {
                    saveCurrentWifiSsid()
                    self.reportSenderConnecting("Joining 5 GHz Wi-Fi Direct (\(ssid))…")
                    print("[BLE-Send] Joining 5GHz P2P group \(ssid) (\(host):\(targetHttpsPort))...")
                    fflush(stdout)

                    let wifiIface = getWifiInterfaceName()
                    var lastSendWarpCheck = Date()
                    let joinedP2p = associateWifiDirectWithRetry(
                        iface: wifiIface,
                        ssid: ssid,
                        pass: pass,
                        matchingGateway: host,
                        timeout: 38.0,
                        logPrefix: "[BLE-Send]",
                        lastWarpCheck: &lastSendWarpCheck
                    ) {
                        self.reportSenderConnecting("Joining 5 GHz Wi-Fi Direct (\(ssid))…")
                    }

                    if isTransferCancelled() {
                        failL2capSession(message: "[BLE-Send] Transfer cancelled by user", clearCancel: true, exitCode: 44)
                    }

                    if let joinedP2p = joinedP2p {
                        let actualCidr = joinedP2p.cidr
                        let localP2pIp = joinedP2p.ip
                        print("[BLE-Send] Obtained 5GHz P2P IP \(localP2pIp) on \(wifiIface) (cidr=\(actualCidr))")
                        fflush(stdout)
                        // Ensure WARP Always-On didn't re-attach and wait briefly for P2P route/ARP settle before spawning HTTPS client
                        let probeDeadline = Date().addingTimeInterval(4.0)
                        var p2pReachable = false
                        while Date() < probeDeadline {
                            if isTransferCancelled() { break }
                            keepCloudflareWarpPausedPeriodically(lastChecked: &lastSendWarpCheck)
                            if isTcpPortReachable(host: host, port: targetHttpsPort, timeoutMs: 400) {
                                p2pReachable = true
                                break
                            }
                            Thread.sleep(forTimeInterval: 0.2)
                        }
                        if !p2pReachable {
                            print("[BLE-Send] Warning: \(host):\(targetHttpsPort) not yet reachable from Swift probe after 4s; attempting glidedrop.sh connect")
                            fflush(stdout)
                        }
                        guard wifiSsidConsistent(on: joinedP2p.interfaceName, expected: joinedP2p.ssid),
                              writeActiveP2pSession(ssid: joinedP2p.ssid, interfaceName: joinedP2p.interfaceName,
                                  gatewayIp: host, cidr: actualCidr, httpsPort: targetHttpsPort, proxyPort: proxyPort),
                              writeAtomicPrivateFile(data: Data(peerPin.utf8), to: STATE_DIR.appendingPathComponent("pinned_peer_tls_fingerprint.txt")) else {
                            failL2capSession(message: "[BLE-Send] Could not publish OS-confirmed pinned P2P session")
                        }
                        writeOutgoingP2pToken(sessionToken, host: host, port: targetHttpsPort)
                        writeTxInProgressLock()
                        self.reportSenderConnecting("Connecting over 5 GHz Wi-Fi Direct (\(host))…")
                        if proxyPort > 0 {
                            enableMacInternetProxy(host: host, port: proxyPort, cidr: actualCidr)
                        }
                        let peerArg = host.contains(":") ? "[\(host)]:\(targetHttpsPort)" : "\(host):\(targetHttpsPort)"
                        func runP2pTxAttempt() -> Int32 {
                            let txProc = Process()
                            txProc.executableURL = URL(fileURLWithPath: SCRIPT_PATH)
                            txProc.environment = ProcessInfo.processInfo.environment
                            txProc.environment?["SKIP_BLE_RESTART"] = "1"
                            txProc.environment?.removeValue(forKey: "GLIDEDROP_P2P_TOKEN")
                            // Peer pin: one-time 0600 file (deleted by glidedrop.sh after read), never argv.
                            // Bearer token: already in the 0600 p2p_outgoing_token.json state file.
                            guard writeAtomicPrivateFile(data: Data(peerPin.utf8),
                                                         to: STATE_DIR.appendingPathComponent("pinned_peer_tls_fingerprint.txt")) else {
                                return 45
                            }
                            txProc.arguments = ["send", "--peer", peerArg] + self.files.map { $0.path } + self.urls
                            return runP2pTxProcess(txProc) {
                                keepCloudflareWarpPausedPeriodically(lastChecked: &lastSendWarpCheck)
                            }
                        }
                        let attemptStart = Date()
                        var txStatus = runP2pTxAttempt()
                        // Retry once on transient initial connect drop if WARP Always-On flickered and payload shouldn't drop to BLE
                        if shouldRetryP2pTx(fileCount: self.files.count, totalRawBytes: self.totalRawBytes,
                                            txExitCode: txStatus, elapsed: Date().timeIntervalSince(attemptStart),
                                            cancelled: isTransferCancelled()) {
                            print("[BLE-Send] Retrying 5 GHz Wi-Fi Direct HTTPS connect once after transient drop (status=\(txStatus))...")
                            fflush(stdout)
                            _ = pauseCloudflareWarpIfNeeded()
                            Thread.sleep(forTimeInterval: 0.5)
                            txStatus = runP2pTxAttempt()
                        }
                        p2pTxExitCode = txStatus
                        if isTransferCancelled() {
                            writeProgressJson(active: false)
                            restoreMacInternetWifi(ssid: ssid)
                            failL2capSession(message: "[BLE-Send] Transfer cancelled by user", clearCancel: true, exitCode: 44)
                        }
                        if txStatus == 44 {
                            writeProgressJson(active: false)
                            restoreMacInternetWifi(ssid: ssid)
                            failL2capSession(message: "[BLE-Send] Transfer cancelled by receiver", clearCancel: true, exitCode: 44)
                        }
                        restoreMacInternetWifi(ssid: ssid)

                        if txStatus == 0 {
                            writeProgressJson(active: false)
                            inp.close()
                            out.close()
                            try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
                            print("[BLE-Send] Delivered via 5GHz Wi-Fi Direct P2P!")
                            exit(0)
                        }
                        if txStatus == 43 {
                            failL2capSession(message: "[BLE-Send] Transfer declined by receiver", exitCode: 43)
                        }
                        if txStatus == 45 {
                            failL2capSession(message: "[BLE-Send] HTTPS sender launch/configuration failed — refusing BLE downgrade", exitCode: 45)
                        }
                        if txStatus == 46 {
                            failL2capSession(message: "[BLE-Send] Peer TLS certificate fingerprint pinning mismatch — aborting transfer. Failed stage: \(WifiDirectStage.tlsPin.rawValue). \(WifiDirectStage.tlsPin.userAction)", exitCode: 46)
                        }
                        if txStatus == 47 {
                            failL2capSession(message: "[BLE-Send] HTTPS protocol/upload error — refusing retry or BLE downgrade", exitCode: 47)
                        }
                    } else {
                        print("[BLE-Send] Failed to verify 5GHz P2P association on \(wifiIface) for \(ssid)")
                        fflush(stdout)
                        logWifiDirectStageFailure(wifiJoinFailureStage(), logPrefix: "[BLE-Send]")
                        restoreMacInternetWifi(ssid: ssid)
                    }
                }
            }

            if isTransferCancelled() {
                failL2capSession(message: "[BLE-Send] Transfer cancelled by user", clearCancel: true, exitCode: 44)
            }
            clearOutgoingP2pToken()
            clearActiveP2pSession()
            try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("pinned_peer_tls_fingerprint.txt"))
            if !shouldAllowBleAutoFallback(fileCount: self.files.count, totalRawBytes: self.totalRawBytes, txExitCode: p2pTxExitCode) {
                failL2capSession(
                    message: "[BLE-Send] 5 GHz Wi-Fi Direct failed for \(formatByteSize(self.totalRawBytes)) transfer — refusing slow Bluetooth LE fallback. Ensure Wi-Fi is enabled and pause Cloudflare WARP if active."
                )
            }

            let preparedPayload: (metaData: Data, gzData: Data)
            if let existingPrep = self.preparedBlePayload {
                preparedPayload = existingPrep
            } else {
                if !self.files.isEmpty && self.totalRawBytes > BLE_RAW_PRECHECK_MAX_BYTES {
                    failL2capSession(
                        message: "[BLE-Send] 5 GHz Wi-Fi Direct failed and payload (\(formatByteSize(self.totalRawBytes))) exceeds the 30 MB Bluetooth LE fallback limit."
                    )
                }

                self.reportSenderConnecting("Preparing fallback Bluetooth LE archive…")
                do {
                    preparedPayload = try prepareBleFallbackPayload(
                        files: self.files,
                        urls: self.urls,
                        totalRawBytes: self.totalRawBytes,
                        senderName: loadMacSettings().deviceName
                    )
                } catch let capErr as BleFallbackCapError {
                    failL2capSession(message: "[BLE-Send] \(capErr.localizedDescription)")
                } catch {
                    failL2capSession(message: "[BLE-Send] Failed to prepare fallback Bluetooth LE archive: \(error.localizedDescription)")
                }
            }

            // Ephemeral ECDH P-256 key agreement for BLE ADRE frame (no static key)
            let bleMacPriv = P256.KeyAgreement.PrivateKey()
            let bleMacPubB64 = bleMacPriv.publicKey.derRepresentation.base64EncodedString()
            let blePubBytes = Data(bleMacPubB64.utf8)
            var blekFrame = Data("BLEK".utf8)
            var blekMetaLen = UInt32(blePubBytes.count).bigEndian
            var blekArchLen = UInt32(0).bigEndian
            blekFrame.append(Data(bytes: &blekMetaLen, count: 4))
            blekFrame.append(Data(bytes: &blekArchLen, count: 4))
            blekFrame.append(blePubBytes)
            if !writeAll(out, data: blekFrame) {
                failL2capSession(message: "[BLE-Send] Failed to send ephemeral BLEK key exchange frame")
            }
            var blekTimedOut = false
            let blekReplyLine = readBleStreamLine(inp, maxLen: 1024, timeout: 15.0, checkCancel: true, onTimeout: {
                blekTimedOut = true
                DispatchQueue.main.async { self.cm?.cancelPeripheralConnection(peripheral) }
            })
            if isTransferCancelled() {
                failL2capSession(message: "[BLE-Send] Transfer cancelled by user", clearCancel: true)
            }
            guard let bleReply = blekReplyLine, bleReply.hasPrefix("OK\t") else {
                let reason = blekTimedOut
                    ? "[BLE-Send] Timed out waiting for BLE ECDH key agreement"
                    : "[BLE-Send] Peer rejected BLE ECDH key agreement"
                failL2capSession(message: reason)
            }
            let peerBlePubB64 = String(bleReply.dropFirst(3)).trimmingCharacters(in: .whitespacesAndNewlines)
            guard let peerBlePubDer = Data(base64Encoded: peerBlePubB64),
                  let peerBlePub = try? P256.KeyAgreement.PublicKey(derRepresentation: peerBlePubDer),
                  let bleSharedSecret = try? bleMacPriv.sharedSecretFromKeyAgreement(with: peerBlePub) else {
                failL2capSession(message: "[BLE-Send] Invalid peer ECDH public key during BLE key agreement")
            }
            let ephemeralBleKey = deriveBleFrameKey(sharedSecret: bleSharedSecret)

            let payloadFrame: Data
            do {
                payloadFrame = try buildEncryptedBleFallbackFrame(
                    metaData: preparedPayload.metaData,
                    gzData: preparedPayload.gzData,
                    totalRawBytes: self.totalRawBytes,
                    sessionKey: ephemeralBleKey
                )
            } catch let capErr as BleFallbackCapError {
                failL2capSession(message: "[BLE-Send] \(capErr.localizedDescription)")
            } catch {
                failL2capSession(message: "[BLE-Send] Failed to encrypt fallback Bluetooth LE archive: \(error.localizedDescription)")
            }

            writeTxInProgressLock()
            let label = self.files.first?.lastPathComponent ?? (self.urls.first ?? "BLE Transfer")
            print("[BLE-Send] Streaming \(payloadFrame.count) bytes over Direct Bluetooth LE L2CAP...")
            fflush(stdout)
            let ok = writeAll(
                out,
                data: payloadFrame,
                trackProgress: true,
                fileLabel: label,
                fileCount: self.itemCount,
                peerName: self.peerLabel,
                clearProgressOnSuccess: false
            )
            var ackData: Data? = nil
            var ackStr = ""
            var ackTimedOut = false
            if ok {
                let emitWaitingAckProgress = {
                    writeProgressJson(
                        active: true,
                        direction: "Sending",
                        fileName: label,
                        fileCount: self.itemCount,
                        doneBytes: Int64(payloadFrame.count),
                        totalBytes: Int64(payloadFrame.count),
                        speedBps: 0,
                        etaSeconds: 0,
                        percent: 99,
                        phase: "Waiting for receiver confirmation…",
                        peerName: self.peerLabel,
                        isConnecting: false
                    )
                }
                emitWaitingAckProgress()
                ackData = readExact(
                    inp,
                    count: 2,
                    timeout: 60.0,
                    checkCancel: true,
                    onWaitTick: emitWaitingAckProgress,
                    onTimeout: {
                        ackTimedOut = true
                        DispatchQueue.main.async {
                            self.cm?.cancelPeripheralConnection(peripheral)
                        }
                    }
                )
                ackStr = ackData.flatMap { String(data: $0, encoding: .ascii) } ?? ""
            }
            writeProgressJson(active: false)
            inp.close()
            out.close()
            try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
            if ok && ackStr == "OK" {
                let resolvedPeer = loadActivePeersFromDisk(maxAge: 30.0).first?.name ?? self.peerLabel
                for f in self.files {
                    let sz = (try? FileManager.default.attributesOfItem(atPath: f.path)[.size] as? NSNumber)?.int64Value ?? 0
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
            } else if ok && ackStr == "NO" {
                if needsMacInternetWifiRestore() { restoreMacInternetWifi() }
                print("[BLE-Send] Transfer declined by receiver")
                exit(43)
            } else if isTransferCancelled() {
                clearCancelFlag()
                if needsMacInternetWifiRestore() { restoreMacInternetWifi() }
                print("[BLE-Send] Transfer cancelled by user")
                exit(44)
            } else if ok && ackData == nil {
                if needsMacInternetWifiRestore() { restoreMacInternetWifi() }
                let msg = ackTimedOut
                    ? "[BLE-Send] Timed out waiting for receiver confirmation"
                    : "[BLE-Send] Receiver disconnected before confirming transfer"
                print(msg)
                exit(1)
            } else {
                if needsMacInternetWifiRestore() { restoreMacInternetWifi() }
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
            .animation(reduceMotion ? nil : .spring(response: 0.20, dampingFraction: 0.80), value: configuration.isPressed)
    }
}

final class MacConnectingBridgeAnim: ObservableObject {
    @Published var phase: CGFloat = 0
}

struct MacConnectingBridgeLine: View {
    let color: Color
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @ObservedObject private var anim = MacConnectingBridgeAnim()

    var body: some View {
        Path { path in
            path.move(to: CGPoint(x: 8, y: 26))
            path.addQuadCurve(to: CGPoint(x: 172, y: 26), control: CGPoint(x: 90, y: -4))
        }
        .stroke(
            color.opacity(0.55),
            style: StrokeStyle(lineWidth: 1.8, lineCap: .round, dash: [5, 5], dashPhase: anim.phase)
        )
        .frame(width: 180, height: 34)
        .onAppear {
            guard !reduceMotion else { return }
            withAnimation(.linear(duration: 1.1).repeatForever(autoreverses: false)) {
                anim.phase = -20
            }
        }
    }
}

final class MacIndeterminateBarAnim: ObservableObject {
    @Published var pulse: Bool = false
}

struct MacIndeterminateConnectingBar: View {
    let color: Color
    let width: CGFloat
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @ObservedObject private var anim = MacIndeterminateBarAnim()

    var body: some View {
        Capsule()
            .fill(color.opacity(0.75))
            .frame(width: max(48, width * 0.28), height: 7)
            .offset(x: anim.pulse ? width * 0.68 : 4)
            .onAppear {
                guard !reduceMotion else { return }
                withAnimation(.easeInOut(duration: 1.2).repeatForever(autoreverses: true)) {
                    anim.pulse = true
                }
            }
    }
}

final class MacRadarAnimationModel: ObservableObject {
    @Published var sweepAngle: Double = 0
    @Published var pulseScale: CGFloat = 0.5
    @Published var pulseOpacity: Double = 0.8
}

struct MacRadarScannerView: View {
    let peers: [MacDiscoveredPeer]
    let palette: MacThemePalette
    let onSelectPeer: (MacDiscoveredPeer) -> Void
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @ObservedObject private var anim = MacRadarAnimationModel()

    private func peerIcon(for peer: MacDiscoveredPeer) -> String {
        let lower = peer.name.lowercased()
        if lower.contains("mac") || lower.contains("book") || lower.contains("desktop") || lower.contains("laptop") {
            return "laptopcomputer"
        } else if lower.contains("pad") || lower.contains("tablet") {
            return "ipad.gen2"
        }
        return peer.transport.lowercased().contains("ble") ? "iphone.gen3" : "laptopcomputer"
    }

    var body: some View {
        ZStack {
            // Ambient radar container circle
            Circle()
                .fill(palette.isDark ? Color(red: 0.05, green: 0.07, blue: 0.12).opacity(0.7) : Color(red: 0.94, green: 0.96, blue: 0.99))
                .frame(width: 240, height: 240)
                .overlay(Circle().stroke(palette.indigo.opacity(palette.isDark ? 0.20 : 0.14), lineWidth: 1))

            // Concentric Guide Rings
            Circle()
                .stroke(palette.indigo.opacity(palette.isDark ? 0.22 : 0.15), lineWidth: 1)
                .frame(width: 216, height: 216)
            Circle()
                .stroke(palette.indigo.opacity(palette.isDark ? 0.28 : 0.20), lineWidth: 1)
                .frame(width: 154, height: 154)
            Circle()
                .stroke(palette.indigo.opacity(palette.isDark ? 0.35 : 0.25), lineWidth: 1)
                .frame(width: 92, height: 92)

            // Smooth Sweeping Radar Cone
            if !reduceMotion {
                Circle()
                    .fill(
                        AngularGradient(
                            gradient: Gradient(colors: [
                                palette.indigo.opacity(0.0),
                                palette.indigo.opacity(0.02),
                                palette.indigo.opacity(palette.isDark ? 0.24 : 0.16)
                            ]),
                            center: .center,
                            startAngle: .degrees(0),
                            endAngle: .degrees(360)
                        )
                    )
                    .frame(width: 216, height: 216)
                    .rotationEffect(.degrees(anim.sweepAngle))
            }

            // Expanding Pulse Wave
            if !reduceMotion {
                Circle()
                    .stroke(palette.indigo.opacity(anim.pulseOpacity * 0.45), lineWidth: 1.5)
                    .frame(width: 216 * anim.pulseScale, height: 216 * anim.pulseScale)
            }

            // Central Pulse Transmitter Node
            ZStack {
                Circle()
                    .fill(palette.indigo.opacity(palette.isDark ? 0.22 : 0.15))
                    .frame(width: 54, height: 54)
                Circle()
                    .fill(LinearGradient(colors: [palette.indigo, palette.indigoHover], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 42, height: 42)
                    .shadow(color: palette.indigo.opacity(0.45), radius: 8, x: 0, y: 2)
                Image(systemName: "dot.radiowaves.left.and.right")
                    .font(.system(size: 16, weight: .bold))
                    .foregroundColor(.white)
            }

            // Discovered Peers positioned on the orbital ring
            ForEach(Array(peers.prefix(3).enumerated()), id: \.element.id) { idx, peer in
                let angle = (-36.0 + Double(idx) * 118.0) * .pi / 180.0
                let r: CGFloat = 92.0
                Button(action: { onSelectPeer(peer) }) {
                    HStack(spacing: 6) {
                        Image(systemName: peerIcon(for: peer))
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundColor(palette.indigo)
                        Text(middleTruncateMacName(peer.name, maxChars: 15))
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(palette.textPrimary)
                        Circle()
                            .fill(palette.emerald)
                            .frame(width: 6, height: 6)
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(
                        Capsule()
                            .fill(palette.bgSurface)
                            .overlay(Capsule().stroke(palette.emerald.opacity(0.65), lineWidth: 1.2))
                            .shadow(color: Color.black.opacity(palette.isDark ? 0.35 : 0.08), radius: 6, x: 0, y: 2)
                    )
                }
                .buttonStyle(MacScaleButtonStyle())
                .offset(x: CGFloat(cos(angle)) * r, y: CGFloat(sin(angle)) * r * 0.72)
            }
        }
        .frame(maxWidth: .infinity)
        .frame(height: 236)
        .onAppear {
            guard !reduceMotion else { return }
            withAnimation(.linear(duration: 4.0).repeatForever(autoreverses: false)) {
                anim.sweepAngle = 360
            }
            withAnimation(.easeOut(duration: 2.2).repeatForever(autoreverses: false)) {
                anim.pulseScale = 1.0
                anim.pulseOpacity = 0.0
            }
        }
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

enum MacAiPillTone: Equatable {
    case standby
    case activeEmerald
    case readyIndigo
    case warningAmber
}

struct MacAiPillState: Equatable {
    let title: String
    let iconName: String
    let tone: MacAiPillTone
}

func resolveClaudeProcessorAvailable(
    scriptPath: String = SCRIPT_PATH,
    stateDir: URL = STATE_DIR,
    repoRoot: URL = REPO_ROOT,
    bundleResourceURL: URL? = Bundle.main.resourceURL
) -> Bool {
    let fm = FileManager.default
    let scriptDir = URL(fileURLWithPath: scriptPath).resolvingSymlinksInPath().deletingLastPathComponent()
    let candidates: [String] = [
        bundleResourceURL?.appendingPathComponent("claude_processor.py").path,
        scriptDir.appendingPathComponent("claude_processor.py").path,
        scriptDir.deletingLastPathComponent().appendingPathComponent("macos/claude_processor.py").path,
        stateDir.appendingPathComponent("claude_processor.py").path,
        repoRoot.appendingPathComponent("macos/claude_processor.py").path,
    ].compactMap { $0 }
    return candidates.contains { fm.fileExists(atPath: $0) }
}

func resolveAiPillStates(
    enabled: Bool,
    processorAvailable: Bool,
    swiftAvailable: Bool
) -> (privacy: MacAiPillState, vision: MacAiPillState) {
    guard enabled else {
        return (
            privacy: MacAiPillState(
                title: "Privacy Guard: Standby",
                iconName: "shield",
                tone: .standby
            ),
            vision: MacAiPillState(
                title: "Local Vision Engine: Standby",
                iconName: "cpu",
                tone: .standby
            )
        )
    }
    let privacy = processorAvailable
        ? MacAiPillState(title: "Privacy Guard: Active", iconName: "checkmark.shield.fill", tone: .activeEmerald)
        : MacAiPillState(title: "Privacy Guard: Unavailable", iconName: "exclamationmark.shield.fill", tone: .warningAmber)
    let vision = (processorAvailable && swiftAvailable)
        ? MacAiPillState(title: "Local Vision Engine: Ready", iconName: "cpu", tone: .readyIndigo)
        : MacAiPillState(title: "Local Vision Engine: Unavailable", iconName: "cpu", tone: .warningAmber)
    return (privacy, vision)
}

func defaultClaudeConfigDir() -> URL {
    return STATE_DIR
}

func readAiSubsystemEnabled(
    env: [String: String] = ProcessInfo.processInfo.environment,
    configDir: URL = defaultClaudeConfigDir()
) -> Bool {
    if let envVal = env["CLAUDE_AI_ENABLED"]?.lowercased(),
       envVal == "1" || envVal == "true" || envVal == "yes" || envVal == "on" {
        return true
    }
    let cfgPath = configDir.appendingPathComponent("claude_config.json")
    if let data = try? Data(contentsOf: cfgPath),
       let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
       let cfgEnabled = obj["enabled"] as? Bool {
        return cfgEnabled
    }
    return false
}

func writeAiSubsystemEnabled(_ enabled: Bool, configDir: URL = defaultClaudeConfigDir()) {
    try? FileManager.default.createDirectory(
        at: configDir,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    let cfgPath = configDir.appendingPathComponent("claude_config.json")
    var dict: [String: Any] = [:]
    if let data = try? Data(contentsOf: cfgPath),
       let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
        dict = obj
    }
    dict["enabled"] = enabled
    guard let out = try? JSONSerialization.data(withJSONObject: dict, options: [.prettyPrinted]) else { return }
    let tmpPath = configDir.appendingPathComponent("claude_config.json.tmp.\(UUID().uuidString)")
    if FileManager.default.createFile(atPath: tmpPath.path, contents: out, attributes: [.posixPermissions: 0o600]) {
        _ = chmod(tmpPath.path, 0o600)
        if Darwin.rename(tmpPath.path, cfgPath.path) != 0 {
            try? FileManager.default.removeItem(at: tmpPath)
        }
    }
}

final class MacGlideDropViewModel: ObservableObject {
    @Published var selectedTab: Int = 0 // 0 = Send, 1 = Receive, 2 = History, 3 = Settings
    @Published var stagedItems: [MacStagedItem] = []
    @Published var showLinkComposer: Bool = false
    @Published var historyFilter: Int = 0 // 0 = All, 1 = Received, 2 = Sent
    @Published var historySearch: String = ""
    @Published var themeMode: String = "system" // "light", "dark", "system"
    @Published var systemIsDark: Bool = true
    @Published var storage: MacStorageSummary = MacStorageSummary.queryLocalDisk()
    @Published var receiverRunning: Bool = false
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
    private var cancelRequestedUntil: TimeInterval = 0
    @Published var pendingAsk: MacPendingAsk? = nil
    @Published var urlInput: String = ""
    @Published var isDropTargeted: Bool = false
    @Published var showLogs: Bool = false
    @Published var aiSubsystemEnabled: Bool = false
    @Published var aiProcessorAvailable: Bool = false
    @Published var localVisionReady: Bool = false
    @Published var historyEntries: [MacHistoryEntry] = []
    @Published var logs: [String] = []
    @Published var bluetoothAuthorized: Bool = true
    @Published var bluetoothPoweredOn: Bool = true
    @Published var wifiPoweredOn: Bool = true

    func refreshAiStatus() {
        let enabled = readAiSubsystemEnabled()
        let procAvail = resolveClaudeProcessorAvailable()
        let visionAvail = FileManager.default.isExecutableFile(atPath: "/usr/bin/swift")
        if aiSubsystemEnabled != enabled {
            aiSubsystemEnabled = enabled
        }
        if aiProcessorAvailable != procAvail {
            aiProcessorAvailable = procAvail
        }
        if localVisionReady != visionAvail {
            localVisionReady = visionAvail
        }
    }

    func toggleAiSubsystem(_ enabled: Bool) {
        aiSubsystemEnabled = enabled
        aiProcessorAvailable = resolveClaudeProcessorAvailable()
        localVisionReady = FileManager.default.isExecutableFile(atPath: "/usr/bin/swift")
        writeAiSubsystemEnabled(enabled)
    }

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
        self.receiverRunning = s.visible
        self.macDeviceName = s.deviceName
        self.editingDeviceName = s.deviceName
        self.themeMode = s.themeMode
        self.systemIsDark = Self.detectSystemDark()
        self.refreshAiStatus()
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
        saveMacSettings(autoAccept: autoAccept, visible: loadMacSettings().visible, deviceName: macDeviceName, themeMode: normalized)
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
        if Date().timeIntervalSince1970 < cancelRequestedUntil {
            if isTransferring { isTransferring = false }
            if liveProgress != nil { liveProgress = nil }
            return
        }
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
        saveMacSettings(autoAccept: directGet, visible: loadMacSettings().visible, deviceName: macDeviceName, themeMode: themeMode)
    }

    func saveDeviceName() {
        let clean = editingDeviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty else { return }
        macDeviceName = clean
        saveMacSettings(autoAccept: autoAccept, visible: loadMacSettings().visible, deviceName: clean, themeMode: themeMode)
    }

    func refreshSlow() {
        refreshAiStatus()
        let s = loadMacSettings()
        receiverRunning = s.visible && isPidAlive("daemon.pid")
        awdlProxyRunning = isPidAlive("awdl-mdns.pid")
        bleRunning = true

        let auth = CBManager.authorization
        bluetoothAuthorized = (auth != .denied && auth != .restricted)
        if let cmState = BleGlideDropDaemon.shared?.cm.state {
            bluetoothPoweredOn = (cmState != .poweredOff)
        }

        let wifiDev = getWifiInterfaceName()
        let wifiOn = (CWWiFiClient.shared().interface(withName: wifiDev) ?? CWWiFiClient.shared().interface())?.powerOn() ?? true
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
        BleGlideDropDaemon.shared?.rescanNow()
        if !receiverRunning {
            DispatchQueue.global(qos: .userInitiated).async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: SCRIPT_PATH)
                p.environment = ProcessInfo.processInfo.environment
                p.environment?["SKIP_BLE_RESTART"] = "1"
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
        receiverRunning = turnOn
        saveMacSettings(autoAccept: autoAccept, visible: turnOn, deviceName: macDeviceName, themeMode: themeMode)
        if turnOn {
            BleGlideDropDaemon.shared?.startAdvertisingAndScanning()
            BleGlideDropDaemon.shared?.rescanNow()
        } else {
            BleGlideDropDaemon.shared?.stopAdvertisingAndScanning()
        }
        DispatchQueue.global(qos: .userInitiated).async {
            if turnOn {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: SCRIPT_PATH)
                p.environment = ProcessInfo.processInfo.environment
                p.environment?["SKIP_BLE_RESTART"] = "1"
                p.arguments = ["restart-receiver"]
                try? p.run()
                p.waitUntilExit()
            } else {
                for pf in ["daemon.pid", "awdl-mdns.pid", "ble-daemon.pid"] {
                    let f = STATE_DIR.appendingPathComponent(pf)
                    if let s = try? String(contentsOf: f, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
                       let pid = Int32(s), pid != getpid() {
                        kill(pid, SIGTERM)
                    }
                    if pf != "ble-daemon.pid" || (try? String(contentsOf: f, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)) != String(getpid()) {
                        try? FileManager.default.removeItem(at: f)
                    }
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
        cancelRequestedUntil = Date().timeIntervalSince1970 + 3.0
        let flag = STATE_DIR.appendingPathComponent("cancel_transfer.flag")
        try? String(Date().timeIntervalSince1970).write(to: flag, atomically: true, encoding: .utf8)
        BleGlideDropDaemon.shared?.cancelActivePing()
        if let proc = activeSendProcess, proc.isRunning {
            proc.terminate()
        }
        activeSendProcess = nil
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("transfer_progress.json"))
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("rx_in_progress.lock"))
        try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("wp2p_authorized_session.json"))
        writeProgressJson(active: false)
        isTransferring = false
        liveProgress = nil
        transferStatus = "Transfer cancelled"
        DispatchQueue.global(qos: .userInitiated).async {
            for pattern in ["GlideDrop send", "glidedrop-daemon send", "glidedrop.sh send"] {
                let killProc = Process()
                killProc.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
                killProc.arguments = ["-f", pattern]
                try? killProc.run()
                killProc.waitUntilExit()
            }
            restoreMacInternetWifi()
        }
    }

    func enableMacWifi() {
        let wifiDev = getWifiInterfaceName()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
            p.arguments = ["-setairportpower", wifiDev, "on"]
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
        let hasFiles = itemsToSend.contains(where: { !$0.isUrl })
        let connectingPhase = (hasFiles && totalBytes >= 65_536)
            ? "Connecting to \(targetName) via 5 GHz Wi-Fi Direct…"
            : "Connecting to \(targetName)…"
        let initialConnecting = MacLiveProgress(
            direction: "Sending",
            fileName: summaryLabel,
            fileCount: count,
            doneBytes: 0,
            totalBytes: totalBytes,
            speedBps: 0,
            etaSeconds: 0,
            percent: 0,
            phase: connectingPhase,
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
            phase: connectingPhase,
            peerName: targetName,
            isConnecting: true
        )
        transferStatus = "Connecting to \(targetName)…"
        writeTxInProgressLock()
        BleGlideDropDaemon.shared?.cancelActivePing()

        DispatchQueue.global(qos: .userInitiated).async {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: SCRIPT_PATH)
            p.environment = ProcessInfo.processInfo.environment
            p.environment?["SKIP_BLE_RESTART"] = "1"
            p.arguments = ["send"] + args
            let pipe = Pipe()
            p.standardOutput = pipe
            p.standardError = pipe
            DispatchQueue.main.async {
                self.activeSendProcess = p
            }
            let outData: Data
            if (try? p.run()) != nil {
                try? pipe.fileHandleForWriting.close()
                outData = pipe.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
            } else {
                try? pipe.fileHandleForWriting.close()
                outData = Data()
            }
            try? pipe.fileHandleForReading.close()
            try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
            writeProgressJson(active: false)
            let wasCancelled = isTransferCancelled() || p.terminationStatus == 44
            let wasDeclined = (p.terminationStatus == 43)
            clearCancelFlag()
            let txLogUrl = STATE_DIR.appendingPathComponent("tx-send.log")
            try? outData.write(to: txLogUrl, options: [.atomic])
            let out = String(data: outData, encoding: .utf8) ?? ""
            let lastLine = out
                .split(separator: "\n")
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .last(where: { !$0.isEmpty }) ?? ""
            let ok = p.terminationStatus == 0 && !wasCancelled
            DispatchQueue.main.async {
                self.activeSendProcess = nil
                self.isTransferring = false
                self.liveProgress = nil
                if wasCancelled {
                    self.transferStatus = "Transfer cancelled"
                } else if wasDeclined {
                    self.transferStatus = "Transfer declined by \(targetName)"
                } else if ok {
                    self.stagedItems.removeAll()
                    self.transferStatus = "Sent \(summaryLabel) to \(targetName)"
                } else {
                    self.transferStatus = "Transfer failed: \(lastLine.isEmpty ? "Open GlideDrop on the receiving device and try again" : lastLine)"
                }
            }
            if needsMacInternetWifiRestore() {
                restoreMacInternetWifi()
            }
            DispatchQueue.main.async {
                self.refreshSlow()
            }
        }
    }
}

struct MacGlideDropMainView: View {
    @ObservedObject var vm: MacGlideDropViewModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var p: MacThemePalette { vm.palette }

    var body: some View {
        ZStack {
            p.bgCanvas.ignoresSafeArea()

            VStack(spacing: 0) {
                topHeaderBar
                    .padding(.horizontal, 20)
                    .padding(.top, 36)
                    .padding(.bottom, 12)

                if !vm.bluetoothAuthorized || !vm.bluetoothPoweredOn || !vm.wifiPoweredOn {
                    systemReadinessBanner
                        .padding(.horizontal, 20)
                        .padding(.bottom, 10)
                }

                if let prog = vm.liveProgress {
                    liveConnectionBridgeCard(prog)
                        .padding(.horizontal, 20)
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
                    .padding(.horizontal, 20)
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
                    .padding(.horizontal, 20)
                    .padding(.vertical, 8)
                }

                bottomTabBar
            }

            if let ask = vm.pendingAsk {
                Color.black.opacity(p.isDark ? 0.65 : 0.35)
                    .ignoresSafeArea()
                    .transition(.opacity)
                incomingAskModal(ask)
                    .padding(28)
                    .transition(.asymmetric(
                        insertion: .scale(scale: 0.95).combined(with: .opacity),
                        removal: .scale(scale: 0.97).combined(with: .opacity)
                    ))
            }
        }
        .animation(.spring(response: 0.28, dampingFraction: 0.82), value: vm.pendingAsk != nil)
        .frame(minWidth: 550, idealWidth: 570, minHeight: 680, idealHeight: 720)
        .preferredColorScheme(p.isDark ? .dark : .light)
    }

    // ========================================================================
    // Top Header Bar (GlideDrop Title + Radio Status + Day/Dark Toggle + Scan)
    // ========================================================================
    private var topHeaderBar: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(p.indigoSubtle)
                    .frame(width: 40, height: 40)
                    .overlay(Circle().stroke(p.indigo.opacity(0.30), lineWidth: 1))
                Image(systemName: "dot.radiowaves.left.and.right")
                    .font(.system(size: 17, weight: .bold))
                    .foregroundColor(p.indigo)
            }

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 7) {
                    Text("GlideDrop")
                        .font(.system(size: 19, weight: .bold, design: .rounded))
                        .foregroundColor(p.textPrimary)
                    HStack(spacing: 4) {
                        Circle()
                            .fill(vm.receiverRunning ? p.emerald : p.amber)
                            .frame(width: 6, height: 6)
                        Text(vm.receiverRunning ? "Discoverable" : "Paused")
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
                Text("Discoverable as \"\(vm.macDeviceName)\" • ~/Downloads")
                    .font(.system(size: 11, weight: .medium))
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
                    MacConnectingBridgeLine(color: p.indigo)

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
                        MacIndeterminateConnectingBar(color: p.indigo, width: geo.size.width)
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
    // TAB 1: Receive (Apple Radar Scanner + Discovered Peers + Recent RX)
    // ========================================================================
    private var receiveRadarTabContent: some View {
        VStack(alignment: .leading, spacing: 14) {
            // Radar Card
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(vm.activePeers.isEmpty ? "Looking for Connections" : "Nearby Devices")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundColor(p.textSecondary)
                        Text(vm.activePeers.isEmpty ? "Radar Scanning…" : "\(vm.activePeers.count) Device\(vm.activePeers.count == 1 ? "" : "s") Ready")
                            .font(.system(size: 20, weight: .bold, design: .rounded))
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

                // Apple Radar Visual
                MacRadarScannerView(
                    peers: vm.activePeers,
                    palette: p,
                    onSelectPeer: { peer in
                        vm.chooseFilesForCategory(title: "Files for \(peer.name)", types: [])
                    }
                )

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
                        Text("Open GlideDrop on your Android phone with Bluetooth enabled.")
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
        let iconName: String = {
            let lower = peer.name.lowercased()
            if lower.contains("mac") || lower.contains("book") || lower.contains("desktop") || lower.contains("laptop") {
                return "laptopcomputer"
            } else if lower.contains("pad") || lower.contains("tablet") {
                return "ipad.gen2"
            }
            return peer.transport.lowercased().contains("ble") ? "iphone.gen3" : "laptopcomputer"
        }()
        return HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(p.indigoSubtle)
                    .frame(width: 44, height: 44)
                Image(systemName: iconName)
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

            // 3. AI Intelligence Subsystem
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    ZStack {
                        Circle()
                            .fill(p.indigoSubtle)
                            .frame(width: 32, height: 32)
                        Image(systemName: "sparkles")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(p.indigo)
                    }
                    VStack(alignment: .leading, spacing: 1) {
                        Text("AI Ingestion & Analysis")
                            .font(.system(size: 14, weight: .bold))
                            .foregroundColor(p.textPrimary)
                        Text("Multimodal summaries, Vision OCR, and code analysis for received files.")
                            .font(.system(size: 11))
                            .foregroundColor(p.textSecondary)
                    }
                    Spacer()
                    Toggle("", isOn: Binding(
                        get: { vm.aiSubsystemEnabled },
                        set: { vm.toggleAiSubsystem($0) }
                    ))
                    .toggleStyle(.switch)
                    .labelsHidden()
                }

                let aiPills = resolveAiPillStates(
                    enabled: vm.aiSubsystemEnabled,
                    processorAvailable: vm.aiProcessorAvailable,
                    swiftAvailable: vm.localVisionReady
                )
                HStack(spacing: 8) {
                    aiStatusPill(aiPills.privacy)
                    aiStatusPill(aiPills.vision)
                }
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 20)
                    .fill(p.bgSurface)
                    .overlay(RoundedRectangle(cornerRadius: 20).stroke(p.border, lineWidth: 1))
            )

            // 4. Device Name & Downloads
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

    private func aiStatusPill(_ pill: MacAiPillState) -> some View {
        let fgColor: Color
        let bgColor: Color
        let borderColor: Color
        switch pill.tone {
        case .standby:
            fgColor = p.textSecondary
            bgColor = p.bgSubtle
            borderColor = p.border
        case .activeEmerald:
            fgColor = p.emerald
            bgColor = p.emeraldSubtle
            borderColor = Color.clear
        case .readyIndigo:
            fgColor = p.indigo
            bgColor = p.indigoSubtle
            borderColor = Color.clear
        case .warningAmber:
            fgColor = p.amber
            bgColor = p.amberSubtle
            borderColor = Color.clear
        }
        return HStack(spacing: 4) {
            Image(systemName: pill.iconName)
                .font(.system(size: 10, weight: .bold))
                .foregroundColor(fgColor)
            Text(pill.title)
                .font(.system(size: 10, weight: .semibold))
                .foregroundColor(fgColor)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(
            Capsule()
                .fill(bgColor)
                .overlay(Capsule().stroke(borderColor, lineWidth: 1))
        )
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
        let isWifiRequest = ask.totalBytes == 0 && (ask.fileNames.first?.contains("Wi-Fi Direct") == true)
        return VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(p.indigo)
                        .frame(width: 44, height: 44)
                    Image(systemName: isWifiRequest ? "wifi" : "arrow.down.doc.fill")
                        .font(.system(size: 20, weight: .bold))
                        .foregroundColor(.white)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text(isWifiRequest ? "Wi-Fi Direct Connection" : "Incoming Files")
                        .font(.system(size: 16, weight: .heavy))
                        .foregroundColor(p.textPrimary)
                    Text("From \(ask.senderName)")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(p.indigo)
                }
                Spacer()
            }

            VStack(alignment: .leading, spacing: 6) {
                if isWifiRequest {
                    Text("Secure Peer-to-Peer Link")
                        .font(.system(size: 12, weight: .bold))
                        .foregroundColor(p.emerald)
                } else {
                    Text("\(ask.fileNames.count) \(ask.fileNames.count == 1 ? "file" : "files") • \(formatByteSize(ask.totalBytes))")
                        .font(.system(size: 12, weight: .bold).monospacedDigit())
                        .foregroundColor(p.emerald)
                }
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
    let viewModel = MacGlideDropViewModel()
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
            if let img = NSImage(systemSymbolName: "antenna.radiowaves.left.and.right", accessibilityDescription: "GlideDrop") {
                img.isTemplate = true
                btn.image = img
                btn.imagePosition = .imageLeading
            }
            btn.title = " GlideDrop"
            let dropView = StatusBarDropView(frame: btn.bounds)
            dropView.autoresizingMask = [.width, .height]
            dropView.onDropFiles = { [weak self] paths in
                self?.viewModel.stagePathsOrUrls(paths)
            }
            btn.addSubview(dropView)
        }

        let menu = NSMenu()
        let openWin = NSMenuItem(title: "Open GlideDrop…", action: #selector(showMainWindow), keyEquivalent: "s")
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
        let quitItem = NSMenuItem(title: "Quit GlideDrop", action: #selector(quitApp), keyEquivalent: "q")
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
                styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
                backing: .buffered,
                defer: false
            )
            win.title = "GlideDrop"
            win.titleVisibility = .hidden
            win.titlebarAppearsTransparent = true
            win.isMovableByWindowBackground = true
            win.center()
            win.isReleasedWhenClosed = false
            win.delegate = self
            win.contentView = NSHostingView(rootView: MacGlideDropMainView(vm: viewModel))
            window = win
        }
        applyWindowAppearance(viewModel.palette)
        viewModel.refreshSlow()
        viewModel.refreshFast()
        window?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func performCleanShutdown() {
        restoreMacInternetWifi()
        BleGlideDropDaemon.shared?.stopAdvertisingAndScanning()
        for pf in ["daemon.pid", "awdl-mdns.pid"] {
            let f = STATE_DIR.appendingPathComponent(pf)
            if let s = try? String(contentsOf: f, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
               let pid = Int32(s) {
                kill(pid, SIGTERM)
            }
            try? FileManager.default.removeItem(at: f)
        }
        for cleanupFile in [
            "ble-daemon.pid",
            "transfer_progress.json",
            "tx_in_progress.lock",
            "rx_in_progress.lock",
            "cancel_transfer.flag",
            "lan_fallback_active.flag",
            "pending_ask.json",
            "prev_proxy_settings.json",
            "proxy_state.lock",
            "p2p_session_token.json",
            "p2p_outgoing_token.json",
            "active_p2p_session.json",
            "awdl_bridge_port",
            "mac_rx_port",
            "finder_proxy_port",
            "finder_proxy_sock",
            "finder_proxy.sock",
            "pinned_peer_tls_fingerprint.txt",
            "wp2p_authorized_session.json"
        ] {
            try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent(cleanupFile))
        }
    }

    private func stopAllDaemonsAndQuit() {
        guard !isShuttingDown else { return }
        isShuttingDown = true
        performCleanShutdown()
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
        if !isShuttingDown {
            isShuttingDown = true
            performCleanShutdown()
        }
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
    private var listener: NWListener
    private let params: NWParameters
    private let sockPathOverride: String?
    private let stateDir: URL
    private var triedEphemeralFallback = false
    private let queue = DispatchQueue(label: "com.glidedrop.awdl-bridge", qos: .userInitiated)

    init(
        listenPort: UInt16 = 0,
        sockPath: String? = nil,
        stateDir: URL = STATE_DIR
    ) throws {
        let p = NWParameters.tcp
        p.includePeerToPeer = true
        // Restrict strictly to AWDL (.other + awdl* interface name); prohibit LAN/cellular/loopback interfaces
        p.prohibitedInterfaceTypes = [.wifi, .wiredEthernet, .cellular, .loopback]
        self.params = p
        self.sockPathOverride = sockPath
        self.stateDir = stateDir
        let nwPort = NWEndpoint.Port(rawValue: listenPort) ?? .any
        self.listener = try NWListener(using: p, on: nwPort)
        configureAndStart(listener: self.listener, requestedPort: listenPort)
    }

    private func configureAndStart(listener activeListener: NWListener, requestedPort: UInt16) {
        activeListener.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                let boundPort = activeListener.port?.rawValue ?? requestedPort
                if boundPort > 0 {
                    writeAwdlBridgePortFile(port: Int(boundPort), stateDir: self.stateDir)
                }
                print("[AWDL-Bridge] NWListener ready on port \(boundPort)")
                fflush(stdout)
            case .failed(let err):
                print("[AWDL-Bridge] NWListener(\(requestedPort)) failed: \(err)")
                fflush(stdout)
                if !self.triedEphemeralFallback && requestedPort != 0 {
                    self.triedEphemeralFallback = true
                    do {
                        let fallback = try NWListener(using: self.params, on: .any)
                        activeListener.cancel()
                        self.listener = fallback
                        self.configureAndStart(listener: fallback, requestedPort: 0)
                    } catch {
                        print("[AWDL-Bridge] Fallback NWListener failed: \(error)")
                        fflush(stdout)
                    }
                }
            default:
                print("[AWDL-Bridge] NWListener(\(requestedPort)) state: \(state)")
                fflush(stdout)
            }
        }
        activeListener.newConnectionHandler = { [weak self] incoming in
            guard let self = self else {
                incoming.cancel()
                return
            }
            incoming.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    guard let path = incoming.currentPath else {
                        incoming.cancel()
                        return
                    }
                    let isProhibited = path.usesInterfaceType(.wifi) ||
                        path.usesInterfaceType(.wiredEthernet) ||
                        path.usesInterfaceType(.cellular) ||
                        path.usesInterfaceType(.loopback)
                    let ifNames = path.availableInterfaces.map { $0.name }
                    let endpointsAllowed = isAllowedAwdlEndpoint(path.localEndpoint) &&
                        isAllowedAwdlEndpoint(path.remoteEndpoint)
                    if isProhibited || !isAllowedAwdlInterfaceNames(ifNames) || !endpointsAllowed {
                        print("[AWDL-Bridge] Dropping unauthorized connection on non-AWDL path (interfaces=\(ifNames))")
                        fflush(stdout)
                        incoming.cancel()
                        return
                    }
                    let resolvedSockPath = self.sockPathOverride ?? readFinderProxySockPath(stateDir: self.stateDir)
                    guard FileManager.default.fileExists(atPath: resolvedSockPath) else {
                        print("[AWDL-Bridge] Finder proxy Unix socket missing at \(resolvedSockPath)")
                        fflush(stdout)
                        incoming.cancel()
                        return
                    }
                    let outgoing = NWConnection(to: .unix(path: resolvedSockPath), using: .tcp)
                    outgoing.stateUpdateHandler = { outState in
                        switch outState {
                        case .failed(_), .cancelled:
                            incoming.cancel()
                        default:
                            break
                        }
                    }
                    outgoing.start(queue: self.queue)
                    Self.pump(from: incoming, to: outgoing)
                    Self.pump(from: outgoing, to: incoming)
                case .failed(_), .cancelled:
                    break
                default:
                    break
                }
            }
            incoming.start(queue: self.queue)
        }
        activeListener.start(queue: self.queue)
    }

    static func pump(from src: NWConnection, to dst: NWConnection) {
        src.receive(minimumIncompleteLength: 1, maximumLength: 1_048_576) { data, _, isComplete, error in
            if let d = data, !d.isEmpty {
                dst.send(content: d, completion: .contentProcessed { sendErr in
                    if sendErr != nil {
                        src.cancel()
                        dst.cancel()
                    } else if !isComplete && error == nil {
                        pump(from: src, to: dst)
                    } else {
                        src.cancel()
                        dst.cancel()
                    }
                })
            } else {
                src.cancel()
                dst.cancel()
            }
        }
    }
}

private var sigIntSource: DispatchSourceSignal?
private var sigTermSource: DispatchSourceSignal?

func terminateActiveChildTxProcess() {
    activeChildTxLock.lock()
    let child = activeChildTxProcess
    activeChildTxLock.unlock()
    if let p = child, p.isRunning {
        p.terminate()
    }
}

func installSafeSignalHandlers() {
    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    let q = DispatchQueue.global(qos: .userInitiated)
    let sInt = DispatchSource.makeSignalSource(signal: SIGINT, queue: q)
    sInt.setEventHandler {
        terminateActiveChildTxProcess()
        restoreMacInternetWifi()
        exit(130)
    }
    sInt.resume()
    sigIntSource = sInt

    let sTerm = DispatchSource.makeSignalSource(signal: SIGTERM, queue: q)
    sTerm.setEventHandler {
        terminateActiveChildTxProcess()
        restoreMacInternetWifi()
        exit(143)
    }
    sTerm.resume()
    sigTermSource = sTerm
}

func runGlideDropMain() throws {
    signal(SIGPIPE, SIG_IGN)
    atexit {
        if proxyEnabledInCurrentProcess {
            disableMacInternetProxy()
        }
    }

    let args = CommandLine.arguments
    if args.count >= 2 && args[1] == "restore-wifi" {
        restoreMacInternetWifi()
        exit(0)
    } else if args.count >= 2 && args[1] == "send" {
        installSafeSignalHandlers()
        var filteredArgs: [String] = []
        let rawArgs = Array(args.dropFirst(2))
        var idx = 0
        while idx < rawArgs.count {
            let cur = rawArgs[idx]
            if cur == "--pin" || cur == "--peer" {
                idx += 2
                continue
            }
            filteredArgs.append(cur)
            idx += 1
        }
        let urls = filteredArgs.filter { $0.hasPrefix("http://") || $0.hasPrefix("https://") }
        let fileUrls = filteredArgs
            .filter { !$0.hasPrefix("http://") && !$0.hasPrefix("https://") }
            .map { URL(fileURLWithPath: $0) }
            .filter { FileManager.default.fileExists(atPath: $0.path) }
        guard !fileUrls.isEmpty || !urls.isEmpty else {
            writeProgressJson(active: false)
            try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
            print("Usage: glidedrop-daemon send <file_or_url1> [file_or_url2 ...]")
            exit(1)
        }
        let sender: BleGlideDropSender
        do {
            sender = try BleGlideDropSender(files: fileUrls, urls: urls)
        } catch {
            writeProgressJson(active: false)
            try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
            print("[BLE-Send] \(error.localizedDescription)")
            exit(1)
        }
        withExtendedLifetime(sender) {
            var deadline = BleSenderActivityDeadline()
            let watchdog = Timer(timeInterval: 1.0, repeats: true) { _ in
                guard deadline.hasTimedOut(transferStarted: sender.connectState.transferStarted,
                                           progressUpdatedAt: senderProgressUpdatedAt(),
                                           now: Date().timeIntervalSince1970) else { return }
                sender.connectState.isTerminalFailure = true
                writeProgressJson(active: false)
                try? FileManager.default.removeItem(at: STATE_DIR.appendingPathComponent("tx_in_progress.lock"))
                clearOutgoingP2pToken()
                if needsMacInternetWifiRestore() {
                    restoreMacInternetWifi()
                } else {
                    clearActiveP2pSession()
                }
                print(sender.connectState.transferStarted
                      ? "[BLE-Send] Send stalled: no sender activity for 300s"
                      : "[BLE-Send] Timed out establishing BLE L2CAP connection")
                exit(1)
            }
            RunLoop.main.add(watchdog, forMode: .common)
            defer { watchdog.invalidate() }
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
        installSafeSignalHandlers()

        // Crash recovery: only in primary daemon after confirming no existing instance is active
        if FileManager.default.fileExists(atPath: PREV_PROXY_FILE.path) {
            print("[BLE-Daemon] Lingering prev_proxy_settings.json detected on startup. Performing proxy crash recovery...")
            fflush(stdout)
        }
        disableMacInternetProxy()

        if !isBackgroundDaemon {
            let daemonPidFile = STATE_DIR.appendingPathComponent("daemon.pid")
            let httpsAlive: Bool = {
                guard let s = try? String(contentsOf: daemonPidFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
                      let p = Int32(s) else { return false }
                return kill(p, 0) == 0
            }()
            let s = loadMacSettings()
            if s.visible && !httpsAlive {
                DispatchQueue.global(qos: .userInitiated).async {
                    let p = Process()
                    p.executableURL = URL(fileURLWithPath: SCRIPT_PATH)
                    p.environment = ProcessInfo.processInfo.environment
                    p.environment?["SKIP_BLE_RESTART"] = "1"
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
        } else if let iconImg = NSImage(contentsOfFile: REPO_ROOT.appendingPathComponent("GlideDrop.app/Contents/Resources/AppIcon.icns").path) {
            app.applicationIconImage = iconImg
        } else if let iconImg = NSImage(contentsOfFile: FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".glidedrop/AppIcon.icns").path) {
            app.applicationIconImage = iconImg
        }
        let daemon = BleGlideDropDaemon()
        let bar = StatusBarController(openWindowOnLaunch: !isBackgroundDaemon)
        app.delegate = bar
        var awdlBridge: AwdlLoopbackBridge? = nil
        do {
            awdlBridge = try AwdlLoopbackBridge()
        } catch {
            print("[AWDL-Bridge] Warning: failed to start AWDL loopback bridge: \(error)")
            fflush(stdout)
        }
        withExtendedLifetime((daemon, bar, awdlBridge)) {
            app.run()
        }
    }
}

#if !GLIDEDROP_TESTING
private let _glideDropEntryPoint: Void = {
    do {
        try runGlideDropMain()
    } catch {
        fputs("[GlideDrop] Fatal error: \(error.localizedDescription)\n", stderr)
        exit(1)
    }
}()
#endif
