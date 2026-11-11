import Foundation
import Security
import CryptoKit

@main
struct GlideDropDaemonTests {
    static var failures = 0
    static let testRoot = URL(fileURLWithPath: NSTemporaryDirectory())
        .appendingPathComponent("glidedrop_swift_tests_\(UUID().uuidString)")
    static let testStateDir = testRoot.appendingPathComponent("state")

    static func check(_ cond: Bool, _ msg: String, file: String = #file, line: Int = #line) {
        if !cond {
            failures += 1
            fputs("[FAIL] \(file):\(line): \(msg)\n", stderr)
        }
    }

    static func cleanTestState() {
        if let items = try? FileManager.default.contentsOfDirectory(at: testStateDir, includingPropertiesForKeys: nil) {
            for item in items {
                try? FileManager.default.removeItem(at: item)
            }
        }
    }

    static func main() {
        signal(SIGPIPE, SIG_IGN)
        try! FileManager.default.createDirectory(at: testStateDir, withIntermediateDirectories: true)
        setenv("GLIDEDROP_STATE_DIR", testStateDir.path, 1)
        defer { try? FileManager.default.removeItem(at: testRoot) }

        // Sanity check: STATE_DIR must be isolated to temp test directory
        check(STATE_DIR.standardizedFileURL.path == testStateDir.standardizedFileURL.path,
              "Expected STATE_DIR=\(testStateDir.path), got \(STATE_DIR.path)")

        // 1. tx_in_progress.lock timestamp & 180s TTL tests
        do {
            cleanTestState()
            let lockFile = STATE_DIR.appendingPathComponent("tx_in_progress.lock")
            check(!hasActiveTxInProgressLock(), "Missing tx_in_progress.lock must return false")

            let now = 2_000_000_000.0
            writeTxInProgressLock(timestamp: now - 5.0)
            let raw = (try? String(contentsOf: lockFile, encoding: .utf8)) ?? ""
            check(Double(raw) != nil, "tx_in_progress.lock must contain a numeric timestamp, got '\(raw)'")
            check(raw != "1", "tx_in_progress.lock must no longer write raw '1'")
            check(hasActiveTxInProgressLock(now: now), "Fresh tx_in_progress.lock (< 180s) must be active")
            check(FileManager.default.fileExists(atPath: lockFile.path), "Fresh tx_in_progress.lock must remain on disk")

            // Exactly at 180s boundary -> expired & auto-removed
            writeTxInProgressLock(timestamp: now - TX_LOCK_TTL_SECONDS)
            check(!hasActiveTxInProgressLock(now: now), "tx_in_progress.lock at 180s TTL must expire")
            check(!FileManager.default.fileExists(atPath: lockFile.path), "Expired tx_in_progress.lock must be deleted")

            // Legacy "1" lock -> treated as expired and cleaned up
            try? Data("1".utf8).write(to: lockFile)
            check(!hasActiveTxInProgressLock(now: now), "Legacy '1' tx_in_progress.lock must expire")
            check(!FileManager.default.fileExists(atPath: lockFile.path), "Legacy '1' tx_in_progress.lock must be deleted")
            print("[PASS] tx_in_progress.lock timestamp & 180s TTL")
        }

        // 2. Dynamic lower PSM updates in recordActivePeerOnDisk / loadActivePeersFromDisk
        do {
            cleanTestState()
            recordActivePeerOnDisk(
                id: "peer-1",
                name: "Galaxy S23 Ultra",
                transport: "5GHz P2P • BLE PSM 190",
                address: "peer-1",
                psm: 190,
                rssi: -45
            )
            var peers = loadActivePeersFromDisk(maxAge: 10.0)
            check(peers.count == 1 && peers[0].psm == 190, "Initial peer PSM should be 190")

            // Immediately re-advertise with lower PSM after Android app restart
            recordActivePeerOnDisk(
                id: "peer-2",
                name: "Galaxy S23 Ultra",
                transport: "5GHz P2P • BLE PSM 132",
                address: "peer-2",
                psm: 132,
                rssi: -46
            )
            peers = loadActivePeersFromDisk(maxAge: 10.0)
            check(peers.count == 1 && peers[0].psm == 132, "Lower dynamic PSM (132 < 190) must be accepted, got \(peers.first?.psm ?? -1)")

            // Unnamed zombie fallback ad must still be ignored while named peer is live
            recordActivePeerOnDisk(
                id: "peer-3",
                name: "Android Peer (ABCD)",
                transport: "5GHz P2P • BLE PSM 140",
                address: "peer-3",
                psm: 140,
                rssi: -60
            )
            peers = loadActivePeersFromDisk(maxAge: 10.0)
            check(peers.count == 1 && peers[0].name == "Galaxy S23 Ultra" && peers[0].psm == 132,
                  "Unnamed zombie advertisement must be ignored while named peer is active")
            print("[PASS] Dynamic lower PSM updates")
        }

        // 3. BLE 30 MB fallback cap + bounded buildDvzipCpio tests
        do {
            cleanTestState()
            let filesDir = testRoot.appendingPathComponent("files")
            try! FileManager.default.createDirectory(at: filesDir, withIntermediateDirectories: true)

            // 3a. Small valid file builds valid ADRE frame within cap using ephemeral ECDH BLE key
            let bleSenderPriv = P256.KeyAgreement.PrivateKey()
            let bleReceiverPriv = P256.KeyAgreement.PrivateKey()
            let bleShared = try! bleSenderPriv.sharedSecretFromKeyAgreement(with: bleReceiverPriv.publicKey)
            let bleSessionKey = deriveBleFrameKey(sharedSecret: bleShared)
            let bleReceiverKey = deriveBleFrameKey(sharedSecret: try! bleReceiverPriv.sharedSecretFromKeyAgreement(with: bleSenderPriv.publicKey))
            let wrongKey = SymmetricKey(data: SHA256.hash(data: Data("GlideDrop-E2EE-AES256GCM-v2".utf8)))

            let smallFile = filesDir.appendingPathComponent("hello.txt")
            try! Data(repeating: 0x41, count: 4096).write(to: smallFile)
            let frame = try! buildEncryptedBleFallbackFrame(
                files: [smallFile],
                urls: [],
                totalRawBytes: 4096,
                senderName: "TestMac",
                sessionKey: bleSessionKey
            )
            check(String(data: frame.prefix(4), encoding: .ascii) == "ADRE", "Frame must start with ADRE")
            let metaLen = readUInt32BE(frame, offset: 4)
            let archLen = readUInt32BE(frame, offset: 8)
            check(frame.count == 12 + metaLen + archLen, "Frame length must match ADRE header lengths")
            check(archLen > 28 && archLen <= MAX_ENCRYPTED_BLE_ARCHIVE_BYTES, "Archive length within cap")
            let encMeta = frame.subdata(in: 12..<(12 + metaLen))
            let encArch = frame.subdata(in: (12 + metaLen)..<frame.count)
            check(decryptBlePayload(encMeta, key: bleReceiverKey) != nil, "Encrypted metadata must decrypt with peer ephemeral BLE key")
            check(decryptBlePayload(encArch, key: bleReceiverKey) != nil, "Encrypted archive must decrypt with peer ephemeral BLE key")
            check(decryptBlePayload(encMeta, key: wrongKey) == nil, "Legacy static key must NOT decrypt ephemeral ADRE metadata")
            check(decryptBlePayload(encArch, key: wrongKey) == nil, "Legacy static key must NOT decrypt ephemeral ADRE archive")

            // 3b. Raw pre-check rejects multi-hundred-MB files without touching disk/gzip
            let missingHuge = filesDir.appendingPathComponent("never_read_200mb.bin")
            var threwRawLimit = false
            do {
                _ = try buildEncryptedBleFallbackFrame(
                    files: [missingHuge],
                    urls: [],
                    totalRawBytes: BLE_RAW_PRECHECK_MAX_BYTES + 1,
                    senderName: "TestMac",
                    sessionKey: bleSessionKey
                )
            } catch BleFallbackCapError.exceedsRawPrecheckLimit {
                threwRawLimit = true
            } catch {
                check(false, "Unexpected error for raw precheck: \(error)")
            }
            check(threwRawLimit, "totalRawBytes > BLE_RAW_PRECHECK_MAX_BYTES must fail fast without reading file")

            // 3c. Bounded gzip output cap rejects incompressible payload early without full buffering
            let randFile = filesDir.appendingPathComponent("random_256k.bin")
            var randBytes = [UInt8](repeating: 0, count: 256 * 1024)
            let secRes = SecRandomCopyBytes(kSecRandomDefault, randBytes.count, &randBytes)
            check(secRes == errSecSuccess, "SecRandomCopyBytes failed")
            try! Data(randBytes).write(to: randFile)

            var threwBounded = false
            do {
                _ = try buildEncryptedBleFallbackFrame(
                    files: [randFile],
                    urls: [],
                    totalRawBytes: Int64(randBytes.count),
                    senderName: "TestMac",
                    sessionKey: bleSessionKey,
                    maxEncryptedArchiveBytes: 64 * 1024,
                    rawPrecheckMaxBytes: 1_000_000
                )
            } catch BleFallbackCapError.exceedsCompressedOrEncryptedLimit {
                threwBounded = true
            } catch {
                check(false, "Unexpected error for bounded compression cap: \(error)")
            }
            check(threwBounded, "Incompressible payload exceeding maxEncryptedArchiveBytes must fail cleanly")

            // 3d. AES-GCM 28-byte overhead boundary check (encryptedBytes > limit even when gz <= maxCompressedBytes)
            let (gzSmall, _) = try! buildDvzipCpio(files: [smallFile])
            var threwExactBoundary = false
            do {
                _ = try buildEncryptedBleFallbackFrame(
                    files: [smallFile],
                    urls: [],
                    totalRawBytes: 4096,
                    senderName: "TestMac",
                    sessionKey: bleSessionKey,
                    maxEncryptedArchiveBytes: gzSmall.count + 20, // < gzSmall + 28
                    rawPrecheckMaxBytes: 1_000_000
                )
            } catch BleFallbackCapError.exceedsCompressedOrEncryptedLimit {
                threwExactBoundary = true
            } catch {
                check(false, "Unexpected error for AES-GCM boundary: \(error)")
            }
            check(threwExactBoundary, "AES-GCM 28B overhead pushing over limit must be caught cleanly")

    // 3e. Unreadable file throws DvzipBuildError.unreadableInputFile
    var threwMissing = false
    do {
        _ = try buildDvzipCpio(files: [filesDir.appendingPathComponent("does_not_exist.bin")])
    } catch DvzipBuildError.unreadableInputFile {
        threwMissing = true
    } catch {
        check(false, "Unexpected error for missing file: \(error)")
    }
    check(threwMissing, "Missing input file must throw unreadableInputFile")

    // 3f. buildDvzipCpio produces valid gzipped CPIO 070707 archive with file payload + TRAILER!!!
    let payloadStr = "GlideDrop-CPIO-Roundtrip-Check-1234567890"
    let cpioTestFile = filesDir.appendingPathComponent("note.txt")
    try! payloadStr.data(using: .utf8)!.write(to: cpioTestFile)
    let (gzBytes, dicts) = try! buildDvzipCpio(files: [cpioTestFile])
    check(dicts.count == 1 && (dicts[0]["FileName"] as? String) == "note.txt", "Metadata dict must match file")
    let gzTmp = filesDir.appendingPathComponent("archive.cpio.gz")
    try! gzBytes.write(to: gzTmp)
    let (gzRc, plainOut) = runProcessCapture("/usr/bin/gzip", ["-dc", gzTmp.path])
    check(gzRc == 0, "gzip -dc must cleanly decompress buildDvzipCpio output")
    check(plainOut.hasPrefix("070707"), "CPIO archive must start with 070707 ODC header")
    check(plainOut.contains("note.txt") && plainOut.contains(payloadStr) && plainOut.contains("TRAILER!!!"),
          "Decompressed CPIO must contain filename, payload, and TRAILER!!!")
    print("[PASS] 30 MB BLE fallback cap & bounded buildDvzipCpio")
        }

        // 4. writeAll preserves transfer_progress.json on success & readExact / readBleStreamLine handle timeouts and delays
        do {
            cleanTestState()
            let progressFile = STATE_DIR.appendingPathComponent("transfer_progress.json")

            var inStream: InputStream?
            var outStream: OutputStream?
            Stream.getBoundStreams(withBufferSize: 8192, inputStream: &inStream, outputStream: &outStream)
            guard let inp = inStream, let out = outStream else {
                fatalError("Could not allocate bound streams")
            }
            inp.open()
            out.open()

            let payload = Data(repeating: 0x5A, count: 1024)
            let ok = writeAll(
                out,
                data: payload,
                trackProgress: true,
                fileLabel: "sample.bin",
                fileCount: 1,
                peerName: "Galaxy S23 Ultra",
                clearProgressOnSuccess: false
            )
            check(ok, "writeAll should succeed on open bound stream")
            check(FileManager.default.fileExists(atPath: progressFile.path),
                  "transfer_progress.json must remain active after writeAll until receiver ACK")
            if let pData = try? Data(contentsOf: progressFile),
               let pObj = (try? JSONSerialization.jsonObject(with: pData)) as? [String: Any] {
                check((pObj["active"] as? Bool) == true, "transfer_progress.json active must still be true")
                check((pObj["peerName"] as? String) == "Galaxy S23 Ultra", "peerName must be preserved")
            } else {
                check(false, "Could not parse transfer_progress.json")
            }

            let drained = readExact(inp, count: 1024, timeout: 2.0)
            check(drained == payload, "readExact should read exact payload within timeout")

            check(readExact(inp, count: 0) == Data(), "readExact count=0 must return empty Data")
            check(readExact(inp, count: -5) == nil, "readExact count<0 must return nil")

            let tStart = Date()
            var readTimeoutCbFired = false
            let timedOutRead = readExact(inp, count: 2, timeout: 0.25, onTimeout: {
                readTimeoutCbFired = true
                out.close()
                inp.close()
            })
            let elapsed = Date().timeIntervalSince(tStart)
            check(timedOutRead == nil, "readExact on silent stream must time out and return nil")
            check(readTimeoutCbFired, "readExact must invoke onTimeout callback when timing out")
            check(elapsed < 1.5, "readExact timeout must exit promptly (elapsed=\(elapsed)s)")

            var in2: InputStream?
            var out2: OutputStream?
            Stream.getBoundStreams(withBufferSize: 8192, inputStream: &in2, outputStream: &out2)
            let inp2 = in2!
            let out2s = out2!
            inp2.open()
            out2s.open()

            DispatchQueue.global().asyncAfter(deadline: .now() + 0.12) {
                let msg = Array("OK\tpub\tenc\n".utf8)
                _ = out2s.write(msg, maxLength: msg.count)
            }
            let line = readBleStreamLine(inp2, timeout: 2.0)
            check(line == "OK\tpub\tenc", "readBleStreamLine must wait past initial r==0 and return delayed line, got \(String(describing: line))")

            DispatchQueue.global().asyncAfter(deadline: .now() + 0.12) {
                let ack = Array("OK".utf8)
                _ = out2s.write(ack, maxLength: ack.count)
            }
            let ackData = readExact(inp2, count: 2, timeout: 2.0)
            check(ackData.flatMap { String(data: $0, encoding: .ascii) } == "OK", "readExact must receive delayed 2-byte OK ACK")

            let lineStart = Date()
            var lineTimeoutCbFired = false
            let silentLine = readBleStreamLine(inp2, timeout: 0.25) {
                lineTimeoutCbFired = true
                out2s.close()
                inp2.close()
            }
            let lineElapsed = Date().timeIntervalSince(lineStart)
            check(silentLine == nil, "readBleStreamLine on silent stream must time out and return nil")
            check(lineTimeoutCbFired, "readBleStreamLine must invoke onTimeout callback when timing out")
            check(lineElapsed < 1.5, "readBleStreamLine timeout must exit promptly (elapsed=\(lineElapsed)s)")

            // 4e. Cancellation clears progress on writeAll and unblocks readExact immediately
            var in3: InputStream?
            var out3: OutputStream?
            Stream.getBoundStreams(withBufferSize: 8192, inputStream: &in3, outputStream: &out3)
            let inp3 = in3!
            let out3s = out3!
            inp3.open()
            out3s.open()
            try! String(Date().timeIntervalSince1970).write(
                to: STATE_DIR.appendingPathComponent("cancel_transfer.flag"),
                atomically: true,
                encoding: .utf8
            )
            writeProgressJson(active: true, direction: "Sending", fileName: "cancel.bin")
            let writeCancelled = writeAll(
                out3s,
                data: payload,
                trackProgress: true,
                fileLabel: "cancel.bin",
                fileCount: 1,
                peerName: "Galaxy S23 Ultra",
                clearProgressOnSuccess: false
            )
            check(!writeCancelled, "writeAll must abort when cancel_transfer.flag is set")
            check(!FileManager.default.fileExists(atPath: progressFile.path),
                  "writeAll failure/cancel must clear transfer_progress.json")

            var cancelReadCbFired = false
            let cancelRead = readExact(inp3, count: 2, timeout: 5.0, checkCancel: true, onTimeout: {
                cancelReadCbFired = true
                out3s.close()
                inp3.close()
            })
            check(cancelRead == nil && cancelReadCbFired, "readExact with checkCancel must abort immediately on cancel flag")
            clearCancelFlag()
            inp3.close()
            out3s.close()

            // 4f. readExact onWaitTick fires periodically during bounded waits
            var in4: InputStream?
            var out4: OutputStream?
            Stream.getBoundStreams(withBufferSize: 1024, inputStream: &in4, outputStream: &out4)
            let inp4 = in4!
            let out4s = out4!
            inp4.open()
            out4s.open()
            var waitTickCount = 0
            let tickTimedOut = readExact(
                inp4,
                count: 2,
                timeout: 2.3,
                onWaitTick: { waitTickCount += 1 },
                onTimeout: {
                    out4s.close()
                    inp4.close()
                }
            )
            check(tickTimedOut == nil && waitTickCount >= 1, "readExact must invoke onWaitTick during waits > 2s (ticks=\(waitTickCount))")
            inp4.close()
            out4s.close()

            inp.close()
            out.close()
            inp2.close()
            out2s.close()
            print("[PASS] writeAll progress preservation, readExact ACK timeout & wait ticks, readBleStreamLine delay handling")
        }

        // 5. Fallback restoreMacInternetWifi predicate + parseAirportNetworkSsid
        do {
            check(parseAirportNetworkSsid("Current Wi-Fi Network: DIRECT-XY-GlideDrop\n") == "DIRECT-XY-GlideDrop",
                  "parseAirportNetworkSsid must preserve DIRECT-* SSIDs for restore detection")
            check(parseAirportNetworkSsid("Current Wi-Fi Network: HomeWiFi\n") == "HomeWiFi",
                  "parseAirportNetworkSsid must parse normal SSID")
            check(parseAirportNetworkSsid("You are not associated with an AirPort network.\n") == "",
                  "parseAirportNetworkSsid must return empty string when unassociated")

            check(!hasPendingWifiRestoreState(
                wifiP2pIp: "",
                wifiSsid: "HomeWiFi",
                hasPrevProxy: false,
                hasPrevWifi: false,
                hasWarpPaused: false
            ), "Must skip duplicate restoreMacInternetWifi when already clean")

            check(hasPendingWifiRestoreState(
                wifiP2pIp: "192.168.49.55",
                wifiSsid: "HomeWiFi",
                hasPrevProxy: false,
                hasPrevWifi: false,
                hasWarpPaused: false
            ), "Must trigger fallback restore when 192.168.49.x IP is still bound")

            check(hasPendingWifiRestoreState(
                wifiP2pIp: "",
                wifiSsid: parseAirportNetworkSsid("Current Wi-Fi Network: DIRECT-XY-GlideDrop"),
                hasPrevProxy: false,
                hasPrevWifi: false,
                hasWarpPaused: false
            ), "Must trigger fallback restore when still associated to DIRECT-*")

            check(hasPendingWifiRestoreState(
                wifiP2pIp: "",
                wifiSsid: "",
                hasPrevProxy: true,
                hasPrevWifi: false,
                hasWarpPaused: false
            ), "Must trigger fallback restore when prev_proxy_settings.json exists")

            check(hasPendingWifiRestoreState(
                wifiP2pIp: "",
                wifiSsid: "",
                hasPrevProxy: false,
                hasPrevWifi: true,
                hasWarpPaused: false
            ), "Must trigger fallback restore when previous_wifi_ssid.txt exists")

            check(hasPendingWifiRestoreState(
                wifiP2pIp: "",
                wifiSsid: "",
                hasPrevProxy: false,
                hasPrevWifi: false,
                hasWarpPaused: true
            ), "Must trigger fallback restore when warp_was_active.flag exists")
            print("[PASS] Fallback restoreMacInternetWifi predicate & DIRECT-* SSID parsing")
        }

        // 6. BleSenderConnectState: stale peripheral switch, timeout double-count prevention, GATT/L2CAP retries
        do {
            let p1 = UUID()
            let p2 = UUID()
            var state = BleSenderConnectState()
            let t0 = Date(timeIntervalSince1970: 1_000_000.0)
            let tok1 = state.beginConnect(peerId: p1, now: t0)
            state.targetPsm = 190

            // Lower dynamic PSM on same active peer updates targetPsm
            let sameAct = state.evaluateDiscoverSwitch(
                discoveredPeerId: p1,
                psm: 132,
                existingConnected: false,
                now: t0.addingTimeInterval(1.0)
            )
            check(sameAct == .keepExisting && state.targetPsm == 132,
                  "Active peer advertising lower dynamic PSM must update targetPsm to 132")

            // After >2.5s, switching from stale p1 to live p2 must ignore late drop of p1
            let switchAct = state.evaluateDiscoverSwitch(
                discoveredPeerId: p2,
                psm: 145,
                existingConnected: false,
                now: t0.addingTimeInterval(3.0)
            )
            check(switchAct == .switchTo(peerId: p1, psm: 145), "Must switch from stale p1 after >2.5s")
            _ = state.beginConnect(peerId: p2, now: t0.addingTimeInterval(3.0))
            let staleDrop = state.onDidDrop(peerId: p1, cancelled: false, failureMessage: "drop")
            check(staleDrop == .ignoreStaleCallback && state.targetPeerId == p2 && state.connectRetryCount == 0,
                  "Late disconnect from cancelled p1 must NOT clobber p2 or increment connectRetryCount")

            // 8s connect timeout must not double-count when late didDisconnect fires
            let p2Tok = state.connectAttemptToken
            let toAct = state.onConnectTimeout(peerId: p2, token: p2Tok, isConnected: false, cancelled: false)
            check(toAct == .restartDiscovery && state.connectRetryCount == 1, "Timeout must increment retry count once")
            let lateAfterTimeout = state.onDidDrop(peerId: p2, cancelled: false, failureMessage: "drop")
            check(lateAfterTimeout == .ignoreStaleCallback && state.connectRetryCount == 1,
                  "Late didDisconnect after timeout must not double-count connectRetryCount")

            // Exhausting connect retries (>3) triggers terminal failure
            let p3 = UUID()
            _ = state.beginConnect(peerId: p3, now: t0.addingTimeInterval(12.0))
            check(state.onDidDrop(peerId: p3, cancelled: false, failureMessage: "drop") == .restartDiscovery && state.connectRetryCount == 2,
                  "Retry 2 must restart discovery")
            _ = state.beginConnect(peerId: p3, now: t0.addingTimeInterval(15.0))
            check(state.onDidDrop(peerId: p3, cancelled: false, failureMessage: "drop") == .restartDiscovery && state.connectRetryCount == 3,
                  "Retry 3 must restart discovery")
            _ = state.beginConnect(peerId: p3, now: t0.addingTimeInterval(18.0))
            if case .fail = state.onDidDrop(peerId: p3, cancelled: false, failureMessage: "drop-fail") {
                // expected
            } else {
                check(false, "Retry 4 (>3) must fail terminally")
            }

            // L2CAP open failure retries: GATT refresh -> restart discovery -> fail, and didModifyServices deferral
            var l2State = BleSenderConnectState()
            let p4 = UUID()
            _ = l2State.beginConnect(peerId: p4, now: t0)
            check(l2State.onDidConnect(peerId: p4), "Active peer didConnect must succeed")
            l2State.startedOpen = true
            // didModifyServices while open is in-flight defers GATT refresh instead of overlapping discoverServices
            check(!l2State.onDidModifyServices(peerId: p4, affectsP2p: true) && l2State.needsGattRefreshOnOpenFail,
                  "didModifyServices during openL2CAPChannel must defer GATT refresh")
            check(l2State.onDidOpenFailure(peerId: p4, isConnected: true, cancelled: false, errorDesc: "e1") == .refreshGatt,
                  "First L2CAP open failure while connected must refresh GATT")
            l2State.gattRefreshInProgress = false
            l2State.startedOpen = true
            check(l2State.onDidOpenFailure(peerId: p4, isConnected: true, cancelled: false, errorDesc: "e2") == .restartDiscovery,
                  "Second L2CAP open failure without new GATT invalidation must restart discovery")
            _ = l2State.beginConnect(peerId: p4, now: t0.addingTimeInterval(5.0))
            l2State.startedOpen = true
            if case .fail = l2State.onDidOpenFailure(peerId: p4, isConnected: true, cancelled: false, errorDesc: "e3") {
                // expected
            } else {
                check(false, "Third L2CAP open failure must fail terminally")
            }
            check(tok1 != 0, "Sanity check token non-zero")
            print("[PASS] BleSenderConnectState stale switch, timeout/drop, and GATT/L2CAP retry logic")
        }

        // 7. makeOdcCpioHeader 4-8 GB (070707 64-bit octal) & >8 GB (070764) formatting
        do {
            let fiveGb: Int64 = 5_000_000_000
            let hdr5 = makeOdcCpioHeader(path: "./big5gb.bin", ino: 2, mode: 0o100644, size: fiveGb, mtime: 1_700_000_000)
            let s5 = String(data: hdr5.prefix(76), encoding: .ascii) ?? ""
            check(s5.hasPrefix("070707") && s5.count == 76, "5 GB file must emit 76-byte 070707 ODC header")
            let octalSize = String(s5.suffix(11))
            check(Int64(octalSize, radix: 8) == fiveGb, "070707 header octal size must encode 5 GB accurately, got '\(octalSize)'")

            let tenGb: Int64 = 10_000_000_000
            let hdr10 = makeOdcCpioHeader(path: "./big10gb.bin", ino: 3, mode: 0o100644, size: tenGb, mtime: 1_700_000_000)
            let s10 = String(data: hdr10.prefix(102), encoding: .ascii) ?? ""
            check(s10.hasPrefix("070764") && s10.count == 102, "10 GB file must emit 102-byte 070764 header")
            let hexSizeStart = s10.index(s10.startIndex, offsetBy: 70)
            let hexSizeEnd = s10.index(hexSizeStart, offsetBy: 16)
            let hexSize = String(s10[hexSizeStart..<hexSizeEnd])
            check(Int64(hexSize, radix: 16) == tenGb, "070764 header hex size must encode 10 GB accurately, got '\(hexSize)'")
            print("[PASS] 64-bit ODC 070707 (5 GB) & 070764 (10 GB) CPIO headers")
        }

        // 8. Phase 2 ephemeral ECDH key/token cross-language vectors, SHA-256 fingerprint validation, & p2p_session_token lifecycle
        do {
            cleanTestState()
            let p2Data = Data((33...64).map { UInt8($0) })
            let priv2 = try! P256.KeyAgreement.PrivateKey(rawRepresentation: p2Data)
            let pub1Der = Data(base64Encoded: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUVw9brnjlrkE0/7Kf1T9zQzB6Ze/N13KUVrQpsO0A19FNr46UPMY+/mlR1kCoiFQK+8NV+CMU7LMClbxfZ+TVA==")!
            let pub1 = try! P256.KeyAgreement.PublicKey(derRepresentation: pub1Der)
            let shared = try! priv2.sharedSecretFromKeyAgreement(with: pub1)

            let sessB64 = deriveSessionKey(sharedSecret: shared).withUnsafeBytes { Data($0) }.base64EncodedString()
            let bleB64 = deriveBleFrameKey(sharedSecret: shared).withUnsafeBytes { Data($0) }.base64EncodedString()
            let bearerTok = deriveSessionToken(sharedSecret: shared)

            check(sessB64 == "yC4CQspFyUEHQ8fiY9BhEhGOrB0F1UGUUtwaSF3WA/4=", "SessionKey vector mismatch: \(sessB64)")
            check(bleB64 == "YrIYKl4YCHCjpy5kHceecyO0ix53rFC6MNbj+dzP6Rg=", "BleFrameKey vector mismatch: \(bleB64)")
            check(bearerTok == "e17df0a3f490020f6fa1834856fca83007dbf426c3a07f58207eb1adb31b415e", "BearerToken vector mismatch: \(bearerTok)")
            check(sessB64 != bleB64, "SessionKey and BleFrameKey must be domain-separated")

            check(isValidSha256Fingerprint(bearerTok), "64 lowercase hex fingerprint must be valid")
            check(isValidSha256Fingerprint(bearerTok.uppercased()), "64 uppercase hex fingerprint must normalize cleanly")
            check(!isValidSha256Fingerprint(""), "Empty fingerprint must fail")
            check(!isValidSha256Fingerprint(String(repeating: "a", count: 63)), "Short fingerprint must fail")
            check(!isValidSha256Fingerprint(String(repeating: "z", count: 64)), "Non-hex fingerprint must fail")

            // Register multiple tokens: verifies cap at 4 entries, 0600 permissions, and clearP2pSessionTokens
            for idx in 0..<6 {
                let tok = String(format: "%064x", idx + 1)
                registerP2pSessionToken(tok, stateDir: testStateDir, ttl: 120.0)
            }
            let tokFile = testStateDir.appendingPathComponent("p2p_session_token.json")
            check(FileManager.default.fileExists(atPath: tokFile.path), "p2p_session_token.json must exist")
            let attrs = try! FileManager.default.attributesOfItem(atPath: tokFile.path)
            let perms = (attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0
            check((perms & 0o777) == 0o600, "p2p_session_token.json must have 0600 permissions, got \(String(perms, radix: 8))")
            let parsed = try! JSONSerialization.jsonObject(with: try! Data(contentsOf: tokFile)) as! [String: Any]
            let entries = parsed["tokens"] as! [[String: Any]]
            check(entries.count == 4, "Token list must be capped at 4 entries, got \(entries.count)")
            let storedSet = Set(entries.compactMap { $0["token"] as? String })
            check(!storedSet.contains(String(format: "%064x", 1)), "Oldest token should be evicted")
            check(storedSet.contains(String(format: "%064x", 6)), "Newest token must be retained")

            // Revoking a specific token preserves active peers and removes the file once empty
            let tok5 = String(format: "%064x", 5)
            let tok6 = String(format: "%064x", 6)
            revokeP2pSessionToken(tok5, stateDir: testStateDir)
            let afterRevokeObj = try! JSONSerialization.jsonObject(with: try! Data(contentsOf: tokFile)) as! [String: Any]
            let afterRevokeEntries = afterRevokeObj["tokens"] as! [[String: Any]]
            let afterRevokeSet = Set(afterRevokeEntries.compactMap { $0["token"] as? String })
            check(!afterRevokeSet.contains(tok5), "Revoked token must be removed")
            check(afterRevokeSet.contains(tok6), "Non-revoked sibling token must remain")

            for remainingTok in afterRevokeSet {
                revokeP2pSessionToken(remainingTok, stateDir: testStateDir)
            }
            check(!FileManager.default.fileExists(atPath: tokFile.path), "Revoking last token must remove token file")

            // Register again and verify clearP2pSessionTokens removes all
            registerP2pSessionToken(tok6, stateDir: testStateDir, ttl: 120.0)
            check(FileManager.default.fileExists(atPath: tokFile.path), "Re-registered token file must exist")
            clearP2pSessionTokens(stateDir: testStateDir)
            check(!FileManager.default.fileExists(atPath: tokFile.path), "clearP2pSessionTokens must remove token file")

            // Empty plaintext AES-GCM (28 bytes) round-trips cleanly
            let emptyCipher = encryptBlePayload(Data(), key: deriveBleFrameKey(sharedSecret: shared))
            check(emptyCipher.count == 28, "Empty AES-GCM packet must be 28 bytes (12 IV + 16 tag)")
            check(decryptBlePayload(emptyCipher, key: deriveBleFrameKey(sharedSecret: shared)) == Data(), "decryptBlePayload must accept 28-byte empty GCM packet")
            print("[PASS] Phase 2 ECDH key/token vectors, fingerprint validation, and p2p_session_token lifecycle")
        }

        // 9. Phase 3 Settings AI runtime pills & claude_processor.py lookup
        do {
            cleanTestState()
            let standby = resolveAiPillStates(enabled: false, processorAvailable: true, swiftAvailable: true)
            check(standby.privacy.title == "Privacy Guard: Standby" && standby.privacy.tone == .standby,
                  "Disabled AI must show Privacy Guard: Standby")
            check(standby.vision.title == "Local Vision Engine: Standby" && standby.vision.tone == .standby,
                  "Disabled AI must show Local Vision Engine: Standby")

            let active = resolveAiPillStates(enabled: true, processorAvailable: true, swiftAvailable: true)
            check(active.privacy.title == "Privacy Guard: Active" && active.privacy.tone == .activeEmerald,
                  "Enabled AI with script present must show Privacy Guard: Active")
            check(active.vision.title == "Local Vision Engine: Ready" && active.vision.tone == .readyIndigo,
                  "Enabled AI with script & /usr/bin/swift must show Local Vision Engine: Ready")

            let missingSwift = resolveAiPillStates(enabled: true, processorAvailable: true, swiftAvailable: false)
            check(missingSwift.privacy.tone == .activeEmerald && missingSwift.vision.tone == .warningAmber,
                  "Missing /usr/bin/swift must mark Local Vision Engine unavailable")

            let missingScript = resolveAiPillStates(enabled: true, processorAvailable: false, swiftAvailable: true)
            check(missingScript.privacy.tone == .warningAmber && missingScript.vision.tone == .warningAmber,
                  "Missing claude_processor.py must mark both AI pills unavailable")

            let emptyDir = testRoot.appendingPathComponent("empty_ai_probe")
            try! FileManager.default.createDirectory(at: emptyDir, withIntermediateDirectories: true)
            check(
                !resolveClaudeProcessorAvailable(
                    scriptPath: emptyDir.appendingPathComponent("glidedrop.sh").path,
                    stateDir: emptyDir,
                    repoRoot: emptyDir,
                    bundleResourceURL: emptyDir
                ),
                "Missing claude_processor.py must return false"
            )
            let fakeScript = emptyDir.appendingPathComponent("claude_processor.py")
            try! Data("#!/usr/bin/env python3\n".utf8).write(to: fakeScript)
            check(
                resolveClaudeProcessorAvailable(
                    scriptPath: emptyDir.appendingPathComponent("glidedrop.sh").path,
                    stateDir: emptyDir,
                    repoRoot: emptyDir,
                    bundleResourceURL: nil
                ),
                "Present claude_processor.py must return true"
            )

            // AI config persistence must enforce 0600 permissions and preserve existing keys
            let aiCfgDir = testRoot.appendingPathComponent("ai_cfg_dir")
            writeAiSubsystemEnabled(true, configDir: aiCfgDir)
            let aiCfgFile = aiCfgDir.appendingPathComponent("claude_config.json")
            let aiAttrs = try! FileManager.default.attributesOfItem(atPath: aiCfgFile.path)
            let aiPerms = (aiAttrs[.posixPermissions] as? NSNumber)?.intValue ?? 0
            check((aiPerms & 0o777) == 0o600, "claude_config.json must have 0600 permissions, got \(String(aiPerms, radix: 8))")
            check(readAiSubsystemEnabled(env: [:], configDir: aiCfgDir), "readAiSubsystemEnabled must return true after enable")
            // Inject api_key and toggle off -> api_key preserved & permissions remain 0600
            let withKey = try! JSONSerialization.data(withJSONObject: ["enabled": true, "api_key": "sk-ant-mock-123"], options: [.prettyPrinted])
            try! withKey.write(to: aiCfgFile)
            writeAiSubsystemEnabled(false, configDir: aiCfgDir)
            let reloaded = try! JSONSerialization.jsonObject(with: try! Data(contentsOf: aiCfgFile)) as! [String: Any]
            check((reloaded["api_key"] as? String) == "sk-ant-mock-123", "writeAiSubsystemEnabled must preserve existing api_key")
            check(!readAiSubsystemEnabled(env: [:], configDir: aiCfgDir), "readAiSubsystemEnabled must return false after disable")
            check(readAiSubsystemEnabled(env: ["CLAUDE_AI_ENABLED": "1"], configDir: aiCfgDir), "CLAUDE_AI_ENABLED env override must return true")
            let aiAttrs2 = try! FileManager.default.attributesOfItem(atPath: aiCfgFile.path)
            let aiPerms2 = (aiAttrs2[.posixPermissions] as? NSNumber)?.intValue ?? 0
            check((aiPerms2 & 0o777) == 0o600, "claude_config.json permissions must stay 0600 after update")
            print("[PASS] Phase 3 Settings AI runtime pills & script detection")
        }

        if failures > 0 {
            fputs("[SUMMARY] \(failures) Swift regression check(s) FAILED\n", stderr)
            exit(1)
        }
        print("[SUMMARY] All Swift regression checks PASSED")
    }
}
