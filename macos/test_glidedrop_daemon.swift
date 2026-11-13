import Foundation
import Security
import CryptoKit
import Network
import Darwin

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
                wifiP2pIp: "192.168.73.55",
                wifiSsid: "HomeWiFi",
                hasPrevProxy: false,
                hasPrevWifi: false,
                hasWarpPaused: false
            ), "Must trigger fallback restore when active P2P IP is still bound")

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

        // Failed HTTPS child launch must return a terminal local-error status, not wait on an unstarted process.
        do {
            cleanTestState()
            let process = Process()
            process.executableURL = testRoot.appendingPathComponent("missing-https-sender")
            let status = runP2pTxProcess(process)
            check(status == 45, "Child launch failure must return local error 45")

            check(!shouldAllowBleAutoFallback(fileCount: 1, totalRawBytes: 100_000, txExitCode: status),
                  "Local HTTPS launch/config errors must not silently downgrade to BLE")
            print("[PASS] HTTPS child launch failure and terminal fallback policy")
        }

        // HTTPS terminal failures may neither retry nor switch transports.
        do {
            for code: Int32 in [43, 44, 45, 46, 47] {
                for bytes: Int64 in [1024, 10_000_000] {
                    check(!shouldRetryP2pTx(fileCount: 1, totalRawBytes: bytes, txExitCode: code,
                                           elapsed: 1, cancelled: false),
                          "Terminal HTTPS status \(code) must not retry for \(bytes) bytes")
                }
            }
            check(shouldRetryP2pTx(fileCount: 1, totalRawBytes: 10_000_000, txExitCode: 1,
                                   elapsed: 1, cancelled: false), "Transient initial failure of large transfer may retry")
            check(!shouldRetryP2pTx(fileCount: 1, totalRawBytes: 1024, txExitCode: 1,
                                    elapsed: 1, cancelled: false), "Small transient failure should use existing BLE fallback policy")
            check(!shouldRetryP2pTx(fileCount: 1, totalRawBytes: 10_000_000, txExitCode: 1,
                                    elapsed: 15, cancelled: false), "Late failure must not replay upload")
            check(!shouldRetryP2pTx(fileCount: 1, totalRawBytes: 10_000_000, txExitCode: 1,
                                    elapsed: 1, cancelled: true), "Cancellation must prevent retry")
            print("[PASS] HTTPS terminal status and retry policy")
        }

        // The establishment timeout is not a total-send timeout; live progress renews the idle deadline.
        do {
            var connecting = BleSenderActivityDeadline(startedAt: 1000)
            check(!connecting.hasTimedOut(transferStarted: false, progressUpdatedAt: 1299, now: 1299),
                  "Connection establishment must retain its 300s allowance")
            check(connecting.hasTimedOut(transferStarted: false, progressUpdatedAt: 1300, now: 1300),
                  "Connecting UI heartbeats must not extend establishment indefinitely")

            var sending = BleSenderActivityDeadline(startedAt: 1000)
            check(!sending.hasTimedOut(transferStarted: true, progressUpdatedAt: nil, now: 1299),
                  "Channel opened near establishment deadline must get a fresh idle allowance")
            check(!sending.hasTimedOut(transferStarted: true, progressUpdatedAt: nil, now: 1301),
                  "Live send must not be killed 300s after startup")
            for now in stride(from: 1359.0, through: 4899.0, by: 60) {
                check(!sending.hasTimedOut(transferStarted: true, progressUpdatedAt: now, now: now),
                      "Progressing transfer must survive beyond an hour without a total-duration limit")
            }
            check(!sending.hasTimedOut(transferStarted: true, progressUpdatedAt: 4899, now: 5198),
                  "Live send may wait just under 300s since its latest progress")
            check(sending.hasTimedOut(transferStarted: true, progressUpdatedAt: 4899, now: 5199),
                  "Stale progress must not keep a stalled send alive indefinitely")

            var idle = BleSenderActivityDeadline(startedAt: 1000)
            check(!idle.hasTimedOut(transferStarted: true, progressUpdatedAt: 999, now: 1001),
                  "Pre-existing progress must not affect a new live send")
            check(idle.hasTimedOut(transferStarted: true, progressUpdatedAt: 9999, now: 1301),
                  "Future progress timestamps must not extend a stalled send")

            cleanTestState()
            let progressFile = STATE_DIR.appendingPathComponent("transfer_progress.json")
            check(senderProgressUpdatedAt() == nil, "Missing progress must not fabricate activity")
            for (active, direction, expected) in [(true, "Sending", Optional(1500.0)),
                                                   (true, "Receiving", nil), (false, "Sending", nil)] {
                let data = try! JSONSerialization.data(withJSONObject: ["active": active, "direction": direction, "updatedAt": 1500.0])
                try! data.write(to: progressFile, options: [.atomic])
                check(senderProgressUpdatedAt() == expected, "Only active Sending progress may renew the sender deadline")
            }
            cleanTestState()
            print("[PASS] Establishment timeout and activity-aware live sender deadline")
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

            // Task 3.5: W2P2 v3 HKDF vector shared with Android (GlideDropNodeRegressionTest.w2p2V3MaterialMatchesSwiftVector)
            let v3Sid = Data((1...16).map { UInt8($0) })
            let v3RespPub = Data(repeating: 0x42, count: 91)
            let v3 = deriveW2p2SessionMaterial(
                sharedSecret: shared, sessionId: v3Sid, initiatorPubDer: pub1Der, responderPubDer: v3RespPub,
                initiatorFingerprint: String(repeating: "aa", count: 32), responderFingerprint: String(repeating: "bb", count: 32))
            check(v3 != nil, "v3 material must derive")
            check(v3?.sessionKey.withUnsafeBytes { Data($0) }.base64EncodedString() == "/UapwvsyFihK9p7CgynCYS3jGftS09bUXvMf27AKBQE=", "v3 AES key vector mismatch")
            check(v3?.token == "8ea5f9f4940b8095d52e539e0b1a8d57bca6d6e9eafd4f34180a7d2dd6f1a161", "v3 token vector mismatch: \(v3?.token ?? "nil")")
            check(v3?.verificationCode == "551 971", "v3 verification code vector mismatch: \(v3?.verificationCode ?? "nil")")
            let v3Tampered = deriveW2p2SessionMaterial(
                sharedSecret: shared, sessionId: v3Sid, initiatorPubDer: pub1Der, responderPubDer: v3RespPub,
                initiatorFingerprint: String(repeating: "aa", count: 32), responderFingerprint: String(repeating: "bc", count: 32))
            check(v3Tampered?.token != v3?.token && v3Tampered?.verificationCode != nil, "tampered fingerprint must change token")
            check(deriveW2p2SessionMaterial(sharedSecret: shared, sessionId: v3Sid, initiatorPubDer: pub1Der, responderPubDer: v3RespPub,
                initiatorFingerprint: "zz", responderFingerprint: String(repeating: "bb", count: 32)) == nil, "malformed fingerprint must be rejected")
            let reqV3 = parseW2p2Request("3\tPUB\t" + String(repeating: "aa", count: 32) + "\t0102030405060708090a0b0c0d0e0f10")
            check(reqV3.version == 3 && reqV3.sessionId?.count == 16 && reqV3.pubB64 == "PUB", "v3 request must parse")
            check(parseW2p2Request("2\tPUB\tFP").version < W2P2_PROTOCOL_VERSION, "v2 request is below the required version")
            check(parseW2p2Request("PUB\tFP").version < W2P2_PROTOCOL_VERSION, "unversioned request is below the required version")
            check(isW2p2UpdateRequiredReply("ERR\tUPDATE\t3") && isW2p2UpdateRequiredReply("NO\tUPDATE\t3") && !isW2p2UpdateRequiredReply("ERR"), "update-required reply detection")

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

        // 10. Dynamic P2P CIDR, active_p2p_session.json, v2 vs legacy JOIN, and AWDL bridge validation
        do {
            cleanTestState()
            check(deriveIpv4Cidr(ip: "192.168.73.1", prefixLen: 24) == "192.168.73.0/24", "deriveIpv4Cidr must compute /24 network")
            check(deriveIpv4Cidr(ip: "192.168.73.130", prefixLen: 25) == "192.168.73.128/25", "deriveIpv4Cidr must compute /25 network")
            check(deriveIpv4Cidr(ip: "192.168.73.1", prefixLen: 0) == nil, "deriveIpv4Cidr must reject prefixLen 0")
            check(deriveIpv4Cidr(ip: "192.168.73.1", prefixLen: -1) == nil, "deriveIpv4Cidr must reject negative prefixLen")
            check(deriveIpv4Cidr(ip: "192.168.73.1", prefixLen: 33) == nil, "deriveIpv4Cidr must reject prefixLen > 32")
            check(parseIpv4Cidr("0.0.0.0/0") == nil, "parseIpv4Cidr must reject /0 wildcard CIDR")
            check(cidrContains(cidr: "192.168.73.128/25", ip: "192.168.73.200"), "cidrContains must match dynamic /25 peer")
            check(!cidrContains(cidr: "192.168.73.128/25", ip: "192.168.73.10"), "cidrContains must reject out-of-range host")

            check(!isRfc1918Ipv4("172.15.255.255"), "172.15.x must NOT be treated as RFC1918")
            check(isRfc1918Ipv4("172.16.0.1"), "172.16.0.1 must be RFC1918")
            check(isRfc1918Ipv4("172.31.255.254"), "172.31.255.254 must be RFC1918")
            check(!isRfc1918Ipv4("172.32.0.1"), "172.32.x must NOT be treated as RFC1918")
            check(isCgnatIpv4("100.64.0.5"), "100.64.0.5 must be CGNAT")
            check(!isCgnatIpv4("100.128.0.5"), "100.128.0.5 must NOT be CGNAT")

            check(isValidP2pGatewayIp("192.168.73.1"), "RFC1918 P2P gateway must be valid")
            check(isValidP2pGatewayIp("fe80::1%p2p0"), "IPv6 link-local gateway must be valid")
            check(!isValidP2pGatewayIp("127.0.0.1"), "Loopback must NOT be valid P2P gateway")
            check(!isValidP2pGatewayIp("8.8.8.8"), "Public IP must NOT be valid P2P gateway")

            check(isNormalWifiIpv4("192.168.1.50", activeP2pCidr: "192.168.73.0/24"), "Normal LAN IP accepted")
            check(isNormalWifiIpv4("100.64.5.10", activeP2pCidr: "192.168.73.0/24"), "CGNAT ISP Wi-Fi IP accepted")
            check(isNormalWifiIpv4("172.15.20.1", activeP2pCidr: "192.168.73.0/24"), "Public Wi-Fi IP accepted")
            check(isNormalWifiIpv4("192.168.49.55", activeP2pCidr: "192.168.73.0/24"), "Unrelated subnet must NOT be treated as P2P without an active matching session")
            check(!isNormalWifiIpv4("192.168.49.55", activeP2pCidr: "192.168.49.0/24"), "Active P2P CIDR must exclude matching IP from normal Wi-Fi")
            check(!isNormalWifiIpv4("192.168.1.50", activeP2pCidr: "192.168.73.0/24", rawWifiSsid: "DIRECT-XY-GlideDrop"), "DIRECT-* SSID must never be treated as normal Wi-Fi")
            check(!isNormalWifiIpv4("192.168.73.55", activeP2pCidr: "192.168.73.0/24"), "Active dynamic P2P IP excluded from normal Wi-Fi")
            check(!isNormalWifiIpv4("169.254.1.2", activeP2pCidr: "192.168.73.0/24"), "Link-local IP excluded from normal Wi-Fi")
            check(!isNormalWifiIpv4("127.0.0.1", activeP2pCidr: "192.168.73.0/24"), "Loopback excluded from normal Wi-Fi")

            writeActiveP2pSession(
                ssid: "DIRECT-TransportTest",
                interfaceName: "en7",
                gatewayIp: "192.168.73.1",
                cidr: "192.168.73.0/24",
                httpsPort: 9443,
                proxyPort: 1081,
                macRxPort: 9772,
                udpKeepalivePort: 9774,
                stateDir: testStateDir,
                now: 1000.0
            )
            let loadedSess = loadActiveP2pSession(stateDir: testStateDir, maxAge: 60.0, now: 1010.0)
            check(loadedSess?.ssid == "DIRECT-TransportTest", "Session must persist OS-confirmed SSID")
            check(loadedSess?.interfaceName == "en7", "Session must persist OS-confirmed interface")
            let sessionFile = testStateDir.appendingPathComponent("active_p2p_session.json")
            let sessionJson = try! JSONSerialization.jsonObject(with: Data(contentsOf: sessionFile)) as! [String: Any]
            check(sessionJson["ssid"] as? String == "DIRECT-TransportTest" && sessionJson["interfaceName"] as? String == "en7",
                  "Session JSON must satisfy the shell provenance contract")
            let sessionPerms = (try! FileManager.default.attributesOfItem(atPath: sessionFile.path)[.posixPermissions] as! NSNumber).intValue
            check(sessionPerms & 0o777 == 0o600, "P2P session provenance must be private")
            let approvedToken = String(repeating: "c", count: 64)
            check(writeWp2pAuthorization(senderName: "TestPeer", ssid: "DIRECT-TransportTest", token: approvedToken,
                      peerIp: "192.168.73.1", stateDir: testStateDir, now: 1010.0), "Verified session must allow bound approval")
            let approvalFile = testStateDir.appendingPathComponent("wp2p_authorized_session.json")
            let approval = try! JSONSerialization.jsonObject(with: Data(contentsOf: approvalFile)) as! [String: Any]
            check(approval["senderName"] as? String == "TestPeer" && approval["ssid"] as? String == "DIRECT-TransportTest" &&
                  approval["token"] as? String == approvedToken && approval["peerIp"] as? String == "192.168.73.1" &&
                  approval["authorizedAt"] as? Double == 1010.0, "Reusable approval must bind exact peer, SSID, token, name and approval time")
            let approvalPerms = (try! FileManager.default.attributesOfItem(atPath: approvalFile.path)[.posixPermissions] as! NSNumber).intValue
            check(approvalPerms & 0o777 == 0o600, "Approval containing a bearer token must be private")
            try! FileManager.default.removeItem(at: approvalFile)
            for (ssid, token, peerIp) in [("DIRECT-Other", approvedToken, "192.168.73.1"),
                                           ("DIRECT-TransportTest", "not-a-token", "192.168.73.1"),
                                           ("DIRECT-TransportTest", approvedToken, "192.168.73.2")] {
                check(!writeWp2pAuthorization(senderName: "TestPeer", ssid: ssid, token: token, peerIp: peerIp,
                          stateDir: testStateDir, now: 1010.0), "Unbound approval must fail closed")
            }
            check(!FileManager.default.fileExists(atPath: approvalFile.path), "Rejected approvals must not publish authorization")
            check(loadedSess?.gatewayIp == "192.168.73.1", "active_p2p_session gatewayIp mismatch")
            check(loadedSess?.cidr == "192.168.73.0/24", "active_p2p_session cidr mismatch")
            check(loadedSess?.httpsPort == 9443, "active_p2p_session httpsPort mismatch")
            check(loadedSess?.proxyPort == 1081, "active_p2p_session proxyPort mismatch")
            check(loadedSess?.macRxPort == 9772, "active_p2p_session macRxPort mismatch")
            check(loadedSess?.udpKeepalivePort == 9774, "active_p2p_session udpKeepalivePort mismatch")
            check(loadActiveP2pSession(stateDir: testStateDir, maxAge: 60.0, now: 1100.0) == nil, "Expired active_p2p_session must not load")
                        check(loadActiveP2pSession(stateDir: testStateDir, maxAge: 60.0, now: 999.0) == nil, "Future-dated session must not load")
            clearActiveP2pSession(stateDir: testStateDir)
            check(loadActiveP2pSession(stateDir: testStateDir, maxAge: 60.0, now: 1010.0) == nil, "Cleared active_p2p_session must be removed")

            let legacyJoin = parseWp2pJoinCredentials("DIRECT-XY-Test\tsecretpass")
            check(legacyJoin?.isV2 == false && legacyJoin?.goIp == "" && legacyJoin?.proxyPort == 0, "Legacy 2-field JOIN must leave goIp empty without guessing a hardcoded IP")
            check(formatWp2pJoinReply(macIp: "192.168.73.8", isV2: false, macRxPort: 9772, udpKeepalivePort: 9774) == "OK 192.168.73.8\n", "Legacy JOIN reply must keep 1-field format")

            let invalidGoJoin = parseWp2pJoinCredentials("DIRECT-XY-Test\tsecretpass\t8.8.8.8\t2080")
            check(invalidGoJoin?.isV2 == true && invalidGoJoin?.goIp == "" && invalidGoJoin?.proxyPort == 2080, "Invalid goIp in JOIN must remain empty rather than substituting a default")

            let v2Join = parseWp2pJoinCredentials("DIRECT-XY-Test\tsecretpass\t192.168.73.1\t2080")
            check(v2Join?.isV2 == true && v2Join?.goIp == "192.168.73.1" && v2Join?.proxyPort == 2080, "v2 4-field JOIN must extract goIp and proxyPort")
            let v2NoProxy = parseWp2pJoinCredentials("DIRECT-XY-Test\tsecretpass\t192.168.73.1\t0")
            check(v2NoProxy?.isV2 == true && v2NoProxy?.proxyPort == 0, "v2 JOIN with proxyPort=0 must stay 0")
            check(formatWp2pJoinReply(macIp: "192.168.73.8", isV2: true, macRxPort: 9772, udpKeepalivePort: 9774) == "OK 192.168.73.8\t9772\t9774\n", "v2 JOIN reply must include negotiated ports")

            check(isAllowedAwdlInterfaceNames(["awdl0"]), "awdl0 must be allowed on AWDL bridge")
            check(!isAllowedAwdlInterfaceNames(["en0"]), "en0 must be rejected by AWDL bridge")
            check(!isAllowedAwdlInterfaceNames(["lo0"]), "lo0 must be rejected by AWDL bridge")
            check(!isAllowedAwdlInterfaceNames([]), "empty interface list must be rejected by AWDL bridge")

            let daemonSource = try! String(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("glidedrop-daemon.swift"), encoding: .utf8)
            check(!daemonSource.contains("publishedPsm > 0 ? publishedPsm : 192"), "Daemon must not substitute fake 192 PSM fallback")
            check(!daemonSource.contains("self?.publishedPsm ?? 192"), "Daemon PING reply must not substitute fake 192 PSM fallback")
            check(!daemonSource.contains("DEFAULT_MAC_RX_PORT") && !daemonSource.contains("DEFAULT_PROXY_PORT") && !daemonSource.contains("DEFAULT_AWDL_BRIDGE_PORT") && !daemonSource.contains("DEFAULT_FINDER_PROXY_PORT"),
                  "Daemon must not define compiled-in port constants")
            check(daemonSource.range(of: "\\b(8771|8772|8773|8774|1080|2080)\\b", options: .regularExpression) == nil,
                  "Daemon must not contain hardcoded transfer/proxy port literals")
            check(!daemonSource.contains("DEFAULT_P2P_") && !daemonSource.contains("192.168.49"), "Daemon must not contain hardcoded DEFAULT_P2P_ or 192.168.49 references")
            check(daemonSource.contains("prohibitedInterfaceTypes = [.wifi, .wiredEthernet, .cellular, .loopback]"), "AwdlLoopbackBridge must prohibit loopback while allowing .other (awdl0)")

            for (ssid, iface, gateway, cidr, port) in [
                ("HomeWiFi", "en7", "10.27.4.1", "10.27.4.0/23", 9443),
                ("DIRECT-TransportTest", "", "10.27.4.1", "10.27.4.0/23", 9443),
                ("DIRECT-TransportTest", "en7", "10.27.6.1", "10.27.4.0/23", 9443),
                ("DIRECT-TransportTest", "en7", "169.254.4.1", "169.254.0.0/16", 9443),
                ("DIRECT-TransportTest", "en7", "10.27.4.1", "10.27.4.0/23", 0)
            ] {
                check(!writeActiveP2pSession(ssid: ssid, interfaceName: iface, gatewayIp: gateway, cidr: cidr,
                          httpsPort: port, proxyPort: 0, stateDir: testStateDir), "Invalid provenance must not publish a P2P session")
            }
            let oldSession = Data("{\"gatewayIp\":\"10.27.4.1\",\"cidr\":\"10.27.4.0/23\",\"httpsPort\":9443,\"proxyPort\":0,\"updatedAt\":1000}".utf8)
            try! oldSession.write(to: sessionFile)
            check(loadActiveP2pSession(stateDir: testStateDir, now: 1010) == nil, "Legacy session without SSID/interface provenance must not load")
            clearActiveP2pSession(stateDir: testStateDir)

            // Missing OS netmask must not be replaced with a guessed /24 or saved CIDR.
                        check(matchWifiP2pInterfaceAddress(
                            ip: "192.168.73.55", netmask: nil, actualSsid: "DIRECT-TransportTest",
                            matchingGateway: "192.168.73.1", matchingCidr: "192.168.73.0/24"
                        ) == nil, "P2P provenance requires an OS netmask, even on DIRECT-* Wi-Fi")
                        writeActiveP2pSession(ssid: "DIRECT-TransportTest", interfaceName: "en7", gatewayIp: "192.168.73.1", cidr: "", httpsPort: 9443, proxyPort: 0, stateDir: testStateDir)
                        check(loadActiveP2pSession(stateDir: testStateDir) == nil, "Session writer must reject missing CIDR instead of guessing /24")

                        // Interface P2P matching must not match stale/other subnet IPs when targeting an explicit P2P CIDR
            check(
                matchWifiP2pInterfaceAddress(
                    ip: "192.168.49.8",
                    netmask: "255.255.255.0",
                    actualSsid: "DIRECT-TransportTest",
                    matchingGateway: "192.168.73.1",
                    matchingCidr: "192.168.73.0/24"
                ) == nil,
                "Unrelated subnet IP must NOT match explicit 192.168.73.0/24 target even when rawSsidIsDirect is true"
            )
            check(
                matchWifiP2pInterfaceAddress(
                    ip: "192.168.49.8",
                    netmask: "255.255.255.0",
                    actualSsid: "",
                    matchingGateway: nil,
                    matchingCidr: nil,
                    activeSession: nil
                ) == nil,
                "Without active session, explicit target, or DIRECT-* SSID, no IP may match as P2P"
            )
            for actualSsid in ["HomeWiFi", "DIRECT-OtherPeer"] {
                check(matchWifiP2pInterfaceAddress(ip: "10.27.5.20", netmask: "255.255.254.0",
                    actualSsid: actualSsid, requestedSsid: "DIRECT-TransportTest", matchingGateway: "10.27.4.1") == nil,
                    "Overlapping subnet on a readable wrong SSID must not satisfy requested association")
            }
            // Redacted SSID (no Location authorization): accepted from interface state only when the
            // advertised group-owner address is on the OS-reported subnet; a gateway is mandatory.
            check(matchWifiP2pInterfaceAddress(ip: "10.27.5.20", netmask: "255.255.254.0",
                actualSsid: "", requestedSsid: "DIRECT-TransportTest", matchingGateway: "10.27.4.1")?.cidr == "10.27.4.0/23",
                "Redacted SSID with matching address, netmask and group-owner router must confirm association")
            check(matchWifiP2pInterfaceAddress(ip: "10.27.5.20", netmask: "255.255.254.0",
                actualSsid: "", requestedSsid: "DIRECT-TransportTest", matchingGateway: nil) == nil,
                "Redacted SSID without an advertised group-owner address must not confirm association")
            let verified = matchWifiP2pInterfaceAddress(ip: "10.27.5.20", netmask: "255.255.254.0",
                actualSsid: "DIRECT-TransportTest", requestedSsid: "DIRECT-TransportTest", matchingGateway: "10.27.4.1")
            check(verified?.ip == "10.27.5.20" && verified?.cidr == "10.27.4.0/23", "Exact SSID and OS /23 must preserve the real subnet")
            let dynMatch = matchWifiP2pInterfaceAddress(
                ip: "192.168.73.200",
                netmask: "255.255.255.128",
                actualSsid: "", // redacted SSID must still work
                matchingGateway: "192.168.73.129",
                matchingCidr: "192.168.73.0/24"
            )
            check(dynMatch?.ip == "192.168.73.200" && dynMatch?.cidr == "192.168.73.128/25",
                  "Redacted SSID must confirm association from OS netmask containing the group-owner address")
            let genericSess = ActiveP2pSession(ssid: "DIRECT-TransportTest", interfaceName: "en7", gatewayIp: "192.168.73.1", cidr: "192.168.73.0/24", httpsPort: 9443, proxyPort: 2080, macRxPort: 9772, udpKeepalivePort: 9774, updatedAt: 1000.0)
            check(
                matchWifiP2pInterfaceAddress(ip: "192.168.73.55", netmask: "255.255.255.0", actualSsid: "", activeSession: genericSess) == nil,
                "Stale session state must not turn overlapping normal Wi-Fi into P2P"
            )
            check(
                matchWifiP2pInterfaceAddress(ip: "192.168.1.50", netmask: "255.255.255.0", actualSsid: "", activeSession: genericSess) == nil,
                "Normal HomeWiFi IP must NOT match P2P probe"
            )
            let broad16Match = matchWifiP2pInterfaceAddress(
                ip: "172.16.5.20",
                netmask: "255.255.0.0",
                actualSsid: "DIRECT-TransportTest",
                matchingGateway: "172.16.0.1",
                matchingCidr: "172.16.0.0/24"
            )
            check(broad16Match?.ip == "172.16.5.20" && broad16Match?.cidr == "172.16.0.0/16", "DIRECT-* /16 P2P subnet must match via OS netmask containing gateway")
            check(
                matchWifiP2pInterfaceAddress(
                    ip: "192.168.73.10",
                    netmask: "255.255.255.128",
                    actualSsid: "",
                    matchingGateway: "192.168.73.129",
                    matchingCidr: "192.168.73.0/24"
                ) == nil,
                "OS /25 netmask contradicting gateway must NOT falsely match guessed /24 CIDR"
            )
            check(
                matchWifiP2pInterfaceAddress(
                    ip: "192.168.73.55",
                    netmask: "255.255.255.0",
                    actualSsid: "",
                    matchingGateway: "10.99.1.1",
                    matchingCidr: nil,
                    activeSession: genericSess
                ) == nil,
                "Stale activeSession CIDR must NOT match when targeting a different gateway"
            )
            check(
                matchWifiP2pInterfaceAddress(
                    ip: "192.168.73.1",
                    netmask: nil,
                    actualSsid: "",
                    matchingGateway: "192.168.73.1",
                    matchingCidr: "192.168.73.0/24"
                ) == nil,
                "Interface IP equal to P2P gateway IP must NOT match as Mac P2P IP"
            )

            // Fallback proxy cleanup must clear dynamic session proxy, router IP on DIRECT-*, & tracked loopback proxy, but preserve unrelated proxies
            check(shouldClearFallbackP2pProxy(ProxyEndpointConfig(enabled: true, server: "192.168.73.1", port: 2080, authenticated: false), session: genericSess), "Dynamic session proxy server must be cleared on fallback")
            check(shouldClearFallbackP2pProxy(ProxyEndpointConfig(enabled: true, server: "10.88.0.1", port: 1080, authenticated: false), session: nil, currentRouterIp: "10.88.0.1"), "Active DIRECT-* router proxy server must be cleared on fallback even when session expired")
            check(shouldClearFallbackP2pProxy(ProxyEndpointConfig(enabled: true, server: "127.0.0.1", port: 2080, authenticated: false), session: genericSess), "Tracked loopback proxy port must be cleared on fallback")
            check(!shouldClearFallbackP2pProxy(ProxyEndpointConfig(enabled: true, server: "127.0.0.1", port: 9999, authenticated: false), session: genericSess), "Unrelated loopback proxy port must be preserved")
            check(!shouldClearFallbackP2pProxy(ProxyEndpointConfig(enabled: true, server: "192.168.1.10", port: 8080, authenticated: false), session: genericSess), "Unrelated LAN proxy must be preserved")
            print("[PASS] Dynamic P2P CIDR, active_p2p_session.json, v2 JOIN compatibility, and AWDL bridge guards")
        }

        // 11. extractDvzipCpioToDownloads bounds, forcePrompt=true, WARP-locked denial, & AWDL Unix socket bridge
        do {
            cleanTestState()
            let rxDir = testRoot.appendingPathComponent("extract_rx")
            let srcDir = testRoot.appendingPathComponent("extract_src")
            try! FileManager.default.createDirectory(at: rxDir, withIntermediateDirectories: true)
            try! FileManager.default.createDirectory(at: srcDir, withIntermediateDirectories: true)

            // 11a. Valid DVZip/CPIO extraction returns true and writes file
            let sampleIn = srcDir.appendingPathComponent("ble_ok.txt")
            try! Data("hello-ble-extract".utf8).write(to: sampleIn)
            let (validGz, _) = try! buildDvzipCpio(files: [sampleIn])
            let okExtract = extractDvzipCpioToDownloads(
                archiveData: validGz,
                metaDict: ["SenderComputerName": "PixelTest"],
                downloadsDir: rxDir
            )
            check(okExtract, "Valid archive must return true from extractDvzipCpioToDownloads")
            check(FileManager.default.fileExists(atPath: rxDir.appendingPathComponent("ble_ok.txt").path),
                  "Extracted file must exist in downloadsDir")

            // 11b. Truncated / corrupt archive must return false (never swallow failure)
            let truncated = Data(validGz.prefix(max(1, validGz.count / 2)))
            check(!extractDvzipCpioToDownloads(archiveData: truncated, metaDict: [:], downloadsDir: rxDir),
                  "Truncated archive must return false")
            check(!extractDvzipCpioToDownloads(archiveData: Data("NOT_A_CPIO".utf8), metaDict: [:], downloadsDir: rxDir),
                  "Corrupt archive must return false")

            // 11c. CPIO namesize overflow (> 4097) must return false
            let badNsHeader = String(format: "070707%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o", 0, 2, 0o100644, 0, 0, 1, 0, 0, 5000, 0)
            check(!extractDvzipCpioToDownloads(archiveData: Data(badNsHeader.utf8), metaDict: [:], downloadsDir: rxDir),
                  "CPIO namesize > 4097 must return false")

            // 11d. Zip-bomb protection: compressed payload expanding past maxDecompressedBytes must return false
            let bombFile = srcDir.appendingPathComponent("zeros.bin")
            try! Data(repeating: 0, count: 256 * 1024).write(to: bombFile)
            let (bombGz, _) = try! buildDvzipCpio(files: [bombFile])
            check(!extractDvzipCpioToDownloads(archiveData: bombGz, metaDict: [:], downloadsDir: rxDir, maxDecompressedBytes: 65_536),
                  "Archive exceeding maxDecompressedBytes must fail closed with false")

            // 11e. forcePrompt: true ignores autoAccept: true and writes pending_ask.json
            saveMacSettings(autoAccept: true, visible: true, deviceName: "TestMac")
            let pendingAskFile = STATE_DIR.appendingPathComponent("pending_ask.json")
            let askDecisionFile = STATE_DIR.appendingPathComponent("ask_decision.json")
            let askWatcher = DispatchQueue.global(qos: .userInitiated)
            var sawPendingAsk = false
            askWatcher.async {
                let deadline = Date().addingTimeInterval(3.0)
                while Date() < deadline {
                    if let d = try? Data(contentsOf: pendingAskFile),
                       let obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any],
                       let reqId = obj["id"] as? String {
                        sawPendingAsk = true
                        let dec = try! JSONSerialization.data(withJSONObject: ["id": reqId, "accepted": true])
                        try? dec.write(to: askDecisionFile, options: [.atomic])
                        return
                    }
                    Thread.sleep(forTimeInterval: 0.05)
                }
            }
            let promptAccepted = waitForMacUserAccept(senderName: "NearbyPeer", fileNames: ["5 GHz Wi-Fi Direct Connection (DIRECT-TEST)"], totalBytes: 0, forcePrompt: true)
            check(sawPendingAsk && promptAccepted, "waitForMacUserAccept(forcePrompt: true) must prompt even when autoAccept is true")

            // 11f. WARP-locked joins fail with ERR after forced approval, never a LAN OK.
            cleanTestState()
            saveMacSettings(autoAccept: true, visible: true, deviceName: "TestMac")
            askWatcher.async {
                let deadline = Date().addingTimeInterval(3.0)
                while Date() < deadline {
                    if let data = try? Data(contentsOf: pendingAskFile),
                       let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                       let id = obj["id"] as? String {
                        let decision = try! JSONSerialization.data(withJSONObject: ["id": id, "accepted": true])
                        try? decision.write(to: askDecisionFile, options: [.atomic])
                        return
                    }
                    Thread.sleep(forTimeInterval: 0.02)
                }
            }
            // Runtime-assigned ports are published by the listeners; a join without them must fail closed.
            let noPortsOut = OutputStream.toMemory()
            noPortsOut.open()
            handleIncomingWp2pJoin(ssid: "DIRECT-TransportTest", pass: "test-passphrase", out: noPortsOut,
                goIp: "10.27.4.1", httpsPort: 9443, isV2Join: true, peerName: "TestPeer",
                sessionToken: String(repeating: "a", count: 64), peerTlsFingerprint: String(repeating: "d", count: 64),
                pauseWarp: { fatalError("Join without runtime-assigned ports must not reach WARP") })
            check(noPortsOut.property(forKey: .dataWrittenToMemoryStreamKey) as? Data == Data("ERR\n".utf8),
                  "Join without published mac_rx_port/awdl_bridge_port must deny instead of using fixed ports")
            noPortsOut.close()
            check(parseWp2pJoinCredentials("DIRECT-XY-Test\tsecretpass\t192.168.49.1\t0\t9443")?.httpsPort == 9443, "Handshake must carry the peer's runtime HTTPS port")
            check(parseWp2pJoinCredentials("DIRECT-XY-Test\tsecretpass\t192.168.49.1\t0")?.httpsPort == 0, "Missing peer HTTPS port must parse as 0, not a default")
            check(readPortFile("mac_rx_port") == nil, "Missing port file must yield nil, not a fallback")
            try! Data("9772\n".utf8).write(to: STATE_DIR.appendingPathComponent("mac_rx_port"))
            try! Data("9774\n".utf8).write(to: STATE_DIR.appendingPathComponent("awdl_bridge_port"))
            let deniedOut = OutputStream.toMemory()
            deniedOut.open()
            var warpChecked = false
            handleIncomingWp2pJoin(ssid: "DIRECT-TransportTest", pass: "test-passphrase", out: deniedOut,
                goIp: "10.27.4.1", httpsPort: 9443, isV2Join: true, peerName: "TestPeer",
                sessionToken: String(repeating: "a", count: 64), peerTlsFingerprint: String(repeating: "d", count: 64), pauseWarp: {
                    warpChecked = true
                    return false
                })
            check(warpChecked, "Approved join must check WARP before association")
            check(deniedOut.property(forKey: .dataWrittenToMemoryStreamKey) as? Data == Data("ERR\n".utf8),
                  "WARP-locked incoming join must deny, not return a LAN endpoint")
            deniedOut.close()
            for name in ["active_p2p_session.json", "wp2p_authorized_session.json", "lan_fallback_active.flag", "p2p_outgoing_token.json"] {
                check(!FileManager.default.fileExists(atPath: STATE_DIR.appendingPathComponent(name).path),
                      "Denied join must not publish \(name)")
            }

            // Busy requests must neither reuse another peer's IP nor remove its pin/approval/token.
            let pinFile = STATE_DIR.appendingPathComponent("pinned_peer_tls_fingerprint.txt")
            let authFile = STATE_DIR.appendingPathComponent("wp2p_authorized_session.json")
            let ownerToken = String(repeating: "b", count: 64)
            registerP2pSessionToken(ownerToken)
            try! Data("owner-pin".utf8).write(to: pinFile)
            try! Data("owner-approval".utf8).write(to: authFile)
            check(beginWp2pJoin(), "First join must acquire ownership")
            check(!beginWp2pJoin(), "Concurrent join must not acquire ownership")
            let busyOut = OutputStream.toMemory()
            busyOut.open()
            handleIncomingWp2pJoin(ssid: "DIRECT-OtherPeer", pass: "other-passphrase", out: busyOut,
                goIp: "10.27.4.1", isV2Join: true, sessionToken: ownerToken, peerTlsFingerprint: String(repeating: "e", count: 64),
                pauseWarp: { fatalError("Busy request must not reach WARP or association") })
            check(busyOut.property(forKey: .dataWrittenToMemoryStreamKey) as? Data == Data("ERR\n".utf8),
                  "Busy join must immediately deny even for overlapping gateways")
            busyOut.close()
            check((try? Data(contentsOf: pinFile)) == Data("owner-pin".utf8), "Busy join must preserve owner's TLS pin")
            check((try? Data(contentsOf: authFile)) == Data("owner-approval".utf8), "Busy join must preserve owner's approval")
            let tokenData = try! Data(contentsOf: STATE_DIR.appendingPathComponent("p2p_session_token.json"))
            check(String(data: tokenData, encoding: .utf8)?.contains(ownerToken) == true, "Busy join must not revoke owner's token")
            finishWp2pJoin()
            check(beginWp2pJoin(), "Join ownership must be available after release")
            finishWp2pJoin()

            // Multi-file raw uncompressed CPIO exceeding maxDecompressedBytes cumulatively must fail closed
            func makeRawOdcEntry(name: String, payload: Data) -> Data {
                let nameBytes = Data((name + "\0").utf8)
                let hdrStr = String(format: "070707%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o", 0, 2, 0o100644, 0, 0, 1, 0, 0, nameBytes.count, payload.count)
                var d = Data(hdrStr.utf8)
                d.append(nameBytes)
                d.append(payload)
                return d
            }
            var rawMultiCpio = makeRawOdcEntry(name: "./part1.bin", payload: Data(repeating: 0x41, count: 40_000))
            rawMultiCpio.append(makeRawOdcEntry(name: "./part2.bin", payload: Data(repeating: 0x42, count: 40_000)))
            rawMultiCpio.append(makeRawOdcEntry(name: "TRAILER!!!", payload: Data()))
            check(!extractDvzipCpioToDownloads(archiveData: rawMultiCpio, metaDict: [:], downloadsDir: rxDir, maxDecompressedBytes: 60_000),
                  "Multi-file raw CPIO exceeding cumulative maxDecompressedBytes must fail closed")

            // 11g. Source invariants for ADRE ordering, forcePrompt: true, and Unix socket bridge
            let daemonSource = try! String(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("glidedrop-daemon.swift"), encoding: .utf8)
            check(daemonSource.contains("if !waitForMacUserAccept(senderName: incomingPeerName, fileNames: [\"5 GHz Wi-Fi Direct Connection (\\(ssid))\" + (verificationCode.map { \" • Verification code \\($0)\" } ?? \"\")], totalBytes: 0, forcePrompt: true, isRemoteAborted: isRemoteAbortedNow)"),
                  "handleIncomingWp2pJoin must always enforce forcePrompt: true and check isRemoteAborted")
            check(daemonSource.contains("if extractDvzipCpioToDownloads(archiveData: archData, metaDict: metaDict) {\n                        _ = writeAll(out, data: Data(\"OK\\r\\n\".utf8))"),
                  "ADRE must extract before sending OK")
            check(daemonSource.contains("NWConnection(to: .unix(path: resolvedSockPath), using: .tcp)"),
                  "AwdlLoopbackBridge must forward to Finder proxy over Unix domain socket")

            // 11h. AwdlLoopbackBridge endpoint validation & real AF_UNIX NWConnection round-trip
            check(!isAllowedAwdlEndpoint(.hostPort(host: .ipv4(IPv4Address("127.0.0.1")!), port: 9774)),
                  "isAllowedAwdlEndpoint must reject IPv4 loopback")
            check(!isAllowedAwdlEndpoint(.hostPort(host: .ipv6(IPv6Address("2001:db8::1")!), port: 9774)),
                  "isAllowedAwdlEndpoint must reject non-link-local IPv6")
            check(isAllowedAwdlEndpoint(.hostPort(host: .ipv6(IPv6Address("fe80::1")!), port: 9774)),
                  "isAllowedAwdlEndpoint must accept link-local IPv6")

            let unixSockPath = "/tmp/gd_unix_bridge_\(getpid()).sock"
            unlink(unixSockPath)
            defer { unlink(unixSockPath) }
            let srvFd = socket(AF_UNIX, SOCK_STREAM, 0)
            check(srvFd >= 0, "AF_UNIX socket creation must succeed")
            if srvFd >= 0 {
                var addr = sockaddr_un()
                addr.sun_family = sa_family_t(AF_UNIX)
                let pathBytes = Array(unixSockPath.utf8CString)
                withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
                    ptr.withMemoryRebound(to: CChar.self, capacity: pathBytes.count) { dst in
                        for (i, b) in pathBytes.enumerated() { dst[i] = b }
                    }
                }
                let oldMask = umask(0o177)
                let bindRes = withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        bind(srvFd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                    }
                }
                umask(oldMask)
                check(bindRes == 0 && listen(srvFd, 4) == 0, "AF_UNIX bind/listen must succeed")

                let srvSem = DispatchSemaphore(value: 0)
                DispatchQueue.global(qos: .userInitiated).async {
                    var cliAddr = sockaddr()
                    var cliLen: socklen_t = socklen_t(MemoryLayout<sockaddr>.size)
                    let cliFd = accept(srvFd, &cliAddr, &cliLen)
                    if cliFd >= 0 {
                        var buf = [UInt8](repeating: 0, count: 16)
                        let n = recv(cliFd, &buf, buf.count, 0)
                        if n > 0 && String(bytes: buf.prefix(n), encoding: .utf8) == "PING" {
                            let reply = Array("PONG".utf8)
                            _ = send(cliFd, reply, reply.count, 0)
                        }
                        close(cliFd)
                    }
                    close(srvFd)
                    srvSem.signal()
                }

                let nwDone = DispatchSemaphore(value: 0)
                var gotPong = false
                let nwConn = NWConnection(to: .unix(path: unixSockPath), using: .tcp)
                nwConn.stateUpdateHandler = { st in
                    if case .ready = st {
                        nwConn.send(content: Data("PING".utf8), completion: .contentProcessed { _ in
                            nwConn.receive(minimumIncompleteLength: 4, maximumLength: 16) { data, _, _, _ in
                                if let d = data, String(data: d, encoding: .utf8) == "PONG" {
                                    gotPong = true
                                }
                                nwConn.cancel()
                                nwDone.signal()
                            }
                        })
                    } else if case .failed(_) = st {
                        nwDone.signal()
                    }
                }
                nwConn.start(queue: DispatchQueue.global(qos: .userInitiated))
                _ = nwDone.wait(timeout: .now() + 3.0)
                _ = srvSem.wait(timeout: .now() + 3.0)
                check(gotPong, "NWConnection(.unix) must round-trip PING/PONG to 0600 AF_UNIX listener")
            }

            print("[PASS] extractDvzipCpioToDownloads bounds, forcePrompt=true, WARP-locked denial, & Unix socket bridge")
        }

        // 12. Cancel-sync & P2P large-file BLE fallback guard tests
        do {
            cleanTestState()
            check(shouldAllowBleAutoFallback(fileCount: 0, totalRawBytes: 0, txExitCode: nil),
                  "URL-only transfer may use BLE channel")
            check(shouldAllowBleAutoFallback(fileCount: 1, totalRawBytes: BLE_AUTO_FALLBACK_MAX_RAW_BYTES, txExitCode: 1),
                  "Small <=5MB file may fall back to BLE on P2P connect error")
            check(!shouldAllowBleAutoFallback(fileCount: 1, totalRawBytes: BLE_AUTO_FALLBACK_MAX_RAW_BYTES + 1, txExitCode: 1),
                  "Large >5MB file must refuse slow automatic BLE fallback")
            for blockedCode: Int32 in [43, 44, 45, 46, 47] {
                check(!shouldAllowBleAutoFallback(fileCount: 1, totalRawBytes: 1024, txExitCode: blockedCode),
                      "Exit code \(blockedCode) must never fall back to BLE even for small files")
            }

            // waitForMacUserAccept must abort immediately (<1.5s vs 60s) and clear pending_ask.json when sender aborts
            let askFile = STATE_DIR.appendingPathComponent("pending_ask.json")
            var remoteAborted = false
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 0.2) {
                remoteAborted = true
            }
            let startedWait = Date()
            let accepted = waitForMacUserAccept(
                senderName: "PixelCancelTest",
                fileNames: ["large.mov"],
                totalBytes: 25_000_000,
                forcePrompt: true,
                isRemoteAborted: { remoteAborted }
            )
            let elapsedWait = Date().timeIntervalSince(startedWait)
            check(!accepted, "waitForMacUserAccept must return false when remote sender aborts")
            check(elapsedWait < 2.5, "waitForMacUserAccept must dismiss promptly on remote abort (took \(elapsedWait)s)")
            check(!FileManager.default.fileExists(atPath: askFile.path), "pending_ask.json must be removed on remote abort")

            print("[PASS] Cancel-sync prompt dismissal & large-file BLE fallback policy")
        }

        // Bug condition exploration (Property 1): Mac fails to join Android Wi-Fi Direct group.
        // These encode EXPECTED behavior and are EXPECTED TO FAIL on unfixed code.
        do {
            let before = failures
            // Redacted SSID (no Location authorization): valid P2P address, real netmask, router == advertised GO.
            for (ip, mask, gw) in [("192.168.49.123", "255.255.255.0", "192.168.49.1"),
                                   ("192.168.73.55", "255.255.255.0", "192.168.73.1")] {
                let m = matchWifiP2pInterfaceAddress(ip: ip, netmask: mask, actualSsid: "",
                    requestedSsid: "DIRECT-ab-Xyz1", matchingGateway: gw, matchingCidr: nil)
                check(m?.ip == ip, "[EXPLORE] empty SSID with valid P2P address \(ip)/\(mask) router \(gw) must confirm association")
            }
            // Scan strategy: nil-SSID scan results must still yield a join candidate.
            let src = (try? String(contentsOfFile: #filePath.replacingOccurrences(of: "test_glidedrop_daemon.swift", with: "glidedrop-daemon.swift"), encoding: .utf8)) ?? ""
            let joinBody = src.components(separatedBy: "func joinWifiDirectNetwork(").dropFirst().first?
                .components(separatedBy: "func associateWifiDirectWithRetry(").first ?? ""
            check(!joinBody.isEmpty, "[EXPLORE] could not locate joinWifiDirectNetwork source")
            check(!joinBody.contains("$0.ssid == ssid") || joinBody.contains("bssid") || joinBody.contains("BSSID") || joinBody.contains("channelHint"),
                  "[EXPLORE] join strategy filters scan results only by readable ssid; nil-SSID scan results can never be selected (no BSSID/channel fallback)")
            let cands = [WifiScanCandidate(ssid: nil, bssid: "aa:bb:cc:00:00:01", channel: 36, rssi: -40),
                         WifiScanCandidate(ssid: nil, bssid: "aa:bb:cc:00:00:02", channel: 149, rssi: -60),
                         WifiScanCandidate(ssid: nil, bssid: "aa:bb:cc:00:00:03", channel: 149, rssi: -50),
                         WifiScanCandidate(ssid: "Home", bssid: "aa:bb:cc:00:00:04", channel: 149, rssi: -30)]
            check(selectWifiJoinCandidate(cands, ssid: "DIRECT-ab-X", hints: WifiJoinHints(bssid: "AA:BB:CC:00:00:02")) == 1, "BSSID hint must select nil-SSID candidate")
            check(selectWifiJoinCandidate(cands, ssid: "DIRECT-ab-X", hints: WifiJoinHints(channelHint: 149)) == 2, "Channel hint must pick strongest hidden-name candidate, not a named network")
            check(selectWifiJoinCandidate(cands, ssid: "DIRECT-ab-X", hints: WifiJoinHints()) == nil, "No hints and no readable name must not guess")
            check(selectWifiJoinCandidate(cands + [WifiScanCandidate(ssid: "DIRECT-ab-X", bssid: nil, channel: 1, rssi: -80)], ssid: "DIRECT-ab-X", hints: WifiJoinHints()) == 4, "Readable name match wins")
            check(wifiJoinBackoff(attempt: 1) == 1.5 && wifiJoinBackoff(attempt: 20) == 6.0, "Backoff grows and is capped")
            check(!WifiDirectStage.association.userAction.isEmpty && WifiDirectStage.tlsPin.rawValue == "TLS pin", "Stages carry user actions")
            check(src.contains("CLLocationManager"), "[EXPLORE] Mac never requests Location authorization (no CLLocationManager)")
            if failures > before { print("[EXPLORE] Swift bug-condition checks FAILED as expected on unfixed code (\(failures - before))") }
        }
        do {
            // History Clear removes log lines only, never the transferred files.
            let dir = FileManager.default.temporaryDirectory.appendingPathComponent("gd-hist-\(UUID().uuidString)")
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: dir) }
            let payload = dir.appendingPathComponent("keep.bin")
            try? Data("x".utf8).write(to: payload)
            let log = dir.appendingPathComponent("received.log")
            let lines = ["1\tFILE\t\(payload.path)\t1\treceived\tPhone", "2\tFILE\t/tmp/out.bin\t1\tsent\tPhone"]
            func seed() { try? (lines.joined(separator: "\n") + "\n").write(to: log, atomically: true, encoding: .utf8) }
            seed(); clearHistoryLog(filter: 1, stateDir: dir)
            let afterRx = (try? String(contentsOf: log, encoding: .utf8)) ?? ""
            check(afterRx.contains("sent") && !afterRx.contains("received"), "Clear on Received keeps Sent history")
            seed(); clearHistoryLog(filter: 2, stateDir: dir)
            let afterTx = (try? String(contentsOf: log, encoding: .utf8)) ?? ""
            check(afterTx.contains("received") && !afterTx.contains("sent"), "Clear on Sent keeps Received history")
            seed(); clearHistoryLog(filter: 0, stateDir: dir)
            check(!FileManager.default.fileExists(atPath: log.path), "Clear on All removes the history log")
            check(FileManager.default.fileExists(atPath: payload.path), "Clearing history never deletes transferred files")
        }
        if failures > 0 {
            fputs("[SUMMARY] \(failures) Swift regression check(s) FAILED\n", stderr)
            exit(1)
        }
        print("[SUMMARY] All Swift regression checks PASSED")
    }
}
