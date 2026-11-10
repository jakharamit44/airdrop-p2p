package com.airdrop.p2p

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ShortcutInfo
import android.content.pm.ShortcutManager
import android.graphics.drawable.Icon
import android.media.MediaScannerConnection
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import java.util.Base64
import android.net.wifi.WifiManager
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build
import android.os.Environment
import android.os.Looper
import android.os.ParcelUuid
import android.os.PowerManager
import android.provider.OpenableColumns
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Collections
import java.util.Date
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal

data class AirDropPeer(
    val id: String,
    val name: String,
    val host: String,
    val port: Int,
    val rssi: Int = -48,
    val transport: String = "5GHz P2P • BLE",
    val lastSeenMs: Long = System.currentTimeMillis()
)

data class IncomingAskPrompt(
    val senderName: String,
    val summary: String,
    val fileNames: List<String> = emptyList(),
    val totalBytes: Long = 0L,
    val decision: CompletableDeferred<Boolean>
)

data class ReceivedItem(
    val title: String,
    val pathOrUrl: String,
    val isUrl: Boolean,
    val sizeBytes: Long = 0L,
    val isOutgoing: Boolean = false,
    val peerName: String = "Nearby Peer",
    val timestampMs: Long = System.currentTimeMillis()
)

data class TransferProgress(
    val label: String,
    val percent: Int,
    val doneBytes: Long,
    val totalBytes: Long,
    val speedBytesPerSec: Long = 0L,
    val etaSeconds: Long = 0L,
    val fileCount: Int = 1,
    val isSending: Boolean = false,
    val isConnecting: Boolean = false,
    val phase: String = "",
    val peerName: String = ""
)

/**
 * Pure P2P zero-router AirDrop engine for Android <-> macOS:
 * - Direct BLE L2CAP CoC server & client (works with zero Wi-Fi / different networks)
 * - 5 GHz Wi-Fi Direct Autonomous Group (192.168.49.1:8771) high-speed P2P receiver
 * - Zero Same-IP / LAN router mDNS dependency
 */
class AirDropNode(private val context: Context) {

    companion object {
        const val AIRDROP_PORT = 8771
        const val PEER_TTL_MS = 4_500L
        private const val KEYSTORE_ALIAS = "airdrop_p2p_ec_v2"
        val MAC_BLE_SERVICE_UUID: UUID = UUID.fromString("52300001-a12d-4000-8000-523a12d00001")
        val MAC_BLE_PSM_CHAR_UUID: UUID = UUID.fromString("52300002-a12d-4000-8000-523a12d00002")
        val P2P_BLE_SERVICE_UUID: UUID = UUID.fromString("52300003-a12d-4000-8000-523a12d00003")
        val P2P_BLE_PSM_CHAR_UUID: UUID = UUID.fromString("52300004-a12d-4000-8000-523a12d00004")
        val P2P_BLE_DATA_UUID: ParcelUuid by lazy { ParcelUuid.fromString("0000cafe-0000-1000-8000-00805f9b34fb") }
        val MAC_BLE_DATA_UUID: ParcelUuid by lazy { ParcelUuid.fromString("0000caff-0000-1000-8000-00805f9b34fb") }
        const val MAX_ENCRYPTED_BLE_ARCHIVE_BYTES = 30_000_000L
        const val MAX_UNENCRYPTED_BLE_ARCHIVE_BYTES = 1_800_000_000L
        const val MAX_BLE_META_BYTES = 1_048_576

        fun isValidBleFrameBounds(metaLen: Int, archiveLen: Int, isEncryptedBle: Boolean): Boolean {
            if (metaLen <= 0 || metaLen > MAX_BLE_META_BYTES) return false
            if (archiveLen < 0) return false
            if (isEncryptedBle && archiveLen.toLong() > MAX_ENCRYPTED_BLE_ARCHIVE_BYTES) return false
            if (!isEncryptedBle && archiveLen.toLong() > MAX_UNENCRYPTED_BLE_ARCHIVE_BYTES) return false
            return true
        }

        fun calculateAggregateStagedBytes(sizes: Iterable<Long>): Long {
            return sizes.sumOf { it.coerceAtLeast(0L) }
        }

        fun formatMultiFileDisplayLabel(firstFileName: String, totalCount: Int): String {
            return if (totalCount > 1) "$firstFileName (+${totalCount - 1} more)" else firstFileName
        }

        fun defaultHardwareName(): String {
            val mfr = Build.MANUFACTURER?.trim().orEmpty().replaceFirstChar { it.uppercase() }
            val mod = Build.MODEL?.trim().orEmpty()
            val combined = if (mod.startsWith(mfr, ignoreCase = true)) mod else "$mfr $mod".trim()
            return combined.ifEmpty { "Android Device" }
        }

        data class EphemeralEcdhKeyPair(val privateKey: PrivateKey, val publicKey: PublicKey)

        fun generateEphemeralEcdhKeyPair(): EphemeralEcdhKeyPair {
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"))
            val kp = kpg.generateKeyPair()
            return EphemeralEcdhKeyPair(kp.private, kp.public)
        }

        fun deriveSessionKey(privateKey: PrivateKey, peerPublicKeyDer: ByteArray): ByteArray {
            val kf = KeyFactory.getInstance("EC")
            val peerPublic = kf.generatePublic(X509EncodedKeySpec(peerPublicKeyDer))
            val ka = KeyAgreement.getInstance("ECDH")
            ka.init(privateKey)
            ka.doPhase(peerPublic, true)
            val rawSecret = ka.generateSecret()
            val md = MessageDigest.getInstance("SHA-256")
            md.update(rawSecret)
            md.update("AirDropP2P-v2-SessionKey".toByteArray(StandardCharsets.UTF_8))
            return md.digest()
        }

        fun encryptAesGcm(plain: ByteArray, sessionKeyBytes: ByteArray): ByteArray {
            val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sessionKeyBytes, "AES"), GCMParameterSpec(128, iv))
            val sealed = cipher.doFinal(plain)
            val out = ByteArray(12 + sealed.size)
            System.arraycopy(iv, 0, out, 0, 12)
            System.arraycopy(sealed, 0, out, 12, sealed.size)
            return out
        }

        fun decryptAesGcm(packet: ByteArray, sessionKeyBytes: ByteArray): ByteArray {
            if (packet.size < 28) throw IOException("Encrypted frame too short")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sessionKeyBytes, "AES"), GCMParameterSpec(128, packet, 0, 12))
            return cipher.doFinal(packet, 12, packet.size - 12)
        }

        fun formatBytes(bytes: Long): String {
            if (bytes <= 0L) return "0 B"
            val kb = 1024.0
            val mb = kb * 1024.0
            val gb = mb * 1024.0
            return when {
                bytes >= gb -> String.format(java.util.Locale.US, "%.2f GB", bytes / gb)
                bytes >= mb -> String.format(java.util.Locale.US, "%.1f MB", bytes / mb)
                bytes >= kb -> String.format(java.util.Locale.US, "%.1f KB", bytes / kb)
                else -> "$bytes B"
            }
        }

        fun formatSpeed(bps: Long): String {
            if (bps <= 0L) return "0 KB/s"
            return "${formatBytes(bps)}/s"
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val random = SecureRandom()
    private val transferMutex = Mutex()
    private val prefs = context.getSharedPreferences("airdrop_p2p", Context.MODE_PRIVATE)
    val authTag = ByteArray(3).also { random.nextBytes(it) }
    val serviceId: String = prefs.getString("service_id", null)
        ?: ByteArray(6)
            .also { random.nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
            .also { prefs.edit().putString("service_id", it).apply() }

    private val initialDeviceName: String = run {
        val saved = prefs.getString("device_name", null)
        if (saved.isNullOrBlank()) {
            defaultHardwareName()
        } else {
            saved
        }
    }

    private val _deviceNameFlow = MutableStateFlow(initialDeviceName)
    val deviceNameFlow: StateFlow<String> = _deviceNameFlow.asStateFlow()

    var deviceName: String
        get() = _deviceNameFlow.value
        set(value) {
            val clean = value.trim().ifEmpty { defaultHardwareName() }
            _deviceNameFlow.value = clean
            prefs.edit().putString("device_name", clean).apply()
            restartBleAdvertisingOnly()
        }

    var deviceModel: String = Build.MODEL ?: "Android"

    private val _autoAcceptFlow = MutableStateFlow(prefs.getBoolean("auto_accept", false))
    val autoAcceptFlow: StateFlow<Boolean> = _autoAcceptFlow.asStateFlow()

    var autoAccept: Boolean
        get() = _autoAcceptFlow.value
        set(value) {
            _autoAcceptFlow.value = value
            prefs.edit().putBoolean("auto_accept", value).apply()
        }

    private val _themeModeFlow = MutableStateFlow(prefs.getString("theme_mode", "system") ?: "system")
    val themeModeFlow: StateFlow<String> = _themeModeFlow.asStateFlow()

    var themeMode: String
        get() = _themeModeFlow.value
        set(value) {
            val normalized = when (value.lowercase(java.util.Locale.US)) {
                "light", "day" -> "light"
                "dark", "night" -> "dark"
                else -> "system"
            }
            _themeModeFlow.value = normalized
            prefs.edit().putString("theme_mode", normalized).apply()
        }

    private var embeddedProxyServer: EmbeddedProxyServer? = null

    private val _shareCellularInternetFlow = MutableStateFlow(prefs.getBoolean("share_cellular_internet", true))
    val shareCellularInternetFlow: StateFlow<Boolean> = _shareCellularInternetFlow.asStateFlow()

    var shareCellularInternet: Boolean
        get() = _shareCellularInternetFlow.value
        set(value) {
            _shareCellularInternetFlow.value = value
            prefs.edit().putBoolean("share_cellular_internet", value).apply()
            if (value) {
                if (wifiDirectCreds.isNotEmpty()) {
                    startEmbeddedProxy()
                }
            } else {
                stopEmbeddedProxy()
            }
        }

    var onItemReceived: ((ReceivedItem) -> Unit)? = null
    var onTransferProgress: ((String, Int, Long, Long, Long, Boolean, Boolean, String) -> Unit)? = null

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    private val _localEndpoints = MutableStateFlow<List<String>>(emptyList())
    val localEndpoints: StateFlow<List<String>> = _localEndpoints.asStateFlow()

    // Strict live P2P discovery: only actively advertising BLE peers within PEER_TTL_MS
    private val _peers = MutableStateFlow<List<AirDropPeer>>(emptyList())
    val peers: StateFlow<List<AirDropPeer>> = _peers.asStateFlow()

    private val _incomingAsk = MutableStateFlow<IncomingAskPrompt?>(null)
    val incomingAsk: StateFlow<IncomingAskPrompt?> = _incomingAsk.asStateFlow()

    private val _receivedItems = MutableStateFlow<List<ReceivedItem>>(loadHistory())
    val receivedItems: StateFlow<List<ReceivedItem>> = _receivedItems.asStateFlow()

    private val _transferProgress = MutableStateFlow<TransferProgress?>(null)
    val transferProgress: StateFlow<TransferProgress?> = _transferProgress.asStateFlow()

    private val _p2pStatus = MutableStateFlow("Starting BLE + 5GHz Wi-Fi Direct P2P\u2026")
    val p2pStatus: StateFlow<String> = _p2pStatus.asStateFlow()

    private val _logs = MutableStateFlow<List<String>>(emptyList())
    val logs: StateFlow<List<String>> = _logs.asStateFlow()

    private val _bluetoothEnabled = MutableStateFlow(true)
    val bluetoothEnabled: StateFlow<Boolean> = _bluetoothEnabled.asStateFlow()

    private val _wifiEnabled = MutableStateFlow(true)
    val wifiEnabled: StateFlow<Boolean> = _wifiEnabled.asStateFlow()

    private val _permissionsGranted = MutableStateFlow(true)
    val permissionsGranted: StateFlow<Boolean> = _permissionsGranted.asStateFlow()

    @Volatile
    private var transferCancelled = false
    @Volatile
    private var activeTransferSocket: java.io.Closeable? = null
    @Volatile
    private var radioReceiverRegistered = false

    private var transferWakeLock: PowerManager.WakeLock? = null
    private var transferWifiLock: WifiManager.WifiLock? = null

    private fun acquireTransferLocks() {
        runCatching {
            val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            if (transferWakeLock == null) {
                transferWakeLock = pm?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "airdropp2p:transfer_node_lock")?.apply {
                    setReferenceCounted(false)
                }
            }
            transferWakeLock?.acquire(60 * 60 * 1000L) // 1 hour max

            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            if (transferWifiLock == null) {
                val lockMode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                } else {
                    @Suppress("DEPRECATION")
                    WifiManager.WIFI_MODE_FULL_HIGH_PERF
                }
                transferWifiLock = wm?.createWifiLock(lockMode, "airdropp2p:transfer_wifi_lock")?.apply {
                    setReferenceCounted(false)
                }
            }
            transferWifiLock?.acquire()
        }
    }

    private fun releaseTransferLocks() {
        runCatching {
            if (transferWakeLock?.isHeld == true) transferWakeLock?.release()
            if (transferWifiLock?.isHeld == true) transferWifiLock?.release()
        }
    }

    private val radioStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context?, intent: Intent?) {
            refreshSystemReadiness()
        }
    }

    fun refreshSystemReadiness() {
        val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        val btOn = bm?.adapter?.isEnabled == true
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
        val wfOn = wm?.isWifiEnabled == true
        val permsOk = if (Build.VERSION.SDK_INT >= 31) {
            ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_ADVERTISE) == PackageManager.PERMISSION_GRANTED &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED
        } else {
            ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        }
        val prevBt = _bluetoothEnabled.value
        _bluetoothEnabled.value = btOn
        _wifiEnabled.value = wfOn
        _permissionsGranted.value = permsOk
        if (btOn && (!prevBt || localBlePsm <= 0) && _running.value && permsOk) {
            startBleWake()
        }
    }

    fun cancelActiveTransfer() {
        transferCancelled = true
        _transferProgress.value = null
        onTransferProgress?.invoke("Transfer cancelled", -1, 0L, 0L, 0L, false, false, "")
        pendingMacTx?.let { tx ->
            pendingMacTx = null
            tx.result.complete(false)
        }
        runCatching { activeTransferSocket?.close() }
        activeTransferSocket = null
        lastMacP2pIp = ""
        stopWifiDirectGroup()
        log("Transfer cancelled by user")
    }

    private fun loadHistory(): List<ReceivedItem> {
        val raw = prefs.getString("history_v2", null) ?: return emptyList()
        return raw.lineSequence()
            .filter { it.isNotBlank() }
            .mapNotNull { line ->
                val p = line.split('\t')
                if (p.size >= 7) {
                    ReceivedItem(
                        title = p[0],
                        pathOrUrl = p[1],
                        isUrl = p[2].toBoolean(),
                        sizeBytes = p[3].toLongOrNull() ?: 0L,
                        isOutgoing = p[4].toBoolean(),
                        peerName = p[5],
                        timestampMs = p[6].toLongOrNull() ?: System.currentTimeMillis()
                    )
                } else null
            }
            .toList()
    }

    private fun recordHistoryItem(item: ReceivedItem) {
        _receivedItems.update { curr ->
            val next = (listOf(item) + curr).take(60)
            val serialized = next.joinToString("\n") {
                "${it.title.replace('\t', ' ')}\t${it.pathOrUrl.replace('\t', ' ')}\t${it.isUrl}\t${it.sizeBytes}\t${it.isOutgoing}\t${it.peerName.replace('\t', ' ')}\t${it.timestampMs}"
            }
            prefs.edit().putString("history_v2", serialized).apply()
            next
        }
    }

    fun clearReceivedItems() {
        _receivedItems.value = emptyList()
        prefs.edit().remove("history_v2").apply()
    }

    fun clearLogs() {
        _logs.value = emptyList()
    }

    /**
     * Refreshes BLE scanning and advertisement without closing the active L2CAP server socket,
     * preventing duplicate PSM / RPA advertisements on the Mac radar.
     */
    fun refreshP2p() {
        refreshSystemReadiness()
        if (!_running.value) {
            start()
            return
        }
        restartBleScanOnly()
        restartBleAdvertisingOnly()
        refreshLocalAddresses()
    }

    private fun clearProgressNotification() {
        _transferProgress.value = null
        onTransferProgress?.invoke("", -1, 0L, 0L, 0L, true, false, "")
    }

    private fun reportConnecting(
        label: String,
        total: Long,
        fileCount: Int,
        isSending: Boolean,
        phase: String,
        peerName: String = learnedMacName ?: "Nearby Peer"
    ) {
        if (transferCancelled) return
        val cleanPeer = peerName.substringBefore(" (PSM").trim().ifEmpty { "Nearby Peer" }
        _transferProgress.value = TransferProgress(
            label = label,
            percent = 0,
            doneBytes = 0L,
            totalBytes = total,
            speedBytesPerSec = 0L,
            etaSeconds = 0L,
            fileCount = fileCount.coerceAtLeast(1),
            isSending = isSending,
            isConnecting = true,
            phase = phase,
            peerName = cleanPeer
        )
        onTransferProgress?.invoke(label, 0, 0L, total, 0L, isSending, true, phase)
    }

    private fun isValidPeerTransferIp(ip: String): Boolean {
        return ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.")
    }

    private fun readBleLineBounded(sock: BluetoothSocket, inp: InputStream, timeoutMs: Long): String? {
        val timer = scope.launch(Dispatchers.IO) {
            kotlinx.coroutines.delay(timeoutMs)
            runCatching { sock.close() }
        }
        return try {
            readHttpLine(inp)
        } finally {
            timer.cancel()
        }
    }

    private fun reportProgress(
        label: String,
        pct: Int,
        done: Long,
        total: Long,
        startedAtMs: Long,
        fileCount: Int,
        isSending: Boolean,
        peerName: String = learnedMacName ?: "Nearby Peer"
    ) {
        if (pct >= 100) {
            _transferProgress.value = null
            onTransferProgress?.invoke(label, 100, total, total, 0L, isSending, false, "")
            return
        }
        val cleanPeer = peerName.substringBefore(" (PSM").trim().ifEmpty { "Nearby Peer" }
        val phaseLabel = if (isSending) "Sending files" else "Receiving files"
        val elapsedMs = (System.currentTimeMillis() - startedAtMs).coerceAtLeast(120L)
        val speedBps = (done * 1000L) / elapsedMs
        val remBytes = (total - done).coerceAtLeast(0L)
        val etaSec = if (speedBps > 0L) remBytes / speedBps else 0L
        _transferProgress.value = TransferProgress(
            label = label,
            percent = pct.coerceIn(0, 99),
            doneBytes = done,
            totalBytes = total,
            speedBytesPerSec = speedBps,
            etaSeconds = etaSec,
            fileCount = fileCount,
            isSending = isSending,
            isConnecting = false,
            phase = phaseLabel,
            peerName = cleanPeer
        )
        onTransferProgress?.invoke(label, pct, done, total, speedBps, isSending, false, phaseLabel)
    }

    private val sslContext: SSLContext by lazy { buildSslContext() }
    private var serverSocket: SSLServerSocket? = null
    private var bleAdvertiser: BluetoothLeAdvertiser? = null
    private val activeAdvertiseCallbacks = Collections.synchronizedList(mutableListOf<AdvertiseCallback>())
    private var bleScanner: BluetoothLeScanner? = null
    private var bleScanCallback: ScanCallback? = null
    private var l2capServer: BluetoothServerSocket? = null
    private var gattServer: BluetoothGattServer? = null
    private var wifiP2pManager: WifiP2pManager? = null
    private var wifiP2pChannel: WifiP2pManager.Channel? = null
    @Volatile
    private var wifiDirectCreds: String = ""
    @Volatile
    private var bleMacDevice: BluetoothDevice? = null
    @Volatile
    private var bleMacPsm: Int = 0
    @Volatile
    private var localBlePsm: Int = 0
    @Volatile
    private var learnedMacName: String? = null
    @Volatile
    private var lastMacP2pIp: String = ""
    private var wifiTeardownJob: Job? = null

    private class PendingMacTx(
        val metaBytes: ByteArray,
        val archiveBytes: ByteArray,
        val entries: List<AirDropCodec.OutgoingEntry>,
        val url: String?,
        val label: String,
        val fileCount: Int,
        val totalRawBytes: Long,
        val result: CompletableDeferred<Boolean>,
        val targetPeerAddress: String? = null,
        @Volatile var claimed: Boolean = false
    )

    @Volatile
    private var pendingMacTx: PendingMacTx? = null

    private fun saveDirectSharePeer(peer: AirDropPeer, remoteName: String) {
        prefs.edit()
            .putString("last_peer_id", peer.id)
            .putString("last_peer_name", remoteName)
            .putString("last_peer_host", peer.host)
            .putInt("last_peer_port", peer.port)
            .apply()
        runCatching {
            val sm = context.getSystemService(ShortcutManager::class.java) ?: return@runCatching
            val shareIntent = Intent(context, MainActivity::class.java).apply {
                action = Intent.ACTION_SEND
                putExtra("direct_peer_host", peer.host)
                putExtra("direct_peer_port", peer.port)
            }
            val shortcut = ShortcutInfo.Builder(context, "mac_airdrop_direct")
                .setShortLabel(remoteName)
                .setLongLabel("AirDrop to $remoteName")
                .setIcon(Icon.createWithResource(context, R.mipmap.ic_launcher_round))
                .setCategories(setOf("com.airdrop.p2p.DIRECT_SHARE"))
                .setIntent(shareIntent)
                .setLongLived(true)
                .setRank(0)
                .build()
            sm.pushDynamicShortcut(shortcut)
        }
    }

    fun log(msg: String) {
        android.util.Log.i("AirDropP2P", msg)
        val time = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(Date())
        _logs.update { (it + "[$time] $msg").takeLast(80) }
    }

    fun start() {
        refreshSystemReadiness()
        if (_running.value) return
        _running.value = true
        if (!radioReceiverRegistered) {
            runCatching {
                val filter = IntentFilter().apply {
                    addAction(BluetoothAdapter.ACTION_STATE_CHANGED)
                    addAction(WifiManager.WIFI_STATE_CHANGED_ACTION)
                }
                context.registerReceiver(radioStateReceiver, filter)
                radioReceiverRegistered = true
            }
        }
        // Tear down any lingering persistent Wi-Fi Direct group from previous sessions;
        // 5GHz Wi-Fi Direct is now created strictly on-demand during file transfers >= 64 KB
        // and removed immediately after so the Mac never loses its Internet Wi-Fi!
        stopWifiDirectGroup()
        startHttpsReceiver()
        startBleWake()
        refreshLocalAddresses()
        startPeerPruningLoop()
    }

    private fun startPeerPruningLoop() {
        scope.launch {
            while (_running.value) {
                kotlinx.coroutines.delay(1_000)
                val now = System.currentTimeMillis()
                _peers.update { curr ->
                    val active = curr.filter { (now - it.lastSeenMs) <= PEER_TTL_MS }
                    if (active.none { it.id == "ble-mac" }) {
                        bleMacDevice = null
                        bleMacPsm = 0
                    }
                    active
                }
            }
        }
    }

    fun stop() {
        if (!_running.value) return
        _running.value = false
        cancelActiveTransfer()
        if (radioReceiverRegistered) {
            runCatching { context.unregisterReceiver(radioStateReceiver) }
            radioReceiverRegistered = false
        }
        _peers.value = emptyList()
        bleMacDevice = null
        bleMacPsm = 0
        stopBleWake()
        stopWifiDirectGroup()
        stopEmbeddedProxy()
        try {
            serverSocket?.close()
        } catch (_: Throwable) {
        }
        serverSocket = null
        log("AirDrop P2P node stopped")
    }

    /**
     * Lists only Pure P2P endpoints (Direct BLE L2CAP + 5GHz Wi-Fi Direct 192.168.49.1).
     * Never exposes or uses shared-router LAN IPs.
     */
    fun refreshLocalAddresses() {
        val list = ArrayList<String>()
        if (localBlePsm > 0) {
            list.add("BLE L2CAP PSM $localBlePsm (Zero-Router P2P)")
        }
        try {
            for (nif in Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!nif.isUp || nif.isLoopback) continue
                for (addr in Collections.list(nif.inetAddresses)) {
                    if (addr is Inet4Address && addr.hostAddress?.startsWith("192.168.49.") == true) {
                        list.add("${addr.hostAddress}:$AIRDROP_PORT (5GHz Wi-Fi Direct)")
                    }
                }
            }
            if (embeddedProxyServer?.running == true) {
                val proxyPort = embeddedProxyServer?.actualPort ?: EmbeddedProxyServer.DEFAULT_PROXY_PORT
                list.add("0.0.0.0:$proxyPort (Dual SOCKS5/HTTP Proxy)")
            }
        } catch (_: Throwable) {
        }
        _localEndpoints.value = list
    }

    // =========================================================================
    // Pure P2P Direct BLE L2CAP CoC Server, Advertiser & Scanner
    // =========================================================================

    @SuppressLint("MissingPermission")
    fun startBleWake() {
        try {
            val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            val adapter = bm?.adapter
            if (adapter == null) {
                log("Bluetooth adapter unavailable")
                return
            }

            // 1. Open Direct BLE L2CAP CoC Server Socket once and reuse across refreshes
            if (l2capServer == null || localBlePsm <= 0) {
                try {
                    val srv = adapter.listenUsingInsecureL2capChannel()
                    l2capServer = srv
                    localBlePsm = srv.psm
                    log("BLE L2CAP receiver listening on PSM $localBlePsm")
                    scope.launch { acceptBleL2capLoop(srv) }
                } catch (t: Throwable) {
                    log("BLE L2CAP server warning: ${t.message}")
                }
            }
            val peerPsm = localBlePsm

            // 2. Open GATT Server so Mac can read PSM + Full Device Name if needed
            if (peerPsm > 0 && gattServer == null) {
                try {
                    val gattCb = object : BluetoothGattServerCallback() {
                        override fun onCharacteristicReadRequest(
                            device: BluetoothDevice,
                            requestId: Int,
                            offset: Int,
                            characteristic: BluetoothGattCharacteristic
                        ) {
                            val fullNameBytes = utf8PrefixBytes(deviceName, 24)
                            val psmBytes = ByteArray(2 + fullNameBytes.size).also { buf ->
                                buf[0] = (localBlePsm and 0xFF).toByte()
                                buf[1] = ((localBlePsm ushr 8) and 0xFF).toByte()
                                System.arraycopy(fullNameBytes, 0, buf, 2, fullNameBytes.size)
                            }
                            gattServer?.sendResponse(
                                device,
                                requestId,
                                BluetoothGatt.GATT_SUCCESS,
                                0,
                                psmBytes
                            )
                        }
                    }
                    val gs = bm.openGattServer(context, gattCb)
                    val svc = BluetoothGattService(
                        P2P_BLE_SERVICE_UUID,
                        BluetoothGattService.SERVICE_TYPE_PRIMARY
                    )
                    val ch = BluetoothGattCharacteristic(
                        P2P_BLE_PSM_CHAR_UUID,
                        BluetoothGattCharacteristic.PROPERTY_READ,
                        BluetoothGattCharacteristic.PERMISSION_READ
                    )
                    svc.addCharacteristic(ch)
                    gs?.addService(svc)
                    gattServer = gs
                } catch (_: Throwable) {
                }
            }

            // 3. Start single tracked BLE advertisement (25B Primary + 18B Scan Response <= 31B BLE limit)
            restartBleAdvertisingOnly()

            // 4. Start BLE Scanner for Mac BLE L2CAP service
            restartBleScanOnly()
        } catch (t: Throwable) {
            log("BLE init warning: ${t.message}")
        }
    }

    @SuppressLint("MissingPermission")
    private fun stopBleAdvertisingOnly() {
        val adv = bleAdvertiser
        synchronized(activeAdvertiseCallbacks) {
            for (cb in activeAdvertiseCallbacks) {
                try {
                    adv?.stopAdvertising(cb)
                } catch (_: Throwable) {
                }
            }
            activeAdvertiseCallbacks.clear()
        }
    }

    private fun utf8PrefixBytes(input: String, maxBytes: Int): ByteArray {
        val raw = input.toByteArray(StandardCharsets.UTF_8)
        if (raw.size <= maxBytes) return raw
        var len = maxBytes
        while (len > 0 && (raw[len].toInt() and 0xC0) == 0x80) {
            len--
        }
        return raw.copyOf(len)
    }

    @SuppressLint("MissingPermission")
    private fun restartBleAdvertisingOnly() {
        try {
            val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            val advertiser = bm?.adapter?.bluetoothLeAdvertiser ?: return
            bleAdvertiser = advertiser
            stopBleAdvertisingOnly()

            val peerPsm = localBlePsm
            if (peerPsm <= 0) return

            val settings = AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                .setConnectable(true)
                .build()

            // Primary AdvertiseData: Flags (3B) + 0xCAFE ServiceData (4B header + 2B PSM + up to 16B UTF-8 name = 22B) = 25B <= 31B!
            val cleanNameBytes = utf8PrefixBytes(deviceName, 16)
            val svcPayload = ByteArray(2 + cleanNameBytes.size).also { buf ->
                buf[0] = (peerPsm and 0xFF).toByte()
                buf[1] = ((peerPsm ushr 8) and 0xFF).toByte()
                System.arraycopy(cleanNameBytes, 0, buf, 2, cleanNameBytes.size)
            }
            val data = AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .addServiceData(P2P_BLE_DATA_UUID, svcPayload)
                .build()

            // Scan Response: 128-bit P2P_BLE_SERVICE_UUID (18B <= 31B!)
            val scanResponse = AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .addServiceUuid(ParcelUuid(P2P_BLE_SERVICE_UUID))
                .build()

            val cb = object : AdvertiseCallback() {
                override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                    log("BLE P2P active (psm=$peerPsm, name=$deviceName)")
                    val p2pSsid = wifiDirectCreds.substringBefore('\t').ifEmpty { "5GHz P2P Ready" }
                    _p2pStatus.value = "BLE PSM $peerPsm • $p2pSsid"
                    refreshLocalAddresses()
                }

                override fun onStartFailure(errorCode: Int) {
                    log("BLE advertise warning (code $errorCode)")
                }
            }
            activeAdvertiseCallbacks.add(cb)
            advertiser.startAdvertising(settings, data, scanResponse, cb)
        } catch (t: Throwable) {
            log("BLE advertise error: ${t.message}")
        }
    }

    @SuppressLint("MissingPermission")
    private fun stopBleScanOnly() {
        try {
            val sc = bleScanner
            val scb = bleScanCallback
            if (sc != null && scb != null) {
                sc.stopScan(scb)
            }
        } catch (_: Throwable) {
        }
        bleScanCallback = null
    }

    @SuppressLint("MissingPermission")
    private fun restartBleScanOnly() {
        try {
            val bm = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            val scanner = bm?.adapter?.bluetoothLeScanner ?: return
            bleScanner = scanner
            stopBleScanOnly()

            val filters = listOf(
                ScanFilter.Builder()
                    .setServiceUuid(ParcelUuid(MAC_BLE_SERVICE_UUID))
                    .build(),
                ScanFilter.Builder()
                    .setServiceUuid(
                        ParcelUuid.fromString("0000AD00-0000-1000-8000-00805F9B34FB"),
                        ParcelUuid.fromString("0000FF00-0000-FFFF-FFFF-FFFFFFFFFFFF")
                    )
                    .build()
            )
            val scanSettings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build()
            val scb = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    handleMacBleScanResult(result)
                }

                override fun onBatchScanResults(results: MutableList<ScanResult>) {
                    for (r in results) handleMacBleScanResult(r)
                }
            }
            scanner.startScan(filters, scanSettings, scb)
            bleScanCallback = scb
        } catch (t: Throwable) {
            log("BLE scan warning: ${t.message}")
        }
    }

    @SuppressLint("MissingPermission")
    private fun handleMacBleScanResult(result: ScanResult) {
        val dev = result.device ?: return
        val record = result.scanRecord ?: return
        val name = record.deviceName ?: dev.name ?: ""
        val uuids = record.serviceUuids.orEmpty()
        var hasMacService = uuids.any { it.uuid == MAC_BLE_SERVICE_UUID }
        var parsedPsm = 0
        var remoteDisplayName = "MacBook Pro"
        if (name.startsWith("AD-")) {
            hasMacService = true
            val rest = name.removePrefix("AD-").trim()
            val psmPart = rest.substringBefore('-')
            parsedPsm = psmPart.toIntOrNull() ?: 0
            val customLabel = rest.substringAfter('-', "").trim()
            if (customLabel.isNotEmpty()) {
                remoteDisplayName = customLabel
            }
        }
        record.getServiceData(MAC_BLE_DATA_UUID)?.let { d ->
            if (d.size >= 2) {
                hasMacService = true
                val p = (d[0].toInt() and 0xFF) or ((d[1].toInt() and 0xFF) shl 8)
                if (p > 0) parsedPsm = p
                if (d.size > 2) {
                    val decoded = String(d, 2, d.size - 2, StandardCharsets.UTF_8).trim()
                    if (decoded.isNotEmpty()) remoteDisplayName = decoded
                }
            }
        }
        if (parsedPsm <= 0) {
            for (pu in uuids) {
                val u16 = ((pu.uuid.mostSignificantBits ushr 32) and 0xFFFFL).toInt()
                if ((u16 and 0xFF00) == 0xAD00 && (u16 and 0xFF) > 0) {
                    hasMacService = true
                    parsedPsm = u16 and 0xFF
                    break
                }
            }
        }
        if (!hasMacService) return

        val prevDev = bleMacDevice
        val prevPsm = bleMacPsm
        bleMacDevice = dev
        if (parsedPsm > 0) bleMacPsm = parsedPsm
        val effectivePsm = if (bleMacPsm > 0) bleMacPsm else 192
        val displayMacName = learnedMacName ?: remoteDisplayName
        val now = System.currentTimeMillis()

        if (prevDev?.address != dev.address || (parsedPsm > 0 && prevPsm != parsedPsm) || _peers.value.none { it.id == "ble-mac" }) {
            log("Discovered live peer over BLE: $displayMacName (${dev.address}, psm=$effectivePsm, rssi=${result.rssi} dBm)")
            val blePeer = AirDropPeer(
                id = "ble-mac",
                name = "$displayMacName (PSM $effectivePsm)",
                host = "ble://${dev.address}",
                port = effectivePsm,
                rssi = result.rssi,
                transport = "5GHz P2P • BLE",
                lastSeenMs = now
            )
            _peers.value = listOf(blePeer)
            saveDirectSharePeer(blePeer, displayMacName)
        } else {
            _peers.update { list ->
                list.map {
                    if (it.id == "ble-mac") {
                        it.copy(
                            name = "$displayMacName (PSM $effectivePsm)",
                            host = "ble://${dev.address}",
                            port = effectivePsm,
                            rssi = result.rssi,
                            lastSeenMs = now
                        )
                    } else it
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    private suspend fun acceptBleL2capLoop(srv: BluetoothServerSocket) = withContext(Dispatchers.IO) {
        while (_running.value) {
            val sock = try {
                srv.accept()
            } catch (_: Throwable) {
                break
            }
            scope.launch { handleBleL2capConnection(sock) }
        }
    }

    @SuppressLint("MissingPermission")
    private fun startWifiDirectGroup() {
        try {
            val mgr = context.getSystemService(Context.WIFI_P2P_SERVICE) as? WifiP2pManager ?: return
            val ch = wifiP2pChannel ?: mgr.initialize(context, Looper.getMainLooper(), null) ?: return
            wifiP2pManager = mgr
            wifiP2pChannel = ch

            fun pollGroupInfo() {
                scope.launch {
                    repeat(20) {
                        kotlinx.coroutines.delay(400)
                        mgr.requestGroupInfo(ch) { group ->
                            if (group != null && group.isGroupOwner && !group.networkName.isNullOrEmpty() && !group.passphrase.isNullOrEmpty()) {
                                val creds = "${group.networkName}\t${group.passphrase}\t192.168.49.1\t$AIRDROP_PORT"
                                if (wifiDirectCreds != creds) {
                                    startEmbeddedProxy()
                                    wifiDirectCreds = creds
                                    val psm = localBlePsm
                                    _p2pStatus.value = "5GHz P2P (${group.networkName}) • BLE PSM $psm"
                                    log("5GHz Wi-Fi Direct P2P Ready: ${group.networkName} (192.168.49.1:$AIRDROP_PORT)")
                                    refreshLocalAddresses()
                                }
                            }
                        }
                        if (wifiDirectCreds.isNotEmpty()) return@launch
                    }
                }
            }

            mgr.requestGroupInfo(ch) { existing ->
                try {
                    if (existing != null && existing.isGroupOwner && !existing.networkName.isNullOrEmpty() && !existing.passphrase.isNullOrEmpty()) {
                        startEmbeddedProxy()
                        wifiDirectCreds = "${existing.networkName}\t${existing.passphrase}\t192.168.49.1\t$AIRDROP_PORT"
                        val psm = localBlePsm
                        _p2pStatus.value = "5GHz P2P (${existing.networkName}) • BLE PSM $psm"
                        log("5GHz Wi-Fi Direct P2P Ready: ${existing.networkName} (192.168.49.1:$AIRDROP_PORT)")
                        refreshLocalAddresses()
                    } else {
                        val listener = object : WifiP2pManager.ActionListener {
                            override fun onSuccess() {
                                pollGroupInfo()
                            }
                            override fun onFailure(reason: Int) {
                                mgr.createGroup(ch, object : WifiP2pManager.ActionListener {
                                    override fun onSuccess() { pollGroupInfo() }
                                    override fun onFailure(r2: Int) { log("Wi-Fi Direct createGroup status: $r2") }
                                })
                            }
                        }
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                            val randomPass = ByteArray(6).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }
                            val cfg = WifiP2pConfig.Builder()
                                .setNetworkName("DIRECT-AirDrop")
                                .setPassphrase(randomPass)
                                .enablePersistentMode(false)
                                .setGroupOperatingBand(WifiP2pConfig.GROUP_OWNER_BAND_5GHZ)
                                .build()
                            mgr.createGroup(ch, cfg, listener)
                        } else {
                            mgr.createGroup(ch, listener)
                        }
                    }
                } catch (t: Throwable) {
                    log("Wi-Fi Direct group setup fallback: ${t.message}")
                }
            }
        } catch (t: Throwable) {
            log("Wi-Fi Direct init warning: ${t.message}")
        }
    }

    @SuppressLint("MissingPermission")
    private fun stopWifiDirectGroup() {
        stopEmbeddedProxy()
        try {
            val mgr = wifiP2pManager ?: (context.getSystemService(Context.WIFI_P2P_SERVICE) as? WifiP2pManager)
            val ch = wifiP2pChannel ?: mgr?.initialize(context, Looper.getMainLooper(), null)
            if (mgr != null && ch != null) {
                wifiP2pManager = mgr
                wifiP2pChannel = ch
                mgr.removeGroup(ch, null)
            }
        } catch (_: Throwable) {
        }
        wifiDirectCreds = ""
        lastMacP2pIp = ""
        if (localBlePsm > 0) {
            _p2pStatus.value = "BLE PSM $localBlePsm • 5GHz On-Demand Ready"
        }
        refreshLocalAddresses()
    }

    private fun startEmbeddedProxy() {
        if (!shareCellularInternet) return
        if (embeddedProxyServer?.running == true) return
        try {
            val proxy = EmbeddedProxyServer(context, EmbeddedProxyServer.DEFAULT_PROXY_PORT) { msg ->
                log(msg)
            }
            if (proxy.start()) {
                embeddedProxyServer = proxy
                log("5GHz Wi-Fi Direct Dual-Protocol Proxy active (0.0.0.0:${EmbeddedProxyServer.DEFAULT_PROXY_PORT})")
                refreshLocalAddresses()
            }
        } catch (t: Throwable) {
            log("EmbeddedProxyServer error: ${t.message}")
        }
    }

    private fun stopEmbeddedProxy() {
        try {
            embeddedProxyServer?.stop()
        } catch (_: Throwable) {
        }
        embeddedProxyServer = null
        refreshLocalAddresses()
    }

    private suspend fun ensureWifiDirectCreds(): String {
        wifiTeardownJob?.cancel()
        if (wifiDirectCreds.isNotEmpty()) return wifiDirectCreds
        startWifiDirectGroup()
        var waited = 0
        while (wifiDirectCreds.isEmpty() && waited < 3400) {
            kotlinx.coroutines.delay(200)
            waited += 200
        }
        return wifiDirectCreds
    }

    // End-to-End AES-256-GCM authenticated encryption for BLE L2CAP frames
    private val bleAesKey: SecretKeySpec by lazy {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest("AirDropP2P-E2EE-AES256GCM-v2".toByteArray(StandardCharsets.UTF_8))
        SecretKeySpec(digest, "AES")
    }


    fun getLocalTlsFingerprint(): String {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val cert = (ks.getCertificate(KEYSTORE_ALIAS) ?: run {
                buildSslContext()
                ks.getCertificate(KEYSTORE_ALIAS)
            }) as? X509Certificate ?: return ""
            val md = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            md.joinToString("") { "%02x".format(it) }
        } catch (_: Throwable) {
            ""
        }
    }

    private fun encryptBlePayload(plain: ByteArray, sessionKey: ByteArray? = null): ByteArray {
        val key = if (sessionKey != null) SecretKeySpec(sessionKey, "AES") else bleAesKey
        val iv = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val sealed = cipher.doFinal(plain)
        return ByteArray(12 + sealed.size).also { out ->
            System.arraycopy(iv, 0, out, 0, 12)
            System.arraycopy(sealed, 0, out, 12, sealed.size)
        }
    }

    private fun decryptBlePayload(packet: ByteArray, sessionKey: ByteArray? = null): ByteArray {
        if (packet.size < 28) throw IOException("Encrypted BLE frame too short")
        val key = if (sessionKey != null) SecretKeySpec(sessionKey, "AES") else bleAesKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, packet, 0, 12))
        return cipher.doFinal(packet, 12, packet.size - 12)
    }

    @SuppressLint("MissingPermission")
    private suspend fun handleBleL2capConnection(sock: BluetoothSocket) = withContext(Dispatchers.IO) {
        val remoteAddr = sock.remoteDevice?.address ?: "BLE"
        try {
            val dis = DataInputStream(BufferedInputStream(sock.inputStream, 65536))
            val out = BufferedOutputStream(sock.outputStream, 16384)
            while (true) {
                val magic = ByteArray(4)
                try {
                    dis.readFully(magic)
                } catch (_: EOFException) {
                    break
                }
                val magicStr = String(magic, StandardCharsets.US_ASCII)
                if (magicStr == "PING") {
                    val metaLen = dis.readInt()
                    val archLen = dis.readInt()
                    if (metaLen in 1..4096 && archLen == 0) {
                        val pingBytes = ByteArray(metaLen)
                        dis.readFully(pingBytes)
                        val pingStr = String(pingBytes, StandardCharsets.UTF_8)
                        val parts = pingStr.split('\t')
                        val macName = parts.getOrNull(0)?.trim().orEmpty().ifEmpty { "MacBook Pro" }
                        val macPsm = parts.getOrNull(1)?.trim()?.toIntOrNull() ?: 192
                        val macRssi = parts.getOrNull(2)?.trim()?.toIntOrNull() ?: -48
                        learnedMacName = macName
                        if (macPsm > 0) bleMacPsm = macPsm
                        sock.remoteDevice?.let { bleMacDevice = it }

                        val effectivePsm = if (bleMacPsm > 0) bleMacPsm else 192
                        val now = System.currentTimeMillis()
                        val wasEmpty = _peers.value.none { it.id == "ble-mac" }
                        val blePeer = AirDropPeer(
                            id = "ble-mac",
                            name = "$macName (PSM $effectivePsm)",
                            host = "ble://${sock.remoteDevice?.address ?: "mac"}",
                            port = effectivePsm,
                            rssi = macRssi,
                            transport = "5GHz P2P • BLE",
                            lastSeenMs = now
                        )
                        _peers.value = listOf(blePeer)
                        if (wasEmpty) {
                            log("Discovered live peer over BLE: $macName ($remoteAddr, psm=$effectivePsm, rssi=$macRssi dBm)")
                            saveDirectSharePeer(blePeer, macName)
                        }

                        val tx = pendingMacTx
                        if (tx == null || (tx.targetPeerAddress != null && tx.targetPeerAddress != remoteAddr)) {
                            val pong = "PONG\t$deviceName\t$localBlePsm\n"
                            out.write(pong.toByteArray(StandardCharsets.UTF_8))
                            out.flush()
                            break
                        } else {
                            tx.claimed = true
                            pendingMacTx = null
                            transferCancelled = false
                            activeTransferSocket = sock
                            var txOk = false
                            var wp2pJoined = false
                            try {
                                val dos = DataOutputStream(out)
                                if (tx.totalRawBytes >= 65_536L && tx.entries.isNotEmpty()) {
                                    reportConnecting(tx.label, tx.totalRawBytes, tx.fileCount, isSending = true, phase = "Starting 5GHz Wi-Fi Direct…", peerName = macName)
                                    val creds = ensureWifiDirectCreds()
                                    if (creds.isNotEmpty()) {
                                        val credParts = creds.split('\t')
                                        if (credParts.size >= 2) {
                                            var pinnedPeerFingerprint: String? = null
                                            // 1. Attempt version 2 ECDH P-256 negotiation
                                            try {
                                                val ecdhPair = generateEphemeralEcdhKeyPair()
                                                val localPubB64 = Base64.getEncoder().encodeToString(ecdhPair.publicKey.encoded)
                                                val localTlsFp = getLocalTlsFingerprint()
                                                out.write("W2P2\t$localPubB64\t$localTlsFp\n".toByteArray(StandardCharsets.UTF_8))
                                                out.flush()
                                                reportConnecting(tx.label, tx.totalRawBytes, tx.fileCount, isSending = true, phase = "Waiting for $macName to join 5GHz link…", peerName = macName)
                                                val ecdhReply = readBleLineBounded(sock, dis, 22_000L).orEmpty()
                                                if (ecdhReply.startsWith("OK\t")) {
                                                    val replyParts = ecdhReply.removePrefix("OK\t").split('\t')
                                                    if (replyParts.isNotEmpty()) {
                                                        val macPubBytes = Base64.getDecoder().decode(replyParts[0])
                                                        pinnedPeerFingerprint = replyParts.getOrNull(1)?.trim()
                                                        val sessionKey = deriveSessionKey(ecdhPair.privateKey, macPubBytes)
                                                        val encCreds = encryptAesGcm("${credParts[0]}\t${credParts[1]}".toByteArray(StandardCharsets.UTF_8), sessionKey)
                                                        val encB64 = Base64.getEncoder().encodeToString(encCreds)
                                                        out.write("JOIN\t$encB64\n".toByteArray(StandardCharsets.UTF_8))
                                                        out.flush()

                                                        val joinReply = readBleLineBounded(sock, dis, 22_000L).orEmpty()
                                                        if (joinReply.startsWith("OK ")) {
                                                            val macIp = joinReply.removePrefix("OK ").trim()
                                                            if (isValidPeerTransferIp(macIp)) {
                                                                wp2pJoined = true
                                                                if (macIp.startsWith("192.168.49.")) lastMacP2pIp = macIp
                                                                log("Mac ready at $macIp:8772 (TLS pinned: $pinnedPeerFingerprint) — streaming over 5GHz Wi-Fi…")
                                                                txOk = sendOverWifiDirectHttps(macIp, 8772, tx.metaBytes, tx.archiveBytes, tx.entries, tx.url, tx.label, tx.fileCount, pinnedPeerFingerprint)
                                                                runCatching {
                                                                    out.write("DONE".toByteArray(StandardCharsets.US_ASCII))
                                                                    out.flush()
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            } catch (t: Throwable) {
                                                log("Piggyback W2P2 ECDH negotiation failed: ${t.message}")
                                            }

                                            // 2. Fallback to legacy v1 WP2P if v2 did not complete
                                            if (!wp2pJoined) {
                                                out.write("WP2P\t${credParts[0]}\t${credParts[1]}\n".toByteArray(StandardCharsets.UTF_8))
                                                out.flush()
                                                reportConnecting(tx.label, tx.totalRawBytes, tx.fileCount, isSending = true, phase = "Waiting for $macName to join 5GHz link…", peerName = macName)
                                                val replyLine = readBleLineBounded(sock, dis, 22_000L).orEmpty()
                                                if (replyLine.startsWith("OK ")) {
                                                    val macIp = replyLine.removePrefix("OK ").trim()
                                                    if (isValidPeerTransferIp(macIp)) {
                                                        wp2pJoined = true
                                                        if (macIp.startsWith("192.168.49.")) {
                                                            lastMacP2pIp = macIp
                                                        }
                                                        log("Mac ready at $macIp:8772 — streaming over 5GHz Wi-Fi…")
                                                        txOk = sendOverWifiDirectHttps(
                                                            macIp,
                                                            8772,
                                                            tx.metaBytes,
                                                            tx.archiveBytes,
                                                            tx.entries,
                                                            tx.url,
                                                            tx.label,
                                                            tx.fileCount,
                                                            null
                                                        )
                                                        runCatching {
                                                            out.write("DONE".toByteArray(StandardCharsets.US_ASCII))
                                                            out.flush()
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                if (!wp2pJoined && !txOk && !transferCancelled) {
                                    val startedAt = System.currentTimeMillis()
                                    val rawArchBytes = if (tx.archiveBytes.isNotEmpty() && tx.archiveBytes.size <= MAX_ENCRYPTED_BLE_ARCHIVE_BYTES) {
                                        tx.archiveBytes
                                    } else if (tx.entries.isNotEmpty() && tx.totalRawBytes <= MAX_ENCRYPTED_BLE_ARCHIVE_BYTES) {
                                        ByteArrayOutputStream().also { AirDropCodec.writeDvzipCpio(tx.entries, it) }.toByteArray()
                                    } else {
                                        ByteArray(0)
                                    }
                                    if (tx.entries.isNotEmpty() && rawArchBytes.isEmpty()) {
                                        log("5GHz Wi-Fi Direct connection failed — file (${formatBytes(tx.totalRawBytes)}) exceeds BLE fallback limit")
                                    } else {
                                        val encMeta = encryptBlePayload(tx.metaBytes)
                                        val encArch = if (rawArchBytes.isNotEmpty()) encryptBlePayload(rawArchBytes) else ByteArray(0)
                                        val total = encArch.size.toLong().coerceAtLeast(1L)
                                        out.write("ADRE\n".toByteArray(StandardCharsets.US_ASCII))
                                        dos.writeInt(encMeta.size)
                                        dos.writeInt(encArch.size)
                                        dos.write(encMeta)
                                        if (encArch.isNotEmpty()) {
                                            reportProgress(tx.label, 0, 0L, total, startedAt, tx.fileCount, isSending = true)
                                            var off = 0
                                            var lastUpdate = 0L
                                            while (off < encArch.size) {
                                                if (transferCancelled) throw IOException("Transfer cancelled")
                                                val step = minOf(16384, encArch.size - off)
                                                dos.write(encArch, off, step)
                                                off += step
                                                val tNow = System.currentTimeMillis()
                                                if (tNow - lastUpdate >= 100L || off == encArch.size) {
                                                    lastUpdate = tNow
                                                    val pct = ((off.toLong() * 100L) / total).toInt().coerceIn(0, 99)
                                                    reportProgress(tx.label, pct, off.toLong(), total, startedAt, tx.fileCount, isSending = true)
                                                }
                                            }
                                        }
                                        dos.flush()
                                        val ack = ByteArray(4)
                                        val ackTimer = scope.launch(Dispatchers.IO) {
                                            kotlinx.coroutines.delay(20_000L)
                                            runCatching { sock.close() }
                                        }
                                        val n = try {
                                            dis.read(ack)
                                        } finally {
                                            ackTimer.cancel()
                                        }
                                        reportProgress(tx.label, 100, total, total, startedAt, tx.fileCount, isSending = true)
                                        val ackStr = if (n > 0) String(ack, 0, n, StandardCharsets.US_ASCII).trim() else ""
                                        txOk = n > 0 && !ackStr.startsWith("NO") && !transferCancelled
                                        if (txOk) {
                                            val macPeerLabel = (learnedMacName ?: "MacBook Pro")
                                            for (e in tx.entries) {
                                                recordHistoryItem(
                                                    ReceivedItem(
                                                        title = e.name,
                                                        pathOrUrl = e.name,
                                                        isUrl = false,
                                                        sizeBytes = e.size,
                                                        isOutgoing = true,
                                                        peerName = macPeerLabel
                                                    )
                                                )
                                            }
                                            if (tx.url != null) {
                                                recordHistoryItem(
                                                    ReceivedItem(
                                                        title = "Sent Link to $macPeerLabel",
                                                        pathOrUrl = tx.url,
                                                        isUrl = true,
                                                        sizeBytes = tx.url.length.toLong(),
                                                        isOutgoing = true,
                                                        peerName = macPeerLabel
                                                    )
                                                )
                                            }
                                        }
                                        log("BLE L2CAP E2EE TX complete (${formatBytes(rawArchBytes.size.toLong())}, ack=$ackStr, ok=$txOk)")
                                    }
                                }
                            } catch (t: Throwable) {
                                log("BLE piggyback TX warning: ${t.message}")
                            } finally {
                                activeTransferSocket = null
                                _transferProgress.value = null
                                clearProgressNotification()
                                tx.result.complete(txOk)
                            }
                            break
                        }
                    }
                    break
                }
                if (magicStr == "W2P2") {
                    val reqLine = readHttpLine(dis).orEmpty()
                    val rawParts = reqLine.trimStart('\t').split('\t')
                    val parts = rawParts.filter { it.isNotEmpty() }
                    val (macPubB64, macCertFingerprint) = when {
                        parts.size >= 3 && (parts[0] == "2" || parts[0] == "1") -> parts[1] to parts[2]
                        parts.size == 2 && (parts[0] == "2" || parts[0] == "1") -> parts[1] to null
                        parts.size >= 2 -> parts[0] to parts[1]
                        parts.size == 1 -> parts[0] to null
                        else -> "" to null
                    }
                    if (macPubB64.isNotEmpty()) {
                        try {
                            val macPubBytes = Base64.getDecoder().decode(macPubB64)
                            val macCertFingerprint = parts.getOrNull(1)?.trim()
                            reportConnecting(
                                label = "Incoming transfer",
                                total = 0L,
                                fileCount = 1,
                                isSending = false,
                                phase = "Opening 5GHz Wi-Fi Direct link…",
                                peerName = learnedMacName ?: "MacBook Pro"
                            )
                            val creds = ensureWifiDirectCreds()
                            if (creds.isNotEmpty()) {
                                val ecdhPair = generateEphemeralEcdhKeyPair()
                                val sessionKey = deriveSessionKey(ecdhPair.privateKey, macPubBytes)
                                val localTlsFp = getLocalTlsFingerprint()
                                val fullCreds = "$creds\t$localTlsFp"
                                val encCreds = encryptAesGcm(fullCreds.toByteArray(StandardCharsets.UTF_8), sessionKey)
                                val androidPubB64 = Base64.getEncoder().encodeToString(ecdhPair.publicKey.encoded)
                                val encCredsB64 = Base64.getEncoder().encodeToString(encCreds)
                                out.write("OK\t$androidPubB64\t$encCredsB64\n".toByteArray(StandardCharsets.UTF_8))
                                out.flush()
                                reportConnecting(
                                    label = "Incoming transfer",
                                    total = 0L,
                                    fileCount = 1,
                                    isSending = false,
                                    phase = "Waiting for peer to join 5GHz link…",
                                    peerName = learnedMacName ?: "MacBook Pro"
                                )
                                scope.launch {
                                    kotlinx.coroutines.delay(18_000L)
                                    if (_transferProgress.value?.isConnecting == true && activeTransferSocket == null) {
                                        clearProgressNotification()
                                    }
                                }
                                log("BLE W2P2 ECDH handshake with $remoteAddr -> 5GHz P2P Ready (TLS pinned: $macCertFingerprint)")
                                continue
                            }
                        } catch (t: Throwable) {
                            log("BLE W2P2 error with $remoteAddr: ${t.message}")
                        }
                    }
                    out.write("NO\n".toByteArray(StandardCharsets.UTF_8))
                    out.flush()
                    continue
                }
                if (magicStr == "WP2P") {
                    val isAuthorized = (pendingMacTx != null && (pendingMacTx?.targetPeerAddress == null || pendingMacTx?.targetPeerAddress == remoteAddr)) ||
                                       (learnedMacName != null && bleMacDevice?.address == remoteAddr)
                    if (isAuthorized) {
                        reportConnecting(
                            label = "Incoming transfer",
                            total = 0L,
                            fileCount = 1,
                            isSending = false,
                            phase = "Opening 5GHz Wi-Fi Direct link…",
                            peerName = learnedMacName ?: "MacBook Pro"
                        )
                    }
                    val creds = if (isAuthorized) ensureWifiDirectCreds() else ""
                    val reply = if (creds.isNotEmpty()) "OK\t$creds\n" else "NO\n"
                    out.write(reply.toByteArray(StandardCharsets.UTF_8))
                    out.flush()
                    if (creds.isNotEmpty()) {
                        reportConnecting(
                            label = "Incoming transfer",
                            total = 0L,
                            fileCount = 1,
                            isSending = false,
                            phase = "Waiting for peer to join 5GHz link…",
                            peerName = learnedMacName ?: "MacBook Pro"
                        )
                        scope.launch {
                            kotlinx.coroutines.delay(18_000L)
                            if (_transferProgress.value?.isConnecting == true && activeTransferSocket == null) {
                                clearProgressNotification()
                            }
                        }
                    } else if (_transferProgress.value?.isConnecting == true) {
                        clearProgressNotification()
                    }
                    log("BLE WP2P handshake with $remoteAddr -> ${if (creds.isNotEmpty()) "5GHz P2P Ready" else "Rejected/Fallback"}")
                    continue
                }
                val isEncryptedBle = (magicStr == "ADRE")
                if (magicStr != "ADRP" && !isEncryptedBle) {
                    log("BLE L2CAP unknown magic from $remoteAddr: $magicStr")
                    break
                }
                transferCancelled = false
                activeTransferSocket = sock
                val metaLen = dis.readInt()
                val archiveLen = dis.readInt()
                if (!isValidBleFrameBounds(metaLen, archiveLen, isEncryptedBle)) {
                    log("BLE L2CAP rejected invalid frame bounds from $remoteAddr (meta=$metaLen, arch=$archiveLen, e2ee=$isEncryptedBle)")
                    break
                }
                log("BLE L2CAP RX from $remoteAddr (meta=$metaLen B, archive=$archiveLen B, e2ee=$isEncryptedBle)")

                val rawMetaBytes = ByteArray(metaLen)
                dis.readFully(rawMetaBytes)
                val metaBytes = if (isEncryptedBle) decryptBlePayload(rawMetaBytes) else rawMetaBytes
                val askDict = AirDropCodec.decodeBplistDict(metaBytes)
                val sender = askDict["SenderComputerName"]?.toString() ?: "MacBook Pro"
                if (sender.isNotBlank() && sender != "Mac") {
                    learnedMacName = sender
                }
                @Suppress("UNCHECKED_CAST")
                val items = (askDict["Items"] as? List<Any?>).orEmpty()
                @Suppress("UNCHECKED_CAST")
                val files = (askDict["Files"] as? List<Map<String, Any?>>).orEmpty()
                val fileNames = files.mapNotNull { it["FileName"]?.toString() }
                val totalAskBytes = files.sumOf { (it["FileSize"] as? Number)?.toLong() ?: 0L }.let {
                    if (it > 0L) it else archiveLen.toLong()
                }
                val summary = if (fileNames.isNotEmpty()) {
                    "${fileNames.joinToString(", ")} (${formatBytes(totalAskBytes)})"
                } else if (items.isNotEmpty()) {
                    items.joinToString(", ") { it.toString() }
                } else {
                    "AirDrop transfer (${formatBytes(archiveLen.toLong())})"
                }

                val accepted = if (autoAccept) {
                    true
                } else {
                    val deferred = CompletableDeferred<Boolean>()
                    _incomingAsk.value = IncomingAskPrompt(
                        senderName = sender,
                        summary = summary,
                        fileNames = fileNames,
                        totalBytes = totalAskBytes,
                        decision = deferred
                    )
                    try {
                        kotlinx.coroutines.withTimeoutOrNull(45_000L) { deferred.await() } ?: false
                    } finally {
                        _incomingAsk.value = null
                    }
                }

                if (!accepted || transferCancelled) {
                    log("Declined/cancelled BLE transfer from $sender")
                    out.write("NO\r\n".toByteArray(StandardCharsets.US_ASCII))
                    out.flush()
                    break
                }

                for (item in items) {
                    val url = item?.toString() ?: continue
                    if (url.startsWith("http://") || url.startsWith("https://")) {
                        val rec = ReceivedItem(
                            title = "Shared Link from $sender",
                            pathOrUrl = url,
                            isUrl = true,
                            sizeBytes = url.length.toLong(),
                            isOutgoing = false,
                            peerName = sender
                        )
                        recordHistoryItem(rec)
                        onItemReceived?.invoke(rec)
                        log("Saved BLE link from $sender: $url")
                    }
                }

                val fileLabel = fileNames.firstOrNull() ?: "AirDrop file"
                val fileCount = maxOf(1, fileNames.size)

                if (archiveLen > 0) {
                    val downloads = File(
                        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                        "AirDrop"
                    )
                    val startedAt = System.currentTimeMillis()
                    reportProgress(fileLabel, 0, 0L, archiveLen.toLong(), startedAt, fileCount, isSending = false)
                    val bounded = object : InputStream() {
                        private var left = archiveLen
                        private var readSoFar = 0L
                        private var lastUpdateMs = 0L
                        override fun read(): Int {
                            if (transferCancelled) throw IOException("Transfer cancelled")
                            if (left <= 0) return -1
                            val b = dis.read()
                            if (b >= 0) {
                                left--
                                readSoFar++
                            }
                            return b
                        }

                        override fun read(b: ByteArray, off: Int, len: Int): Int {
                            if (transferCancelled) throw IOException("Transfer cancelled")
                            if (left <= 0) return -1
                            val n = dis.read(b, off, minOf(len, left))
                            if (n > 0) {
                                left -= n
                                readSoFar += n
                                val now = System.currentTimeMillis()
                                if (now - lastUpdateMs >= 120L || left == 0) {
                                    lastUpdateMs = now
                                    val pct = ((readSoFar * 100L) / maxOf(1, archiveLen)).toInt().coerceIn(0, 99)
                                    reportProgress(fileLabel, pct, readSoFar, archiveLen.toLong(), startedAt, fileCount, isSending = false)
                                }
                            }
                            return n
                        }
                    }
                    val extracted = try {
                        if (isEncryptedBle) {
                            if (archiveLen.toLong() > MAX_ENCRYPTED_BLE_ARCHIVE_BYTES) {
                                throw IOException("Encrypted BLE archive exceeds 30 MB safe limit: $archiveLen bytes")
                            }
                            val encBuf = ByteArrayOutputStream(archiveLen)
                            bounded.copyTo(encBuf)
                            val decArch = decryptBlePayload(encBuf.toByteArray())
                            AirDropCodec.extractDvzipCpio(decArch.inputStream(), downloads)
                        } else {
                            AirDropCodec.extractDvzipCpio(bounded, downloads)
                        }
                    } finally {
                        reportProgress(fileLabel, 100, archiveLen.toLong(), archiveLen.toLong(), startedAt, fileCount, isSending = false)
                    }
                    for (f in extracted) {
                        MediaScannerConnection.scanFile(context, arrayOf(f.absolutePath), null, null)
                        val rec = ReceivedItem(
                            title = f.name,
                            pathOrUrl = f.absolutePath,
                            isUrl = false,
                            sizeBytes = f.length(),
                            isOutgoing = false,
                            peerName = sender
                        )
                        recordHistoryItem(rec)
                        onItemReceived?.invoke(rec)
                        log("Saved via BLE to Downloads/AirDrop/${f.name} (${formatBytes(f.length())})")
                    }
                }

                out.write("OK\r\n".toByteArray(StandardCharsets.US_ASCII))
                out.flush()
                break
            }
        } catch (t: Throwable) {
            log("BLE L2CAP RX error ($remoteAddr): ${t.message}")
        } finally {
            if (activeTransferSocket === sock) activeTransferSocket = null
            clearProgressNotification()
            try {
                sock.close()
            } catch (_: Throwable) {
            }
        }
    }

    /**
     * Sends files or URLs from Android -> Mac over Direct BLE L2CAP CoC.
     * Pauses BLE scanning during the L2CAP socket connection to prevent HCI LE connection collisions,
     * and retries up to 3 times if the BLE peripheral address rotated.
     */
    @SuppressLint("MissingPermission")
    private suspend fun sendOverBleL2cap(
        entries: List<AirDropCodec.OutgoingEntry>,
        url: String?
    ): Boolean = withContext(Dispatchers.IO) {
        transferMutex.withLock {
            acquireTransferLocks()
            transferCancelled = false
            try {
                val fileDicts = entries.map { e ->
                    mapOf(
                        "FileName" to e.name,
                        "FileType" to AirDropCodec.utiForName(e.name),
                        "FileSize" to e.size,
                        "FileBomPath" to "./${e.name}",
                        "FileIsDirectory" to false
                    )
                }
                val metaBytes = AirDropCodec.encodeBplist(
                    mapOf(
                        "SenderComputerName" to deviceName,
                        "SenderModelName" to deviceModel,
                        "SenderID" to serviceId,
                        "Items" to if (url != null) listOf(url) else emptyList<Any>(),
                        "Files" to fileDicts
                    )
                )
                val totalRawBytes = entries.sumOf { it.size }
                val archiveBytes = if (entries.isNotEmpty() && totalRawBytes < 65_536L) {
                    val bos = ByteArrayOutputStream()
                    AirDropCodec.writeDvzipCpio(entries, bos)
                    bos.toByteArray()
                } else {
                    ByteArray(0)
                }

                val label = if (entries.isNotEmpty()) {
                    formatMultiFileDisplayLabel(entries.first().name, entries.size)
                } else {
                    url ?: "BLE Transfer"
                }
                val fileCount = maxOf(1, entries.size)
                val targetPeerLabel = learnedMacName ?: "MacBook Pro"

                // Pre-warm 5GHz Wi-Fi Direct group concurrently with BLE handshake so SSID/passphrase are ready immediately
                if (totalRawBytes >= 65_536L && entries.isNotEmpty() && wifiDirectCreds.isEmpty()) {
                    wifiTeardownJob?.cancel()
                    startWifiDirectGroup()
                }

                // 1. Fast path: if Mac is already joined to our 5GHz Wi-Fi Direct group, stream directly at 5GHz speed!
                val cachedIp = lastMacP2pIp
                if (cachedIp.startsWith("192.168.49.")) {
                    reportConnecting(label, totalRawBytes, fileCount, isSending = true, phase = "Connecting over 5GHz Wi-Fi Direct…", peerName = targetPeerLabel)
                    log("Streaming directly over active 5GHz Wi-Fi Direct link ($cachedIp:8772)…")
                    if (sendOverWifiDirectHttps(cachedIp, 8772, metaBytes, archiveBytes, entries, url, label, fileCount)) {
                        return@withLock true
                    }
                    lastMacP2pIp = ""
                }

                // 2. Queue transfer for Mac's 1.5s BLE L2CAP heartbeat (works even when Android BLE scan is blocked by OS Location toggle)
                reportConnecting(label, totalRawBytes, fileCount, isSending = true, phase = "Connecting via Bluetooth LE…", peerName = targetPeerLabel)
                val deferred = CompletableDeferred<Boolean>()
                val targetAddr = bleMacDevice?.address
                val tx = PendingMacTx(
                    metaBytes = metaBytes,
                    archiveBytes = archiveBytes,
                    entries = entries,
                    url = url,
                    label = label,
                    fileCount = fileCount,
                    totalRawBytes = totalRawBytes,
                    result = deferred,
                    targetPeerAddress = targetAddr
                )
                pendingMacTx = tx
                log("Queued transfer for Mac BLE L2CAP P2P channel\u2026")

                // Wait one heartbeat window (2.2s) if we already scanned the peer's PSM so we can connect directly without delay;
                // otherwise wait full 12s for passive BLE heartbeat pickup.
                val initialHeartbeatWaitMs = if (bleMacDevice != null && bleMacPsm > 0) 2_200L else 12_000L
                var waitedMs = 0L
                while (waitedMs < initialHeartbeatWaitMs && !deferred.isCompleted && !tx.claimed && !transferCancelled) {
                    kotlinx.coroutines.delay(100)
                    waitedMs += 100
                }
                if (transferCancelled) {
                    pendingMacTx = null
                    return@withLock false
                }
                if (deferred.isCompleted || tx.claimed) {
                    return@withLock deferred.await()
                }

                // 4. Fallback: if Mac heartbeat did not arrive within 12s and we have a scanned BLE peripheral, try direct L2CAP
                val dev = bleMacDevice
                val psm = bleMacPsm
                if (dev != null && psm > 0 && !tx.claimed) {
                    pendingMacTx = null
                    var lastErr: Throwable? = null
                    for (attempt in 1..2) {
                        if (transferCancelled) return@withLock false
                        val targetDev = bleMacDevice ?: dev
                        val targetPsm = if (bleMacPsm > 0) bleMacPsm else psm
                        stopBleScanOnly()
                        kotlinx.coroutines.delay(80)
                        try {
                            reportConnecting(label, totalRawBytes, fileCount, isSending = true, phase = "Connecting via Bluetooth LE…", peerName = targetPeerLabel)
                            log("Connecting to Mac via Direct BLE L2CAP (${targetDev.address} PSM $targetPsm, attempt $attempt)\u2026")
                            targetDev.createInsecureL2capChannel(targetPsm).use { sock ->
                                activeTransferSocket = sock
                                sock.connect()
                                val dos = DataOutputStream(BufferedOutputStream(sock.outputStream, 65536))
                                val inp = sock.inputStream

                                if (totalRawBytes >= 65_536L && entries.isNotEmpty()) {
                                    reportConnecting(label, totalRawBytes, fileCount, isSending = true, phase = "Starting 5GHz Wi-Fi Direct…", peerName = targetPeerLabel)
                                    val creds = ensureWifiDirectCreds()
                                    if (creds.isNotEmpty()) {
                                        val credParts = creds.split('\t')
                                        if (credParts.size >= 2) {
                                            var pinnedPeerFingerprint: String? = null
                                            // 1. Attempt version 2 ECDH P-256 negotiation
                                            try {
                                                val ecdhPair = generateEphemeralEcdhKeyPair()
                                                val localPubB64 = Base64.getEncoder().encodeToString(ecdhPair.publicKey.encoded)
                                                val localTlsFp = getLocalTlsFingerprint()
                                                val w2p2Payload = "2\t$localPubB64\t$localTlsFp".toByteArray(StandardCharsets.UTF_8)
                                                dos.write("W2P2".toByteArray(StandardCharsets.US_ASCII))
                                                dos.writeInt(w2p2Payload.size)
                                                dos.writeInt(0)
                                                dos.write(w2p2Payload)
                                                dos.flush()

                                                reportConnecting(label, totalRawBytes, fileCount, isSending = true, phase = "Waiting for $targetPeerLabel to join 5GHz link…", peerName = targetPeerLabel)
                                                val ecdhReply = readBleLineBounded(sock, inp, 22_000L).orEmpty()
                                                if (ecdhReply.startsWith("OK\t")) {
                                                    val replyParts = ecdhReply.removePrefix("OK\t").split('\t')
                                                    if (replyParts.isNotEmpty()) {
                                                        val macPubBytes = Base64.getDecoder().decode(replyParts[0])
                                                        pinnedPeerFingerprint = replyParts.getOrNull(1)?.trim()
                                                        val sessionKey = deriveSessionKey(ecdhPair.privateKey, macPubBytes)
                                                        val encCreds = encryptAesGcm("${credParts[0]}\t${credParts[1]}".toByteArray(StandardCharsets.UTF_8), sessionKey)
                                                        val encB64 = Base64.getEncoder().encodeToString(encCreds)
                                                        dos.write("JOIN\t$encB64\n".toByteArray(StandardCharsets.UTF_8))
                                                        dos.flush()

                                                        val joinReply = readBleLineBounded(sock, inp, 22_000L).orEmpty()
                                                        if (joinReply.startsWith("OK ")) {
                                                            val macIp = joinReply.removePrefix("OK ").trim()
                                                            if (isValidPeerTransferIp(macIp)) {
                                                                if (macIp.startsWith("192.168.49.")) lastMacP2pIp = macIp
                                                                log("Mac ready at $macIp:8772 (TLS pinned: $pinnedPeerFingerprint) — streaming over 5GHz Wi-Fi…")
                                                                val p2pOk = sendOverWifiDirectHttps(macIp, 8772, metaBytes, archiveBytes, entries, url, label, fileCount, pinnedPeerFingerprint)
                                                                runCatching {
                                                                    dos.write("DONE".toByteArray(StandardCharsets.US_ASCII))
                                                                    dos.flush()
                                                                }
                                                                return@withLock p2pOk
                                                            }
                                                        }
                                                    }
                                                }
                                            } catch (t: Throwable) {
                                                log("Direct W2P2 ECDH negotiation failed: ${t.message}")
                                            }

                                            // 2. Fallback to legacy v1 WP2P
                                            val wp2pPayload = "${credParts[0]}\t${credParts[1]}".toByteArray(StandardCharsets.UTF_8)
                                            dos.write("WP2P".toByteArray(StandardCharsets.US_ASCII))
                                            dos.writeInt(wp2pPayload.size)
                                            dos.writeInt(0)
                                            dos.write(wp2pPayload)
                                            dos.flush()

                                            reportConnecting(label, totalRawBytes, fileCount, isSending = true, phase = "Waiting for $targetPeerLabel to join 5GHz link…", peerName = targetPeerLabel)
                                            val replyLine = readBleLineBounded(sock, inp, 22_000L).orEmpty()
                                            if (replyLine.startsWith("OK ")) {
                                                val macIp = replyLine.removePrefix("OK ").trim()
                                                if (isValidPeerTransferIp(macIp)) {
                                                    if (macIp.startsWith("192.168.49.")) {
                                                        lastMacP2pIp = macIp
                                                    }
                                                    log("Mac ready at $macIp:8772 — streaming over 5GHz Wi-Fi…")
                                                    val p2pOk = sendOverWifiDirectHttps(macIp, 8772, metaBytes, archiveBytes, entries, url, label, fileCount, null)
                                                    runCatching {
                                                        dos.write("DONE".toByteArray(StandardCharsets.US_ASCII))
                                                        dos.flush()
                                                    }
                                                    return@withLock p2pOk
                                                }
                                            }
                                            log("WP2P negotiation declined or failed, falling back to direct BLE L2CAP")
                                        }
                                    }
                                }

                                val startedAt = System.currentTimeMillis()
                                val rawArchBytes = if (archiveBytes.isNotEmpty() && archiveBytes.size <= MAX_ENCRYPTED_BLE_ARCHIVE_BYTES) {
                                    archiveBytes
                                } else if (entries.isNotEmpty() && totalRawBytes <= MAX_ENCRYPTED_BLE_ARCHIVE_BYTES) {
                                    ByteArrayOutputStream().also { AirDropCodec.writeDvzipCpio(entries, it) }.toByteArray()
                                } else {
                                    ByteArray(0)
                                }
                                if (entries.isNotEmpty() && rawArchBytes.isEmpty()) {
                                    log("5GHz Wi-Fi Direct connection failed — file (${formatBytes(totalRawBytes)}) exceeds BLE fallback limit")
                                    return@withLock false
                                }
                                val encMeta = encryptBlePayload(metaBytes)
                                val encArch = if (rawArchBytes.isNotEmpty()) encryptBlePayload(rawArchBytes) else ByteArray(0)
                                val encTotal = encArch.size.toLong().coerceAtLeast(1L)
                                dos.write("ADRE".toByteArray(StandardCharsets.US_ASCII))
                                dos.writeInt(encMeta.size)
                                dos.writeInt(encArch.size)
                                dos.write(encMeta)
                                if (encArch.isNotEmpty()) {
                                    reportProgress(label, 0, 0L, encTotal, startedAt, fileCount, isSending = true)
                                    var off = 0
                                    var lastUpdate = 0L
                                    while (off < encArch.size) {
                                        if (transferCancelled) throw IOException("Transfer cancelled")
                                        val step = minOf(16384, encArch.size - off)
                                        dos.write(encArch, off, step)
                                        off += step
                                        val now = System.currentTimeMillis()
                                        if (now - lastUpdate >= 100L || off == encArch.size) {
                                            lastUpdate = now
                                            val pct = ((off.toLong() * 100L) / encTotal).toInt().coerceIn(0, 99)
                                            reportProgress(label, pct, off.toLong(), encTotal, startedAt, fileCount, isSending = true)
                                        }
                                    }
                                }
                                dos.flush()
                                val ack = ByteArray(4)
                                val ackTimer = scope.launch(Dispatchers.IO) {
                                    kotlinx.coroutines.delay(20_000L)
                                    runCatching { sock.close() }
                                }
                                val n = try {
                                    inp.read(ack)
                                } finally {
                                    ackTimer.cancel()
                                }
                                reportProgress(label, 100, encTotal, encTotal, startedAt, fileCount, isSending = true)
                                val ackStr = if (n > 0) String(ack, 0, n, StandardCharsets.US_ASCII).trim() else ""
                                val ok = n > 0 && !ackStr.startsWith("NO") && !transferCancelled
                                if (ok) {
                                    val macPeerLabel = (learnedMacName ?: "MacBook Pro")
                                    for (e in entries) {
                                        recordHistoryItem(
                                            ReceivedItem(
                                                title = e.name,
                                                pathOrUrl = e.name,
                                                isUrl = false,
                                                sizeBytes = e.size,
                                                isOutgoing = true,
                                                peerName = macPeerLabel
                                            )
                                        )
                                    }
                                    if (url != null) {
                                        recordHistoryItem(
                                            ReceivedItem(
                                                title = "Sent Link to $macPeerLabel",
                                                pathOrUrl = url,
                                                isUrl = true,
                                                sizeBytes = url.length.toLong(),
                                                isOutgoing = true,
                                                peerName = macPeerLabel
                                            )
                                        )
                                    }
                                }
                                log("BLE L2CAP E2EE TX complete (${formatBytes(rawArchBytes.size.toLong())}, ack=$ackStr, ok=$ok)")
                                return@withLock ok
                            }
                        } catch (t: Throwable) {
                            lastErr = t
                            _transferProgress.value = null
                            log("BLE L2CAP attempt $attempt warning: ${t.message}")
                            if (attempt < 2 && !transferCancelled) {
                                restartBleScanOnly()
                                kotlinx.coroutines.delay(350)
                            }
                        } finally {
                            activeTransferSocket = null
                        }
                    }
                    log("BLE L2CAP direct warning: ${lastErr?.message}")
                }

                // Wait remaining window for Mac BLE L2CAP heartbeat pickup
                if (!tx.claimed && !deferred.isCompleted) {
                    pendingMacTx = tx
                }
                while (waitedMs < 14_000L && !deferred.isCompleted && !tx.claimed && !transferCancelled) {
                    kotlinx.coroutines.delay(150)
                    waitedMs += 150
                }
                if (pendingMacTx === tx && !tx.claimed) {
                    pendingMacTx = null
                }
                if (transferCancelled) return@withLock false
                if (deferred.isCompleted || tx.claimed) {
                    return@withLock deferred.await()
                }
                log("BLE L2CAP: Mac peer did not respond in time")
                return@withLock false
            } catch (t: Throwable) {
                log("Send error: ${t.message}")
                return@withLock false
            } finally {
                releaseTransferLocks()
                activeTransferSocket = null
                _transferProgress.value = null
                clearProgressNotification()
                if (_running.value && bleScanCallback == null) {
                    restartBleScanOnly()
                }
            }
        }
    }

    private fun sendOverWifiDirectHttps(
        host: String,
        port: Int,
        metaBytes: ByteArray,
        archiveBytes: ByteArray,
        entries: List<AirDropCodec.OutgoingEntry>,
        url: String?,
        label: String,
        fileCount: Int,
        pinnedFingerprint: String? = null
    ): Boolean {
        acquireTransferLocks()
        wifiTeardownJob?.cancel()
        var keepAliveJob: Job? = null
        var writeWatchdogJob: Job? = null
        var txSuccess = false
        return try {
            val sslCtx = sslContext
            var rawSock: Socket? = null
            var lastConnErr: Throwable? = null
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val isP2pTarget = host.startsWith("192.168.49.")
            val p2pNetwork = if (isP2pTarget) {
                cm?.allNetworks?.firstOrNull { net ->
                    val caps = cm.getNetworkCapabilities(net)
                    caps != null && (
                        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_WIFI_P2P) ||
                        cm.getLinkProperties(net)?.linkAddresses?.any { it.address.hostAddress?.startsWith("192.168.49.") == true } == true
                    )
                }
            } else {
                null
            }
            val totalPlannedBytes = entries.sumOf { it.size }
            reportConnecting(
                label = label,
                total = totalPlannedBytes,
                fileCount = fileCount,
                isSending = true,
                phase = "Opening 5GHz TLS channel…",
                peerName = learnedMacName ?: "MacBook Pro"
            )
            for (attempt in 1..10) {
                if (transferCancelled) return false
                try {
                    val candidate = Socket()
                    runCatching {
                        candidate.tcpNoDelay = true
                        candidate.keepAlive = true
                        candidate.sendBufferSize = 4_194_304
                        candidate.receiveBufferSize = 4_194_304
                    }
                    if (isP2pTarget) {
                        p2pNetwork?.bindSocket(candidate)
                    }
                    candidate.connect(InetSocketAddress(host, port), 2500)
                    rawSock = candidate
                    break
                } catch (e: Throwable) {
                    lastConnErr = e
                    Thread.sleep(300)
                }
            }
            val connectedRaw = rawSock ?: throw (lastConnErr ?: IOException("Could not connect to $host:$port"))
            connectedRaw.use { raw ->
                activeTransferSocket = raw
                raw.soTimeout = 60_000
                raw.tcpNoDelay = true
                raw.keepAlive = true
                runCatching {
                    raw.sendBufferSize = 4_194_304
                    raw.receiveBufferSize = 4_194_304
                }

                // Launch active ARP keepalive coroutine during 5GHz Wi-Fi Direct transfers
                // Bound to p2pNetwork so pulses egress on p2p-wlan0-* rather than wlan0
                if (isP2pTarget) {
                    keepAliveJob = scope.launch(Dispatchers.IO) {
                        DatagramSocket().use { udpSock ->
                            runCatching { p2pNetwork?.bindSocket(udpSock) }
                            val dummy = byteArrayOf(0xAD.toByte())
                            val targetAddr = InetAddress.getByName(host)
                            while (isActive && activeTransferSocket != null && !transferCancelled) {
                                runCatching { udpSock.send(DatagramPacket(dummy, 1, targetAddr, 8774)) }
                                kotlinx.coroutines.delay(2000)
                            }
                        }
                    }
                }
                (sslCtx.socketFactory.createSocket(raw, host, port, true) as SSLSocket).use { tls ->
                    activeTransferSocket = tls
                    configureHighThroughputTls(tls)
                    tls.startHandshake()
                    if (!pinnedFingerprint.isNullOrBlank()) {
                        val peerCerts = tls.session.peerCertificates
                        val serverCert = peerCerts.firstOrNull() as? X509Certificate
                            ?: throw SSLPeerUnverifiedException("No server certificate presented by $host:$port")
                        val sha256 = MessageDigest.getInstance("SHA-256").digest(serverCert.encoded)
                        val actualFp = sha256.joinToString("") { "%02x".format(it) }.lowercase()
                        val expectedFp = pinnedFingerprint.replace(":", "").replace("-", "").trim().lowercase()
                        if (actualFp != expectedFp) {
                            log("FATAL: TLS certificate fingerprint pinning mismatch! Expected: $expectedFp, Actual: $actualFp")
                            throw SSLPeerUnverifiedException("Certificate fingerprint pinning failed! Expected $expectedFp, got $actualFp")
                        }
                        log("TLS certificate fingerprint pinned and verified: $actualFp")
                    }
                    val inp = BufferedInputStream(tls.inputStream, 65536)
                    val rawOut = tls.outputStream

                    // 1. /Ask
                    reportConnecting(
                        label = label,
                        total = totalPlannedBytes,
                        fileCount = fileCount,
                        isSending = true,
                        phase = "Waiting for receiver approval…",
                        peerName = learnedMacName ?: "MacBook Pro"
                    )
                    val askHdr = buildString {
                        append("POST /Ask HTTP/1.1\r\n")
                        append("Host: $host:$port\r\n")
                        append("Content-Type: application/octet-stream\r\n")
                        append("Content-Length: ${metaBytes.size}\r\n")
                        append("Connection: keep-alive\r\n\r\n")
                    }
                    rawOut.write(askHdr.toByteArray(StandardCharsets.US_ASCII))
                    rawOut.write(metaBytes)
                    rawOut.flush()

                    val askStatus = readHttpLine(inp).orEmpty()
                    val askHeaders = LinkedHashMap<String, String>()
                    while (true) {
                        val l = readHttpLine(inp) ?: break
                        if (l.isEmpty()) break
                        val c = l.indexOf(':')
                        if (c > 0) askHeaders[l.substring(0, c).trim().lowercase()] = l.substring(c + 1).trim()
                    }
                    readHttpBodyBytes(inp, askHeaders)
                    if (!askStatus.contains("200") || transferCancelled) return false

                    // 2. /Upload — Stream directly from source files over HTTP chunked encoding (zero OOM even for multi-GB files)
                    if (entries.isNotEmpty()) {
                        raw.soTimeout = 30_000
                        val lastWriteActivityMs = java.util.concurrent.atomic.AtomicLong(System.currentTimeMillis())
                        writeWatchdogJob = scope.launch(Dispatchers.IO) {
                            while (isActive) {
                                kotlinx.coroutines.delay(1000)
                                val idleMs = System.currentTimeMillis() - lastWriteActivityMs.get()
                                if (transferCancelled || idleMs > 25_000L) {
                                    if (!transferCancelled) {
                                        log("5GHz P2P write stall timeout (${idleMs / 1000}s) — aborting stuck socket")
                                    }
                                    runCatching { tls.close() }
                                    runCatching { raw.close() }
                                    break
                                }
                            }
                        }

                        val startedAt = System.currentTimeMillis()
                        val total = entries.sumOf { it.size }.coerceAtLeast(1L)
                        val upHdr = buildString {
                            append("POST /Upload HTTP/1.1\r\n")
                            append("Host: $host:$port\r\n")
                            append("Content-Type: application/x-dvzip\r\n")
                            append("TotalBytes: $total\r\n")
                            append("Transfer-Encoding: chunked\r\n")
                            append("Connection: keep-alive\r\n\r\n")
                        }
                        rawOut.write(upHdr.toByteArray(StandardCharsets.US_ASCII))
                        rawOut.flush()
                        lastWriteActivityMs.set(System.currentTimeMillis())
                        reportProgress(label, 0, 0L, total, startedAt, fileCount, isSending = true)
                        var lastUpdate = 0L

                        // Contiguous 1 MiB chunk buffer: 16 bytes reserved for hex prefix + 1048576 bytes data + 2 bytes CRLF
                        // Emits entire 1 MiB HTTP chunk in ONE socket write, maximizing 5GHz Wi-Fi Direct A-MPDU aggregation
                        val chunkCap = 1_048_576
                        val flushThreshold = 4_194_304
                        val chunkBuffer = ByteArray(16 + chunkCap + 2)
                        val dataOffset = 16
                        var buffered = 0

                        fun flushChunk() {
                            if (buffered <= 0) return
                            if (transferCancelled) throw IOException("Transfer cancelled")
                            val hex = buffered.toString(16) + "\r\n"
                            val hexBytes = hex.toByteArray(StandardCharsets.US_ASCII)
                            val start = dataOffset - hexBytes.size
                            System.arraycopy(hexBytes, 0, chunkBuffer, start, hexBytes.size)
                            chunkBuffer[dataOffset + buffered] = '\r'.code.toByte()
                            chunkBuffer[dataOffset + buffered + 1] = '\n'.code.toByte()
                            val totalLen = hexBytes.size + buffered + 2
                            lastWriteActivityMs.set(System.currentTimeMillis())
                            rawOut.write(chunkBuffer, start, totalLen)
                            lastWriteActivityMs.set(System.currentTimeMillis())
                            buffered = 0
                        }

                        val chunkedOut = object : OutputStream() {
                            private var bytesSinceFlush = 0

                            override fun write(b: Int) {
                                chunkBuffer[dataOffset + buffered++] = b.toByte()
                                if (buffered == chunkCap) {
                                    flushChunk()
                                    bytesSinceFlush += chunkCap
                                    if (bytesSinceFlush >= flushThreshold) {
                                        lastWriteActivityMs.set(System.currentTimeMillis())
                                        rawOut.flush()
                                        lastWriteActivityMs.set(System.currentTimeMillis())
                                        bytesSinceFlush = 0
                                    }
                                }
                            }

                            override fun write(b: ByteArray, off: Int, len: Int) {
                                var o = off
                                var rem = len
                                while (rem > 0) {
                                    val take = minOf(rem, chunkCap - buffered)
                                    System.arraycopy(b, o, chunkBuffer, dataOffset + buffered, take)
                                    buffered += take
                                    o += take
                                    rem -= take
                                    if (buffered == chunkCap) {
                                        flushChunk()
                                        bytesSinceFlush += chunkCap
                                        if (bytesSinceFlush >= flushThreshold) {
                                            lastWriteActivityMs.set(System.currentTimeMillis())
                                            rawOut.flush()
                                            lastWriteActivityMs.set(System.currentTimeMillis())
                                            bytesSinceFlush = 0
                                        }
                                    }
                                }
                            }

                            override fun flush() {
                                flushChunk()
                                lastWriteActivityMs.set(System.currentTimeMillis())
                                rawOut.flush()
                                lastWriteActivityMs.set(System.currentTimeMillis())
                                bytesSinceFlush = 0
                            }

                            override fun close() {
                                flushChunk()
                                lastWriteActivityMs.set(System.currentTimeMillis())
                                rawOut.write("0\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
                                rawOut.flush()
                                lastWriteActivityMs.set(System.currentTimeMillis())
                            }
                        }
                        AirDropCodec.writeDvzipCpio(entries, chunkedOut) { doneBytes ->
                            if (transferCancelled) throw IOException("Transfer cancelled")
                            val now = System.currentTimeMillis()
                            if (now - lastUpdate >= 350L || doneBytes >= total) {
                                lastUpdate = now
                                val pct = ((doneBytes * 100L) / total).toInt().coerceIn(0, 99)
                                reportProgress(label, pct, minOf(doneBytes, total), total, startedAt, fileCount, isSending = true)
                            }
                        }
                        chunkedOut.close()
                        writeWatchdogJob?.cancel()
                        val upStatus = readHttpLine(inp).orEmpty()
                        reportProgress(label, 100, total, total, startedAt, fileCount, isSending = true)
                        if (!upStatus.contains("200") || transferCancelled) return false
                    }

                    val macPeerLabel = (learnedMacName ?: "MacBook Pro")
                    for (e in entries) {
                        recordHistoryItem(
                            ReceivedItem(
                                title = e.name,
                                pathOrUrl = e.name,
                                isUrl = false,
                                sizeBytes = e.size,
                                isOutgoing = true,
                                peerName = macPeerLabel
                            )
                        )
                    }
                    if (url != null) {
                        recordHistoryItem(
                            ReceivedItem(
                                title = "Sent Link to $macPeerLabel",
                                pathOrUrl = url,
                                isUrl = true,
                                sizeBytes = url.length.toLong(),
                                isOutgoing = true,
                                peerName = macPeerLabel
                            )
                        )
                    }
                    txSuccess = true
                    true
                }
            }
        } catch (t: Throwable) {
            log("5GHz Wi-Fi Direct HTTPS fallback: ${t.message}")
            false
        } finally {
            writeWatchdogJob?.cancel()
            keepAliveJob?.cancel()
            _transferProgress.value = null
            clearProgressNotification()
            releaseTransferLocks()
            activeTransferSocket = null
            lastMacP2pIp = ""
            // Tear down ephemeral 5GHz Wi-Fi Direct group immediately if cancelled or failed, or after grace period on success
            if (host.startsWith("192.168.49.")) {
                wifiTeardownJob?.cancel()
                if (transferCancelled || !txSuccess) {
                    stopWifiDirectGroup()
                } else {
                    wifiTeardownJob = scope.launch {
                        kotlinx.coroutines.delay(5000)
                        if (!isTransferInProgress) {
                            stopWifiDirectGroup()
                        }
                    }
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun stopBleWake() {
        stopBleAdvertisingOnly()
        stopBleScanOnly()
        try {
            l2capServer?.close()
        } catch (_: Throwable) {
        }
        try {
            gattServer?.close()
        } catch (_: Throwable) {
        }
        bleAdvertiser = null
        bleScanner = null
        l2capServer = null
        localBlePsm = 0
        gattServer = null
    }

    // =========================================================================
    // 5 GHz Wi-Fi Direct P2P HTTPS Receiver (/Discover, /Ask, /Upload) on :8771
    // =========================================================================

    private fun configureHighThroughputTls(tls: SSLSocket) {
        runCatching {
            val supportedProtos = tls.supportedProtocols.orEmpty()
            val desiredProtos = listOf("TLSv1.3", "TLSv1.2").filter { it in supportedProtos }
            if (desiredProtos.isNotEmpty()) {
                tls.enabledProtocols = desiredProtos.toTypedArray()
            }
            val currentSuites = tls.enabledCipherSuites ?: return@runCatching
            val fastSuite = "TLS_AES_128_GCM_SHA256"
            if (fastSuite in currentSuites && currentSuites.firstOrNull() != fastSuite) {
                tls.enabledCipherSuites = (listOf(fastSuite) + currentSuites.filter { it != fastSuite }).toTypedArray()
            }
        }
    }

    private fun startHttpsReceiver() {
        scope.launch {
            try {
                val srv = sslContext.serverSocketFactory
                    .createServerSocket() as SSLServerSocket
                srv.reuseAddress = true
                runCatching { srv.receiveBufferSize = 4_194_304 }
                srv.bind(InetSocketAddress(AIRDROP_PORT), 32)
                srv.wantClientAuth = true
                srv.needClientAuth = false
                serverSocket = srv
                log("5GHz P2P HTTPS receiver listening on port $AIRDROP_PORT")
                while (_running.value) {
                    val client = try {
                        srv.accept() as SSLSocket
                    } catch (e: Throwable) {
                        if (srv.isClosed || !_running.value) break
                        log("Receiver accept error (recovering): ${e.message}")
                        kotlinx.coroutines.delay(100)
                        continue
                    }
                    scope.launch { handleReceiverConnection(client) }
                }
            } catch (t: Throwable) {
                log("Receiver error: ${t.message}")
            }
        }
    }

    private suspend fun handleReceiverConnection(sock: SSLSocket) = withContext(Dispatchers.IO) {
        val remoteIp = sock.inetAddress?.hostAddress.orEmpty()
        if (!remoteIp.startsWith("192.168.49.") && remoteIp != "127.0.0.1" && remoteIp != "::1" && !remoteIp.endsWith(":127.0.0.1")) {
            log("Rejecting non-P2P incoming connection from $remoteIp")
            runCatching { sock.close() }
            return@withContext
        }
        if (remoteIp.startsWith("192.168.49.")) {
            lastMacP2pIp = remoteIp
        }
        val remote = "$remoteIp:${sock.port}"
        var didUpload = false
        try {
            sock.soTimeout = 30_000
            sock.tcpNoDelay = true
            sock.keepAlive = true
            runCatching {
                sock.receiveBufferSize = 4_194_304
                sock.sendBufferSize = 4_194_304
            }
            configureHighThroughputTls(sock)
            sock.startHandshake()
            val inp = BufferedInputStream(sock.inputStream, 1_048_576)
            val out = BufferedOutputStream(sock.outputStream, 65536)
            var lastSenderName = "MacBook Pro"
            var lastAskLabel = "Incoming AirDrop"
            var lastAskFileCount = 1
            var lastAskTotalBytes = 0L
            var connectionAskApproved = false

            while (_running.value) {
                val reqLine = readHttpLine(inp) ?: break
                if (reqLine.isEmpty()) continue
                val parts = reqLine.split(' ')
                if (parts.size < 2) break
                val method = parts[0]
                val path = parts[1]

                val headers = LinkedHashMap<String, String>()
                while (true) {
                    val line = readHttpLine(inp) ?: break
                    if (line.isEmpty()) break
                    val colon = line.indexOf(':')
                    if (colon > 0) {
                        headers[line.substring(0, colon).trim().lowercase()] =
                            line.substring(colon + 1).trim()
                    }
                }

                if (headers["expect"]?.equals("100-continue", ignoreCase = true) == true) {
                    out.write("HTTP/1.1 100 Continue\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
                    out.flush()
                }

                log("RX $method $path from $remote")
                when {
                    method == "GET" || method == "HEAD" -> {
                        writeHttpResponse(out, 200, "OK", ByteArray(0))
                    }
                    method == "POST" && path == "/Discover" -> {
                        readHttpBodyBytes(inp, headers)
                        reportConnecting(
                            label = "Incoming transfer",
                            total = 0L,
                            fileCount = 1,
                            isSending = false,
                            phase = "Handshaking over 5GHz Wi-Fi Direct…",
                            peerName = learnedMacName ?: "MacBook Pro"
                        )
                        val resp = AirDropCodec.encodeBplist(
                            mapOf(
                                "ReceiverComputerName" to deviceName,
                                "ReceiverModelName" to deviceModel,
                                "ReceiverMediaCapabilities" to AirDropCodec.MEDIA_CAPABILITIES_BYTES,
                                "IsAirDropable" to true
                            )
                        )
                        writeHttpResponse(out, 200, "OK", resp)
                    }
                    method == "POST" && path == "/Ask" -> {
                        transferCancelled = false
                        activeTransferSocket = sock
                        val bodyBytes = readHttpBodyBytes(inp, headers)
                        val askDict = AirDropCodec.decodeBplistDict(bodyBytes)
                        val sender = askDict["SenderComputerName"]?.toString() ?: "MacBook Pro"
                        lastSenderName = sender
                        if (sender.isNotBlank()) learnedMacName = sender
                        @Suppress("UNCHECKED_CAST")
                        val files = (askDict["Files"] as? List<Map<String, Any?>>).orEmpty()
                        @Suppress("UNCHECKED_CAST")
                        val items = (askDict["Items"] as? List<Any?>).orEmpty()

                        val fileNames = files.mapNotNull { it["FileName"]?.toString() }
                        val totalAskBytes = files.sumOf { (it["FileSize"] as? Number)?.toLong() ?: 0L }
                        lastAskLabel = fileNames.firstOrNull() ?: "Incoming AirDrop"
                        lastAskFileCount = maxOf(1, fileNames.size)
                        lastAskTotalBytes = totalAskBytes

                        val summary = if (files.isNotEmpty()) {
                            files.joinToString(", ") { f ->
                                val sz = (f["FileSize"] as? Number)?.toLong() ?: 0L
                                "${f["FileName"] ?: "file"} (${formatBytes(sz)})"
                            }
                        } else if (items.isNotEmpty()) {
                            items.joinToString(", ") { it.toString() }
                        } else {
                            "AirDrop item"
                        }

                        log("ASK from $sender: $summary")
                        reportConnecting(
                            label = lastAskLabel,
                            total = totalAskBytes,
                            fileCount = lastAskFileCount,
                            isSending = false,
                            phase = if (autoAccept) "Starting incoming stream…" else "Waiting for your approval…",
                            peerName = sender
                        )
                        val accepted = if (autoAccept) {
                            true
                        } else {
                            val deferred = CompletableDeferred<Boolean>()
                            _incomingAsk.value = IncomingAskPrompt(
                                senderName = sender,
                                summary = summary,
                                fileNames = fileNames,
                                totalBytes = totalAskBytes,
                                decision = deferred
                            )
                            try {
                                kotlinx.coroutines.withTimeoutOrNull(45_000L) { deferred.await() } ?: false
                            } finally {
                                _incomingAsk.value = null
                            }
                        }

                        if (!accepted || transferCancelled) {
                            log("Declined transfer from $sender")
                            didUpload = true
                            writeHttpResponse(out, 403, "Forbidden", ByteArray(0), close = true)
                            break
                        }
                        connectionAskApproved = true

                        for (item in items) {
                            val url = item?.toString() ?: continue
                            if (url.startsWith("http://") || url.startsWith("https://")) {
                                val rec = ReceivedItem(
                                    title = "Shared Link from $sender",
                                    pathOrUrl = url,
                                    isUrl = true,
                                    sizeBytes = url.length.toLong(),
                                    isOutgoing = false,
                                    peerName = sender
                                )
                                recordHistoryItem(rec)
                                onItemReceived?.invoke(rec)
                                log("Stored link from $sender: $url")
                            }
                        }

                        val resp = AirDropCodec.encodeBplist(
                            mapOf(
                                "ReceiverComputerName" to deviceName,
                                "ReceiverModelName" to deviceModel,
                                "ReceiverMediaCapabilities" to AirDropCodec.MEDIA_CAPABILITIES_BYTES,
                                "IsAirDropable" to true
                            )
                        )
                        writeHttpResponse(out, 200, "OK", resp)
                        sock.soTimeout = 60_000
                    }
                    method == "POST" && path == "/Upload" -> {
                        if (!connectionAskApproved) {
                            log("Rejected unauthorized /Upload from $remote without approved /Ask")
                            didUpload = true
                            writeHttpResponse(out, 403, "Forbidden", ByteArray(0), close = true)
                            break
                        }
                        didUpload = true
                        acquireTransferLocks()
                        activeTransferSocket = sock
                        sock.soTimeout = 30_000
                        val downloads = File(
                            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                            "AirDrop"
                        )
                        val expectedBytes = (headers["totalbytes"]?.toLongOrNull() ?: 0L).let {
                            if (it > 0L) it else lastAskTotalBytes
                        }
                        val label = lastAskLabel
                        val fileCount = lastAskFileCount
                        val rawBody = openHttpBodyStream(inp, headers)
                        val startedAt = System.currentTimeMillis()
                        val bodyStream = if (expectedBytes > 0L) {
                            reportProgress(label, 0, 0L, expectedBytes, startedAt, fileCount, isSending = false)
                            object : InputStream() {
                                private var done = 0L
                                private var lastUpdateMs = 0L
                                private var lastTimeoutResetBytes = 0L
                                override fun read(): Int {
                                    if (transferCancelled) throw IOException("Transfer cancelled")
                                    return rawBody.read().also { if (it >= 0) done++ }
                                }
                                override fun read(b: ByteArray, off: Int, len: Int): Int {
                                    if (transferCancelled) throw IOException("Transfer cancelled")
                                    val n = rawBody.read(b, off, len)
                                    if (n > 0) {
                                        done += n
                                        if (done - lastTimeoutResetBytes >= 4_194_304L) {
                                            lastTimeoutResetBytes = done
                                            runCatching { sock.soTimeout = 30_000 }
                                        }
                                        val now = System.currentTimeMillis()
                                        if (now - lastUpdateMs >= 350L || done >= expectedBytes) {
                                            lastUpdateMs = now
                                            val pct = ((done * 100L) / expectedBytes).toInt().coerceIn(0, 99)
                                            reportProgress(label, pct, minOf(done, expectedBytes), expectedBytes, startedAt, fileCount, isSending = false)
                                        }
                                    }
                                    return n
                                }
                            }
                        } else {
                            rawBody
                        }
                        val extracted = try {
                            AirDropCodec.extractDvzipCpio(bodyStream, downloads)
                        } finally {
                            reportProgress(label, 100, expectedBytes, expectedBytes, startedAt, fileCount, isSending = false)
                        }
                        for (f in extracted) {
                            MediaScannerConnection.scanFile(
                                context,
                                arrayOf(f.absolutePath),
                                null,
                                null
                            )
                            val rec = ReceivedItem(
                                title = f.name,
                                pathOrUrl = f.absolutePath,
                                isUrl = false,
                                sizeBytes = f.length(),
                                isOutgoing = false,
                                peerName = lastSenderName
                            )
                            recordHistoryItem(rec)
                            onItemReceived?.invoke(rec)
                            log("Saved to Downloads/AirDrop/${f.name} (${formatBytes(f.length())})")
                        }
                        writeHttpResponse(out, 200, "OK", ByteArray(0))
                        break
                    }
                    else -> {
                        writeHttpResponse(out, 400, "Bad Request", ByteArray(0), close = true)
                        break
                    }
                }
            }
        } catch (t: Throwable) {
            log("RX session ($remote) ended: ${t.message}")
        } finally {
            if (didUpload) releaseTransferLocks()
            if (activeTransferSocket === sock) activeTransferSocket = null
            clearProgressNotification()
            try {
                sock.close()
            } catch (_: Throwable) {
            }
            if (didUpload || transferCancelled) {
                lastMacP2pIp = ""
                // Tear down ephemeral 5GHz Wi-Fi Direct group with grace period so consecutive transfers reuse group
                wifiTeardownJob?.cancel()
                wifiTeardownJob = scope.launch {
                    kotlinx.coroutines.delay(5000)
                    if (!isTransferInProgress) {
                        stopWifiDirectGroup()
                    }
                }
            }
        }
    }

    // =========================================================================
    // Pure P2P Outgoing Transfers (Direct BLE L2CAP)
    // =========================================================================

    val isTransferInProgress: Boolean
        get() = _transferProgress.value != null || pendingMacTx != null || activeTransferSocket != null

    fun sendUrisAsync(
        peer: AirDropPeer,
        uris: List<Uri>,
        onComplete: ((Boolean) -> Unit)? = null
    ): Job = scope.launch {
        val ok = sendUrisToPeer(peer, uris)
        onComplete?.let { cb ->
            withContext(Dispatchers.Main) { cb(ok) }
        }
    }

    fun sendTextSnippetAsync(
        peer: AirDropPeer,
        text: String,
        onComplete: ((Boolean) -> Unit)? = null
    ): Job = scope.launch {
        val ok = sendTextSnippetToPeer(peer, text)
        onComplete?.let { cb ->
            withContext(Dispatchers.Main) { cb(ok) }
        }
    }

    fun sendUrlAsync(
        peer: AirDropPeer,
        url: String,
        onComplete: ((Boolean) -> Unit)? = null
    ): Job = scope.launch {
        val ok = sendUrlToPeer(peer, url)
        onComplete?.let { cb ->
            withContext(Dispatchers.Main) { cb(ok) }
        }
    }

    suspend fun sendUrisToPeer(peer: AirDropPeer, uris: List<Uri>): Boolean =
        withContext(Dispatchers.IO) {
            if (uris.isEmpty()) return@withContext false
            val peerClean = peer.name.substringBefore(" (PSM").trim().ifEmpty { learnedMacName ?: "MacBook Pro" }
            val stagedMetas = uris.map { inspectUriMeta(it) }
            val firstMeta = stagedMetas.first()
            val totalStagedBytes = calculateAggregateStagedBytes(stagedMetas.map { it.second })
            val displayLabel = formatMultiFileDisplayLabel(firstMeta.first, uris.size)
            reportConnecting(
                label = displayLabel,
                total = totalStagedBytes,
                fileCount = uris.size,
                isSending = true,
                phase = "Preparing ${uris.size} file(s)…",
                peerName = peerClean
            )
            val entries = uris.mapNotNull { uri -> resolveUriEntry(uri) }
            if (entries.isEmpty()) {
                clearProgressNotification()
                log("No readable files selected")
                return@withContext false
            }
            return@withContext sendOverBleL2cap(entries, null)
        }

    fun inspectUriMeta(uri: Uri): Pair<String, Long> {
        if (uri.scheme == "file") {
            val f = File(uri.path ?: return "shared_file" to 0L)
            return (f.name.ifEmpty { "shared_file" }) to f.length().coerceAtLeast(0L)
        }
        val cr = context.contentResolver
        var name = uri.lastPathSegment?.substringAfterLast('/') ?: "shared_file"
        var size = -1L
        runCatching {
            cr.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)
                ?.use { c ->
                    if (c.moveToFirst()) {
                        val nameIdx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        val sizeIdx = c.getColumnIndex(OpenableColumns.SIZE)
                        if (nameIdx >= 0 && !c.isNull(nameIdx)) name = c.getString(nameIdx)
                        if (sizeIdx >= 0 && !c.isNull(sizeIdx)) size = c.getLong(sizeIdx)
                    }
                }
        }
        if (size < 0L) {
            runCatching {
                cr.openFileDescriptor(uri, "r")?.use { pfd ->
                    if (pfd.statSize >= 0L) size = pfd.statSize
                }
            }
        }
        return name to size.coerceAtLeast(0L)
    }

    suspend fun sendTextSnippetToPeer(peer: AirDropPeer, text: String): Boolean =
        withContext(Dispatchers.IO) {
            val trimmed = text.trim()
            if (trimmed.isEmpty()) return@withContext false
            if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
                return@withContext sendUrlToPeer(peer, trimmed)
            }
            val bytes = trimmed.toByteArray(StandardCharsets.UTF_8)
            val stamp = java.text.SimpleDateFormat("HHmmss", java.util.Locale.US).format(Date())
            val entry = AirDropCodec.OutgoingEntry(
                name = "Note-$stamp.txt",
                size = bytes.size.toLong(),
                openStream = { bytes.inputStream() }
            )
            return@withContext sendOverBleL2cap(listOf(entry), null)
        }

    suspend fun sendUrlToPeer(peer: AirDropPeer, url: String): Boolean =
        withContext(Dispatchers.IO) {
            return@withContext sendOverBleL2cap(emptyList(), url)
        }

    private fun resolveUriEntry(uri: Uri): AirDropCodec.OutgoingEntry? {
        if (uri.scheme == "file") {
            val f = File(uri.path ?: return null)
            if (!f.isFile) return null
            return AirDropCodec.OutgoingEntry(
                name = f.name,
                size = f.length(),
                openStream = { f.inputStream() }
            )
        }
        val cr = context.contentResolver
        var name = uri.lastPathSegment?.substringAfterLast('/') ?: "shared_file"
        var size = -1L
        try {
            cr.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)
                ?.use { c ->
                    if (c.moveToFirst()) {
                        val nameIdx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        val sizeIdx = c.getColumnIndex(OpenableColumns.SIZE)
                        if (nameIdx >= 0 && !c.isNull(nameIdx)) name = c.getString(nameIdx)
                        if (sizeIdx >= 0 && !c.isNull(sizeIdx)) size = c.getLong(sizeIdx)
                    }
                }
        } catch (t: Throwable) {
            log("Querying URI $uri failed: ${t.message}")
        }
        if (size < 0) {
            try {
                cr.openFileDescriptor(uri, "r")?.use { pfd ->
                    if (pfd.statSize >= 0) size = pfd.statSize
                }
            } catch (_: Throwable) {
            }
        }
        if (size < 0) {
            try {
                val stream = cr.openInputStream(uri) ?: return null
                var counted = 0L
                stream.use { inp ->
                    val buf = ByteArray(65_536)
                    while (true) {
                        val n = inp.read(buf)
                        if (n <= 0) break
                        counted += n
                    }
                }
                size = counted
            } catch (t: Throwable) {
                log("Counting bytes for $uri failed: ${t.message}")
                return null
            }
        }
        return AirDropCodec.OutgoingEntry(
            name = name,
            size = size,
            openStream = {
                cr.openInputStream(uri) ?: throw EOFException("Cannot open $uri")
            }
        )
    }

    // =========================================================================
    // TLS 1.2/1.3 & HTTP/1.1 Chunked Framing Helpers
    // =========================================================================

    @SuppressLint("CustomX509TrustManager")
    private fun buildSslContext(): SSLContext {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!ks.containsAlias(KEYSTORE_ALIAS)) {
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )
            val spec = KeyGenParameterSpec.Builder(
                KEYSTORE_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(
                    KeyProperties.DIGEST_NONE,
                    KeyProperties.DIGEST_SHA256,
                    KeyProperties.DIGEST_SHA384,
                    KeyProperties.DIGEST_SHA512
                )
                .setCertificateSubject(X500Principal("CN=airdrop"))
                .setCertificateSerialNumber(BigInteger.ONE)
                .setCertificateNotBefore(Date(System.currentTimeMillis() - 86_400_000L))
                .setCertificateNotAfter(Date(System.currentTimeMillis() + 315_360_000_000L))
                .build()
            kpg.initialize(spec)
            kpg.generateKeyPair()
        }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(ks, null)
        }
        val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                require(!chain.isNullOrEmpty()) { "Client TLS certificate chain is empty" }
            }
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                require(!chain.isNullOrEmpty()) { "Server TLS certificate chain is empty" }
            }
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        })
        return SSLContext.getInstance("TLS").apply {
            init(kmf.keyManagers, trustAll, random)
        }
    }

    private fun readHttpLine(inp: InputStream): String? {
        val sb = ByteArrayOutputStream(128)
        while (true) {
            val b = inp.read()
            if (b < 0) return if (sb.size() == 0) null else sb.toString("ISO-8859-1").trimEnd('\r')
            if (b == '\n'.code) return sb.toString("ISO-8859-1").trimEnd('\r')
            if (sb.size() >= 8192) throw IOException("HTTP line length exceeded 8KB limit")
            sb.write(b)
        }
    }

    private fun readHttpBodyBytes(inp: InputStream, headers: Map<String, String>): ByteArray {
        val out = ByteArrayOutputStream()
        openHttpBodyStream(inp, headers).copyTo(out)
        return out.toByteArray()
    }

    private fun openHttpBodyStream(inp: InputStream, headers: Map<String, String>): InputStream {
        val te = headers["transfer-encoding"]?.lowercase().orEmpty()
        if (te.contains("chunked")) {
            return object : InputStream() {
                private var chunkLeft = 0L
                private var eof = false
                private val one = ByteArray(1)

                override fun read(): Int {
                    val n = read(one, 0, 1)
                    return if (n <= 0) -1 else (one[0].toInt() and 0xFF)
                }

                override fun read(b: ByteArray, off: Int, len: Int): Int {
                    if (len == 0) return 0
                    if (eof) return -1
                    if (chunkLeft == 0L) {
                        var sizeLine = readHttpLine(inp) ?: throw EOFException("Truncated chunk line")
                        while (sizeLine.isEmpty()) {
                            sizeLine = readHttpLine(inp) ?: throw EOFException("Truncated chunk line")
                        }
                        val hex = sizeLine.substringBefore(';').trim()
                        val sz = hex.toLongOrNull(16)
                            ?: throw IllegalArgumentException("Bad chunk size: $sizeLine")
                        if (sz == 0L) {
                            while (true) {
                                val tr = readHttpLine(inp) ?: break
                                if (tr.isEmpty()) break
                            }
                            eof = true
                            return -1
                        }
                        chunkLeft = sz
                    }
                    val want = minOf(len.toLong(), chunkLeft).toInt()
                    val n = inp.read(b, off, want)
                    if (n <= 0) throw EOFException("Truncated chunk data")
                    chunkLeft -= n
                    if (chunkLeft == 0L) {
                        readHttpLine(inp)
                    }
                    return n
                }
            }
        }
        val contentLen = headers["content-length"]?.toLongOrNull() ?: 0L
        return object : InputStream() {
            private var left = contentLen
            override fun read(): Int {
                if (left <= 0) return -1
                val b = inp.read()
                if (b >= 0) left--
                return b
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (left <= 0) return -1
                val want = minOf(len.toLong(), left).toInt()
                val n = inp.read(b, off, want)
                if (n > 0) left -= n
                return n
            }
        }
    }

    private fun writeHttpResponse(
        out: OutputStream,
        status: Int,
        reason: String,
        body: ByteArray,
        close: Boolean = false
    ) {
        val sb = StringBuilder()
        sb.append("HTTP/1.1 $status $reason\r\n")
        sb.append("Content-Length: ${body.size}\r\n")
        if (close) sb.append("Connection: close\r\n")
        sb.append("\r\n")
        out.write(sb.toString().toByteArray(StandardCharsets.US_ASCII))
        if (body.isNotEmpty()) out.write(body)
        out.flush()
    }
}
