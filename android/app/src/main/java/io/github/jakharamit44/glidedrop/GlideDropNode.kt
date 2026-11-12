package io.github.jakharamit44.glidedrop

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
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
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
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
import androidx.core.content.edit
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
import java.net.BindException
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
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Collections
import java.util.Date
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
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
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal

data class GlideDropPeer(
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
 * Pure P2P zero-router GlideDrop engine for Android <-> macOS:
 * - Direct BLE L2CAP CoC server & client (works with zero Wi-Fi / different networks)
 * - 5 GHz Wi-Fi Direct Autonomous Group (dynamic GO IP/prefix + HTTPS receiver)
 * - Zero Same-IP / LAN router mDNS dependency
 */
class GlideDropNode(private val context: Context) {

    /**
     * Strict X509TrustManager enforcing exact SHA-256 leaf certificate pinning
     * negotiated out-of-band during the ECDH-authenticated BLE W2P2 handshake.
     */
    @SuppressLint("CustomX509TrustManager")
    class PinnedTlsTrustManager(expectedFingerprint: String) : X509TrustManager {
        private val expectedDigest: ByteArray = parseSha256FingerprintBytes(expectedFingerprint)

        @Throws(CertificateException::class)
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            throw CertificateException("Client certificates are not accepted by peer-pinning TrustManager")
        }

        @Throws(CertificateException::class)
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            if (chain.isNullOrEmpty()) {
                throw CertificateException("Server TLS certificate chain is empty")
            }
            val serverCert = chain[0]
            val actualDigest = try {
                MessageDigest.getInstance("SHA-256").digest(serverCert.encoded)
            } catch (e: Exception) {
                throw CertificateException("Unable to compute server TLS certificate fingerprint", e)
            }
            if (!MessageDigest.isEqual(actualDigest, expectedDigest)) {
                val expectedHex = expectedDigest.joinToString("") { "%02x".format(java.util.Locale.US, it) }
                val actualHex = actualDigest.joinToString("") { "%02x".format(java.util.Locale.US, it) }
                throw CertificateException(
                    "TLS certificate fingerprint pinning mismatch: expected $expectedHex, got $actualHex"
                )
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    internal class HttpFramingException(
        val statusCode: Int,
        val reason: String,
        message: String
    ) : IOException(message)

    internal data class HttpRequestHead(
        val method: String,
        val path: String,
        val headers: LinkedHashMap<String, String>
    )

    internal enum class WifiDirectPostTransferAction {
        PRESERVE_FOR_REUSE_AND_SCHEDULE_TEARDOWN,
        CLEAR_AND_STOP_GROUP_NOW,
        CLEAR_ONLY
    }

    companion object {
        const val GLIDEDROP_PORT = 8771
        const val DEFAULT_MAC_RX_PORT = 8772
        const val DEFAULT_UDP_KEEPALIVE_PORT = 8774
        const val INCOMING_SESSION_TOKEN_TTL_MS = 300_000L
        const val MAX_INCOMING_SESSION_TOKENS = 4
        const val PEER_TTL_MS = 4_500L
        private const val KEYSTORE_ALIAS = "glidedrop_ec_v2"
        val MAC_BLE_SERVICE_UUID: UUID = UUID.fromString("52300001-a12d-4000-8000-523a12d00001")
        val MAC_BLE_PSM_CHAR_UUID: UUID = UUID.fromString("52300002-a12d-4000-8000-523a12d00002")
        val P2P_BLE_SERVICE_UUID: UUID = UUID.fromString("52300003-a12d-4000-8000-523a12d00003")
        val P2P_BLE_PSM_CHAR_UUID: UUID = UUID.fromString("52300004-a12d-4000-8000-523a12d00004")
        val P2P_BLE_DATA_UUID: ParcelUuid by lazy { ParcelUuid.fromString("0000cafe-0000-1000-8000-00805f9b34fb") }
        val MAC_BLE_DATA_UUID: ParcelUuid by lazy { ParcelUuid.fromString("0000caff-0000-1000-8000-00805f9b34fb") }
        private val BLUETOOTH_BASE_UUID: UUID = UUID.fromString("00000000-0000-1000-8000-00805f9b34fb")
        const val MAX_ENCRYPTED_BLE_ARCHIVE_BYTES = 30_000_000L
        const val MAX_BLE_AUTO_FALLBACK_BYTES = 5_000_000L
        const val MAX_UNENCRYPTED_BLE_ARCHIVE_BYTES = 1_800_000_000L
        const val MAX_BLE_META_BYTES = 1_048_576
        const val W2P2_JOIN_REPLY_TIMEOUT_MS = 100_000L
        const val ADRE_ACK_TIMEOUT_MS = 65_000L
        const val MAX_HTTP_LINE_BYTES = 8_192
        const val MAX_HTTP_HEADER_LINES = 64
        const val MAX_HTTP_HEADER_BYTES = 16_384
        const val MAX_HTTP_META_BODY_BYTES = 1_048_576

        internal fun shouldAllowBleAutoFallback(totalRawBytes: Long, hasEntries: Boolean): Boolean {
            return !hasEntries || totalRawBytes <= MAX_BLE_AUTO_FALLBACK_BYTES
        }

        internal fun resolveWifiDirectPostTransferAction(
            txSuccess: Boolean,
            transferCancelled: Boolean,
            isP2pHost: Boolean,
            hasWifiDirectCreds: Boolean
        ): WifiDirectPostTransferAction {
            return when {
                txSuccess && !transferCancelled && isP2pHost ->
                    WifiDirectPostTransferAction.PRESERVE_FOR_REUSE_AND_SCHEDULE_TEARDOWN
                isP2pHost || hasWifiDirectCreds ->
                    WifiDirectPostTransferAction.CLEAR_AND_STOP_GROUP_NOW
                else ->
                    WifiDirectPostTransferAction.CLEAR_ONLY
            }
        }

        internal data class W2P2JoinReplyParsed(
            val macIp: String,
            val macRxPort: Int,
            val udpKeepalivePort: Int
        )

        internal data class MacBleAdvParsed(
            val hasMacService: Boolean,
            val psm: Int,
            val displayName: String
        )

        internal fun parseStrictIpv4Bytes(raw: String): ByteArray? {
            val parts = raw.split('.')
            if (parts.size != 4) return null
            val out = ByteArray(4)
            for (i in 0 until 4) {
                val tok = parts[i]
                if (tok.isEmpty() || tok.length > 3 || !tok.all { it in '0'..'9' }) return null
                val v = tok.toIntOrNull() ?: return null
                if (v !in 0..255) return null
                out[i] = v.toByte()
            }
            return out
        }

        internal fun parseNumericIpBytes(rawIp: String): ByteArray? {
            val trimmed = rawIp.trim()
            if (trimmed.isEmpty()) return null
            val unwrapped = if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                trimmed.substring(1, trimmed.length - 1)
            } else {
                trimmed
            }
            val zoneStripped = unwrapped.substringBefore('%')
            if (zoneStripped.isEmpty()) return null
            return if (zoneStripped.contains(':')) {
                EmbeddedProxyServer.parseIpv6Literal(zoneStripped)
            } else {
                parseStrictIpv4Bytes(zoneStripped)
            }
        }

        internal fun computeNetworkCidr(ip: String, prefixLen: Int): String? {
            if (prefixLen <= 0) return null
            val raw = parseNumericIpBytes(ip) ?: return null
            val addr = EmbeddedProxyServer.unwrapMappedIpv4Bytes(raw)
            val maxBits = addr.size * 8
            if (prefixLen > maxBits) return null
            val masked = addr.copyOf()
            for (i in masked.indices) {
                val bitStart = i * 8
                val keepBits = (prefixLen - bitStart).coerceIn(0, 8)
                val mask = if (keepBits == 0) 0 else (0xFF shl (8 - keepBits)) and 0xFF
                masked[i] = (masked[i].toInt() and mask).toByte()
            }
            val netStr = runCatching { InetAddress.getByAddress(masked).hostAddress }.getOrNull()
                ?: return null
            return "$netStr/$prefixLen"
        }

        internal fun parseCidr(cidr: String): Pair<ByteArray, Int>? {
            val parts = cidr.trim().split('/')
            if (parts.size != 2) return null
            val ipBytes = parseNumericIpBytes(parts[0]) ?: return null
            val addr = EmbeddedProxyServer.unwrapMappedIpv4Bytes(ipBytes)
            val prefix = parts[1].toIntOrNull() ?: return null
            if (prefix !in 1..(addr.size * 8)) return null
            return addr to prefix
        }

        internal fun isIpInCidrList(ip: String, cidrs: List<Pair<ByteArray, Int>>): Boolean {
            val raw = parseNumericIpBytes(ip) ?: return false
            return cidrs.any { (net, prefix) -> EmbeddedProxyServer.matchesCidr(raw, net, prefix) }
        }

        fun isValidPeerTransferIp(
            ip: String,
            activeP2pSubnets: List<Pair<ByteArray, Int>> = emptyList()
        ): Boolean {
            val raw = parseNumericIpBytes(ip) ?: return false
            val bytes = EmbeddedProxyServer.unwrapMappedIpv4Bytes(raw)
            if (EmbeddedProxyServer.isLoopbackBytes(bytes)) return false
            if (bytes.size == 4) {
                val b0 = bytes[0].toInt() and 0xFF
                val b1 = bytes[1].toInt() and 0xFF
                if (b0 == 0 || b0 == 127 || b0 >= 224) return false
                if (activeP2pSubnets.any { (net, prefix) -> EmbeddedProxyServer.matchesCidr(bytes, net, prefix) }) {
                    return true
                }
                if (b0 == 169 && b1 == 254) return false
                if (b0 == 10) return true
                if (b0 == 172 && b1 in 16..31) return true
                if (b0 == 192 && b1 == 168) return true
                return false
            }
            if (bytes.size == 16) {
                if (bytes.all { it == 0.toByte() }) return false
                val b0 = bytes[0].toInt() and 0xFF
                val b1 = bytes[1].toInt() and 0xFF
                if (b0 == 0xFF) return false // multicast
                if (activeP2pSubnets.any { (net, prefix) -> EmbeddedProxyServer.matchesCidr(bytes, net, prefix) }) {
                    return true
                }
                if (b0 == 0xFE && (b1 and 0xC0) == 0x80) return true // fe80::/10 link-local
                if ((b0 and 0xFE) == 0xFC) return true // fc00::/7 ULA
                return false
            }
            return false
        }

        fun isReceiverClientAllowed(
            remoteIp: String,
            activeP2pSubnets: List<Pair<ByteArray, Int>> = emptyList(),
            allowLoopback: Boolean = false
        ): Boolean {
            val raw = parseNumericIpBytes(remoteIp) ?: return false
            val addr = runCatching { InetAddress.getByAddress(raw) }.getOrNull() ?: return false
            return EmbeddedProxyServer.isClientAllowed(addr, activeP2pSubnets, allowLoopback)
        }

        fun isReceiverRequestClientAllowed(
            remoteIp: String,
            activeP2pSubnets: List<Pair<ByteArray, Int>> = emptyList(),
            hasActiveSessionToken: Boolean = false,
            allowLoopback: Boolean = false
        ): Boolean {
            if (isReceiverClientAllowed(remoteIp, activeP2pSubnets, allowLoopback)) {
                return true
            }
            if (!hasActiveSessionToken) {
                return false
            }
            val raw = parseNumericIpBytes(remoteIp) ?: return false
            val bytes = EmbeddedProxyServer.unwrapMappedIpv4Bytes(raw)
            if (EmbeddedProxyServer.isLoopbackBytes(bytes)) {
                return false
            }
            if (bytes.size == 16 && bytes.all { it == 0.toByte() }) {
                return false
            }
            return isValidPeerTransferIp(remoteIp, activeP2pSubnets)
        }

        internal fun parseJoinReply(replyLine: String): W2P2JoinReplyParsed? {
            if (!replyLine.startsWith("OK ") && !replyLine.startsWith("OK\t")) return null
            val tokens = replyLine.drop(3).trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
            val macIp = tokens.getOrNull(0) ?: return null
            val macRxPort = tokens.getOrNull(1)?.toIntOrNull()?.takeIf { it in 1..65535 } ?: DEFAULT_MAC_RX_PORT
            val udpKeepalivePort = tokens.getOrNull(2)?.toIntOrNull()?.takeIf { it in 1..65535 } ?: DEFAULT_UDP_KEEPALIVE_PORT
            return W2P2JoinReplyParsed(macIp, macRxPort, udpKeepalivePort)
        }

        internal fun parseMacBleAdvertisement(
            serviceUuids: List<UUID>,
            macDataBytes: ByteArray?,
            deviceName: String
        ): MacBleAdvParsed {
            val hasMacServiceUuid = serviceUuids.any { it == MAC_BLE_SERVICE_UUID }
            val hasMacData = macDataBytes != null && macDataBytes.size >= 2
            if (!hasMacServiceUuid && !hasMacData) {
                return MacBleAdvParsed(hasMacService = false, psm = 0, displayName = "MacBook Pro")
            }

            var parsedPsm = 0
            var remoteDisplayName = "MacBook Pro"
            if (macDataBytes != null && macDataBytes.size >= 2) {
                val p = (macDataBytes[0].toInt() and 0xFF) or ((macDataBytes[1].toInt() and 0xFF) shl 8)
                if (p > 0) parsedPsm = p
                if (macDataBytes.size > 2) {
                    val decoded = String(macDataBytes, 2, macDataBytes.size - 2, StandardCharsets.UTF_8).trim()
                    if (decoded.isNotEmpty()) remoteDisplayName = decoded
                }
            }
            if (deviceName.startsWith("AD-")) {
                val rest = deviceName.removePrefix("AD-").trim()
                val psmPart = rest.substringBefore('-')
                if (parsedPsm <= 0) {
                    parsedPsm = psmPart.toIntOrNull()?.takeIf { it > 0 } ?: 0
                }
                val customLabel = rest.substringAfter('-', "").trim()
                if (customLabel.isNotEmpty() && remoteDisplayName == "MacBook Pro") {
                    remoteDisplayName = customLabel
                }
            }
            if (parsedPsm <= 0) {
                for (uuid in serviceUuids) {
                    val isSig16Bit = uuid.leastSignificantBits == BLUETOOTH_BASE_UUID.leastSignificantBits &&
                        (uuid.mostSignificantBits and 0xFFFF_0000_FFFF_FFFFuL.toLong()) == BLUETOOTH_BASE_UUID.mostSignificantBits
                    if (!isSig16Bit) continue
                    val u16 = ((uuid.mostSignificantBits ushr 32) and 0xFFFFL).toInt()
                    if ((u16 and 0xFF00) == 0xAD00 && (u16 and 0xFF) > 0) {
                        parsedPsm = u16 and 0xFF
                        break
                    }
                }
            }
            return MacBleAdvParsed(hasMacService = true, psm = parsedPsm, displayName = remoteDisplayName)
        }

        internal fun isValidSessionBearerToken(
            presented: String?,
            activeTokens: Map<String, Long>,
            nowMs: Long = System.currentTimeMillis()
        ): Boolean {
            val clean = presented?.trim()?.lowercase(java.util.Locale.US).orEmpty()
            if (clean.length != 64 || !clean.all { it in '0'..'9' || it in 'a'..'f' }) return false
            val presentedBytes = clean.toByteArray(StandardCharsets.US_ASCII)
            var matched = false
            for ((tok, expiresAtMs) in activeTokens) {
                if (expiresAtMs > nowMs && tok.length == 64) {
                    if (MessageDigest.isEqual(presentedBytes, tok.toByteArray(StandardCharsets.US_ASCII))) {
                        matched = true
                    }
                }
            }
            return matched
        }

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

        fun deriveEcdhRawSecret(privateKey: PrivateKey, peerPublicKeyDer: ByteArray): ByteArray {
            val kf = KeyFactory.getInstance("EC")
            val peerPublic = kf.generatePublic(X509EncodedKeySpec(peerPublicKeyDer))
            val ka = KeyAgreement.getInstance("ECDH")
            ka.init(privateKey)
            ka.doPhase(peerPublic, true)
            return ka.generateSecret()
        }

        fun deriveSessionKey(privateKey: PrivateKey, peerPublicKeyDer: ByteArray): ByteArray {
            val rawSecret = deriveEcdhRawSecret(privateKey, peerPublicKeyDer)
            try {
                val md = MessageDigest.getInstance("SHA-256")
                md.update(rawSecret)
                md.update("GlideDrop-v2-SessionKey".toByteArray(StandardCharsets.UTF_8))
                return md.digest()
            } finally {
                rawSecret.fill(0)
            }
        }

        fun deriveBleFrameKey(privateKey: PrivateKey, peerPublicKeyDer: ByteArray): ByteArray {
            val rawSecret = deriveEcdhRawSecret(privateKey, peerPublicKeyDer)
            try {
                val md = MessageDigest.getInstance("SHA-256")
                md.update(rawSecret)
                md.update("GlideDrop-v2-BleFrameKey".toByteArray(StandardCharsets.UTF_8))
                return md.digest()
            } finally {
                rawSecret.fill(0)
            }
        }

        fun deriveSessionToken(privateKey: PrivateKey, peerPublicKeyDer: ByteArray): String {
            val rawSecret = deriveEcdhRawSecret(privateKey, peerPublicKeyDer)
            try {
                val md = MessageDigest.getInstance("SHA-256")
                md.update(rawSecret)
                md.update("GlideDrop-v2-BearerToken".toByteArray(StandardCharsets.UTF_8))
                return md.digest().joinToString("") { "%02x".format(java.util.Locale.US, it) }
            } finally {
                rawSecret.fill(0)
            }
        }

        fun deriveSessionKeyAndToken(privateKey: PrivateKey, peerPublicKeyDer: ByteArray): Pair<ByteArray, String> {
            val rawSecret = deriveEcdhRawSecret(privateKey, peerPublicKeyDer)
            try {
                val keyMd = MessageDigest.getInstance("SHA-256")
                keyMd.update(rawSecret)
                keyMd.update("GlideDrop-v2-SessionKey".toByteArray(StandardCharsets.UTF_8))
                val sessionKey = keyMd.digest()

                val tokMd = MessageDigest.getInstance("SHA-256")
                tokMd.update(rawSecret)
                tokMd.update("GlideDrop-v2-BearerToken".toByteArray(StandardCharsets.UTF_8))
                val token = tokMd.digest().joinToString("") { "%02x".format(java.util.Locale.US, it) }
                return sessionKey to token
            } finally {
                rawSecret.fill(0)
            }
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

        fun parseW2P2Line(line: String): Pair<String, String?> {
            val rawParts = line.trimStart('\t').split('\t')
            val parts = rawParts.filter { it.isNotEmpty() }
            return when {
                parts.size >= 3 && (parts[0] == "2" || parts[0] == "1") -> parts[1] to parts[2]
                parts.size == 2 && (parts[0] == "2" || parts[0] == "1") -> parts[1] to null
                parts.size >= 2 -> parts[0] to parts[1]
                parts.size == 1 -> parts[0] to null
                else -> "" to null
            }
        }

        fun normalizeTlsFingerprint(raw: String): String {
            return raw.replace(":", "").replace("-", "").trim().lowercase(java.util.Locale.US)
        }

        fun isValidSha256Fingerprint(raw: String?): Boolean {
            if (raw.isNullOrBlank()) return false
            val hex = normalizeTlsFingerprint(raw)
            return hex.length == 64 && hex.all { it in '0'..'9' || it in 'a'..'f' }
        }

        fun parseSha256FingerprintBytes(raw: String): ByteArray {
            val hex = normalizeTlsFingerprint(raw)
            require(hex.length == 64 && hex.all { it in '0'..'9' || it in 'a'..'f' }) {
                "Invalid SHA-256 TLS certificate fingerprint"
            }
            return ByteArray(32) { idx ->
                val hi = Character.digit(hex[idx * 2], 16)
                val lo = Character.digit(hex[idx * 2 + 1], 16)
                ((hi shl 4) or lo).toByte()
            }
        }

        fun sha256FingerprintHex(cert: X509Certificate): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
            return digest.joinToString("") { "%02x".format(java.util.Locale.US, it) }
        }

        fun configureHighThroughputTls(tls: SSLSocket) {
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

        fun configureClientTlsSocket(tls: SSLSocket, isPinned: Boolean) {
            configureHighThroughputTls(tls)
            if (!isPinned) {
                tls.sslParameters = tls.sslParameters.apply {
                    endpointIdentificationAlgorithm = "HTTPS"
                }
            }
        }

        fun buildPinnedClientSslContext(
            pinnedFingerprint: String,
            secureRandom: SecureRandom = SecureRandom()
        ): SSLContext {
            val trustManagers = arrayOf<TrustManager>(PinnedTlsTrustManager(pinnedFingerprint))
            return SSLContext.getInstance("TLS").apply {
                init(null, trustManagers, secureRandom)
            }
        }

        fun buildDefaultClientSslContext(
            secureRandom: SecureRandom = SecureRandom()
        ): SSLContext {
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
                init(null as KeyStore?)
            }
            return SSLContext.getInstance("TLS").apply {
                init(null, tmf.trustManagers, secureRandom)
            }
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

        internal fun isHttpTokenChar(ch: Char): Boolean {
            return ch in '0'..'9' || ch in 'A'..'Z' || ch in 'a'..'z' ||
                ch in "!#$%&'*+-.^_`|~"
        }

        internal fun readHttpLineBounded(
            inp: InputStream,
            maxLineBytes: Int = MAX_HTTP_LINE_BYTES
        ): String? {
            val sb = ByteArrayOutputStream(128)
            while (true) {
                val b = inp.read()
                if (b < 0) {
                    if (sb.size() == 0) return null
                    val raw = sb.toString("ISO-8859-1")
                    if (raw.any { it == '\r' || it == '\u0000' || (it.code < 0x20 && it != '\t') }) {
                        throw HttpFramingException(400, "Bad Request", "Malformed control character in HTTP line")
                    }
                    return raw
                }
                if (b == '\n'.code) {
                    val bytes = sb.toByteArray()
                    val len = if (bytes.isNotEmpty() && bytes[bytes.size - 1] == '\r'.code.toByte()) {
                        bytes.size - 1
                    } else {
                        bytes.size
                    }
                    val line = String(bytes, 0, len, StandardCharsets.ISO_8859_1)
                    if (line.any { it == '\r' || it == '\u0000' || (it.code < 0x20 && it != '\t') }) {
                        throw HttpFramingException(400, "Bad Request", "Malformed control character in HTTP line")
                    }
                    return line
                }
                if (sb.size() >= maxLineBytes) {
                    throw HttpFramingException(431, "Request Header Fields Too Large", "HTTP line length exceeded $maxLineBytes byte limit")
                }
                sb.write(b)
            }
        }

        internal fun parseNonNegativeHeaderInt(raw: String?, fieldName: String): Long? {
            if (raw == null) return null
            val clean = raw.trim()
            if (clean.isEmpty() || !clean.all { it in '0'..'9' }) {
                throw HttpFramingException(400, "Bad Request", "Invalid $fieldName header: '$raw'")
            }
            return clean.toLongOrNull()
                ?: throw HttpFramingException(400, "Bad Request", "Overflow in $fieldName header")
        }

        internal fun readHttpRequestHead(
            inp: InputStream,
            maxHeaderLines: Int = MAX_HTTP_HEADER_LINES,
            maxHeaderBytes: Int = MAX_HTTP_HEADER_BYTES,
            maxLineBytes: Int = MAX_HTTP_LINE_BYTES
        ): HttpRequestHead? {
            var reqLine: String? = null
            var emptyLeading = 0
            while (true) {
                val candidate = readHttpLineBounded(inp, maxLineBytes) ?: return null
                if (candidate.isNotEmpty()) {
                    reqLine = candidate
                    break
                }
                emptyLeading++
                if (emptyLeading > 4) {
                    throw HttpFramingException(400, "Bad Request", "Too many empty lines before request line")
                }
            }
            var totalBytes = reqLine.length + 2
            if (totalBytes > maxHeaderBytes) {
                throw HttpFramingException(431, "Request Header Fields Too Large", "Request line exceeds $maxHeaderBytes bytes")
            }
            val parts = reqLine.split(' ').filter { it.isNotEmpty() }
            if (parts.size !in 2..3) {
                throw HttpFramingException(400, "Bad Request", "Malformed HTTP request line")
            }
            val method = parts[0]
            val path = parts[1]
            if (!method.all { it in 'A'..'Z' } || !path.startsWith("/")) {
                throw HttpFramingException(400, "Bad Request", "Invalid HTTP method or path")
            }

            val headers = LinkedHashMap<String, String>()
            var headerLines = 0
            while (true) {
                val line = readHttpLineBounded(inp, maxLineBytes)
                    ?: throw HttpFramingException(400, "Bad Request", "Truncated HTTP headers")
                if (line.isEmpty()) break
                headerLines++
                totalBytes += line.length + 2
                if (headerLines > maxHeaderLines || totalBytes > maxHeaderBytes) {
                    throw HttpFramingException(431, "Request Header Fields Too Large", "HTTP headers exceeded $maxHeaderLines lines / $maxHeaderBytes bytes")
                }
                val colon = line.indexOf(':')
                if (colon <= 0) {
                    throw HttpFramingException(400, "Bad Request", "Malformed HTTP header line")
                }
                val rawName = line.substring(0, colon)
                if (!rawName.all { isHttpTokenChar(it) }) {
                    throw HttpFramingException(400, "Bad Request", "Invalid HTTP header name")
                }
                val name = rawName.lowercase(java.util.Locale.US)
                val value = line.substring(colon + 1).trim()
                if (name == "content-length") {
                    if (headers.containsKey("content-length")) {
                        throw HttpFramingException(400, "Bad Request", "Duplicate Content-Length header")
                    }
                    parseNonNegativeHeaderInt(value, "Content-Length")
                } else if (name == "totalbytes") {
                    parseNonNegativeHeaderInt(value, "TotalBytes")
                }
                headers[name] = value
            }

            if (headers.containsKey("content-length") && headers.containsKey("transfer-encoding")) {
                throw HttpFramingException(400, "Bad Request", "Conflicting Content-Length and Transfer-Encoding headers")
            }
            return HttpRequestHead(method, path, headers)
        }

        internal fun parseChunkSizeLine(sizeLine: String): Long {
            val hex = sizeLine.substringBefore(';').trim()
            if (hex.isEmpty() || !hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
                throw HttpFramingException(400, "Bad Request", "Malformed chunk size: $sizeLine")
            }
            val sz = hex.toLongOrNull(16)
                ?: throw HttpFramingException(400, "Bad Request", "Invalid chunk size: $sizeLine")
            if (sz < 0L) {
                throw HttpFramingException(400, "Bad Request", "Negative chunk size: $sizeLine")
            }
            return sz
        }

        internal fun openHttpBodyStream(inp: InputStream, headers: Map<String, String>): InputStream {
            val te = headers["transfer-encoding"]?.lowercase(java.util.Locale.US).orEmpty()
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
                            val sizeLine = readHttpLineBounded(inp) ?: throw EOFException("Truncated chunk line")
                            val sz = parseChunkSizeLine(sizeLine)
                            if (sz == 0L) {
                                while (true) {
                                    val tr = readHttpLineBounded(inp) ?: break
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
                            val cr = inp.read()
                            val lf = inp.read()
                            if (cr != '\r'.code || lf != '\n'.code) {
                                throw HttpFramingException(400, "Bad Request", "Missing CRLF terminator after HTTP chunk")
                            }
                        }
                        return n
                    }
                }
            }
            val contentLen = parseNonNegativeHeaderInt(headers["content-length"], "Content-Length") ?: 0L
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

        internal fun readHttpBodyBytesBounded(
            inp: InputStream,
            headers: Map<String, String>,
            maxBytes: Int = MAX_HTTP_META_BODY_BYTES
        ): ByteArray {
            val declaredLen = parseNonNegativeHeaderInt(headers["content-length"], "Content-Length")
            if (declaredLen != null && declaredLen > maxBytes.toLong()) {
                throw HttpFramingException(413, "Payload Too Large", "Content-Length $declaredLen exceeds $maxBytes byte limit")
            }
            val bodyStream = openHttpBodyStream(inp, headers)
            val out = ByteArrayOutputStream()
            val buf = ByteArray(16_384)
            var total = 0L
            while (true) {
                val n = bodyStream.read(buf)
                if (n <= 0) break
                total += n
                if (total > maxBytes.toLong()) {
                    throw HttpFramingException(413, "Payload Too Large", "Request body exceeded $maxBytes byte limit")
                }
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val random = SecureRandom()
    private val transferMutex = Mutex()
    private val prefs = context.getSharedPreferences("glidedrop_prefs", Context.MODE_PRIVATE)
    val authTag = ByteArray(3).also { random.nextBytes(it) }
    val serviceId: String = prefs.getString("service_id", null)
        ?: ByteArray(6)
            .also { random.nextBytes(it) }
            .joinToString("") { "%02x".format(it) }
            .also { prefs.edit { putString("service_id", it) } }

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
            prefs.edit { putString("device_name", clean) }
            restartBleAdvertisingOnly()
        }

    var deviceModel: String = Build.MODEL ?: "Android"

    private val _autoAcceptFlow = MutableStateFlow(prefs.getBoolean("auto_accept", false))
    val autoAcceptFlow: StateFlow<Boolean> = _autoAcceptFlow.asStateFlow()

    var autoAccept: Boolean
        get() = _autoAcceptFlow.value
        set(value) {
            _autoAcceptFlow.value = value
            prefs.edit { putBoolean("auto_accept", value) }
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
            prefs.edit { putString("theme_mode", normalized) }
        }

    private var embeddedProxyServer: EmbeddedProxyServer? = null

    private val _proxyActualPortFlow = MutableStateFlow(0)
    val proxyActualPortFlow: StateFlow<Int> = _proxyActualPortFlow.asStateFlow()

    private val _shareCellularInternetFlow = MutableStateFlow(prefs.getBoolean("share_cellular_internet", false))
    val shareCellularInternetFlow: StateFlow<Boolean> = _shareCellularInternetFlow.asStateFlow()

    var shareCellularInternet: Boolean
        get() = _shareCellularInternetFlow.value
        set(value) {
            _shareCellularInternetFlow.value = value
            prefs.edit { putBoolean("share_cellular_internet", value) }
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
    private val _peers = MutableStateFlow<List<GlideDropPeer>>(emptyList())
    val peers: StateFlow<List<GlideDropPeer>> = _peers.asStateFlow()

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
                transferWakeLock = pm?.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "glidedrop:transfer_node_lock")?.apply {
                    setReferenceCounted(false)
                }
            }
            transferWakeLock?.acquire(60 * 60 * 1000L) // 1 hour max

            val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
            if (transferWifiLock == null) {
                val lockMode = WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                transferWifiLock = wm?.createWifiLock(lockMode, "glidedrop:transfer_wifi_lock")?.apply {
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
        val localNetOk = Build.VERSION.SDK_INT < 37 ||
            ContextCompat.checkSelfPermission(context, "android.permission.ACCESS_LOCAL_NETWORK") == PackageManager.PERMISSION_GRANTED
        val permsOk =
            ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_ADVERTISE) == PackageManager.PERMISSION_GRANTED &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED &&
                localNetOk
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
        clearProgressNotification()
        _incomingAsk.value?.let { ask ->
            _incomingAsk.value = null
            ask.decision.complete(false)
        }
        onTransferProgress?.invoke("Transfer cancelled", -1, 0L, 0L, 0L, false, false, "")
        pendingMacTx?.let { tx ->
            pendingMacTx = null
            tx.tryClaim()
            tx.result.complete(false)
        }
        runCatching { activeTransferSocket?.close() }
        activeTransferSocket = null
        clearLastMacSessionState()
        clearIncomingSessionTokens()
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
            prefs.edit { putString("history_v2", serialized) }
            next
        }
    }

    fun clearReceivedItems() {
        _receivedItems.value = emptyList()
        prefs.edit { remove("history_v2") }
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
        return isValidPeerTransferIp(ip, activeP2pSubnets())
    }

    private fun readBleLineBounded(sock: BluetoothSocket, inp: InputStream, timeoutMs: Long): String? {
        val timer = scope.launch(Dispatchers.IO) {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (isActive) {
                if (transferCancelled) {
                    runCatching { sock.close() }
                    break
                }
                val rem = deadline - System.currentTimeMillis()
                if (rem <= 0L) {
                    runCatching { sock.close() }
                    break
                }
                kotlinx.coroutines.delay(minOf(200L, rem))
            }
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

    private val serverSslContext: SSLContext by lazy { buildServerSslContext() }
    private var serverSocket: java.net.ServerSocket? = null
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
    @Volatile
    private var lastMacP2pPort: Int = DEFAULT_MAC_RX_PORT
    @Volatile
    private var lastMacUdpKeepalivePort: Int = DEFAULT_UDP_KEEPALIVE_PORT
    @Volatile
    private var lastMacTlsFingerprint: String = ""
    @Volatile
    private var lastMacSessionToken: String = ""
    @Volatile
    private var activeWifiDirectGoIp: String = ""
    @Volatile
    private var activeWifiDirectPrefixLen: Int = 0
    @Volatile
    private var activeP2pNetworkCidr: String = ""
    @Volatile
    private var activeP2pInterfaceName: String? = null
    @Volatile
    private var hasResolvedActualGoIp: Boolean = false
    @Volatile
    private var actualHttpsPort: Int = GLIDEDROP_PORT
    @Volatile
    private var activeGroupSsid: String = ""
    @Volatile
    private var activeGroupPassphrase: String = ""
    private val incomingSessionTokensLock = Any()
    private val incomingSessionTokens = LinkedHashMap<String, Long>()
    private val p2pStateLock = Any()
    private val gattPsmResolveInFlight = java.util.concurrent.atomic.AtomicBoolean(false)
    private var wifiTeardownJob: Job? = null
    @Volatile
    private var lastWifiGroupReadyAtMs: Long = 0L
    @Volatile
    private var lastIncomingDiscoverAtMs: Long = 0L
    @Volatile
    private var trackedP2pNetwork: Network? = null
    private var p2pNetworkCallback: ConnectivityManager.NetworkCallback? = null

    private fun clearLastMacSessionState() {
        lastMacP2pIp = ""
        lastMacP2pPort = DEFAULT_MAC_RX_PORT
        lastMacUdpKeepalivePort = DEFAULT_UDP_KEEPALIVE_PORT
        lastMacTlsFingerprint = ""
        lastMacSessionToken = ""
    }

    private fun registerIncomingSessionToken(token: String) {
        val clean = token.trim().lowercase(java.util.Locale.US)
        if (clean.length != 64 || !clean.all { it in '0'..'9' || it in 'a'..'f' }) return
        val now = System.currentTimeMillis()
        synchronized(incomingSessionTokensLock) {
            val it = incomingSessionTokens.entries.iterator()
            while (it.hasNext()) {
                if (it.next().value <= now) it.remove()
            }
            incomingSessionTokens.remove(clean)
            incomingSessionTokens[clean] = now + INCOMING_SESSION_TOKEN_TTL_MS
            while (incomingSessionTokens.size > MAX_INCOMING_SESSION_TOKENS) {
                val eldest = incomingSessionTokens.keys.firstOrNull() ?: break
                incomingSessionTokens.remove(eldest)
            }
        }
    }

    private fun isValidIncomingSessionToken(presented: String?): Boolean {
        val snapshot: Map<String, Long> = synchronized(incomingSessionTokensLock) {
            val now = System.currentTimeMillis()
            val it = incomingSessionTokens.entries.iterator()
            while (it.hasNext()) {
                if (it.next().value <= now) it.remove()
            }
            LinkedHashMap(incomingSessionTokens)
        }
        return isValidSessionBearerToken(presented, snapshot)
    }

    private fun clearIncomingSessionTokens() {
        synchronized(incomingSessionTokensLock) {
            incomingSessionTokens.clear()
        }
    }

    private fun hasActiveIncomingSessionTokens(): Boolean {
        val now = System.currentTimeMillis()
        synchronized(incomingSessionTokensLock) {
            val it = incomingSessionTokens.entries.iterator()
            while (it.hasNext()) {
                if (it.next().value <= now) it.remove()
            }
            return incomingSessionTokens.isNotEmpty()
        }
    }

    internal fun activeP2pSubnets(): List<Pair<ByteArray, Int>> {
        val list = ArrayList<Pair<ByteArray, Int>>(4)
        val seen = HashSet<String>()
        fun addCidr(cidr: String?) {
            if (cidr.isNullOrBlank()) return
            val parsed = parseCidr(cidr) ?: return
            val key = "${parsed.first.joinToString(".") { (it.toInt() and 0xFF).toString() }}/${parsed.second}"
            if (seen.add(key)) {
                list.add(parsed)
            }
        }

        if (activeP2pNetworkCidr.isNotBlank()) {
            addCidr(activeP2pNetworkCidr)
        }

        runCatching {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            trackedP2pNetwork?.let { net ->
                cm?.getLinkProperties(net)?.linkAddresses?.forEach { la ->
                    val addr = la.address
                    if (!addr.isLoopbackAddress && !addr.isLinkLocalAddress && la.prefixLength > 0) {
                        val host = addr.hostAddress?.substringBefore('%')
                        if (!host.isNullOrBlank()) {
                            addCidr(computeNetworkCidr(host, la.prefixLength))
                        }
                    }
                }
            }
        }

        runCatching {
            val ifaces = NetworkInterface.getNetworkInterfaces()
            if (ifaces != null) {
                for (nif in Collections.list(ifaces)) {
                    if (!nif.isUp || nif.isLoopback) continue
                    val isP2pIface = nif.name.startsWith("p2p", ignoreCase = true) ||
                        (!activeP2pInterfaceName.isNullOrBlank() && nif.name == activeP2pInterfaceName)
                    if (!isP2pIface) continue
                    for (ia in nif.interfaceAddresses) {
                        val addr = ia.address ?: continue
                        if (addr.isLoopbackAddress || addr.isLinkLocalAddress) continue
                        val prefix = ia.networkPrefixLength.toInt()
                        if (prefix <= 0) continue
                        val host = addr.hostAddress?.substringBefore('%') ?: continue
                        addCidr(computeNetworkCidr(host, prefix))
                    }
                }
            }
        }

        return list
    }

    private fun isAddressInActiveP2pSubnet(ip: String): Boolean {
        return isIpInCidrList(ip, activeP2pSubnets())
    }

    private fun currentHttpsPort(): Int {
        val bound = serverSocket?.localPort ?: 0
        return if (bound > 0) bound else actualHttpsPort
    }

    private fun activeProxyPortOr0(): Int {
        if (!shareCellularInternet) return 0
        val proxy = embeddedProxyServer ?: return 0
        return if (proxy.running && proxy.actualPort > 0) proxy.actualPort else 0
    }

    internal class PendingMacTx(
        val metaBytes: ByteArray,
        val archiveBytes: ByteArray,
        val entries: List<GlideDropCodec.OutgoingEntry>,
        val url: String?,
        val label: String,
        val fileCount: Int,
        val totalRawBytes: Long,
        val result: CompletableDeferred<Boolean>,
        val targetPeerAddress: String? = null
    ) {
        private val claimedFlag = AtomicBoolean(false)
        val isClaimed: Boolean
            get() = claimedFlag.get()

        fun tryClaim(): Boolean = claimedFlag.compareAndSet(false, true)
    }

    @Volatile
    private var pendingMacTx: PendingMacTx? = null

    private fun saveDirectSharePeer(peer: GlideDropPeer, remoteName: String) {
        prefs.edit {
            putString("last_peer_id", peer.id)
            putString("last_peer_name", remoteName)
            putString("last_peer_host", peer.host)
            putInt("last_peer_port", peer.port)
        }
        runCatching {
            val sm = context.getSystemService(ShortcutManager::class.java) ?: return@runCatching
            val shareIntent = Intent(context, MainActivity::class.java).apply {
                action = Intent.ACTION_SEND
                putExtra("direct_peer_host", peer.host)
                putExtra("direct_peer_port", peer.port)
            }
            val shortcut = ShortcutInfo.Builder(context, "mac_glidedrop_direct")
                .setShortLabel(remoteName)
                .setLongLabel("Send to $remoteName")
                .setIcon(Icon.createWithResource(context, R.mipmap.ic_launcher_round))
                .setCategories(setOf("io.github.jakharamit44.glidedrop.DIRECT_SHARE"))
                .setIntent(shareIntent)
                .setLongLived(true)
                .setRank(0)
                .build()
            sm.pushDynamicShortcut(shortcut)
        }
    }

    fun log(msg: String) {
        android.util.Log.i("GlideDrop", msg)
        val time = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(Date())
        _logs.update { (it + "[$time] $msg").takeLast(80) }
    }

    private fun updateActiveP2pInterfaceState(
        goIp: String,
        prefixLen: Int,
        ifaceName: String? = null,
        resolvedFromOs: Boolean = false
    ) {
        val cleanIp = goIp.trim()
        val rawBytes = parseNumericIpBytes(cleanIp) ?: return
        val unwrapped = EmbeddedProxyServer.unwrapMappedIpv4Bytes(rawBytes)
        val maxBits = unwrapped.size * 8
        if (prefixLen !in 1..maxBits) return
        val cidr = computeNetworkCidr(cleanIp, prefixLen) ?: return
        val changed = synchronized(p2pStateLock) {
            val diff = (activeWifiDirectGoIp != cleanIp || activeWifiDirectPrefixLen != prefixLen || activeP2pNetworkCidr != cidr || (ifaceName != null && activeP2pInterfaceName != ifaceName))
            activeWifiDirectGoIp = cleanIp
            activeWifiDirectPrefixLen = prefixLen
            activeP2pNetworkCidr = cidr
            if (resolvedFromOs) {
                hasResolvedActualGoIp = true
            }
            if (!ifaceName.isNullOrBlank()) {
                activeP2pInterfaceName = ifaceName
            }
            if (hasResolvedActualGoIp && activeGroupSsid.isNotEmpty() && activeGroupPassphrase.isNotEmpty()) {
                wifiDirectCreds = "$activeGroupSsid\t$activeGroupPassphrase\t$cleanIp\t${currentHttpsPort()}"
            }
            diff
        }
        if (changed) {
            refreshLocalAddresses()
        }
    }

    private fun extractP2pAddressFromLinkProperties(lp: LinkProperties?): Triple<String, Int, String?>? {
        if (lp == null) return null
        val v4 = lp.linkAddresses.firstOrNull { la ->
            val addr = la.address
            addr is Inet4Address && !addr.isLoopbackAddress && !addr.isLinkLocalAddress && la.prefixLength > 0
        }
        val chosen = v4 ?: lp.linkAddresses.firstOrNull { la ->
            !la.address.isLoopbackAddress && !la.address.isLinkLocalAddress && la.prefixLength > 0
        } ?: return null
        val host = chosen.address.hostAddress?.substringBefore('%') ?: return null
        return Triple(host, chosen.prefixLength, lp.interfaceName)
    }

    private fun findP2pInterfaceAddress(preferredIfaceName: String? = null, targetHostIp: String? = null): Triple<String, Int, String>? {
        runCatching {
            val ifaces = Collections.list(NetworkInterface.getNetworkInterfaces())
            if (!targetHostIp.isNullOrBlank()) {
                for (nif in ifaces) {
                    if (!nif.isUp || nif.isLoopback) continue
                    for (ia in nif.interfaceAddresses) {
                        if (ia.address.isLoopbackAddress || ia.address.isLinkLocalAddress) continue
                        val host = ia.address.hostAddress?.substringBefore('%') ?: continue
                        val prefix = ia.networkPrefixLength.toInt()
                        if (host == targetHostIp && prefix > 0) {
                            return Triple(host, prefix, nif.name)
                        }
                    }
                }
            }
            val ordered = ifaces.filter { it.isUp && !it.isLoopback }.sortedByDescending { nif ->
                when {
                    !preferredIfaceName.isNullOrBlank() && nif.name == preferredIfaceName -> 3
                    !activeP2pInterfaceName.isNullOrBlank() && nif.name == activeP2pInterfaceName -> 2
                    nif.name.startsWith("p2p", ignoreCase = true) -> 1
                    else -> 0
                }
            }
            for (nif in ordered) {
                val isCandidateP2p = (!preferredIfaceName.isNullOrBlank() && nif.name == preferredIfaceName) ||
                    (!activeP2pInterfaceName.isNullOrBlank() && nif.name == activeP2pInterfaceName) ||
                    nif.name.startsWith("p2p", ignoreCase = true)
                if (!isCandidateP2p) continue
                val v4 = nif.interfaceAddresses.firstOrNull { ia ->
                    ia.address is Inet4Address && !ia.address.isLoopbackAddress && !ia.address.isLinkLocalAddress && ia.networkPrefixLength.toInt() > 0
                }
                val chosen = v4 ?: nif.interfaceAddresses.firstOrNull {
                    !it.address.isLoopbackAddress && !it.address.isLinkLocalAddress && it.networkPrefixLength.toInt() > 0
                }
                if (chosen != null) {
                    val host = chosen.address.hostAddress?.substringBefore('%') ?: continue
                    val prefix = chosen.networkPrefixLength.toInt()
                    return Triple(host, prefix, nif.name)
                }
            }
        }
        return null
    }

    @SuppressLint("MissingPermission")
    private fun resolveWifiDirectGoInterface(
        mgr: WifiP2pManager? = wifiP2pManager,
        ch: WifiP2pManager.Channel? = wifiP2pChannel,
        groupInterface: String? = null,
        onResolved: ((String, Int) -> Unit)? = null
    ): Pair<String, Int>? {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val netTriple = trackedP2pNetwork?.let { net ->
            extractP2pAddressFromLinkProperties(cm?.getLinkProperties(net))
        } ?: findP2pInterfaceAddress(preferredIfaceName = groupInterface)

        if (netTriple != null) {
            updateActiveP2pInterfaceState(netTriple.first, netTriple.second, netTriple.third, resolvedFromOs = true)
        }

        if (mgr != null && ch != null) {
            runCatching {
                mgr.requestConnectionInfo(ch) { info ->
                    val goAddr = info?.groupOwnerAddress
                    val goIp = goAddr?.hostAddress?.substringBefore('%')
                    if (!goIp.isNullOrBlank() && !goAddr.isLoopbackAddress && !goAddr.isLinkLocalAddress) {
                        var resolvedPrefix: Int? = null
                        var resolvedIface: String? = null
                        val lp = trackedP2pNetwork?.let { cm?.getLinkProperties(it) }
                        val matchingLa = lp?.linkAddresses?.firstOrNull { la ->
                            la.address?.hostAddress?.substringBefore('%') == goIp && la.prefixLength > 0
                        }
                        if (matchingLa != null) {
                            resolvedPrefix = matchingLa.prefixLength
                            resolvedIface = lp.interfaceName
                        } else {
                            val ifaceInfo = findP2pInterfaceAddress(preferredIfaceName = groupInterface, targetHostIp = goIp)
                            if (ifaceInfo != null && ifaceInfo.second > 0) {
                                resolvedPrefix = ifaceInfo.second
                                resolvedIface = ifaceInfo.third
                            }
                        }
                        if (resolvedPrefix != null && resolvedPrefix > 0) {
                            val ifName = resolvedIface ?: groupInterface
                            updateActiveP2pInterfaceState(goIp, resolvedPrefix, ifName, resolvedFromOs = true)
                            onResolved?.invoke(goIp, resolvedPrefix)
                        }
                    }
                }
            }
        }

        return if (netTriple != null) {
            netTriple.first to netTriple.second
        } else if (hasResolvedActualGoIp && activeWifiDirectGoIp.isNotBlank() && activeWifiDirectPrefixLen > 0) {
            activeWifiDirectGoIp to activeWifiDirectPrefixLen
        } else {
            null
        }
    }

    private fun isP2pNetwork(
        cm: ConnectivityManager,
        network: Network,
        caps: NetworkCapabilities? = null,
        lp: LinkProperties? = null
    ): Boolean {
        val resolvedCaps = caps ?: cm.getNetworkCapabilities(network) ?: return false
        if (resolvedCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_WIFI_P2P)) return true
        val resolvedLp = lp ?: cm.getLinkProperties(network)
        if (resolvedLp?.interfaceName?.startsWith("p2p", ignoreCase = true) == true) return true
        val activeSubnets = activeP2pSubnets()
        return resolvedLp?.linkAddresses?.any { la ->
            val host = la.address.hostAddress?.substringBefore('%') ?: return@any false
            isIpInCidrList(host, activeSubnets)
        } == true
    }

    private fun registerP2pNetworkCallback() {
        if (p2pNetworkCallback != null) return
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (isP2pNetwork(cm, network)) {
                    trackedP2pNetwork = network
                    extractP2pAddressFromLinkProperties(cm.getLinkProperties(network))?.let { (ip, prefix, ifName) ->
                        updateActiveP2pInterfaceState(ip, prefix, ifName, resolvedFromOs = true)
                    }
                }
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                if (isP2pNetwork(cm, network, caps = networkCapabilities)) {
                    trackedP2pNetwork = network
                    extractP2pAddressFromLinkProperties(cm.getLinkProperties(network))?.let { (ip, prefix, ifName) ->
                        updateActiveP2pInterfaceState(ip, prefix, ifName, resolvedFromOs = true)
                    }
                } else if (trackedP2pNetwork == network) {
                    trackedP2pNetwork = null
                }
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                if (isP2pNetwork(cm, network, lp = linkProperties)) {
                    trackedP2pNetwork = network
                    extractP2pAddressFromLinkProperties(linkProperties)?.let { (ip, prefix, ifName) ->
                        updateActiveP2pInterfaceState(ip, prefix, ifName, resolvedFromOs = true)
                    }
                } else if (trackedP2pNetwork == network &&
                    cm.getNetworkCapabilities(network)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_WIFI_P2P) != true
                ) {
                    trackedP2pNetwork = null
                }
            }

            override fun onLost(network: Network) {
                if (trackedP2pNetwork == network) {
                    trackedP2pNetwork = null
                }
            }
        }
        runCatching {
            val request = NetworkRequest.Builder()
                .clearCapabilities()
                .build()
            cm.registerNetworkCallback(request, cb)
            p2pNetworkCallback = cb
        }
    }

    private fun unregisterP2pNetworkCallback() {
        val cb = p2pNetworkCallback ?: return
        p2pNetworkCallback = null
        trackedP2pNetwork = null
        runCatching {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            cm?.unregisterNetworkCallback(cb)
        }
    }

    fun start() {
        refreshSystemReadiness()
        if (_running.value) return
        _running.value = true
        registerP2pNetworkCallback()
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
        unregisterP2pNetworkCallback()
        stopBleWake()
        stopWifiDirectGroup()
        stopEmbeddedProxy()
        try {
            serverSocket?.close()
        } catch (_: Throwable) {
        }
        serverSocket = null
        actualHttpsPort = GLIDEDROP_PORT
        log("GlideDrop node stopped")
    }

    /**
     * Lists only Pure P2P endpoints (Direct BLE L2CAP + active 5GHz Wi-Fi Direct interface).
     * Never exposes or uses shared-router LAN IPs.
     */
    fun refreshLocalAddresses() {
        val list = ArrayList<String>()
        if (localBlePsm > 0) {
            list.add("BLE L2CAP PSM $localBlePsm (Zero-Router P2P)")
        }
        try {
            val activeSubnets = activeP2pSubnets()
            val httpsPort = currentHttpsPort()
            for (nif in Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!nif.isUp || nif.isLoopback) continue
                val isP2pIface = nif.name.startsWith("p2p", ignoreCase = true) ||
                    (!activeP2pInterfaceName.isNullOrBlank() && nif.name == activeP2pInterfaceName)
                for (addr in Collections.list(nif.inetAddresses)) {
                    if (addr !is Inet4Address || addr.isLoopbackAddress || addr.isLinkLocalAddress) continue
                    val host = addr.hostAddress ?: continue
                    if (isP2pIface || (!nif.name.startsWith("wlan", ignoreCase = true) && isIpInCidrList(host, activeSubnets))) {
                        list.add("$host:$httpsPort (5GHz Wi-Fi Direct)")
                    }
                }
            }
            if (embeddedProxyServer?.running == true) {
                val proxyPort = embeddedProxyServer?.actualPort ?: 0
                if (proxyPort > 0) {
                    list.add("0.0.0.0:$proxyPort (Dual SOCKS5/HTTP Proxy)")
                }
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
                    .setServiceData(MAC_BLE_DATA_UUID, ByteArray(0), ByteArray(0))
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
    private suspend fun resolveMacGattPsm(dev: BluetoothDevice, timeoutMs: Long = 4_000L): Int {
        val result = CompletableDeferred<Int>()
        var gatt: BluetoothGatt? = null
        val cb = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(g: BluetoothGatt, status: Int, newState: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    result.complete(0)
                    runCatching { g.close() }
                    return
                }
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    if (!g.discoverServices()) {
                        result.complete(0)
                    }
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    result.complete(0)
                }
            }

            override fun onServicesDiscovered(g: BluetoothGatt, status: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    result.complete(0)
                    return
                }
                val svc = g.getService(MAC_BLE_SERVICE_UUID)
                val ch = svc?.getCharacteristic(MAC_BLE_PSM_CHAR_UUID)
                if (ch == null || !g.readCharacteristic(ch)) {
                    result.complete(0)
                }
            }

            @Suppress("DEPRECATION")
            override fun onCharacteristicRead(g: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
                if (status == BluetoothGatt.GATT_SUCCESS && characteristic.uuid == MAC_BLE_PSM_CHAR_UUID) {
                    val v = characteristic.value
                    val psm = if (v != null && v.size >= 2) {
                        (v[0].toInt() and 0xFF) or ((v[1].toInt() and 0xFF) shl 8)
                    } else 0
                    result.complete(psm)
                } else {
                    result.complete(0)
                }
            }

            override fun onCharacteristicRead(
                g: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                value: ByteArray,
                status: Int
            ) {
                if (status == BluetoothGatt.GATT_SUCCESS && characteristic.uuid == MAC_BLE_PSM_CHAR_UUID && value.size >= 2) {
                    val psm = (value[0].toInt() and 0xFF) or ((value[1].toInt() and 0xFF) shl 8)
                    result.complete(psm)
                } else {
                    result.complete(0)
                }
            }
        }
        return try {
            gatt = dev.connectGatt(context, false, cb, BluetoothDevice.TRANSPORT_LE)
            kotlinx.coroutines.withTimeoutOrNull(timeoutMs) { result.await() } ?: 0
        } catch (_: Throwable) {
            0
        } finally {
            runCatching { gatt?.disconnect() }
            runCatching { gatt?.close() }
        }
    }

    @SuppressLint("MissingPermission")
    private fun handleMacBleScanResult(result: ScanResult) {
        val dev = result.device ?: return
        val record = result.scanRecord ?: return
        val name = record.deviceName ?: dev.name ?: ""
        val uuids = record.serviceUuids.orEmpty().map { it.uuid }
        val macDataBytes = record.getServiceData(MAC_BLE_DATA_UUID)
        val parsed = parseMacBleAdvertisement(uuids, macDataBytes, name)
        if (!parsed.hasMacService) return

        val prevDev = bleMacDevice
        val prevPsm = bleMacPsm
        bleMacDevice = dev
        if (parsed.psm > 0) {
            bleMacPsm = parsed.psm
        } else if (prevDev?.address != dev.address) {
            bleMacPsm = 0
        }
        val effectivePsm = if (bleMacPsm > 0) bleMacPsm else 0
        val displayMacName = learnedMacName ?: parsed.displayName
        val peerDisplayLabel = if (effectivePsm > 0) "$displayMacName (PSM $effectivePsm)" else displayMacName
        val now = System.currentTimeMillis()

        if (effectivePsm <= 0 && gattPsmResolveInFlight.compareAndSet(false, true)) {
            scope.launch(Dispatchers.IO) {
                try {
                    val gattPsm = resolveMacGattPsm(dev)
                    if (gattPsm > 0 && bleMacDevice?.address == dev.address) {
                        bleMacPsm = gattPsm
                        _peers.update { list ->
                            list.map {
                                if (it.id == "ble-mac") {
                                    it.copy(name = "$displayMacName (PSM $gattPsm)", port = gattPsm)
                                } else it
                            }
                        }
                    }
                } finally {
                    gattPsmResolveInFlight.set(false)
                }
            }
        }

        if (prevDev?.address != dev.address || (parsed.psm > 0 && prevPsm != parsed.psm) || _peers.value.none { it.id == "ble-mac" }) {
            log("Discovered live peer over BLE: $displayMacName (${dev.address}, psm=$effectivePsm, rssi=${result.rssi} dBm)")
            val blePeer = GlideDropPeer(
                id = "ble-mac",
                name = peerDisplayLabel,
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
                            name = peerDisplayLabel,
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

            fun publishGroupReady(group: android.net.wifi.p2p.WifiP2pGroup) {
                val ssid = group.networkName ?: return
                val pass = group.passphrase ?: return
                if (ssid.isEmpty() || pass.isEmpty()) return
                activeGroupSsid = ssid
                activeGroupPassphrase = pass
                val groupIface = runCatching { group.`interface` }.getOrNull()
                if (!groupIface.isNullOrBlank()) {
                    activeP2pInterfaceName = groupIface
                }
                startEmbeddedProxy()
                val resolved = resolveWifiDirectGoInterface(mgr, ch, groupInterface = groupIface) { resolvedIp, _ ->
                    val httpsPort = currentHttpsPort()
                    val creds = "$ssid\t$pass\t$resolvedIp\t$httpsPort"
                    if (wifiDirectCreds != creds) {
                        wifiDirectCreds = creds
                        lastWifiGroupReadyAtMs = System.currentTimeMillis()
                        val psm = localBlePsm
                        _p2pStatus.value = "5GHz P2P ($ssid) • BLE PSM $psm"
                        log("5GHz Wi-Fi Direct P2P Ready: $ssid ($resolvedIp:$httpsPort, cidr=$activeP2pNetworkCidr)")
                        refreshLocalAddresses()
                    }
                }
                if (resolved != null && hasResolvedActualGoIp) {
                    val (goIp, _) = resolved
                    val httpsPort = currentHttpsPort()
                    val creds = "$ssid\t$pass\t$goIp\t$httpsPort"
                    if (wifiDirectCreds != creds) {
                        wifiDirectCreds = creds
                        lastWifiGroupReadyAtMs = System.currentTimeMillis()
                        val psm = localBlePsm
                        _p2pStatus.value = "5GHz P2P ($ssid) • BLE PSM $psm"
                        log("5GHz Wi-Fi Direct P2P Ready: $ssid ($goIp:$httpsPort, cidr=$activeP2pNetworkCidr)")
                        refreshLocalAddresses()
                    }
                }
            }

            fun pollGroupInfo() {
                scope.launch {
                    repeat(20) {
                        kotlinx.coroutines.delay(400)
                        mgr.requestGroupInfo(ch) { group ->
                            if (group != null && group.isGroupOwner) {
                                publishGroupReady(group)
                            }
                        }
                        if (wifiDirectCreds.isNotEmpty() && hasResolvedActualGoIp) return@launch
                    }
                }
            }

            mgr.requestGroupInfo(ch) { existing ->
                try {
                    if (existing != null && existing.isGroupOwner && !existing.networkName.isNullOrEmpty() && !existing.passphrase.isNullOrEmpty()) {
                        publishGroupReady(existing)
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
                        val randomPass = ByteArray(6).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }
                        val cfg = WifiP2pConfig.Builder()
                            .setNetworkName("DIRECT-GlideDrop")
                            .setPassphrase(randomPass)
                            .enablePersistentMode(false)
                            .setGroupOperatingBand(WifiP2pConfig.GROUP_OWNER_BAND_5GHZ)
                            .build()
                        mgr.createGroup(ch, cfg, listener)
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
        synchronized(p2pStateLock) {
            wifiDirectCreds = ""
            activeGroupSsid = ""
            activeGroupPassphrase = ""
            activeWifiDirectGoIp = ""
            activeWifiDirectPrefixLen = 0
            activeP2pNetworkCidr = ""
            activeP2pInterfaceName = null
            hasResolvedActualGoIp = false
            lastWifiGroupReadyAtMs = 0L
            lastIncomingDiscoverAtMs = 0L
        }
        clearLastMacSessionState()
        clearIncomingSessionTokens()
        if (localBlePsm > 0) {
            _p2pStatus.value = "BLE PSM $localBlePsm • 5GHz On-Demand Ready"
        }
        refreshLocalAddresses()
    }

    private fun startEmbeddedProxy() {
        if (!shareCellularInternet) return
        if (embeddedProxyServer?.running == true) return
        try {
            val proxy = EmbeddedProxyServer(
                context = context,
                port = EmbeddedProxyServer.DEFAULT_PROXY_PORT,
                logger = { msg -> log(msg) },
                allowedP2pSubnetsProvider = { activeP2pSubnets() },
                allowLoopbackClients = false
            )
            if (proxy.start()) {
                embeddedProxyServer = proxy
                _proxyActualPortFlow.value = proxy.actualPort
                log("5GHz Wi-Fi Direct Dual-Protocol Proxy active (0.0.0.0:${proxy.actualPort})")
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
        _proxyActualPortFlow.value = 0
        refreshLocalAddresses()
    }

    private suspend fun ensureWifiDirectCreds(): String {
        wifiTeardownJob?.cancel()
        val groupAgeMs = System.currentTimeMillis() - lastWifiGroupReadyAtMs
        val isStaleUnjoinedGroup =
            wifiDirectCreds.isNotEmpty() &&
                !isTransferInProgress &&
                lastMacP2pIp.isEmpty() &&
                groupAgeMs > 35_000L
        if (isStaleUnjoinedGroup) {
            log("Recycling stale unjoined Wi-Fi Direct group (${groupAgeMs}ms idle) for fresh 5GHz beacons")
            stopWifiDirectGroup()
            kotlinx.coroutines.delay(450)
        }
        if (wifiDirectCreds.isNotEmpty() && hasResolvedActualGoIp && activeWifiDirectGoIp.isNotBlank()) {
            if (shareCellularInternet && embeddedProxyServer?.running != true) {
                startEmbeddedProxy()
            }
            return wifiDirectCreds
        }
        for (attempt in 1..2) {
            if (transferCancelled) return ""
            startWifiDirectGroup()
            var waited = 0
            while ((activeGroupSsid.isEmpty() || activeGroupPassphrase.isEmpty()) && waited < 4_200) {
                if (transferCancelled) return ""
                kotlinx.coroutines.delay(200)
                waited += 200
            }
            if (activeGroupSsid.isNotEmpty() && activeGroupPassphrase.isNotEmpty()) break
            if (attempt == 1 && !transferCancelled) {
                log("Retrying 5GHz Wi-Fi Direct group startup…")
                stopWifiDirectGroup()
                kotlinx.coroutines.delay(400)
            }
        }
        if (activeGroupSsid.isNotEmpty() && activeGroupPassphrase.isNotEmpty() && !hasResolvedActualGoIp) {
            var goWait = 0
            while (!hasResolvedActualGoIp && goWait < 2_000) {
                if (transferCancelled) return ""
                val resolved = resolveWifiDirectGoInterface()
                if (resolved != null && hasResolvedActualGoIp) break
                kotlinx.coroutines.delay(150)
                goWait += 150
            }
        }
        if (!hasResolvedActualGoIp || activeWifiDirectGoIp.isBlank() || activeGroupSsid.isEmpty() || activeGroupPassphrase.isEmpty()) {
            return ""
        }
        val expectedCreds = "$activeGroupSsid\t$activeGroupPassphrase\t$activeWifiDirectGoIp\t${currentHttpsPort()}"
        if (wifiDirectCreds != expectedCreds) {
            wifiDirectCreds = expectedCreds
        }
        if (shareCellularInternet && embeddedProxyServer?.running != true) {
            startEmbeddedProxy()
        }
        return wifiDirectCreds
    }

    fun getLocalTlsFingerprint(): String {
        return try {
            val ks = getOrCreateIdentityKeyStore()
            val cert = ks.getCertificate(KEYSTORE_ALIAS) as? X509Certificate ?: return ""
            sha256FingerprintHex(cert)
        } catch (_: Throwable) {
            ""
        }
    }

    private fun encryptBlePayload(plain: ByteArray, sessionKey: ByteArray): ByteArray {
        require(sessionKey.size == 32) { "BLE E2EE requires a 256-bit ephemeral session key" }
        val iv = ByteArray(12).also { random.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sessionKey, "AES"), GCMParameterSpec(128, iv))
        val sealed = cipher.doFinal(plain)
        return ByteArray(12 + sealed.size).also { out ->
            System.arraycopy(iv, 0, out, 0, 12)
            System.arraycopy(sealed, 0, out, 12, sealed.size)
        }
    }

    private fun decryptBlePayload(packet: ByteArray, sessionKey: ByteArray): ByteArray {
        require(sessionKey.size == 32) { "BLE E2EE requires a 256-bit ephemeral session key" }
        if (packet.size < 28) throw IOException("Encrypted BLE frame too short")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sessionKey, "AES"), GCMParameterSpec(128, packet, 0, 12))
        return cipher.doFinal(packet, 12, packet.size - 12)
    }

    private fun buildBoundedBleFallbackArchive(
        cachedArchive: ByteArray,
        entries: List<GlideDropCodec.OutgoingEntry>,
        totalRawBytes: Long
    ): ByteArray? {
        if (entries.isEmpty()) return ByteArray(0)
        if (!shouldAllowBleAutoFallback(totalRawBytes, hasEntries = true)) {
            log("5GHz Wi-Fi Direct unavailable — refusing slow Bluetooth LE fallback for large file (${formatBytes(totalRawBytes)})")
            return null
        }
        val maxRawBleArchiveBytes = MAX_ENCRYPTED_BLE_ARCHIVE_BYTES - 28L
        val rawArchBytes = if (cachedArchive.isNotEmpty() && cachedArchive.size.toLong() <= maxRawBleArchiveBytes) {
            cachedArchive
        } else {
            ByteArrayOutputStream().also { GlideDropCodec.writeDvzipCpio(entries, it) }.toByteArray()
        }
        if (rawArchBytes.isEmpty() || rawArchBytes.size.toLong() > maxRawBleArchiveBytes) {
            log("5GHz Wi-Fi Direct connection failed — file (${formatBytes(totalRawBytes)}) exceeds BLE fallback limit")
            return null
        }
        return rawArchBytes
    }

    private enum class W2p2TransferState {
        NOT_ATTEMPTED,
        FAILED_CLOSED,
        SUCCEEDED
    }

    private suspend fun negotiateW2p2AndTransfer(
        sock: BluetoothSocket,
        inp: InputStream,
        out: OutputStream,
        framedW2p2: Boolean,
        metaBytes: ByteArray,
        archiveBytes: ByteArray,
        entries: List<GlideDropCodec.OutgoingEntry>,
        url: String?,
        label: String,
        fileCount: Int,
        totalRawBytes: Long,
        peerDisplayName: String,
        sendPhasePrefix: String
    ): W2p2TransferState {
        if (totalRawBytes < 65_536L || entries.isEmpty()) {
            return W2p2TransferState.NOT_ATTEMPTED
        }
        reportConnecting(label, totalRawBytes, fileCount, isSending = true, phase = "Starting 5GHz Wi-Fi Direct…", peerName = peerDisplayName)
        val creds = ensureWifiDirectCreds()
        val credParts = if (creds.isNotEmpty()) creds.split('\t') else emptyList()
        val goIp = credParts.getOrNull(2)?.trim().orEmpty()
        val validCreds = creds.isNotEmpty() &&
            credParts.size >= 3 &&
            credParts[0].isNotEmpty() &&
            credParts[1].isNotEmpty() &&
            goIp.isNotEmpty() &&
            parseNumericIpBytes(goIp) != null
        if (!validCreds) {
            if (!shouldAllowBleAutoFallback(totalRawBytes, hasEntries = true)) {
                log("${sendPhasePrefix}5GHz Wi-Fi Direct group failed to initialize for large file (${formatBytes(totalRawBytes)}) — refusing slow Bluetooth LE fallback")
                return W2p2TransferState.FAILED_CLOSED
            }
            return W2p2TransferState.NOT_ATTEMPTED
        }

        var pinnedPeerFingerprint: String? = null
        var w2p2PinRejected = false
        var w2p2JoinSent = false
        var wp2pJoined = false
        var txOk = false

        try {
            val ecdhPair = generateEphemeralEcdhKeyPair()
            val localPubB64 = Base64.getEncoder().encodeToString(ecdhPair.publicKey.encoded)
            val localTlsFp = getLocalTlsFingerprint()
            if (framedW2p2) {
                val dos = out as? DataOutputStream ?: DataOutputStream(out)
                val w2p2Payload = "2\t$localPubB64\t$localTlsFp".toByteArray(StandardCharsets.UTF_8)
                dos.write("W2P2".toByteArray(StandardCharsets.US_ASCII))
                dos.writeInt(w2p2Payload.size)
                dos.writeInt(0)
                dos.write(w2p2Payload)
                dos.flush()
            } else {
                out.write("W2P2\t$localPubB64\t$localTlsFp\n".toByteArray(StandardCharsets.UTF_8))
                out.flush()
            }
            reportConnecting(label, totalRawBytes, fileCount, isSending = true, phase = "Waiting for $peerDisplayName to join 5GHz link…", peerName = peerDisplayName)
            val ecdhReply = readBleLineBounded(sock, inp, 22_000L).orEmpty()
            if (ecdhReply.startsWith("OK\t")) {
                val replyParts = ecdhReply.removePrefix("OK\t").split('\t')
                if (replyParts.isNotEmpty()) {
                    val rawPin = replyParts.getOrNull(1)?.trim().orEmpty()
                    if (!isValidSha256Fingerprint(rawPin)) {
                        w2p2PinRejected = true
                        log("${sendPhasePrefix}W2P2 reply missing or invalid peer TLS fingerprint — failing closed")
                    } else {
                        val macPubBytes = Base64.getDecoder().decode(replyParts[0])
                        pinnedPeerFingerprint = normalizeTlsFingerprint(rawPin)
                        val (sessionKey, sessionToken) = deriveSessionKeyAndToken(ecdhPair.privateKey, macPubBytes)
                        registerIncomingSessionToken(sessionToken)
                        val proxyPort = activeProxyPortOr0()
                        val joinPayload = "${credParts[0]}\t${credParts[1]}\t$goIp\t$proxyPort"
                        val encCreds = encryptAesGcm(joinPayload.toByteArray(StandardCharsets.UTF_8), sessionKey)
                        val encB64 = Base64.getEncoder().encodeToString(encCreds)
                        out.write("JOIN\t$encB64\n".toByteArray(StandardCharsets.UTF_8))
                        out.flush()
                        w2p2JoinSent = true

                        val joinReply = readBleLineBounded(sock, inp, W2P2_JOIN_REPLY_TIMEOUT_MS).orEmpty()
                        val parsedJoin = parseJoinReply(joinReply)
                        if (parsedJoin != null && isValidPeerTransferIp(parsedJoin.macIp)) {
                            wp2pJoined = true
                            val macIp = parsedJoin.macIp
                            val macRxPort = parsedJoin.macRxPort
                            val udpKeepalivePort = parsedJoin.udpKeepalivePort
                            if (isAddressInActiveP2pSubnet(macIp)) {
                                lastMacP2pIp = macIp
                                lastMacP2pPort = macRxPort
                                lastMacUdpKeepalivePort = udpKeepalivePort
                                lastMacTlsFingerprint = pinnedPeerFingerprint.orEmpty()
                                lastMacSessionToken = sessionToken
                            }
                            log("Mac ready at $macIp:$macRxPort (TLS pinned: $pinnedPeerFingerprint) — streaming over 5GHz Wi-Fi…")
                            txOk = sendOverWifiDirectHttps(
                                host = macIp,
                                port = macRxPort,
                                metaBytes = metaBytes,
                                archiveBytes = archiveBytes,
                                entries = entries,
                                url = url,
                                label = label,
                                fileCount = fileCount,
                                pinnedFingerprint = pinnedPeerFingerprint,
                                authToken = sessionToken,
                                requireSessionAuth = true,
                                udpKeepalivePort = udpKeepalivePort
                            )
                            runCatching {
                                out.write("DONE".toByteArray(StandardCharsets.US_ASCII))
                                out.flush()
                            }
                        }
                    }
                }
            } else if (ecdhReply.isNotEmpty()) {
                w2p2PinRejected = true
                log("${sendPhasePrefix}W2P2 rejected by peer ($ecdhReply) — refusing unpinned downgrade")
            }
        } catch (t: Throwable) {
            log("${sendPhasePrefix}W2P2 ECDH negotiation failed: ${t.message}")
        }

        if (!wp2pJoined && (w2p2PinRejected || w2p2JoinSent)) {
            stopWifiDirectGroup()
        }
        return when {
            wp2pJoined -> if (txOk) W2p2TransferState.SUCCEEDED else W2p2TransferState.FAILED_CLOSED
            w2p2PinRejected || w2p2JoinSent -> W2p2TransferState.FAILED_CLOSED
            else -> W2p2TransferState.NOT_ATTEMPTED
        }
    }

    @SuppressLint("MissingPermission")
    private suspend fun handleBleL2capConnection(sock: BluetoothSocket) = withContext(Dispatchers.IO) {
        val remoteAddr = sock.remoteDevice?.address ?: "BLE"
        var bleSessionKey: ByteArray? = null
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
                        val macPsm = parts.getOrNull(1)?.trim()?.toIntOrNull()?.takeIf { it > 0 } ?: 0
                        val macRssi = parts.getOrNull(2)?.trim()?.toIntOrNull() ?: -48
                        learnedMacName = macName
                        if (macPsm > 0) bleMacPsm = macPsm
                        sock.remoteDevice?.let { bleMacDevice = it }

                        val effectivePsm = if (bleMacPsm > 0) bleMacPsm else 0
                        val psmSuffix = if (effectivePsm > 0) " (PSM $effectivePsm)" else ""
                        val now = System.currentTimeMillis()
                        val wasEmpty = _peers.value.none { it.id == "ble-mac" }
                        val blePeer = GlideDropPeer(
                            id = "ble-mac",
                            name = "$macName$psmSuffix",
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
                        if (tx == null || (tx.targetPeerAddress != null && tx.targetPeerAddress != remoteAddr) || !tx.tryClaim()) {
                            val pong = "PONG\t$deviceName\t$localBlePsm\n"
                            out.write(pong.toByteArray(StandardCharsets.UTF_8))
                            out.flush()
                            break
                        } else {
                            if (pendingMacTx === tx) {
                                pendingMacTx = null
                            }
                            transferCancelled = false
                            activeTransferSocket = sock
                            var txOk = false
                            var wp2pJoined = false
                            try {
                                val dos = DataOutputStream(out)
                                when (
                                    negotiateW2p2AndTransfer(
                                        sock = sock,
                                        inp = dis,
                                        out = out,
                                        framedW2p2 = false,
                                        metaBytes = tx.metaBytes,
                                        archiveBytes = tx.archiveBytes,
                                        entries = tx.entries,
                                        url = tx.url,
                                        label = tx.label,
                                        fileCount = tx.fileCount,
                                        totalRawBytes = tx.totalRawBytes,
                                        peerDisplayName = macName,
                                        sendPhasePrefix = "Piggyback "
                                    )
                                ) {
                                    W2p2TransferState.SUCCEEDED -> {
                                        txOk = true
                                        wp2pJoined = true
                                    }
                                    W2p2TransferState.FAILED_CLOSED -> {
                                        txOk = false
                                        wp2pJoined = true
                                    }
                                    W2p2TransferState.NOT_ATTEMPTED -> {
                                        wp2pJoined = false
                                    }
                                }
                                if (!wp2pJoined && !txOk && !transferCancelled) {
                                    val startedAt = System.currentTimeMillis()
                                    val rawArchBytes = buildBoundedBleFallbackArchive(tx.archiveBytes, tx.entries, tx.totalRawBytes)
                                    if (rawArchBytes != null) {
                                        val bleEcdh = generateEphemeralEcdhKeyPair()
                                        val blePubB64 = Base64.getEncoder().encodeToString(bleEcdh.publicKey.encoded)
                                        out.write("BLEK\t$blePubB64\n".toByteArray(StandardCharsets.UTF_8))
                                        out.flush()
                                        val blekReply = readBleLineBounded(sock, dis, 15_000L).orEmpty()
                                        if (!blekReply.startsWith("OK\t")) {
                                            throw IOException("BLEK ephemeral key exchange failed (reply='$blekReply')")
                                        }
                                        val peerBlePubBytes = Base64.getDecoder().decode(blekReply.removePrefix("OK\t").trim())
                                        val ephemeralBleKey = deriveBleFrameKey(bleEcdh.privateKey, peerBlePubBytes)
                                        try {
                                            val encMeta = encryptBlePayload(tx.metaBytes, ephemeralBleKey)
                                            val encArch = if (rawArchBytes.isNotEmpty()) encryptBlePayload(rawArchBytes, ephemeralBleKey) else ByteArray(0)
                                            if (!isValidBleFrameBounds(encMeta.size, encArch.size, isEncryptedBle = true)) {
                                                throw IOException("Encrypted BLE frame exceeds cap (meta=${encMeta.size}, arch=${encArch.size})")
                                            }
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
                                            val ackStr = readBleLineBounded(sock, dis, ADRE_ACK_TIMEOUT_MS).orEmpty().trim()
                                            reportProgress(tx.label, 100, total, total, startedAt, tx.fileCount, isSending = true)
                                            txOk = ackStr == "OK" && !transferCancelled
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
                                        } finally {
                                            ephemeralBleKey.fill(0)
                                        }
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
                    val (macPubB64, macCertFingerprint) = parseW2P2Line(reqLine)
                    if (macPubB64.isNotEmpty() && isValidSha256Fingerprint(macCertFingerprint)) {
                        try {
                            val macPubBytes = Base64.getDecoder().decode(macPubB64)
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
                                val credFields = creds.split('\t')
                                val ssidOut = credFields.getOrNull(0).orEmpty()
                                val passOut = credFields.getOrNull(1).orEmpty()
                                val goIpOut = credFields.getOrNull(2)?.trim().orEmpty()
                                val httpsPortOut = credFields.getOrNull(3)?.toIntOrNull()?.takeIf { it in 1..65535 } ?: currentHttpsPort()
                                val proxyPortOut = activeProxyPortOr0()
                                if (ssidOut.isNotEmpty() && passOut.isNotEmpty() && parseNumericIpBytes(goIpOut) != null) {
                                    val ecdhPair = generateEphemeralEcdhKeyPair()
                                    val (sessionKey, expectedToken) = deriveSessionKeyAndToken(ecdhPair.privateKey, macPubBytes)
                                    registerIncomingSessionToken(expectedToken)
                                    val localTlsFp = getLocalTlsFingerprint()
                                    val fullCreds = "$ssidOut\t$passOut\t$goIpOut\t$httpsPortOut\t$localTlsFp\t$proxyPortOut"
                                    val encCreds = encryptAesGcm(fullCreds.toByteArray(StandardCharsets.UTF_8), sessionKey)
                                    val androidPubB64 = Base64.getEncoder().encodeToString(ecdhPair.publicKey.encoded)
                                    val encCredsB64 = Base64.getEncoder().encodeToString(encCreds)
                                    out.write("OK\t$androidPubB64\t$encCredsB64\n".toByteArray(StandardCharsets.UTF_8))
                                    out.flush()
                                    clearLastMacSessionState()
                                    lastMacTlsFingerprint = normalizeTlsFingerprint(macCertFingerprint!!)
                                    reportConnecting(
                                        label = "Incoming transfer",
                                        total = 0L,
                                        fileCount = 1,
                                        isSending = false,
                                        phase = "Waiting for peer to join 5GHz link…",
                                        peerName = learnedMacName ?: "MacBook Pro"
                                    )
                                    wifiTeardownJob?.cancel()
                                    wifiTeardownJob = scope.launch {
                                        kotlinx.coroutines.delay(40_000L)
                                        val recentDiscover = (System.currentTimeMillis() - lastIncomingDiscoverAtMs) < 35_000L
                                        if (!recentDiscover && _transferProgress.value?.isConnecting == true && activeTransferSocket == null) {
                                            clearProgressNotification()
                                        }
                                        kotlinx.coroutines.delay(25_000L)
                                        val stillRecentDiscover = (System.currentTimeMillis() - lastIncomingDiscoverAtMs) < 35_000L
                                        if (!isTransferInProgress && !stillRecentDiscover && lastMacP2pIp.isEmpty() && activeTransferSocket == null) {
                                            stopWifiDirectGroup()
                                        }
                                    }
                                    log("BLE W2P2 ECDH handshake with $remoteAddr -> 5GHz P2P Ready (TLS pinned: $lastMacTlsFingerprint)")
                                    continue
                                }
                            }
                        } catch (t: Throwable) {
                            log("BLE W2P2 error with $remoteAddr: ${t.message}")
                        }
                    } else {
                        log("BLE W2P2 rejected from $remoteAddr: missing or invalid peer TLS fingerprint")
                    }
                    out.write("NO\n".toByteArray(StandardCharsets.UTF_8))
                    out.flush()
                    continue
                }
                if (magicStr == "WP2P") {
                    log("Rejected unpinned legacy WP2P downgrade attempt from $remoteAddr")
                    out.write("NO\n".toByteArray(StandardCharsets.UTF_8))
                    out.flush()
                    break
                }
                if (magicStr == "BLEK") {
                    val metaLen = dis.readInt()
                    val archLen = dis.readInt()
                    if (bleSessionKey != null || metaLen !in 1..4096 || archLen != 0) {
                        log("BLE L2CAP rejected invalid BLEK frame from $remoteAddr (meta=$metaLen, arch=$archLen)")
                        out.write("NO\n".toByteArray(StandardCharsets.US_ASCII))
                        out.flush()
                        break
                    }
                    val pubBytesRaw = ByteArray(metaLen)
                    dis.readFully(pubBytesRaw)
                    try {
                        val macPubB64 = String(pubBytesRaw, StandardCharsets.UTF_8).trim()
                        val macPubBytes = Base64.getDecoder().decode(macPubB64)
                        val ecdhPair = generateEphemeralEcdhKeyPair()
                        bleSessionKey = deriveBleFrameKey(ecdhPair.privateKey, macPubBytes)
                        val androidPubB64 = Base64.getEncoder().encodeToString(ecdhPair.publicKey.encoded)
                        out.write("OK\t$androidPubB64\n".toByteArray(StandardCharsets.UTF_8))
                        out.flush()
                        continue
                    } catch (t: Throwable) {
                        log("BLEK ECDH key agreement failed from $remoteAddr: ${t.message}")
                        out.write("NO\n".toByteArray(StandardCharsets.US_ASCII))
                        out.flush()
                        break
                    }
                }
                val isEncryptedBle = (magicStr == "ADRE")
                if (!isEncryptedBle) {
                    if (magicStr == "ADRP") {
                        log("BLE L2CAP rejected plaintext ADRP frame from $remoteAddr — ephemeral E2EE required")
                        out.write("NO\r\n".toByteArray(StandardCharsets.US_ASCII))
                        out.flush()
                    } else {
                        log("BLE L2CAP unknown magic from $remoteAddr: $magicStr")
                    }
                    break
                }
                val activeBleKey = bleSessionKey
                if (activeBleKey == null) {
                    log("BLE L2CAP rejected ADRE frame without prior BLEK ephemeral ECDH from $remoteAddr")
                    out.write("NO\r\n".toByteArray(StandardCharsets.US_ASCII))
                    out.flush()
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
                log("BLE L2CAP RX from $remoteAddr (meta=$metaLen B, archive=$archiveLen B, e2ee=true)")

                val rawMetaBytes = ByteArray(metaLen)
                dis.readFully(rawMetaBytes)
                val metaBytes = decryptBlePayload(rawMetaBytes, activeBleKey)
                val askDict = GlideDropCodec.decodeBplistDict(metaBytes)
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
                    "GlideDrop transfer (${formatBytes(archiveLen.toLong())})"
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

                val fileLabel = fileNames.firstOrNull() ?: "GlideDrop file"
                val fileCount = maxOf(1, fileNames.size)

                if (archiveLen > 0) {
                    val downloads = File(
                        Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
                        "GlideDrop"
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
                        if (archiveLen.toLong() > MAX_ENCRYPTED_BLE_ARCHIVE_BYTES) {
                            throw IOException("Encrypted BLE archive exceeds 30 MB safe limit: $archiveLen bytes")
                        }
                        val encBuf = ByteArrayOutputStream(archiveLen)
                        bounded.copyTo(encBuf)
                        val decArch = decryptBlePayload(encBuf.toByteArray(), activeBleKey)
                        GlideDropCodec.extractDvzipCpio(decArch.inputStream(), downloads, context)
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
                        log("Saved via BLE to Downloads/GlideDrop/${f.name} (${formatBytes(f.length())})")
                    }
                }

                out.write("OK\r\n".toByteArray(StandardCharsets.US_ASCII))
                out.flush()
                break
            }
        } catch (t: Throwable) {
            log("BLE L2CAP RX error ($remoteAddr): ${t.message}")
        } finally {
            bleSessionKey?.fill(0)
            bleSessionKey = null
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
        entries: List<GlideDropCodec.OutgoingEntry>,
        url: String?
    ): Boolean = withContext(Dispatchers.IO) {
        transferMutex.withLock {
            acquireTransferLocks()
            transferCancelled = false
            try {
                val fileDicts = entries.map { e ->
                    mapOf(
                        "FileName" to e.name,
                        "FileType" to GlideDropCodec.utiForName(e.name),
                        "FileSize" to e.size,
                        "FileBomPath" to "./${e.name}",
                        "FileIsDirectory" to false
                    )
                }
                val metaBytes = GlideDropCodec.encodeBplist(
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
                    GlideDropCodec.writeDvzipCpio(entries, bos)
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

                // 1. Fast path: if Mac is already joined to our 5GHz Wi-Fi Direct group with a pinned fingerprint + session token, stream directly at 5GHz speed!
                val cachedIp = lastMacP2pIp
                val cachedPort = lastMacP2pPort.takeIf { it in 1..65535 } ?: DEFAULT_MAC_RX_PORT
                val cachedUdpPort = lastMacUdpKeepalivePort.takeIf { it in 1..65535 } ?: DEFAULT_UDP_KEEPALIVE_PORT
                val cachedFp = lastMacTlsFingerprint
                val cachedToken = lastMacSessionToken
                if (isAddressInActiveP2pSubnet(cachedIp) && isValidSha256Fingerprint(cachedFp) && cachedToken.isNotBlank()) {
                    reportConnecting(label, totalRawBytes, fileCount, isSending = true, phase = "Connecting over 5GHz Wi-Fi Direct…", peerName = targetPeerLabel)
                    log("Streaming directly over active 5GHz Wi-Fi Direct link ($cachedIp:$cachedPort)…")
                    if (
                        sendOverWifiDirectHttps(
                            host = cachedIp,
                            port = cachedPort,
                            metaBytes = metaBytes,
                            archiveBytes = archiveBytes,
                            entries = entries,
                            url = url,
                            label = label,
                            fileCount = fileCount,
                            pinnedFingerprint = cachedFp,
                            authToken = cachedToken,
                            requireSessionAuth = true,
                            udpKeepalivePort = cachedUdpPort
                        )
                    ) {
                        return@withLock true
                    }
                    clearLastMacSessionState()
                }

                // 2. Queue transfer for Mac's 1.5s BLE L2CAP heartbeat (works even when Android BLE scan is blocked by OS Location toggle)
                val initialConnectPhase = if (totalRawBytes >= 65_536L && entries.isNotEmpty()) {
                    "Preparing 5GHz Wi-Fi Direct…"
                } else {
                    "Connecting via Bluetooth LE…"
                }
                reportConnecting(label, totalRawBytes, fileCount, isSending = true, phase = initialConnectPhase, peerName = targetPeerLabel)
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
                val queueStartNs = System.nanoTime()
                val initialHeartbeatDeadlineNs = queueStartNs + initialHeartbeatWaitMs * 1_000_000L
                val totalHeartbeatDeadlineNs = queueStartNs + 14_000L * 1_000_000L
                while (System.nanoTime() < initialHeartbeatDeadlineNs && !deferred.isCompleted && !tx.isClaimed && !transferCancelled) {
                    kotlinx.coroutines.delay(100)
                }
                if (transferCancelled) {
                    if (pendingMacTx === tx) pendingMacTx = null
                    tx.tryClaim()
                    return@withLock false
                }
                if (deferred.isCompleted || tx.isClaimed) {
                    return@withLock deferred.await()
                }

                // 4. Fallback: if Mac heartbeat did not arrive within initial window and we have a scanned BLE peripheral, try direct L2CAP
                val dev = bleMacDevice
                var psm = bleMacPsm
                if (dev != null && psm <= 0 && !tx.isClaimed) {
                    val resolved = resolveMacGattPsm(dev)
                    if (resolved > 0) {
                        bleMacPsm = resolved
                        psm = resolved
                    }
                }
                if (dev != null && tx.tryClaim()) {
                    if (pendingMacTx === tx) {
                        pendingMacTx = null
                    }
                    var lastErr: Throwable? = null
                    for (attempt in 1..2) {
                        if (transferCancelled) return@withLock false
                        val targetDev = bleMacDevice ?: dev
                        var targetPsm = if (bleMacPsm > 0) bleMacPsm else psm
                        if (targetPsm <= 0 || attempt > 1) {
                            val resolved = resolveMacGattPsm(targetDev)
                            if (resolved > 0) {
                                bleMacPsm = resolved
                                psm = resolved
                                targetPsm = resolved
                            }
                        }
                        if (targetPsm <= 0) {
                            lastErr = IOException("BLE L2CAP PSM unavailable for peer ${targetDev.address}")
                            break
                        }
                        stopBleScanOnly()
                        kotlinx.coroutines.delay(80)
                        try {
                            reportConnecting(label, totalRawBytes, fileCount, isSending = true, phase = initialConnectPhase, peerName = targetPeerLabel)
                            log("Connecting to Mac via Direct BLE L2CAP (${targetDev.address} PSM $targetPsm, attempt $attempt)\u2026")
                            targetDev.createInsecureL2capChannel(targetPsm).use { sock ->
                                activeTransferSocket = sock
                                sock.connect()
                                val dos = DataOutputStream(BufferedOutputStream(sock.outputStream, 65536))
                                val inp = sock.inputStream

                                when (
                                    negotiateW2p2AndTransfer(
                                        sock = sock,
                                        inp = inp,
                                        out = dos,
                                        framedW2p2 = true,
                                        metaBytes = metaBytes,
                                        archiveBytes = archiveBytes,
                                        entries = entries,
                                        url = url,
                                        label = label,
                                        fileCount = fileCount,
                                        totalRawBytes = totalRawBytes,
                                        peerDisplayName = targetPeerLabel,
                                        sendPhasePrefix = "Direct "
                                    )
                                ) {
                                    W2p2TransferState.SUCCEEDED -> return@withLock true
                                    W2p2TransferState.FAILED_CLOSED -> return@withLock false
                                    W2p2TransferState.NOT_ATTEMPTED -> Unit
                                }

                                val startedAt = System.currentTimeMillis()
                                val rawArchBytes = buildBoundedBleFallbackArchive(archiveBytes, entries, totalRawBytes)
                                    ?: return@withLock false
                                val bleEcdh = generateEphemeralEcdhKeyPair()
                                val blePubBytes = Base64.getEncoder().encodeToString(bleEcdh.publicKey.encoded).toByteArray(StandardCharsets.UTF_8)
                                dos.write("BLEK".toByteArray(StandardCharsets.US_ASCII))
                                dos.writeInt(blePubBytes.size)
                                dos.writeInt(0)
                                dos.write(blePubBytes)
                                dos.flush()
                                val blekReply = readBleLineBounded(sock, inp, 15_000L).orEmpty()
                                if (!blekReply.startsWith("OK\t")) {
                                    throw IOException("Direct BLEK ephemeral key exchange failed (reply='$blekReply')")
                                }
                                val peerBlePubBytes = Base64.getDecoder().decode(blekReply.removePrefix("OK\t").trim())
                                val ephemeralBleKey = deriveBleFrameKey(bleEcdh.privateKey, peerBlePubBytes)
                                val ok: Boolean
                                try {
                                    val encMeta = encryptBlePayload(metaBytes, ephemeralBleKey)
                                    val encArch = if (rawArchBytes.isNotEmpty()) encryptBlePayload(rawArchBytes, ephemeralBleKey) else ByteArray(0)
                                    if (!isValidBleFrameBounds(encMeta.size, encArch.size, isEncryptedBle = true)) {
                                        throw IOException("Encrypted BLE frame exceeds cap (meta=${encMeta.size}, arch=${encArch.size})")
                                    }
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
                                    val ackStr = readBleLineBounded(sock, inp, ADRE_ACK_TIMEOUT_MS).orEmpty().trim()
                                    reportProgress(label, 100, encTotal, encTotal, startedAt, fileCount, isSending = true)
                                    ok = ackStr == "OK" && !transferCancelled
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
                                } finally {
                                    ephemeralBleKey.fill(0)
                                }
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
                } else if (dev != null && (deferred.isCompleted || tx.isClaimed)) {
                    return@withLock deferred.await()
                }

                // Wait remaining window for Mac BLE L2CAP heartbeat pickup using a fresh unclaimed PendingMacTx if direct L2CAP failed
                val activeWaitTx = if (!tx.isClaimed && !deferred.isCompleted) {
                    pendingMacTx = tx
                    tx
                } else if (!transferCancelled && System.nanoTime() < totalHeartbeatDeadlineNs) {
                    val retryDeferred = CompletableDeferred<Boolean>()
                    PendingMacTx(
                        metaBytes = metaBytes,
                        archiveBytes = archiveBytes,
                        entries = entries,
                        url = url,
                        label = label,
                        fileCount = fileCount,
                        totalRawBytes = totalRawBytes,
                        result = retryDeferred,
                        targetPeerAddress = targetAddr
                    ).also { pendingMacTx = it }
                } else {
                    null
                }
                if (activeWaitTx != null) {
                    while (System.nanoTime() < totalHeartbeatDeadlineNs && !activeWaitTx.result.isCompleted && !activeWaitTx.isClaimed && !transferCancelled) {
                        kotlinx.coroutines.delay(150)
                    }
                    if (pendingMacTx === activeWaitTx && !activeWaitTx.isClaimed) {
                        pendingMacTx = null
                    }
                    if (transferCancelled) return@withLock false
                    if (activeWaitTx.result.isCompleted || activeWaitTx.isClaimed) {
                        return@withLock activeWaitTx.result.await()
                    }
                }
                if (transferCancelled) return@withLock false
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
        entries: List<GlideDropCodec.OutgoingEntry>,
        url: String?,
        label: String,
        fileCount: Int,
        pinnedFingerprint: String? = null,
        authToken: String = "",
        requireSessionAuth: Boolean = true,
        udpKeepalivePort: Int = DEFAULT_UDP_KEEPALIVE_PORT
    ): Boolean {
        acquireTransferLocks()
        wifiTeardownJob?.cancel()
        var keepAliveJob: Job? = null
        var writeWatchdogJob: Job? = null
        var txSuccess = false
        return try {
            val normalizedPin = pinnedFingerprint?.let { normalizeTlsFingerprint(it) }.orEmpty()
            if (!isValidSha256Fingerprint(normalizedPin)) {
                log("FATAL: Refusing unpinned 5GHz Wi-Fi Direct HTTPS connection to $host:$port")
                return false
            }
            if (requireSessionAuth && authToken.isBlank()) {
                log("FATAL: Missing W2P2 ECDH session bearer token for $host:$port")
                return false
            }
            val sslCtx = buildPinnedClientSslContext(normalizedPin, random)
            var rawSock: Socket? = null
            var lastConnErr: Throwable? = null
            val isP2pTarget = isAddressInActiveP2pSubnet(host)
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
                val candidate = Socket()
                try {
                    runCatching {
                        candidate.tcpNoDelay = true
                        candidate.keepAlive = true
                        candidate.sendBufferSize = 4_194_304
                        candidate.receiveBufferSize = 4_194_304
                    }
                    if (isP2pTarget) {
                        trackedP2pNetwork?.let { net ->
                            runCatching { net.bindSocket(candidate) }.onFailure {
                                if (trackedP2pNetwork === net) trackedP2pNetwork = null
                            }
                        }
                    }
                    candidate.connect(InetSocketAddress(host, port), 2500)
                    rawSock = candidate
                    break
                } catch (e: Throwable) {
                    runCatching { candidate.close() }
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
                // Bound to trackedP2pNetwork so pulses egress on p2p-wlan0-* rather than wlan0
                if (isP2pTarget) {
                    val p2pNetwork = trackedP2pNetwork
                    keepAliveJob = scope.launch(Dispatchers.IO) {
                        DatagramSocket().use { udpSock ->
                            runCatching { (trackedP2pNetwork ?: p2pNetwork)?.bindSocket(udpSock) }
                            val dummy = byteArrayOf(0xAD.toByte())
                            val targetAddr = InetAddress.getByName(host)
                            val keepaliveTargetPort = udpKeepalivePort.takeIf { it in 1..65535 } ?: DEFAULT_UDP_KEEPALIVE_PORT
                            while (isActive && activeTransferSocket != null && !transferCancelled) {
                                runCatching { udpSock.send(DatagramPacket(dummy, 1, targetAddr, keepaliveTargetPort)) }
                                kotlinx.coroutines.delay(2000)
                            }
                        }
                    }
                }
                (sslCtx.socketFactory.createSocket(raw, host, port, true) as SSLSocket).use { tls ->
                    activeTransferSocket = tls
                    configureClientTlsSocket(tls, isPinned = normalizedPin.isNotEmpty())
                    tls.startHandshake()
                    if (normalizedPin.isNotEmpty()) {
                        val peerCerts = tls.session.peerCertificates
                        val serverCert = peerCerts.firstOrNull() as? X509Certificate
                            ?: throw SSLPeerUnverifiedException("No server certificate presented by $host:$port")
                        val actualFp = sha256FingerprintHex(serverCert)
                        if (!MessageDigest.isEqual(
                                actualFp.toByteArray(StandardCharsets.US_ASCII),
                                normalizedPin.toByteArray(StandardCharsets.US_ASCII)
                            )
                        ) {
                            log("FATAL: TLS certificate fingerprint pinning mismatch! Expected: $normalizedPin, Actual: $actualFp")
                            throw SSLPeerUnverifiedException("Certificate fingerprint pinning failed! Expected $normalizedPin, got $actualFp")
                        }
                        log("TLS certificate fingerprint pinned and verified: $actualFp")
                    }
                    val inp = BufferedInputStream(tls.inputStream, 65536)
                    val rawOut = tls.outputStream
                    val cleanHostHdr = host.trim().removeSurrounding("[", "]").substringBefore('%')
                    val hostHeader = if (cleanHostHdr.contains(':')) "[$cleanHostHdr]:$port" else "$cleanHostHdr:$port"

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
                        append("Host: $hostHeader\r\n")
                        if (authToken.isNotBlank()) {
                            append("X-GlideDrop-Token: $authToken\r\n")
                        }
                        append("Content-Type: application/octet-stream\r\n")
                        append("Content-Length: ${metaBytes.size}\r\n")
                        append("Connection: keep-alive\r\n\r\n")
                    }
                    rawOut.write(askHdr.toByteArray(StandardCharsets.US_ASCII))
                    rawOut.write(metaBytes)
                    rawOut.flush()

                    val askStatus = readHttpLineBounded(inp).orEmpty()
                    val askHeaders = LinkedHashMap<String, String>()
                    var askHdrCount = 0
                    var askHdrBytes = askStatus.length + 2
                    while (true) {
                        val l = readHttpLineBounded(inp) ?: break
                        if (l.isEmpty()) break
                        askHdrCount++
                        askHdrBytes += l.length + 2
                        if (askHdrCount > MAX_HTTP_HEADER_LINES || askHdrBytes > MAX_HTTP_HEADER_BYTES) {
                            throw HttpFramingException(431, "Request Header Fields Too Large", "Response headers too large")
                        }
                        val c = l.indexOf(':')
                        if (c > 0) askHeaders[l.substring(0, c).trim().lowercase(java.util.Locale.US)] = l.substring(c + 1).trim()
                    }
                    readHttpBodyBytesBounded(inp, askHeaders, MAX_HTTP_META_BODY_BYTES)
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
                            append("Host: $hostHeader\r\n")
                            if (authToken.isNotBlank()) {
                                append("X-GlideDrop-Token: $authToken\r\n")
                            }
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
                        GlideDropCodec.writeDvzipCpio(entries, chunkedOut) { doneBytes ->
                            if (transferCancelled) throw IOException("Transfer cancelled")
                            val now = System.currentTimeMillis()
                            if (now - lastUpdate >= 350L || doneBytes >= total) {
                                lastUpdate = now
                                val pct = ((doneBytes * 100L) / total).toInt().coerceIn(0, 99)
                                reportProgress(label, pct, minOf(doneBytes, total), total, startedAt, fileCount, isSending = true)
                            }
                        }
                        chunkedOut.close()
                        writeWatchdogJob.cancel()
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
            when (
                resolveWifiDirectPostTransferAction(
                    txSuccess = txSuccess,
                    transferCancelled = transferCancelled,
                    isP2pHost = isAddressInActiveP2pSubnet(host),
                    hasWifiDirectCreds = wifiDirectCreds.isNotEmpty()
                )
            ) {
                WifiDirectPostTransferAction.PRESERVE_FOR_REUSE_AND_SCHEDULE_TEARDOWN -> {
                    wifiTeardownJob?.cancel()
                    wifiTeardownJob = scope.launch {
                        kotlinx.coroutines.delay(5000)
                        if (!isTransferInProgress) {
                            stopWifiDirectGroup()
                        }
                    }
                }
                WifiDirectPostTransferAction.CLEAR_AND_STOP_GROUP_NOW -> {
                    clearLastMacSessionState()
                    wifiTeardownJob?.cancel()
                    stopWifiDirectGroup()
                }
                WifiDirectPostTransferAction.CLEAR_ONLY -> {
                    clearLastMacSessionState()
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

    private fun startHttpsReceiver() {
        scope.launch {
            try {
                // Accept on a standard ServerSocket without oversized pre-bind SO_RCVBUF so
                // SYN-ACK window scaling stays compatible and unauthorized TCP peers fail fast.
                var srv = java.net.ServerSocket()
                srv.reuseAddress = true
                try {
                    srv.bind(InetSocketAddress(GLIDEDROP_PORT), 32)
                } catch (_: BindException) {
                    log("Port $GLIDEDROP_PORT busy — binding HTTPS receiver to ephemeral port")
                    runCatching { srv.close() }
                    srv = java.net.ServerSocket().apply {
                        reuseAddress = true
                        bind(InetSocketAddress(0), 32)
                    }
                }
                val boundPort = srv.localPort.takeIf { it > 0 } ?: GLIDEDROP_PORT
                actualHttpsPort = boundPort
                if (hasResolvedActualGoIp && activeWifiDirectGoIp.isNotBlank() && activeGroupSsid.isNotEmpty() && activeGroupPassphrase.isNotEmpty()) {
                    wifiDirectCreds = "$activeGroupSsid\t$activeGroupPassphrase\t$activeWifiDirectGoIp\t$boundPort"
                }
                serverSocket = srv
                refreshLocalAddresses()
                log("5GHz P2P HTTPS receiver listening on port $boundPort")
                while (_running.value) {
                    val client = try {
                        srv.accept()
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

    private suspend fun handleReceiverConnection(rawClient: Socket) = withContext(Dispatchers.IO) {
        val remoteIp = rawClient.inetAddress?.hostAddress.orEmpty().substringBefore('%')
        if (!isReceiverRequestClientAllowed(remoteIp, activeP2pSubnets(), hasActiveIncomingSessionTokens(), allowLoopback = false)) {
            log("Rejecting non-P2P incoming connection from $remoteIp")
            runCatching { rawClient.close() }
            return@withContext
        }
        val remote = "$remoteIp:${rawClient.port}"
        var didUpload = false
        var tlsSockRef: SSLSocket? = null
        try {
            rawClient.soTimeout = 30_000
            rawClient.tcpNoDelay = true
            rawClient.keepAlive = true
            val sock = (serverSslContext.socketFactory.createSocket(
                rawClient,
                remoteIp,
                rawClient.port,
                true
            ) as SSLSocket).apply {
                useClientMode = false
                wantClientAuth = false
                needClientAuth = false
                soTimeout = 30_000
            }
            tlsSockRef = sock
            configureHighThroughputTls(sock)
            sock.startHandshake()
            val inp = BufferedInputStream(sock.inputStream, 1_048_576)
            val out = BufferedOutputStream(sock.outputStream, 65536)
            var lastSenderName = "MacBook Pro"
            var lastAskLabel = "Incoming Transfer"
            var lastAskFileCount = 1
            var lastAskTotalBytes = 0L
            var connectionAskApproved = false

            while (_running.value) {
                val head = try {
                    readHttpRequestHead(inp)
                } catch (e: HttpFramingException) {
                    log("Rejected malformed/oversized HTTP request from $remote: ${e.message}")
                    writeHttpResponse(out, e.statusCode, e.reason, ByteArray(0), close = true)
                    break
                } ?: break
                val method = head.method
                val path = head.path
                val headers = head.headers

                if (!isValidIncomingSessionToken(headers["x-glidedrop-token"])) {
                    log("Rejecting unauthenticated $method $path from $remote (missing/invalid X-GlideDrop-Token)")
                    writeHttpResponse(out, 401, "Unauthorized", "Unauthorized\n".toByteArray(StandardCharsets.US_ASCII), close = true)
                    break
                }
                if (isAddressInActiveP2pSubnet(remoteIp)) {
                    lastMacP2pIp = remoteIp
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
                        lastIncomingDiscoverAtMs = System.currentTimeMillis()
                        try {
                            readHttpBodyBytesBounded(inp, headers, MAX_HTTP_META_BODY_BYTES)
                        } catch (e: HttpFramingException) {
                            writeHttpResponse(out, e.statusCode, e.reason, ByteArray(0), close = true)
                            break
                        }
                        reportConnecting(
                            label = "Incoming transfer",
                            total = 0L,
                            fileCount = 1,
                            isSending = false,
                            phase = "Handshaking over 5GHz Wi-Fi Direct…",
                            peerName = learnedMacName ?: "MacBook Pro"
                        )
                        val resp = GlideDropCodec.encodeBplist(
                            mapOf(
                                "ReceiverComputerName" to deviceName,
                                "ReceiverModelName" to deviceModel,
                                "ReceiverMediaCapabilities" to GlideDropCodec.MEDIA_CAPABILITIES_BYTES,
                                "IsAirDropable" to true // Apple AWDL Discover wire-protocol bplist key
                            )
                        )
                        writeHttpResponse(out, 200, "OK", resp)
                    }
                    method == "POST" && path == "/Ask" -> {
                        transferCancelled = false
                        activeTransferSocket = sock
                        val bodyBytes = try {
                            readHttpBodyBytesBounded(inp, headers, MAX_HTTP_META_BODY_BYTES)
                        } catch (e: HttpFramingException) {
                            writeHttpResponse(out, e.statusCode, e.reason, ByteArray(0), close = true)
                            break
                        }
                        val askDict = GlideDropCodec.decodeBplistDict(bodyBytes)
                        val sender = askDict["SenderComputerName"]?.toString() ?: "MacBook Pro"
                        lastSenderName = sender
                        if (sender.isNotBlank()) learnedMacName = sender
                        @Suppress("UNCHECKED_CAST")
                        val files = (askDict["Files"] as? List<Map<String, Any?>>).orEmpty()
                        @Suppress("UNCHECKED_CAST")
                        val items = (askDict["Items"] as? List<Any?>).orEmpty()

                        val fileNames = files.mapNotNull { it["FileName"]?.toString() }
                        val totalAskBytes = files.sumOf { (it["FileSize"] as? Number)?.toLong() ?: 0L }
                        lastAskLabel = fileNames.firstOrNull() ?: "Incoming Transfer"
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
                            "GlideDrop item"
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

                        val resp = GlideDropCodec.encodeBplist(
                            mapOf(
                                "ReceiverComputerName" to deviceName,
                                "ReceiverModelName" to deviceModel,
                                "ReceiverMediaCapabilities" to GlideDropCodec.MEDIA_CAPABILITIES_BYTES,
                                "IsAirDropable" to true // Apple AWDL Discover wire-protocol bplist key
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
                            "GlideDrop"
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
                            GlideDropCodec.extractDvzipCpio(bodyStream, downloads, context)
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
                            log("Saved to Downloads/GlideDrop/${f.name} (${formatBytes(f.length())})")
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
            if (activeTransferSocket === tlsSockRef) activeTransferSocket = null
            clearProgressNotification()
            runCatching { tlsSockRef?.close() }
            runCatching { rawClient.close() }
            if (didUpload || transferCancelled) {
                clearLastMacSessionState()
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
        peer: GlideDropPeer,
        uris: List<Uri>,
        onComplete: ((Boolean) -> Unit)? = null
    ): Job = scope.launch {
        val ok = sendUrisToPeer(peer, uris)
        onComplete?.let { cb ->
            withContext(Dispatchers.Main) { cb(ok) }
        }
    }

    fun sendTextSnippetAsync(
        peer: GlideDropPeer,
        text: String,
        onComplete: ((Boolean) -> Unit)? = null
    ): Job = scope.launch {
        val ok = sendTextSnippetToPeer(peer, text)
        onComplete?.let { cb ->
            withContext(Dispatchers.Main) { cb(ok) }
        }
    }

    suspend fun sendUrisToPeer(peer: GlideDropPeer, uris: List<Uri>): Boolean =
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

    suspend fun sendTextSnippetToPeer(peer: GlideDropPeer, text: String): Boolean =
        withContext(Dispatchers.IO) {
            val trimmed = text.trim()
            if (trimmed.isEmpty()) return@withContext false
            if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
                return@withContext sendUrlToPeer(peer, trimmed)
            }
            val bytes = trimmed.toByteArray(StandardCharsets.UTF_8)
            val stamp = java.text.SimpleDateFormat("HHmmss", java.util.Locale.US).format(Date())
            val entry = GlideDropCodec.OutgoingEntry(
                name = "Note-$stamp.txt",
                size = bytes.size.toLong(),
                openStream = { bytes.inputStream() }
            )
            return@withContext sendOverBleL2cap(listOf(entry), null)
        }

    suspend fun sendUrlToPeer(peer: GlideDropPeer, url: String): Boolean =
        withContext(Dispatchers.IO) {
            return@withContext sendOverBleL2cap(emptyList(), url)
        }

    private fun resolveUriEntry(uri: Uri): GlideDropCodec.OutgoingEntry? {
        if (uri.scheme == "file") {
            val f = File(uri.path ?: return null)
            if (!f.isFile) return null
            return GlideDropCodec.OutgoingEntry(
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
        return GlideDropCodec.OutgoingEntry(
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

    @Synchronized
    private fun getOrCreateIdentityKeyStore(): KeyStore {
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
                .setCertificateSubject(X500Principal("CN=glidedrop"))
                .setCertificateSerialNumber(BigInteger.ONE)
                .setCertificateNotBefore(Date(System.currentTimeMillis() - 86_400_000L))
                .setCertificateNotAfter(Date(System.currentTimeMillis() + 315_360_000_000L))
                .build()
            kpg.initialize(spec)
            kpg.generateKeyPair()
        }
        return ks
    }

    private fun buildServerSslContext(): SSLContext {
        val ks = getOrCreateIdentityKeyStore()
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(ks, null)
        }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(null as KeyStore?)
        }
        return SSLContext.getInstance("TLS").apply {
            init(kmf.keyManagers, tmf.trustManagers, random)
        }
    }

    private fun readHttpLine(inp: InputStream): String? = readHttpLineBounded(inp)

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
