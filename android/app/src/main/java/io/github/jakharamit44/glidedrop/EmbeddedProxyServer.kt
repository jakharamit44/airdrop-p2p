package io.github.jakharamit44.glidedrop

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.URI
import java.net.UnknownHostException
import java.nio.charset.StandardCharsets
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Dual-Protocol Embedded Proxy Server (SOCKS5 + HTTP CONNECT & Forward Proxy) on port 1080.
 *
 * Runs on Android during Wi-Fi Direct P2P transfers so connected macOS peers
 * can route internet traffic through Android's active upstream cellular connection.
 *
 * Security & Reliability features:
 * - Listens on wildcard 0.0.0.0:1080 to avoid EADDRNOTAVAIL during async P2P IP allocation.
 * - Client IP Whitelist: strictly accepts connections only from 192.168.49.0/24, 127.0.0.1, ::1.
 * - SSRF Protection: blocks loopback, wildcard, link-local/cloud metadata, RFC 1918 private LAN,
 *   IPv6 ULA/site-local, and multicast targets across all destination ports (1-65535), both
 *   pre-DNS (including obfuscated numeric/hex/octal IPv4 and IPv6 literals) and post-DNS.
 * - Dual-Protocol parser multiplexing SOCKS5 (0x05) and HTTP (CONNECT, GET, POST, HEAD, etc.).
 * - Constant-memory sliding-window HTTP header parser (bounded at 8 KB), strips hop-by-hop and
 *   proxy credential headers, blocks Upgrade protocol-switch requests, and enforces Connection: close.
 * - Bounded concurrency (max 128 clients).
 * - Upstream routing: binds outbound sockets and resolves DNS via ConnectivityManager active internet network.
 * - Bidirectional streaming with half-close handling (shutdownOutput) and immediate error teardown.
 */
class EmbeddedProxyServer internal constructor(
    private val context: Context? = null,
    val port: Int = DEFAULT_PROXY_PORT,
    private val logger: ((String) -> Unit)? = null,
    private val outboundAddressResolver: ((Network?, String) -> Array<InetAddress>)? = null,
    private val outboundSocketConnectHook: ((Socket, InetAddress, Int, Int) -> Unit)? = null
) : Closeable {

    constructor(
        context: Context? = null,
        port: Int = DEFAULT_PROXY_PORT,
        logger: ((String) -> Unit)? = null
    ) : this(context, port, logger, null, null)

    companion object {
        const val DEFAULT_PROXY_PORT = 1080
        private const val HANDSHAKE_TIMEOUT_MS = 15_000
        private const val RELAY_IDLE_TIMEOUT_MS = 60_000
        private const val OUTBOUND_CONNECT_TIMEOUT_MS = 10_000
        private const val MAX_HTTP_HEADER_BYTES = 8_192
        private const val BUFFER_SIZE = 32 * 1024
        private const val MAX_CONCURRENT_CLIENTS = 128

        // SOCKS5 Constants (RFC 1928)
        private const val SOCKS_VERSION = 0x05
        private const val SOCKS_AUTH_NONE = 0x00
        private const val SOCKS_AUTH_NO_ACCEPTABLE = 0xFF

        private const val SOCKS_CMD_CONNECT = 0x01

        private const val SOCKS_ATYP_IPV4 = 0x01
        private const val SOCKS_ATYP_DOMAIN = 0x03
        private const val SOCKS_ATYP_IPV6 = 0x04

        private const val SOCKS_REP_SUCCESS = 0x00
        private const val SOCKS_REP_GENERAL_FAILURE = 0x01
        private const val SOCKS_REP_NOT_ALLOWED = 0x02
        private const val SOCKS_REP_NETWORK_UNREACHABLE = 0x03
        private const val SOCKS_REP_CONNECTION_REFUSED = 0x05
        private const val SOCKS_REP_CMD_NOT_SUPPORTED = 0x07
        private const val SOCKS_REP_ADDR_NOT_SUPPORTED = 0x08

        fun isClientAllowed(addr: InetAddress?): Boolean {
            if (addr == null) return false
            if (addr.isLoopbackAddress) return true
            val host = addr.hostAddress ?: return false
            val normalized = if (host.startsWith("::ffff:")) host.removePrefix("::ffff:") else host
            if (normalized == "127.0.0.1" || normalized == "::1") return true
            if (addr is Inet4Address || (normalized.contains('.') && !normalized.contains(':'))) {
                val parts = normalized.split('.')
                if (parts.size == 4 && parts[0] == "192" && parts[1] == "168" && parts[2] == "49") {
                    val last = parts[3].toIntOrNull()
                    if (last != null && last in 0..255) return true
                }
            }
            return false
        }

        fun isP2pSubnetAddress(addr: InetAddress?): Boolean {
            if (addr == null) return false
            val host = addr.hostAddress ?: return false
            val normalized = if (host.startsWith("::ffff:")) host.removePrefix("::ffff:") else host
            val parts = normalized.split('.')
            if (parts.size == 4 && parts[0] == "192" && parts[1] == "168" && parts[2] == "49") {
                val last = parts[3].toIntOrNull()
                if (last != null && last in 0..255) return true
            }
            return false
        }

        private val STRIPPED_HOP_BY_HOP_HEADERS = setOf(
            "connection",
            "proxy-connection",
            "proxy-authorization",
            "proxy-authenticate",
            "keep-alive",
            "te",
            "trailer",
            "upgrade",
            "http2-settings"
        )

        internal fun parseIpv4Literal(host: String): ByteArray? {
            if (host.isEmpty() || host.contains(':')) return null
            val parts = host.split('.')
            if (parts.size !in 1..4 || parts.any { it.isEmpty() }) return null

            fun parsePart(part: String): Long? {
                val lower = part.lowercase(java.util.Locale.US)
                return when {
                    lower.startsWith("0x") -> {
                        val digits = lower.substring(2)
                        if (digits.isEmpty() || !digits.all { it in '0'..'9' || it in 'a'..'f' }) null
                        else digits.toLongOrNull(16)
                    }
                    lower.length > 1 && lower.startsWith("0") -> {
                        if (!lower.all { it in '0'..'7' }) null
                        else lower.toLongOrNull(8)
                    }
                    else -> {
                        if (!lower.all { it in '0'..'9' }) null
                        else lower.toLongOrNull(10)
                    }
                }
            }

            val nums = LongArray(parts.size)
            for (i in parts.indices) {
                val v = parsePart(parts[i]) ?: return null
                if (v < 0) return null
                nums[i] = v
            }
            for (i in 0 until nums.size - 1) {
                if (nums[i] > 255L) return null
            }
            val last = nums.last()
            val maxLast = when (nums.size) {
                1 -> 0xFFFFFFFFL
                2 -> 0xFFFFFFL
                3 -> 0xFFFFL
                else -> 0xFFL
            }
            if (last > maxLast) return null

            val ip32: Long = when (nums.size) {
                1 -> last
                2 -> (nums[0] shl 24) or last
                3 -> (nums[0] shl 24) or (nums[1] shl 16) or last
                else -> (nums[0] shl 24) or (nums[1] shl 16) or (nums[2] shl 8) or last
            }
            return byteArrayOf(
                ((ip32 ushr 24) and 0xFF).toByte(),
                ((ip32 ushr 16) and 0xFF).toByte(),
                ((ip32 ushr 8) and 0xFF).toByte(),
                (ip32 and 0xFF).toByte()
            )
        }

        internal fun parseIpv6Literal(host: String): ByteArray? {
            if (!host.contains(':')) return null
            if (!host.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) {
                return null
            }

            val dblIdx = host.indexOf("::")
            if (dblIdx >= 0 && host.indexOf("::", dblIdx + 2) >= 0) return null

            val leftPart: String
            val rightPart: String
            if (dblIdx >= 0) {
                leftPart = host.substring(0, dblIdx)
                rightPart = host.substring(dblIdx + 2)
            } else {
                leftPart = host
                rightPart = ""
            }

            val leftTokens = if (leftPart.isEmpty()) emptyList() else leftPart.split(':')
            val rightTokens = if (rightPart.isEmpty()) emptyList() else rightPart.split(':')
            if (leftTokens.any { it.isEmpty() } || rightTokens.any { it.isEmpty() }) return null

            var tailIpv4: ByteArray? = null
            val rightHextets: List<String>
            val leftHextets: List<String>

            if (rightTokens.isNotEmpty() && rightTokens.last().contains('.')) {
                val lastTok = rightTokens.last()
                tailIpv4 = parseDottedDecimalIpv4(lastTok) ?: return null
                rightHextets = rightTokens.dropLast(1)
                leftHextets = leftTokens
            } else if (dblIdx < 0 && leftTokens.isNotEmpty() && leftTokens.last().contains('.')) {
                val lastTok = leftTokens.last()
                tailIpv4 = parseDottedDecimalIpv4(lastTok) ?: return null
                leftHextets = leftTokens.dropLast(1)
                rightHextets = emptyList()
            } else {
                leftHextets = leftTokens
                rightHextets = rightTokens
            }

            if (leftHextets.any { it.contains('.') } || rightHextets.any { it.contains('.') }) return null

            val targetHextets = if (tailIpv4 != null) 6 else 8
            val explicitCount = leftHextets.size + rightHextets.size
            if (dblIdx < 0 && explicitCount != targetHextets) return null
            if (dblIdx >= 0 && explicitCount >= targetHextets) return null

            val zeroFill = targetHextets - explicitCount
            val hextets = IntArray(targetHextets)
            var idx = 0

            fun parseHextet(tok: String): Int? {
                if (tok.isEmpty() || tok.length > 4) return null
                val v = tok.toIntOrNull(16) ?: return null
                return if (v in 0..0xFFFF) v else null
            }

            for (tok in leftHextets) {
                hextets[idx++] = parseHextet(tok) ?: return null
            }
            for (z in 0 until zeroFill) {
                hextets[idx++] = 0
            }
            for (tok in rightHextets) {
                hextets[idx++] = parseHextet(tok) ?: return null
            }

            val out = ByteArray(16)
            for (i in 0 until targetHextets) {
                out[i * 2] = ((hextets[i] ushr 8) and 0xFF).toByte()
                out[i * 2 + 1] = (hextets[i] and 0xFF).toByte()
            }
            if (tailIpv4 != null) {
                System.arraycopy(tailIpv4, 0, out, 12, 4)
            }
            return out
        }

        private fun parseDottedDecimalIpv4(s: String): ByteArray? {
            val parts = s.split('.')
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

        internal fun isBlockedIpv4Bytes(b: ByteArray): Boolean {
            if (b.size != 4) return true
            val b0 = b[0].toInt() and 0xFF
            val b1 = b[1].toInt() and 0xFF
            if (b0 == 0) return true                              // 0.0.0.0/8 (wildcard / "this" network)
            if (b0 == 10) return true                             // 10.0.0.0/8 (RFC 1918)
            if (b0 == 127) return true                            // 127.0.0.0/8 (loopback)
            if (b0 == 169 && b1 == 254) return true               // 169.254.0.0/16 (link-local / cloud metadata)
            if (b0 == 172 && b1 in 16..31) return true            // 172.16.0.0/12 (RFC 1918)
            if (b0 == 192 && b1 == 168) return true               // 192.168.0.0/16 (RFC 1918, incl. 192.168.49.0/24)
            if (b0 >= 224) return true                            // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved/broadcast
            return false
        }

        internal fun isBlockedIpv6Bytes(b: ByteArray): Boolean {
            if (b.size != 16) return true
            // :: (unspecified / wildcard)
            if (b.all { it == 0.toByte() }) return true
            // ::1 (loopback)
            if ((0 until 15).all { b[it] == 0.toByte() } && b[15] == 1.toByte()) return true

            val b0 = b[0].toInt() and 0xFF
            val b1 = b[1].toInt() and 0xFF
            if (b0 == 0xFE && (b1 and 0xC0) == 0x80) return true  // fe80::/10 (link-local)
            if (b0 == 0xFE && (b1 and 0xC0) == 0xC0) return true  // fec0::/10 (site-local)
            if ((b0 and 0xFE) == 0xFC) return true                // fc00::/7 (ULA: fc00::/8 & fd00::/8)
            if (b0 == 0xFF) return true                           // ff00::/8 (multicast)

            // IPv4-mapped (::ffff:0:0/96) and IPv4-compatible (::/96)
            val prefixZeros0to9 = (0 until 10).all { b[it] == 0.toByte() }
            if (prefixZeros0to9 && (
                    (b[10] == 0xFF.toByte() && b[11] == 0xFF.toByte()) ||
                    (b[10] == 0.toByte() && b[11] == 0.toByte())
                )
            ) {
                return isBlockedIpv4Bytes(b.copyOfRange(12, 16))
            }

            // NAT64 well-known prefix (64:ff9b::/96) & local-use prefix (64:ff9b:1::/48)
            if (b[0] == 0x00.toByte() && b[1] == 0x64.toByte() &&
                b[2] == 0xFF.toByte() && b[3] == 0x9B.toByte()
            ) {
                if ((4 until 12).all { b[it] == 0.toByte() }) {
                    return isBlockedIpv4Bytes(b.copyOfRange(12, 16))
                }
                if (b[4] == 0x00.toByte() && b[5] == 0x01.toByte()) {
                    return true
                }
            }
            return false
        }

        fun isBlockedInetAddress(addr: InetAddress?): Boolean {
            if (addr == null) return true
            if (addr.isAnyLocalAddress ||
                addr.isLoopbackAddress ||
                addr.isLinkLocalAddress ||
                addr.isSiteLocalAddress ||
                addr.isMulticastAddress
            ) {
                return true
            }
            if (isP2pSubnetAddress(addr)) return true
            val raw = addr.address ?: return true
            return when (raw.size) {
                4 -> isBlockedIpv4Bytes(raw)
                16 -> isBlockedIpv6Bytes(raw)
                else -> true
            }
        }

        fun isTargetSafe(host: String, port: Int): Boolean {
            if (port !in 1..65535) return false
            val trimmed = host.trim()
            if (trimmed.isEmpty()) return false
            if (trimmed.any { it.isWhitespace() || it.code < 0x20 || it == '/' || it == '\\' || it == '@' || it == '?' || it == '#' }) {
                return false
            }

            val unwrapped = if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
                trimmed.substring(1, trimmed.length - 1)
            } else {
                trimmed
            }
            if (unwrapped.contains('[') || unwrapped.contains(']')) return false
            // Zone-scoped IPv6 targets (e.g. fe80::1%eth0, ::1%lo0) are always local interface addresses
            if (unwrapped.contains('%')) return false

            val cleanHost = unwrapped.lowercase(java.util.Locale.US).trimEnd('.')
            if (cleanHost.isEmpty()) return false

            // Block local, loopback, mDNS, and internal/cloud metadata hostnames across all ports
            if (cleanHost == "localhost" ||
                cleanHost.endsWith(".localhost") ||
                cleanHost == "localhost.localdomain" ||
                cleanHost.endsWith(".localdomain") ||
                cleanHost == "ip6-localhost" ||
                cleanHost == "ip6-loopback" ||
                cleanHost == "local" ||
                cleanHost.endsWith(".local") ||
                cleanHost == "internal" ||
                cleanHost.endsWith(".internal") ||
                cleanHost == "metadata" ||
                cleanHost == "instance-data"
            ) {
                return false
            }

            // Block restricted IPv4 literals (including decimal/hex/octal/shortened forms) across all ports
            parseIpv4Literal(cleanHost)?.let { ipv4Bytes ->
                return !isBlockedIpv4Bytes(ipv4Bytes)
            }

            // Block restricted IPv6 literals across all ports
            if (cleanHost.contains(':')) {
                val ipv6Bytes = parseIpv6Literal(cleanHost) ?: return false
                return !isBlockedIpv6Bytes(ipv6Bytes)
            }

            return true
        }

        internal fun hasInvalidHttpHeaderSyntax(rawHeaderBlock: String): Boolean {
            for (i in rawHeaderBlock.indices) {
                val ch = rawHeaderBlock[i]
                if (ch == '\r') {
                    if (i + 1 >= rawHeaderBlock.length || rawHeaderBlock[i + 1] != '\n') {
                        return true
                    }
                } else if (ch != '\n' && ch != '\t' && ch.code < 0x20) {
                    return true
                }
            }
            return false
        }

        internal fun hasUpgradeHeader(rawHeaderBlock: String): Boolean {
            val allLines = rawHeaderBlock.split(Regex("\\r\\n|\\n|\\r"))
            for (i in 1 until allLines.size) {
                val line = allLines[i]
                if (line.isEmpty()) continue
                val colonIdx = line.indexOf(':')
                if (colonIdx <= 0) continue
                val name = line.substring(0, colonIdx).trim().lowercase(java.util.Locale.US)
                val value = line.substring(colonIdx + 1).lowercase(java.util.Locale.US)
                if (name == "upgrade") return true
                if (name == "connection" || name == "proxy-connection") {
                    val tokens = value.split(',').map { it.trim() }
                    if ("upgrade" in tokens) return true
                }
            }
            return false
        }

        internal fun <T> selectBestUpstreamNetwork(
            active: NetworkCandidate<T>?,
            requestedCellular: NetworkCandidate<T>?,
            allNetworks: List<NetworkCandidate<T>>
        ): T? {
            if (active != null && active.hasInternet && active.isValidated) {
                return active.network
            }
            if (requestedCellular != null && requestedCellular.hasInternet && requestedCellular.isValidated) {
                return requestedCellular.network
            }
            allNetworks.firstOrNull { it.hasInternet && it.isValidated && it.isCellular }?.let { return it.network }
            allNetworks.firstOrNull { it.hasInternet && it.isValidated }?.let { return it.network }
            if (requestedCellular != null && requestedCellular.hasInternet) {
                return requestedCellular.network
            }
            if (active != null && active.hasInternet) {
                return active.network
            }
            allNetworks.firstOrNull { it.hasInternet && it.isCellular }?.let { return it.network }
            allNetworks.firstOrNull { it.hasInternet }?.let { return it.network }
            return active?.network
        }

        internal fun rewriteForwardHttpHeaders(
            method: String,
            rewrittenUri: String,
            httpVersion: String,
            rawHeaderBlock: String
        ): String {
            val lines = rawHeaderBlock
                .split(Regex("\\r\\n|\\n|\\r"))
                .drop(1)
                .filter { it.isNotEmpty() }

            val connectionNamedHeaders = HashSet<String>()
            for (line in lines) {
                val colonIdx = line.indexOf(':')
                if (colonIdx <= 0) continue
                val name = line.substring(0, colonIdx).trim().lowercase(java.util.Locale.US)
                if (name == "connection" || name == "proxy-connection") {
                    val value = line.substring(colonIdx + 1)
                    for (token in value.split(',')) {
                        val cleanToken = token.trim().lowercase(java.util.Locale.US)
                        if (cleanToken.isNotEmpty()) {
                            connectionNamedHeaders.add(cleanToken)
                        }
                    }
                }
            }

            val sb = StringBuilder()
            sb.append(method).append(' ').append(rewrittenUri).append(' ').append(httpVersion).append("\r\n")
            for (line in lines) {
                val colonIdx = line.indexOf(':')
                if (colonIdx <= 0) continue
                val rawName = line.substring(0, colonIdx)
                val name = rawName.trim().lowercase(java.util.Locale.US)
                if (name in STRIPPED_HOP_BY_HOP_HEADERS || name in connectionNamedHeaders) {
                    continue
                }
                if (rawName.any { it.isWhitespace() }) {
                    continue
                }
                sb.append(line).append("\r\n")
            }
            sb.append("Connection: close\r\n")
            sb.append("\r\n")
            return sb.toString()
        }
    }

    internal data class NetworkCandidate<T>(
        val network: T,
        val hasInternet: Boolean,
        val isValidated: Boolean,
        val isCellular: Boolean
    )

    private val isRunning = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null
    private var executor: ExecutorService? = null
    private val activeSockets = Collections.newSetFromMap(ConcurrentHashMap<Socket, Boolean>())
    private val clientCount = AtomicInteger(0)
    private val cellularNetworkRef = AtomicReference<Network?>(null)
    @Volatile
    private var cellularNetworkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile
    private var cellularReadyLatch: CountDownLatch? = null
    @Volatile
    private var cellularRequestDeadlineMs: Long = 0L

    var actualPort: Int = port
        private set

    val running: Boolean
        get() = isRunning.get()

    @Synchronized
    fun start(): Boolean {
        if (isRunning.getAndSet(true)) return true
        try {
            val srv = ServerSocket()
            srv.reuseAddress = true
            srv.bind(InetSocketAddress(InetAddress.getByName("0.0.0.0"), port))
            serverSocket = srv
            actualPort = srv.localPort
            requestCellularUpstreamNetwork()
            logger?.invoke("EmbeddedProxyServer listening on 0.0.0.0:$actualPort (Dual SOCKS5 + HTTP CONNECT/Forward)")

            executor = Executors.newCachedThreadPool { r ->
                Thread(r, "EmbeddedProxy-Worker").apply { isDaemon = true }
            }

            acceptThread = Thread({
                while (isRunning.get()) {
                    val client = try {
                        srv.accept()
                    } catch (_: Throwable) {
                        break
                    }

                    // 1. Client IP Whitelist Check
                    if (!isClientAllowed(client.inetAddress)) {
                        logger?.invoke("EmbeddedProxyServer: rejected unauthorized client ${client.remoteSocketAddress}")
                        runCatching { client.close() }
                        continue
                    }

                    // 2. Concurrency limit
                    if (clientCount.incrementAndGet() > MAX_CONCURRENT_CLIENTS) {
                        clientCount.decrementAndGet()
                        logger?.invoke("EmbeddedProxyServer: client limit reached ($MAX_CONCURRENT_CLIENTS), dropping connection")
                        runCatching { client.close() }
                        continue
                    }

                    executor?.submit {
                        try {
                            handleClient(client)
                        } catch (_: EOFException) {
                            // Client closed before completing handshake
                        } catch (_: SocketException) {
                            // Client reset or closed connection (e.g. P2P teardown / probe)
                        } catch (t: Throwable) {
                            if (isRunning.get()) {
                                logger?.invoke("EmbeddedProxyServer client error: ${t.message}")
                            }
                        } finally {
                            clientCount.decrementAndGet()
                            runCatching { client.close() }
                        }
                    }
                }
            }, "EmbeddedProxy-Accept").apply {
                isDaemon = true
                start()
            }
            return true
        } catch (e: Exception) {
            releaseCellularUpstreamNetwork()
            isRunning.set(false)
            logger?.invoke("Failed to bind EmbeddedProxyServer on port $port: ${e.message}")
            return false
        }
    }

    @Synchronized
    fun stop() {
        if (!isRunning.getAndSet(false)) return
        runCatching { serverSocket?.close() }
        serverSocket = null

        acceptThread?.interrupt()
        acceptThread = null

        for (sock in activeSockets) {
            runCatching { sock.close() }
        }
        activeSockets.clear()

        executor?.shutdownNow()
        executor = null

        releaseCellularUpstreamNetwork()
        logger?.invoke("EmbeddedProxyServer stopped")
    }

    override fun close() {
        stop()
    }

    private fun handleClient(clientSocket: Socket) {
        clientSocket.soTimeout = HANDSHAKE_TIMEOUT_MS
        clientSocket.tcpNoDelay = true
        activeSockets.add(clientSocket)

        val input = PushbackInputStream(clientSocket.getInputStream(), 1024)
        try {
            val firstByte = input.read()
            if (firstByte == -1) return

            val upstreamNetwork = getUpstreamNetwork()

            if (firstByte == SOCKS_VERSION) {
                handleSocks5(clientSocket, input, upstreamNetwork)
            } else if ((firstByte in 'A'.code..'Z'.code) || (firstByte in 'a'.code..'z'.code)) {
                input.unread(firstByte)
                handleHttpRequest(clientSocket, input, upstreamNetwork)
            } else {
                logger?.invoke("EmbeddedProxyServer: unrecognized protocol byte 0x%02X from %s".format(firstByte, clientSocket.remoteSocketAddress))
            }
        } finally {
            activeSockets.remove(clientSocket)
            runCatching { clientSocket.close() }
        }
    }

    // =========================================================================
    // SOCKS5 Handler (RFC 1928)
    // =========================================================================

    private fun handleSocks5(client: Socket, input: InputStream, upstreamNetwork: Network?) {
        val output = client.getOutputStream()

        // 1. Greeting & Authentication Negotiation
        val nmethods = input.read()
        if (nmethods <= 0) return
        val methods = ByteArray(nmethods)
        readFully(input, methods)

        var hasNoAuth = false
        for (m in methods) {
            if ((m.toInt() and 0xFF) == SOCKS_AUTH_NONE) {
                hasNoAuth = true
                break
            }
        }

        if (!hasNoAuth) {
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), SOCKS_AUTH_NO_ACCEPTABLE.toByte()))
            output.flush()
            return
        }

        output.write(byteArrayOf(SOCKS_VERSION.toByte(), SOCKS_AUTH_NONE.toByte()))
        output.flush()

        // 2. Client Connection Request
        val ver = input.read()
        if (ver != SOCKS_VERSION) return
        val cmd = input.read()
        val rsv = input.read()
        val atyp = input.read()

        if (cmd != SOCKS_CMD_CONNECT) {
            sendSocksReply(output, SOCKS_REP_CMD_NOT_SUPPORTED)
            return
        }

        val targetHost: String = when (atyp) {
            SOCKS_ATYP_IPV4 -> {
                val ipBytes = ByteArray(4)
                readFully(input, ipBytes)
                InetAddress.getByAddress(ipBytes).hostAddress ?: ""
            }
            SOCKS_ATYP_DOMAIN -> {
                val domainLen = input.read()
                if (domainLen <= 0) return
                val domainBytes = ByteArray(domainLen)
                readFully(input, domainBytes)
                String(domainBytes, StandardCharsets.US_ASCII)
            }
            SOCKS_ATYP_IPV6 -> {
                val ipBytes = ByteArray(16)
                readFully(input, ipBytes)
                InetAddress.getByAddress(ipBytes).hostAddress ?: ""
            }
            else -> {
                sendSocksReply(output, SOCKS_REP_ADDR_NOT_SUPPORTED)
                return
            }
        }

        val portHi = input.read()
        val portLo = input.read()
        if (portHi == -1 || portLo == -1) return
        val targetPort = ((portHi and 0xFF) shl 8) or (portLo and 0xFF)

        if (!isTargetSafe(targetHost, targetPort)) {
            sendSocksReply(output, SOCKS_REP_NOT_ALLOWED)
            return
        }

        // 3. Connect to target via upstream network (with cellular fallback if primary upstream fails)
        val outboundSocket = try {
            connectWithUpstreamFallback(upstreamNetwork, targetHost, targetPort)
        } catch (e: SecurityException) {
            sendSocksReply(output, SOCKS_REP_NOT_ALLOWED)
            return
        } catch (e: UnknownHostException) {
            sendSocksReply(output, SOCKS_REP_NETWORK_UNREACHABLE)
            return
        } catch (e: Exception) {
            sendSocksReply(output, SOCKS_REP_CONNECTION_REFUSED)
            return
        }

        sendSocksReply(output, SOCKS_REP_SUCCESS)
        relayBidirectional(client, input, outboundSocket)
    }

    private fun sendSocksReply(output: OutputStream, rep: Int) {
        val reply = byteArrayOf(
            SOCKS_VERSION.toByte(),
            rep.toByte(),
            0x00, // RSV
            SOCKS_ATYP_IPV4.toByte(),
            0, 0, 0, 0, // BND.ADDR
            0, 0        // BND.PORT
        )
        output.write(reply)
        output.flush()
    }

    // =========================================================================
    // HTTP CONNECT & Forward Proxy Handler (RFC 7231 / RFC 9110)
    // =========================================================================

    private fun handleHttpRequest(client: Socket, input: InputStream, upstreamNetwork: Network?) {
        val output = client.getOutputStream()

        // 1. Read request headers with length bound and O(1) delimiter check
        val headerBytes = ByteArrayOutputStream()
        var window = 0
        var headerComplete = false
        while (headerBytes.size() < MAX_HTTP_HEADER_BYTES) {
            val b = input.read()
            if (b == -1) return
            headerBytes.write(b)
            window = (window shl 8) or (b and 0xFF)
            if ((window and 0x0000FFFF) == 0x0A0A || window == 0x0D0A0D0A) {
                headerComplete = true
                break
            }
        }

        if (!headerComplete) {
            sendHttpResponse(output, 431, "Request Header Fields Too Large")
            return
        }

        val headerStr = headerBytes.toString("US-ASCII")
        if (hasInvalidHttpHeaderSyntax(headerStr)) {
            sendHttpResponse(output, 400, "Bad Request")
            return
        }
        val requestLine = headerStr.lineSequence().firstOrNull()?.trim() ?: return
        val parts = requestLine.split("\\s+".toRegex())
        if (parts.size < 2) {
            sendHttpResponse(output, 400, "Bad Request")
            return
        }

        val method = parts[0].uppercase(java.util.Locale.US)
        val uriStr = parts[1]

        if (hasUpgradeHeader(headerStr)) {
            sendHttpResponse(output, 403, "Forbidden")
            return
        }

        if (method == "CONNECT") {
            // HTTP CONNECT Tunneling (HTTPS)
            val (targetHost, targetPort) = parseAuthority(uriStr)
            if (!isTargetSafe(targetHost, targetPort)) {
                sendHttpResponse(output, 403, "Forbidden")
                return
            }

            val outboundSocket = try {
                connectWithUpstreamFallback(upstreamNetwork, targetHost, targetPort)
            } catch (_: SecurityException) {
                sendHttpResponse(output, 403, "Forbidden")
                return
            } catch (_: Exception) {
                sendHttpResponse(output, 502, "Bad Gateway")
                return
            }

            sendHttpResponse(output, 200, "Connection Established", closeConnection = false)
            relayBidirectional(client, input, outboundSocket)
        } else {
            // Standard HTTP Forward Proxy (GET, POST, HEAD, PUT, DELETE, etc.)
            val (targetHost, targetPort, rewrittenUri) = parseForwardHttpTarget(uriStr, headerStr)
            if (targetHost.isEmpty() || !isTargetSafe(targetHost, targetPort)) {
                sendHttpResponse(output, 403, "Forbidden")
                return
            }

            val outboundSocket = try {
                connectWithUpstreamFallback(upstreamNetwork, targetHost, targetPort)
            } catch (_: SecurityException) {
                sendHttpResponse(output, 403, "Forbidden")
                return
            } catch (_: Exception) {
                sendHttpResponse(output, 502, "Bad Gateway")
                return
            }

            // Rewrite first line to origin-form (e.g., "GET /path HTTP/1.1") and normalize connection headers
            val httpVersion = if (parts.size >= 3) parts[2] else "HTTP/1.1"
            val rewrittenHeader = rewriteForwardHttpHeaders(method, rewrittenUri, httpVersion, headerStr)
            val outboundOut = outboundSocket.getOutputStream()
            outboundOut.write(rewrittenHeader.toByteArray(StandardCharsets.US_ASCII))
            outboundOut.flush()

            relayBidirectional(client, input, outboundSocket)
        }
    }

    internal fun parseForwardHttpTarget(uriStr: String, fullHeaders: String): Triple<String, Int, String> {
        if (uriStr.startsWith("http://", ignoreCase = true) || uriStr.startsWith("https://", ignoreCase = true)) {
            val isHttps = uriStr.startsWith("https://", ignoreCase = true)
            val defaultPort = if (isHttps) 443 else 80
            try {
                val uri = URI(uriStr)
                val host = uri.host
                if (!host.isNullOrEmpty()) {
                    val port = if (uri.port == -1) defaultPort else uri.port
                    val rawPath = uri.rawPath.ifEmpty { "/" }
                    val query = if (uri.rawQuery != null) "?${uri.rawQuery}" else ""
                    return Triple(host, port, rawPath + query)
                }
            } catch (_: Exception) {
            }
            val schemeEnd = uriStr.indexOf("://")
            val afterScheme = uriStr.substring(schemeEnd + 3).substringBefore('#')
            val slashIdx = afterScheme.indexOf('/')
            val qIdx = afterScheme.indexOf('?')
            val splitIdx = listOf(slashIdx, qIdx).filter { it >= 0 }.minOrNull() ?: afterScheme.length
            val rawAuthoritySegment = afterScheme.substring(0, splitIdx)
            if (rawAuthoritySegment.any { it == '\\' || it.isWhitespace() || it.code < 0x20 }) {
                return Triple("", -1, "")
            }
            val rawAuthority = rawAuthoritySegment.substringAfterLast('@')
            val (host, port) = parseAuthority(rawAuthority, defaultPort = defaultPort)
            val tail = if (splitIdx < afterScheme.length) afterScheme.substring(splitIdx) else "/"
            val rewritten = if (tail.startsWith("?")) "/$tail" else tail.ifEmpty { "/" }
            return Triple(host, port, rewritten)
        }

        // Relative URI — locate host from Host: header
        var hostHeader = ""
        for (line in fullHeaders.lineSequence()) {
            val trimmed = line.trim()
            if (trimmed.startsWith("Host:", ignoreCase = true)) {
                hostHeader = trimmed.substringAfter(":").trim()
                break
            }
        }

        if (hostHeader.isNotEmpty()) {
            val (host, port) = parseAuthority(hostHeader, defaultPort = 80)
            return Triple(host, port, if (uriStr.startsWith("/")) uriStr else "/$uriStr")
        }

        return Triple("", 80, uriStr)
    }

    internal fun parseAuthority(authority: String, defaultPort: Int = 443): Pair<String, Int> {
        return if (authority.startsWith("[") && authority.contains("]")) {
            val host = authority.substringBefore("]").removePrefix("[")
            val afterBracket = authority.substringAfter("]")
            val port = when {
                afterBracket.isEmpty() -> defaultPort
                afterBracket.startsWith(":") -> afterBracket.substring(1).toIntOrNull() ?: -1
                else -> -1
            }
            Pair(host, port)
        } else {
            val colonIdx = authority.lastIndexOf(':')
            if (colonIdx >= 0) {
                val host = authority.substring(0, colonIdx)
                val portStr = authority.substring(colonIdx + 1)
                val port = portStr.toIntOrNull() ?: -1
                Pair(host, port)
            } else {
                Pair(authority, defaultPort)
            }
        }
    }

    private fun sendHttpResponse(output: OutputStream, statusCode: Int, reason: String, closeConnection: Boolean = true) {
        val closeHdr = if (closeConnection) "Connection: close\r\n" else ""
        val response = "HTTP/1.1 $statusCode $reason\r\n$closeHdr\r\n"
        output.write(response.toByteArray(StandardCharsets.US_ASCII))
        output.flush()
    }

    // =========================================================================
    // Upstream Network & Socket Factory
    // =========================================================================

    private fun requestCellularUpstreamNetwork() {
        val ctx = context ?: return
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        if (cellularNetworkCallback != null) return

        val latch = CountDownLatch(1)
        cellularReadyLatch = latch
        cellularRequestDeadlineMs = System.currentTimeMillis() + 2_000L

        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (!isRunning.get()) return
                cellularNetworkRef.set(network)
                latch.countDown()
                logger?.invoke("EmbeddedProxyServer: cellular upstream network available ($network)")
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                if (!isRunning.get()) return
                if (networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
                ) {
                    cellularNetworkRef.set(network)
                    if (networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                        latch.countDown()
                    }
                }
            }

            override fun onLost(network: Network) {
                if (cellularNetworkRef.compareAndSet(network, null) && isRunning.get()) {
                    logger?.invoke("EmbeddedProxyServer: cellular upstream network lost ($network)")
                }
            }

            override fun onUnavailable() {
                latch.countDown()
            }
        }

        try {
            val request = NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            cm.requestNetwork(request, callback)
            cellularNetworkCallback = callback
        } catch (t: Throwable) {
            cellularReadyLatch = null
            cellularNetworkCallback = null
            logger?.invoke("EmbeddedProxyServer: cellular requestNetwork unavailable (${t.message})")
        }
    }

    private fun releaseCellularUpstreamNetwork() {
        val callback = cellularNetworkCallback
        cellularNetworkCallback = null
        cellularReadyLatch?.countDown()
        cellularReadyLatch = null
        cellularNetworkRef.set(null)
        val ctx = context
        if (callback != null && ctx != null) {
            runCatching {
                val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                cm?.unregisterNetworkCallback(callback)
            }
        }
    }

    private fun toCandidate(cm: ConnectivityManager, net: Network?): NetworkCandidate<Network>? {
        if (net == null) return null
        val caps = cm.getNetworkCapabilities(net) ?: return null
        val usableInternet = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED)
        return NetworkCandidate(
            network = net,
            hasInternet = usableInternet,
            isValidated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            isCellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
        )
    }

    @Suppress("DEPRECATION")
    private fun getUpstreamNetwork(): Network? {
        val ctx = context ?: return null
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return null

        val activeCandidate = toCandidate(cm, cm.activeNetwork)
        if (activeCandidate != null && activeCandidate.hasInternet && activeCandidate.isValidated) {
            return activeCandidate.network
        }

        var cellularCandidate = toCandidate(cm, cellularNetworkRef.get())
        var allCandidates = cm.allNetworks.mapNotNull { toCandidate(cm, it) }

        val hasAnyValidated = (cellularCandidate != null && cellularCandidate.hasInternet && cellularCandidate.isValidated) ||
            allCandidates.any { it.hasInternet && it.isValidated }

        if (!hasAnyValidated && cellularCandidate == null && cellularNetworkCallback != null) {
            val remainingMs = cellularRequestDeadlineMs - System.currentTimeMillis()
            if (remainingMs > 0L) {
                runCatching {
                    cellularReadyLatch?.await(minOf(1_500L, remainingMs), TimeUnit.MILLISECONDS)
                }
                cellularCandidate = toCandidate(cm, cellularNetworkRef.get())
                allCandidates = cm.allNetworks.mapNotNull { toCandidate(cm, it) }
            }
        }

        return selectBestUpstreamNetwork(activeCandidate, cellularCandidate, allCandidates)
    }

    @Suppress("DEPRECATION")
    private fun getCellularFallbackNetwork(exclude: Network?): Network? {
        val ctx = context ?: return null
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return null

        val cellularNet = cellularNetworkRef.get()
        if (cellularNet != null && cellularNet != exclude) {
            val cand = toCandidate(cm, cellularNet)
            if (cand != null && cand.hasInternet) return cellularNet
        }

        val allCandidates = cm.allNetworks.mapNotNull { toCandidate(cm, it) }
        return allCandidates.firstOrNull { it.network != exclude && it.hasInternet && it.isValidated && it.isCellular }?.network
            ?: allCandidates.firstOrNull { it.network != exclude && it.hasInternet && it.isCellular }?.network
    }

    private fun connectWithUpstreamFallback(primaryNetwork: Network?, host: String, port: Int): Socket {
        return try {
            createOutboundSocket(primaryNetwork, host, port)
        } catch (se: SecurityException) {
            throw se
        } catch (primaryErr: Exception) {
            val fallback = getCellularFallbackNetwork(exclude = primaryNetwork)
            if (fallback != null) {
                logger?.invoke("EmbeddedProxyServer: primary upstream ($primaryNetwork) failed for $host:$port (${primaryErr.message}), retrying via cellular ($fallback)")
                createOutboundSocket(fallback, host, port)
            } else {
                throw primaryErr
            }
        }
    }

    private fun createOutboundSocket(network: Network?, host: String, port: Int): Socket {
        if (port !in 1..65535) {
            throw SecurityException("SSRF blocked: invalid destination port $port")
        }
        val cleanHost = host.trim().removeSurrounding("[", "]").trimEnd('.')
        val addresses = outboundAddressResolver?.invoke(network, cleanHost) ?: if (network != null) {
            network.getAllByName(cleanHost)
        } else {
            InetAddress.getAllByName(cleanHost)
        }

        if (addresses.isEmpty()) {
            throw UnknownHostException("No address found for $host")
        }

        // Post-DNS SSRF validation across ALL destination ports (1-65535):
        // reject loopback, wildcard, link-local/metadata, RFC 1918 private LAN, IPv6 ULA/site-local, and multicast.
        for (addr in addresses) {
            if (isBlockedInetAddress(addr)) {
                throw SecurityException("SSRF blocked: target $host resolves to restricted address ${addr.hostAddress}:$port")
            }
        }

        val deadlineMs = System.currentTimeMillis() + OUTBOUND_CONNECT_TIMEOUT_MS
        var lastError: Exception? = null
        for (i in addresses.indices) {
            val remainingMs = (deadlineMs - System.currentTimeMillis()).toInt()
            if (remainingMs <= 0) break
            val remainingCount = addresses.size - i
            val attemptTimeoutMs = if (remainingCount == 1) {
                remainingMs
            } else {
                minOf(remainingMs, maxOf(1_500, remainingMs / remainingCount))
            }
            val addr = addresses[i]
            val sock = if (network != null) {
                network.socketFactory.createSocket()
            } else {
                Socket()
            }
            activeSockets.add(sock)
            try {
                sock.tcpNoDelay = true
                sock.soTimeout = RELAY_IDLE_TIMEOUT_MS
                if (outboundSocketConnectHook != null) {
                    outboundSocketConnectHook.invoke(sock, addr, port, attemptTimeoutMs)
                } else {
                    sock.connect(InetSocketAddress(addr, port), attemptTimeoutMs)
                }
                return sock
            } catch (e: Exception) {
                activeSockets.remove(sock)
                lastError = e
                runCatching { sock.close() }
            }
        }
        throw lastError ?: IOException("Failed to connect to $host:$port")
    }

    // =========================================================================
    // Bidirectional Relay Streaming & Half-Close
    // =========================================================================

    private fun relayBidirectional(client: Socket, clientIn: InputStream, outbound: Socket) {
        client.tcpNoDelay = true
        outbound.tcpNoDelay = true
        client.soTimeout = RELAY_IDLE_TIMEOUT_MS
        outbound.soTimeout = RELAY_IDLE_TIMEOUT_MS

        activeSockets.add(outbound)

        val clientOut = client.getOutputStream()
        val outboundIn = outbound.getInputStream()
        val outboundOut = outbound.getOutputStream()

        val relayDone = AtomicBoolean(false)

        val relayRemoteToClient = {
            var error = false
            try {
                pipeStream(outboundIn, clientOut)
            } catch (_: Throwable) {
                error = true
            } finally {
                runCatching { client.shutdownOutput() }
                if (error || relayDone.get()) {
                    runCatching { client.close() }
                    runCatching { outbound.close() }
                }
            }
        }

        val future = executor?.submit {
            relayRemoteToClient()
        }

        try {
            var error = false
            try {
                pipeStream(clientIn, outboundOut)
            } catch (_: Throwable) {
                error = true
            } finally {
                runCatching { outbound.shutdownOutput() }
                if (error) {
                    runCatching { client.close() }
                    runCatching { outbound.close() }
                }
            }
            relayDone.set(true)
            future?.get()
        } catch (_: Throwable) {
        } finally {
            activeSockets.remove(outbound)
            runCatching { client.close() }
            runCatching { outbound.close() }
        }
    }

    private fun pipeStream(input: InputStream, output: OutputStream) {
        val buf = ByteArray(BUFFER_SIZE)
        try {
            while (isRunning.get()) {
                val bytesRead = input.read(buf)
                if (bytesRead == -1) break
                output.write(buf, 0, bytesRead)
                output.flush()
            }
        } catch (_: SocketTimeoutException) {
            // Idle timeout reached
        } catch (_: SocketException) {
            // Normal socket closure or connection reset
        } catch (_: IOException) {
            // Stream closed
        }
    }

    private fun readFully(input: InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val read = input.read(buffer, offset, buffer.size - offset)
            if (read == -1) throw EOFException("Unexpected end of stream while reading ${buffer.size} bytes")
            offset += read
        }
    }
}

