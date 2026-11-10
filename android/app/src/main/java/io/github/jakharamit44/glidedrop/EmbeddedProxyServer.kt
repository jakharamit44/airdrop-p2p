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
 * - SSRF Protection: blocks loopback to sensitive local ports (8771, 1080) across all loopback variants
 *   and validates post-DNS resolution IP addresses against loopback and P2P subnets.
 * - Dual-Protocol parser multiplexing SOCKS5 (0x05) and HTTP (CONNECT, GET, POST, HEAD, etc.).
 * - Constant-memory sliding-window HTTP header parser (bounded at 8 KB).
 * - Bounded concurrency (max 128 clients).
 * - Upstream routing: binds outbound sockets and resolves DNS via ConnectivityManager active internet network.
 * - Bidirectional streaming with half-close handling (shutdownOutput) and immediate error teardown.
 */
class EmbeddedProxyServer(
    private val context: Context? = null,
    val port: Int = DEFAULT_PROXY_PORT,
    private val logger: ((String) -> Unit)? = null
) : Closeable {

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

        fun isTargetSafe(host: String, port: Int): Boolean {
            if (port !in 1..65535) return false
            val cleanHost = host.trim().lowercase(java.util.Locale.US)
                .removeSurrounding("[", "]")
                .trimEnd('.')
            if (cleanHost.isEmpty()) return false

            // Prevent SSRF loop back to local GlideDrop or proxy daemon
            if (port == 8771 || port == DEFAULT_PROXY_PORT) {
                if (cleanHost == "localhost" ||
                    cleanHost == "0.0.0.0" ||
                    cleanHost == "0" ||
                    cleanHost == "::" ||
                    cleanHost == "::1" ||
                    cleanHost.startsWith("127.") ||
                    cleanHost.startsWith("::ffff:127.") ||
                    cleanHost.startsWith("192.168.49.") ||
                    cleanHost.startsWith("::ffff:192.168.49.")
                ) {
                    return false
                }
            }
            return true
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
            val firstLineEnd = rawHeaderBlock.indexOf('\n')
            val rest = if (firstLineEnd >= 0) rawHeaderBlock.substring(firstLineEnd + 1) else ""
            val lines = rest.split('\n').map { it.trimEnd('\r') }.filter { it.isNotEmpty() }
            val isUpgrade = lines.any {
                val lower = it.lowercase(java.util.Locale.US)
                lower.startsWith("connection:") && lower.contains("upgrade")
            }
            val sb = StringBuilder()
            sb.append(method).append(' ').append(rewrittenUri).append(' ').append(httpVersion).append("\r\n")
            for (line in lines) {
                val lower = line.lowercase(java.util.Locale.US)
                if (lower.startsWith("proxy-connection:")) continue
                if (!isUpgrade && lower.startsWith("connection:")) continue
                sb.append(line).append("\r\n")
            }
            if (!isUpgrade) {
                sb.append("Connection: close\r\n")
            }
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
        val requestLine = headerStr.lineSequence().firstOrNull()?.trim() ?: return
        val parts = requestLine.split("\\s+".toRegex())
        if (parts.size < 2) {
            sendHttpResponse(output, 400, "Bad Request")
            return
        }

        val method = parts[0].uppercase(java.util.Locale.US)
        val uriStr = parts[1]

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
                    val port = if (uri.port > 0) uri.port else defaultPort
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
            val rawAuthority = afterScheme.substring(0, splitIdx).substringAfterLast('@')
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
        val cleanHost = host.removeSurrounding("[", "]").trimEnd('.')
        val addresses = if (network != null) {
            network.getAllByName(cleanHost)
        } else {
            InetAddress.getAllByName(cleanHost)
        }

        if (addresses.isEmpty()) {
            throw UnknownHostException("No address found for $host")
        }

        // Post-DNS SSRF validation: ensure resolved IP does not route back to sensitive local ports
        if (port == 8771 || port == DEFAULT_PROXY_PORT || port == actualPort) {
            for (addr in addresses) {
                if (addr.isLoopbackAddress || addr.isAnyLocalAddress || isP2pSubnetAddress(addr)) {
                    throw SecurityException("SSRF blocked: target $host resolves to local address ${addr.hostAddress}:$port")
                }
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
                sock.connect(InetSocketAddress(addr, port), attemptTimeoutMs)
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

