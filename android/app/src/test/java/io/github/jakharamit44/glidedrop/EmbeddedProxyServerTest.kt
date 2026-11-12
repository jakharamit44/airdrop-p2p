package io.github.jakharamit44.glidedrop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class EmbeddedProxyServerTest {

    @Test
    fun testClientIpWhitelist() {
        // Default production mode with no active P2P subnet denies loopback and any non-active P2P IP
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("127.0.0.1")))
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("::1")))
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("192.168.49.1")))
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("192.168.49.100")))
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("::ffff:192.168.49.50")))
        assertFalse(EmbeddedProxyServer.isP2pSubnetAddress(InetAddress.getByName("192.168.49.1")))

        // Explicit loopback test mode permits loopback even with no active P2P subnet
        assertTrue(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("127.0.0.1"), allowLoopbackClients = true))
        assertTrue(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("::1"), allowLoopbackClients = true))

        // Dynamic P2P subnet list enforces only the active OS-resolved subnet
        val dynamicSubnet = listOf(byteArrayOf(192.toByte(), 168.toByte(), 73, 0) to 24)
        assertTrue(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("192.168.73.44"), dynamicSubnet))
        assertTrue(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("::ffff:192.168.73.50"), dynamicSubnet))
        assertTrue(EmbeddedProxyServer.isP2pSubnetAddress(InetAddress.getByName("192.168.73.44"), dynamicSubnet))
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("192.168.49.100"), dynamicSubnet))
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("127.0.0.1"), dynamicSubnet))
        assertTrue(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("127.0.0.1"), dynamicSubnet, allowLoopbackClients = true))

        assertFalse(EmbeddedProxyServer.isClientAllowed(null, dynamicSubnet))
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("192.168.1.1"), dynamicSubnet))
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("10.0.0.1"), dynamicSubnet))
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("172.16.0.5"), dynamicSubnet))
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("8.8.8.8"), dynamicSubnet))
        assertFalse(EmbeddedProxyServer.matchesCidr(byteArrayOf(10, 0, 0, 1), byteArrayOf(0, 0, 0, 0), 0))
    }

    private fun newRelayTestProxy(mockPort: Int): EmbeddedProxyServer {
        val publicTestIp = byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34)
        return EmbeddedProxyServer(
            context = null,
            port = 0,
            outboundAddressResolver = { _, host ->
                if (host == "relay.example.test" || host == "93.184.216.34") {
                    arrayOf(InetAddress.getByAddress(host, publicTestIp))
                } else {
                    InetAddress.getAllByName(host)
                }
            },
            outboundSocketConnectHook = { sock, addr, port, timeoutMs ->
                if (addr.address.contentEquals(publicTestIp) && port == mockPort) {
                    sock.connect(InetSocketAddress(InetAddress.getByName("127.0.0.1"), mockPort), timeoutMs)
                } else {
                    sock.connect(InetSocketAddress(addr, port), timeoutMs)
                }
            },
            allowLoopbackClients = true
        )
    }

    @Test
    fun testIsTargetSafe() {
        assertTrue(EmbeddedProxyServer.isTargetSafe("example.com", 443))
        assertTrue(EmbeddedProxyServer.isTargetSafe("1.1.1.1", 80))
        assertTrue(EmbeddedProxyServer.isTargetSafe("93.184.216.34", 8080))
        assertTrue(EmbeddedProxyServer.isTargetSafe("2606:4700:4700::1111", 443))
        // Non-RFC1918 boundary checks around 172.16.0.0/12 and 192.168.0.0/16
        assertTrue(EmbeddedProxyServer.isTargetSafe("172.15.255.255", 80))
        assertTrue(EmbeddedProxyServer.isTargetSafe("172.32.0.1", 80))
        assertTrue(EmbeddedProxyServer.isTargetSafe("192.167.1.1", 80))
        assertTrue(EmbeddedProxyServer.isTargetSafe("11.0.0.1", 80))

        // Blocked SSRF loopback across ALL ports (not just 8771/1080)
        for (port in listOf(80, 443, 8080, 8771, 1080, 22, 65535)) {
            assertFalse(EmbeddedProxyServer.isTargetSafe("127.0.0.1", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("127.0.0.2", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("127.255.255.254", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("127.1", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("2130706433", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("0177.0.0.1", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("0x7f.0.0.1", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("localhost", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("localhost.", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("localhost.localdomain", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("api.localhost", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("::1", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("[::1]", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("0:0:0:0:0:0:0:1", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("::ffff:127.0.0.1", port))
            assertFalse(EmbeddedProxyServer.isTargetSafe("::ffff:7f00:1", port))
        }

        // Wildcard / unspecified addresses across all ports
        assertFalse(EmbeddedProxyServer.isTargetSafe("0.0.0.0", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("0.0.0.0", 8771))
        assertFalse(EmbeddedProxyServer.isTargetSafe("0.1.2.3", 8080))
        assertFalse(EmbeddedProxyServer.isTargetSafe("0", 8080))
        assertFalse(EmbeddedProxyServer.isTargetSafe("::", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("[::]", 443))
        assertFalse(EmbeddedProxyServer.isTargetSafe("0:0:0:0:0:0:0:0", 8080))

        // RFC 1918 private LAN ranges across all ports
        assertFalse(EmbeddedProxyServer.isTargetSafe("10.0.0.1", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("10.255.255.254", 443))
        assertFalse(EmbeddedProxyServer.isTargetSafe("172.16.0.1", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("172.31.255.254", 8080))
        assertFalse(EmbeddedProxyServer.isTargetSafe("192.168.1.1", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("192.168.73.1", 8771))
        assertFalse(EmbeddedProxyServer.isTargetSafe("192.168.73.1", 1080))
        assertFalse(EmbeddedProxyServer.isTargetSafe("192.168.73.1", 8771, listOf(byteArrayOf(192.toByte(), 168.toByte(), 73, 0) to 24)))
        assertFalse(EmbeddedProxyServer.isTargetSafe("::ffff:192.168.1.1", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("::ffff:10.0.0.1", 443))

        // Cloud metadata & IPv4/IPv6 link-local across all ports
        assertFalse(EmbeddedProxyServer.isTargetSafe("169.254.169.254", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("169.254.0.1", 443))
        assertFalse(EmbeddedProxyServer.isTargetSafe("2852039166", 80)) // 169.254.169.254
        assertFalse(EmbeddedProxyServer.isTargetSafe("::ffff:169.254.169.254", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("metadata.google.internal", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("fe80::1", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("[fe80::1]", 443))
        assertFalse(EmbeddedProxyServer.isTargetSafe("fe80::1%eth0", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("febf:ffff::1", 8080))

        // IPv6 ULA (fc00::/7) & site-local (fec0::/10) & multicast across all ports
        assertFalse(EmbeddedProxyServer.isTargetSafe("fd00::1", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("fc00::1", 443))
        assertFalse(EmbeddedProxyServer.isTargetSafe("fd12:3456:789a::1", 8080))
        assertFalse(EmbeddedProxyServer.isTargetSafe("fec0::1", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("224.0.0.1", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("239.255.255.250", 1900))
        assertFalse(EmbeddedProxyServer.isTargetSafe("ff02::1", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("255.255.255.255", 80))

        // Invalid ports / empty / malformed
        assertFalse(EmbeddedProxyServer.isTargetSafe("example.com", 0))
        assertFalse(EmbeddedProxyServer.isTargetSafe("example.com", -1))
        assertFalse(EmbeddedProxyServer.isTargetSafe("example.com", 65536))
        assertFalse(EmbeddedProxyServer.isTargetSafe("", 443))
    }

    @Test
    fun testSocks5HandshakeAndEchoRelay() {
        val mockServer = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
        val mockPort = mockServer.localPort

        val echoLatch = CountDownLatch(1)
        val serverThread = Thread {
            try {
                val sock = mockServer.accept()
                val inp = sock.getInputStream()
                val out = sock.getOutputStream()
                val buf = ByteArray(1024)
                val n = inp.read(buf)
                if (n > 0) {
                    out.write(buf, 0, n)
                    out.flush()
                }
                sock.close()
            } catch (_: Exception) {
            } finally {
                echoLatch.countDown()
            }
        }
        serverThread.isDaemon = true
        serverThread.start()

        val proxy = newRelayTestProxy(mockPort)
        assertTrue(proxy.start())
        val proxyPort = proxy.actualPort

        try {
            val client = Socket("127.0.0.1", proxyPort)
            val clientIn = client.getInputStream()
            val clientOut = client.getOutputStream()

            // Step 1: SOCKS5 greeting [VER=5, NMETHODS=1, METHOD=0(NO_AUTH)]
            clientOut.write(byteArrayOf(0x05, 0x01, 0x00))
            clientOut.flush()

            val ver = clientIn.read()
            val method = clientIn.read()
            assertEquals(0x05, ver)
            assertEquals(0x00, method)

            // Step 2: SOCKS5 connect to public test IP 93.184.216.34:mockPort
            val portHi = (mockPort shr 8) and 0xFF
            val portLo = mockPort and 0xFF
            val connectReq = byteArrayOf(
                0x05, 0x01, 0x00, 0x01,
                93, 184.toByte(), 216.toByte(), 34,
                portHi.toByte(), portLo.toByte()
            )
            clientOut.write(connectReq)
            clientOut.flush()

            // Step 3: Read SOCKS5 reply
            val replyBuf = ByteArray(10)
            readFully(clientIn, replyBuf)
            assertEquals(0x05, replyBuf[0].toInt() and 0xFF)
            assertEquals(0x00, replyBuf[1].toInt() and 0xFF) // REP = SUCCESS

            // Step 4: Send data through tunnel
            val testMsg = "Hello SOCKS5 Relay!"
            clientOut.write(testMsg.toByteArray(StandardCharsets.UTF_8))
            clientOut.flush()

            val echoed = ByteArray(testMsg.length)
            readFully(clientIn, echoed)
            assertEquals(testMsg, String(echoed, StandardCharsets.UTF_8))

            client.close()
            assertTrue(echoLatch.await(5, TimeUnit.SECONDS))
        } finally {
            proxy.stop()
            mockServer.close()
        }
    }

    @Test
    fun testHttpConnectHandshakeAndEchoRelay() {
        val mockServer = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
        val mockPort = mockServer.localPort

        val echoLatch = CountDownLatch(1)
        val serverThread = Thread {
            try {
                val sock = mockServer.accept()
                val inp = sock.getInputStream()
                val out = sock.getOutputStream()
                val buf = ByteArray(1024)
                val n = inp.read(buf)
                if (n > 0) {
                    out.write(buf, 0, n)
                    out.flush()
                }
                sock.close()
            } catch (_: Exception) {
            } finally {
                echoLatch.countDown()
            }
        }
        serverThread.isDaemon = true
        serverThread.start()

        val proxy = newRelayTestProxy(mockPort)
        assertTrue(proxy.start())
        val proxyPort = proxy.actualPort

        try {
            val client = Socket("127.0.0.1", proxyPort)
            val clientIn = client.getInputStream()
            val clientOut = client.getOutputStream()

            val req = "CONNECT relay.example.test:$mockPort HTTP/1.1\r\nHost: relay.example.test:$mockPort\r\n\r\n"
            clientOut.write(req.toByteArray(StandardCharsets.US_ASCII))
            clientOut.flush()

            val resp = StringBuilder()
            while (true) {
                val line = readLine(clientIn) ?: break
                resp.append(line).append("\n")
                if (line.isEmpty()) break
            }
            assertTrue(resp.toString().contains("200 Connection Established"))

            val testMsg = "Hello HTTP CONNECT Tunnel!"
            clientOut.write(testMsg.toByteArray(StandardCharsets.UTF_8))
            clientOut.flush()

            val echoed = ByteArray(testMsg.length)
            readFully(clientIn, echoed)
            assertEquals(testMsg, String(echoed, StandardCharsets.UTF_8))

            client.close()
            assertTrue(echoLatch.await(5, TimeUnit.SECONDS))
        } finally {
            proxy.stop()
            mockServer.close()
        }
    }

    @Test
    fun testHttpForwardProxyGetRequest() {
        val mockServer = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
        val mockPort = mockServer.localPort

        val requestLatch = CountDownLatch(1)
        var receivedRequest = ""
        val serverThread = Thread {
            try {
                val sock = mockServer.accept()
                val inp = sock.getInputStream()
                val out = sock.getOutputStream()
                val sb = StringBuilder()
                while (true) {
                    val line = readLine(inp) ?: break
                    sb.append(line).append("\r\n")
                    if (line.isEmpty()) break
                }
                receivedRequest = sb.toString()
                val body = "Hello From Mock HTTP Server"
                val httpResp = "HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body"
                out.write(httpResp.toByteArray(StandardCharsets.US_ASCII))
                out.flush()
                sock.close()
            } catch (_: Exception) {
            } finally {
                requestLatch.countDown()
            }
        }
        serverThread.isDaemon = true
        serverThread.start()

        val proxy = newRelayTestProxy(mockPort)
        assertTrue(proxy.start())

        try {
            val client = Socket("127.0.0.1", proxy.actualPort)
            val clientIn = client.getInputStream()
            val clientOut = client.getOutputStream()

            // Standard HTTP forward proxy request with hop-by-hop & proxy auth headers that MUST be stripped
            val req = "GET http://relay.example.test:$mockPort/index.html HTTP/1.1\r\n" +
                "Host: relay.example.test:$mockPort\r\n" +
                "Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n" +
                "Proxy-Authenticate: Basic realm=\"proxy\"\r\n" +
                "Proxy-Connection: keep-alive\r\n" +
                "Connection: keep-alive, X-Custom-Hop\r\n" +
                "X-Custom-Hop: leak-me\r\n" +
                "User-Agent: curl/8.0\r\n\r\n"
            clientOut.write(req.toByteArray(StandardCharsets.US_ASCII))
            clientOut.flush()

            val resp = StringBuilder()
            while (true) {
                val line = readLine(clientIn) ?: break
                resp.append(line).append("\n")
                if (line.isEmpty()) break
            }
            assertTrue(resp.toString().contains("200 OK"))

            val bodyBuf = ByteArray("Hello From Mock HTTP Server".length)
            readFully(clientIn, bodyBuf)
            assertEquals("Hello From Mock HTTP Server", String(bodyBuf, StandardCharsets.US_ASCII))

            client.close()
            assertTrue(requestLatch.await(5, TimeUnit.SECONDS))
            assertTrue(receivedRequest.startsWith("GET /index.html HTTP/1.1"))
            assertFalse(receivedRequest.contains("Proxy-Authorization", ignoreCase = true))
            assertFalse(receivedRequest.contains("Proxy-Authenticate", ignoreCase = true))
            assertFalse(receivedRequest.contains("Proxy-Connection", ignoreCase = true))
            assertFalse(receivedRequest.contains("X-Custom-Hop", ignoreCase = true))
            assertFalse(receivedRequest.contains("keep-alive", ignoreCase = true))
            assertTrue(receivedRequest.contains("Connection: close\r\n"))
        } finally {
            proxy.stop()
            mockServer.close()
        }
    }

    @Test
    fun testHttpConnectHeaderTooLarge() {
        val proxy = EmbeddedProxyServer(context = null, port = 0, allowLoopbackClients = true)
        assertTrue(proxy.start())

        try {
            val client = Socket("127.0.0.1", proxy.actualPort)
            val clientIn = client.getInputStream()
            val clientOut = client.getOutputStream()

            // Send 10 KB without CRLF CRLF
            val junk = "X".repeat(10_000)
            clientOut.write("CONNECT example.com:443 HTTP/1.1\r\nHeader: $junk\r\n".toByteArray(StandardCharsets.US_ASCII))
            clientOut.flush()

            val resp = StringBuilder()
            while (true) {
                val line = readLine(clientIn) ?: break
                resp.append(line).append("\n")
                if (line.isEmpty()) break
            }
            assertTrue(resp.toString().contains("431 Request Header Fields Too Large"))
            client.close()
        } finally {
            proxy.stop()
        }
    }

    @Test
    fun testSocks5NoAcceptableMethods() {
        val proxy = EmbeddedProxyServer(context = null, port = 0, allowLoopbackClients = true)
        assertTrue(proxy.start())

        try {
            val client = Socket("127.0.0.1", proxy.actualPort)
            val clientIn = client.getInputStream()
            val clientOut = client.getOutputStream()

            // Send greeting with only method 0x02 (Username/Password), missing 0x00
            clientOut.write(byteArrayOf(0x05, 0x01, 0x02))
            clientOut.flush()

            val ver = clientIn.read()
            val method = clientIn.read()
            assertEquals(0x05, ver)
            assertEquals(0xFF, method) // 0xFF = No acceptable methods

            client.close()
        } finally {
            proxy.stop()
        }
    }

    @Test
    fun testServerLifecycle() {
        val proxy = EmbeddedProxyServer(context = null, port = 0, allowLoopbackClients = true)
        assertFalse(proxy.running)
        assertTrue(proxy.start())
        assertTrue(proxy.running)
        assertTrue(proxy.actualPort > 0)
        proxy.stop()
        assertFalse(proxy.running)
    }

    @Test
    fun testUpstreamNetworkSelectionPriorities() {
        val wifiValidated = EmbeddedProxyServer.NetworkCandidate("wifi", hasInternet = true, isValidated = true, isCellular = false)
        val wifiUnvalidated = EmbeddedProxyServer.NetworkCandidate("wifi-offline", hasInternet = true, isValidated = false, isCellular = false)
        val imsOnly = EmbeddedProxyServer.NetworkCandidate("cell-ims", hasInternet = false, isValidated = true, isCellular = true)
        val cellValidated = EmbeddedProxyServer.NetworkCandidate("cell", hasInternet = true, isValidated = true, isCellular = true)
        val cellUnvalidated = EmbeddedProxyServer.NetworkCandidate("cell-pending", hasInternet = true, isValidated = false, isCellular = true)
        val otherValidated = EmbeddedProxyServer.NetworkCandidate("vpn", hasInternet = true, isValidated = true, isCellular = false)

        // 1. Validated active Wi-Fi takes priority when healthy
        assertEquals(
            "wifi",
            EmbeddedProxyServer.selectBestUpstreamNetwork(
                active = wifiValidated,
                requestedCellular = cellValidated,
                allNetworks = listOf(wifiValidated, cellValidated)
            )
        )

        // 2. Unvalidated/offline active Wi-Fi falls back to validated requested cellular
        assertEquals(
            "cell",
            EmbeddedProxyServer.selectBestUpstreamNetwork(
                active = wifiUnvalidated,
                requestedCellular = cellValidated,
                allNetworks = listOf(wifiUnvalidated, cellValidated)
            )
        )

        // 3. Unvalidated active Wi-Fi prefers pending requested cellular with INTERNET over dead Wi-Fi
        assertEquals(
            "cell-pending",
            EmbeddedProxyServer.selectBestUpstreamNetwork(
                active = wifiUnvalidated,
                requestedCellular = cellUnvalidated,
                allNetworks = listOf(wifiUnvalidated, cellUnvalidated)
            )
        )

        // 4. Active IMS-only cellular (no INTERNET) yields to requested cellular with INTERNET
        assertEquals(
            "cell",
            EmbeddedProxyServer.selectBestUpstreamNetwork(
                active = imsOnly,
                requestedCellular = cellValidated,
                allNetworks = listOf(imsOnly, cellValidated)
            )
        )

        // 5. Null active network uses validated requested cellular, or scans allNetworks (preferring cellular)
        assertEquals(
            "cell",
            EmbeddedProxyServer.selectBestUpstreamNetwork(
                active = null,
                requestedCellular = cellValidated,
                allNetworks = listOf(otherValidated, cellValidated)
            )
        )
        assertEquals(
            "cell",
            EmbeddedProxyServer.selectBestUpstreamNetwork(
                active = null,
                requestedCellular = null,
                allNetworks = listOf(otherValidated, cellValidated)
            )
        )

        // 6. Unvalidated Wi-Fi still works as fallback if no cellular exists
        assertEquals(
            "wifi-offline",
            EmbeddedProxyServer.selectBestUpstreamNetwork(
                active = wifiUnvalidated,
                requestedCellular = null,
                allNetworks = listOf(wifiUnvalidated, imsOnly)
            )
        )

        // 7. No internet networks available
        assertNull(
            EmbeddedProxyServer.selectBestUpstreamNetwork<String>(
                active = null,
                requestedCellular = null,
                allNetworks = listOf(imsOnly)
            )
        )
    }

    @Test
    fun testForwardHttpHeaderNormalization() {
        val raw = "GET http://example.com/test HTTP/1.1\r\n" +
            "Host: example.com\r\n" +
            "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n" +
            "Proxy-Authenticate: Basic realm=\"test\"\r\n" +
            "Proxy-Connection: Keep-Alive\r\n" +
            "Connection: keep-alive, X-Hop-Secret, X-Other-Hop\r\n" +
            "X-Hop-Secret: secret123\r\n" +
            "X-Other-Hop: leak\r\n" +
            "Keep-Alive: timeout=5\r\n" +
            "TE: trailers\r\n" +
            "Trailer: X-Checksum\r\n" +
            "User-Agent: curl/8.0\r\n\r\n"
        val rewritten = EmbeddedProxyServer.rewriteForwardHttpHeaders("GET", "/test", "HTTP/1.1", raw)
        assertTrue(rewritten.startsWith("GET /test HTTP/1.1\r\n"))
        assertFalse(rewritten.contains("Proxy-Authorization", ignoreCase = true))
        assertFalse(rewritten.contains("Proxy-Authenticate", ignoreCase = true))
        assertFalse(rewritten.contains("Proxy-Connection", ignoreCase = true))
        assertFalse(rewritten.contains("X-Hop-Secret", ignoreCase = true))
        assertFalse(rewritten.contains("X-Other-Hop", ignoreCase = true))
        assertFalse(rewritten.contains("Keep-Alive", ignoreCase = true))
        assertFalse(rewritten.contains("TE:", ignoreCase = true))
        assertFalse(rewritten.contains("Trailer:", ignoreCase = true))
        assertTrue(rewritten.contains("Host: example.com\r\n"))
        assertTrue(rewritten.contains("User-Agent: curl/8.0\r\n"))
        assertTrue(rewritten.contains("Connection: close\r\n"))
        assertTrue(rewritten.endsWith("\r\n\r\n"))

        // Upgrade headers must also be stripped if rewriteForwardHttpHeaders is invoked directly, enforcing Connection: close
        val upgradeRaw = "GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        assertTrue(EmbeddedProxyServer.hasUpgradeHeader(upgradeRaw))
        val upgradeRewritten = EmbeddedProxyServer.rewriteForwardHttpHeaders("GET", "/ws", "HTTP/1.1", upgradeRaw)
        assertFalse(upgradeRewritten.contains("Upgrade", ignoreCase = true))
        assertTrue(upgradeRewritten.contains("Connection: close\r\n"))
    }

    @Test
    fun testForwardTargetAndAuthorityParsingEdgeCases() {
        val proxy = EmbeddedProxyServer(context = null, port = 0, allowLoopbackClients = true)

        // Unencoded query characters like |, [, ] must not fail with empty host / 403
        val (h1, p1, path1) = proxy.parseForwardHttpTarget(
            "http://example.com/search?q=a|b&arr[]=1",
            "Host: example.com\r\n\r\n"
        )
        assertEquals("example.com", h1)
        assertEquals(80, p1)
        assertEquals("/search?q=a|b&arr[]=1", path1)

        // Missing path with query
        val (h2, p2, path2) = proxy.parseForwardHttpTarget(
            "http://example.com:8080?x=1|2",
            "Host: example.com:8080\r\n\r\n"
        )
        assertEquals("example.com", h2)
        assertEquals(8080, p2)
        assertEquals("/?x=1|2", path2)

        // Invalid port must produce -1 so isTargetSafe rejects it instead of silently defaulting
        assertEquals(Pair("example.com", -1), proxy.parseAuthority("example.com:notaport", 80))
        assertEquals(Pair("::1", 8771), proxy.parseAuthority("[::1]:8771", 443))
        assertEquals(Pair("::1", -1), proxy.parseAuthority("[::1]:bad", 443))
        assertFalse(EmbeddedProxyServer.isTargetSafe("example.com", -1))
    }

    @Test
    fun testMalformedPortAndPostDnsSelfSsrfBlocked() {
        val proxy = EmbeddedProxyServer(context = null, port = 0, allowLoopbackClients = true)
        assertTrue(proxy.start())
        val proxyPort = proxy.actualPort

        try {
            // 1. Malformed port in CONNECT returns 403 Forbidden
            Socket("127.0.0.1", proxyPort).use { client ->
                val out = client.getOutputStream()
                val inp = client.getInputStream()
                out.write("CONNECT example.com:badport HTTP/1.1\r\nHost: example.com:badport\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
                out.flush()
                val status = readLine(inp).orEmpty()
                assertTrue("Expected 403 Forbidden for malformed port, got: $status", status.contains("403"))
            }

            // 2. Post-DNS self-loopback SSRF via decimal/alternative loopback to proxy's actualPort returns 403
            Socket("127.0.0.1", proxyPort).use { client ->
                val out = client.getOutputStream()
                val inp = client.getInputStream()
                out.write("CONNECT 2130706433:$proxyPort HTTP/1.1\r\nHost: 2130706433:$proxyPort\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
                out.flush()
                val status = readLine(inp).orEmpty()
                assertTrue("Expected 403 Forbidden for post-DNS loopback SSRF, got: $status", status.contains("403"))
            }
        } finally {
            proxy.stop()
        }
    }

    @Test
    fun testHttpForwardProxyPostWithBody() {
        val mockServer = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
        val mockPort = mockServer.localPort

        val reqBodyPayload = "{\"msg\":\"hello-proxy-post\"}"
        val doneLatch = CountDownLatch(1)
        var capturedMethodAndPath = ""
        var capturedBody = ""

        val serverThread = Thread {
            try {
                mockServer.accept().use { sock ->
                    val inp = sock.getInputStream()
                    val out = sock.getOutputStream()
                    val hdrLines = mutableListOf<String>()
                    var contentLen = 0
                    while (true) {
                        val line = readLine(inp) ?: break
                        if (line.isEmpty()) break
                        hdrLines.add(line)
                        if (line.startsWith("Content-Length:", ignoreCase = true)) {
                            contentLen = line.substringAfter(":").trim().toIntOrNull() ?: 0
                        }
                    }
                    capturedMethodAndPath = hdrLines.firstOrNull().orEmpty()
                    val bodyBuf = ByteArray(contentLen)
                    readFully(inp, bodyBuf)
                    capturedBody = String(bodyBuf, StandardCharsets.UTF_8)

                    val respBody = "OK:$capturedBody"
                    val resp = "HTTP/1.1 200 OK\r\nContent-Length: ${respBody.length}\r\nConnection: close\r\n\r\n$respBody"
                    out.write(resp.toByteArray(StandardCharsets.US_ASCII))
                    out.flush()
                }
            } catch (_: Exception) {
            } finally {
                doneLatch.countDown()
            }
        }
        serverThread.isDaemon = true
        serverThread.start()

        val proxy = newRelayTestProxy(mockPort)
        assertTrue(proxy.start())

        try {
            Socket("127.0.0.1", proxy.actualPort).use { client ->
                val inp = client.getInputStream()
                val out = client.getOutputStream()
                val req = "POST http://relay.example.test:$mockPort/submit?a=1|2 HTTP/1.1\r\nHost: relay.example.test:$mockPort\r\nProxy-Connection: keep-alive\r\nContent-Length: ${reqBodyPayload.length}\r\n\r\n$reqBodyPayload"
                out.write(req.toByteArray(StandardCharsets.UTF_8))
                out.flush()

                val status = readLine(inp).orEmpty()
                assertTrue("Expected 200 OK, got: $status", status.contains("200 OK"))
                while (true) {
                    val line = readLine(inp) ?: break
                    if (line.isEmpty()) break
                }
                val expectedResp = "OK:$reqBodyPayload"
                val respBuf = ByteArray(expectedResp.length)
                readFully(inp, respBuf)
                assertEquals(expectedResp, String(respBuf, StandardCharsets.UTF_8))
            }
            assertTrue(doneLatch.await(5, TimeUnit.SECONDS))
            assertEquals("POST /submit?a=1|2 HTTP/1.1", capturedMethodAndPath)
            assertEquals(reqBodyPayload, capturedBody)
        } finally {
            proxy.stop()
            mockServer.close()
        }
    }

    @Test
    fun testExactMaxHeaderBoundaryAcceptedAndOverflowRejected() {
        val mockServer = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
        val mockPort = mockServer.localPort

        val serverThread = Thread {
            try {
                mockServer.accept().use { sock ->
                    val inp = sock.getInputStream()
                    val out = sock.getOutputStream()
                    while (true) {
                        val line = readLine(inp) ?: break
                        if (line.isEmpty()) break
                    }
                    out.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".toByteArray(StandardCharsets.US_ASCII))
                    out.flush()
                }
            } catch (_: Exception) {
            }
        }
        serverThread.isDaemon = true
        serverThread.start()

        val proxy = newRelayTestProxy(mockPort)
        assertTrue(proxy.start())

        try {
            // Exact 8192-byte HTTP request header must succeed (not spuriously rejected with 431)
            val prefix = "GET http://relay.example.test:$mockPort/ HTTP/1.1\r\nHost: relay.example.test:$mockPort\r\nX-Pad: "
            val suffix = "\r\n\r\n"
            val padLen = 8192 - prefix.length - suffix.length
            val exactReq = prefix + "A".repeat(padLen) + suffix
            assertEquals(8192, exactReq.length)

            Socket("127.0.0.1", proxy.actualPort).use { client ->
                client.getOutputStream().apply {
                    write(exactReq.toByteArray(StandardCharsets.US_ASCII))
                    flush()
                }
                val status = readLine(client.getInputStream()).orEmpty()
                assertTrue("Expected 200 OK for exact 8192-byte header, got: $status", status.contains("200 OK"))
            }

            // 8193-byte header without completing inside 8192 bytes must return 431
            val overReq = prefix + "A".repeat(padLen + 1) + suffix
            assertEquals(8193, overReq.length)
            Socket("127.0.0.1", proxy.actualPort).use { client ->
                client.getOutputStream().apply {
                    write(overReq.toByteArray(StandardCharsets.US_ASCII))
                    flush()
                }
                val status = readLine(client.getInputStream()).orEmpty()
                assertTrue("Expected 431 for 8193-byte header, got: $status", status.contains("431"))
            }
        } finally {
            proxy.stop()
            mockServer.close()
        }
    }

    @Test
    fun testSocks5DomainAndIpv4SsrfBlocked() {
        val proxy = EmbeddedProxyServer(context = null, port = 0, allowLoopbackClients = true)
        assertTrue(proxy.start())
        val proxyPort = proxy.actualPort

        try {
            // 1. SOCKS5 IPv4 target 127.0.0.1:8771 must return REP=0x02 (Not Allowed)
            Socket("127.0.0.1", proxyPort).use { client ->
                val inp = client.getInputStream()
                val out = client.getOutputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                assertEquals(0x05, inp.read())
                assertEquals(0x00, inp.read())

                val pHi = (8771 shr 8) and 0xFF
                val pLo = 8771 and 0xFF
                out.write(byteArrayOf(0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, pHi.toByte(), pLo.toByte()))
                out.flush()
                val reply = ByteArray(10)
                readFully(inp, reply)
                assertEquals(0x05, reply[0].toInt() and 0xFF)
                assertEquals(0x02, reply[1].toInt() and 0xFF)
            }

            // 2. SOCKS5 DOMAIN target "localhost" to proxyPort must return REP=0x02 (Not Allowed)
            Socket("127.0.0.1", proxyPort).use { client ->
                val inp = client.getInputStream()
                val out = client.getOutputStream()
                out.write(byteArrayOf(0x05, 0x01, 0x00))
                out.flush()
                assertEquals(0x05, inp.read())
                assertEquals(0x00, inp.read())

                val hostBytes = "localhost".toByteArray(StandardCharsets.US_ASCII)
                val pHi = (proxyPort shr 8) and 0xFF
                val pLo = proxyPort and 0xFF
                val req = ByteArray(4 + 1 + hostBytes.size + 2)
                req[0] = 0x05
                req[1] = 0x01
                req[2] = 0x00
                req[3] = 0x03
                req[4] = hostBytes.size.toByte()
                System.arraycopy(hostBytes, 0, req, 5, hostBytes.size)
                req[5 + hostBytes.size] = pHi.toByte()
                req[6 + hostBytes.size] = pLo.toByte()
                out.write(req)
                out.flush()

                val reply = ByteArray(10)
                readFully(inp, reply)
                assertEquals(0x05, reply[0].toInt() and 0xFF)
                assertEquals(0x02, reply[1].toInt() and 0xFF)
            }
        } finally {
            proxy.stop()
        }
    }

    @Test
    fun testSsrfBlockedAcrossAllPortsAndAddressClassesOverHttpAndSocks5() {
        val proxy = EmbeddedProxyServer(context = null, port = 0, allowLoopbackClients = true)
        assertTrue(proxy.start())
        val proxyPort = proxy.actualPort

        val blockedConnectTargets = listOf(
            "127.0.0.1:8080",
            "127.0.0.1:80",
            "[::1]:80",
            "[::1]:8080",
            "localhost:8080",
            "10.0.0.1:80",
            "172.16.0.1:443",
            "192.168.1.1:8080",
            "169.254.169.254:80",
            "[fe80::1]:80",
            "[fd00::1]:80",
            "[fc00::1]:443",
            "0.0.0.0:80",
            "[::]:80"
        )

        try {
            // 1. HTTP CONNECT SSRF targets across arbitrary ports
            for (target in blockedConnectTargets) {
                Socket("127.0.0.1", proxyPort).use { client ->
                    val out = client.getOutputStream()
                    val inp = client.getInputStream()
                    out.write("CONNECT $target HTTP/1.1\r\nHost: $target\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
                    out.flush()
                    val status = readLine(inp).orEmpty()
                    assertTrue("Expected 403 Forbidden for CONNECT $target, got: $status", status.contains("403"))
                }
            }

            // 2. HTTP Forward GET SSRF targets across arbitrary ports
            for (target in listOf("127.0.0.1:8080", "[::1]:80", "10.0.0.1:80", "172.16.0.1:80", "192.168.1.1:80", "169.254.169.254:80", "[fe80::1]:80", "[fd00::1]:80")) {
                Socket("127.0.0.1", proxyPort).use { client ->
                    val out = client.getOutputStream()
                    val inp = client.getInputStream()
                    out.write("GET http://$target/latest/meta-data/ HTTP/1.1\r\nHost: $target\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
                    out.flush()
                    val status = readLine(inp).orEmpty()
                    assertTrue("Expected 403 Forbidden for GET http://$target/, got: $status", status.contains("403"))
                }
            }

            // 3. SOCKS5 IPv4 & IPv6 targets across arbitrary ports
            val socksTargets: List<Pair<Byte, ByteArray>> = listOf(
                0x01.toByte() to byteArrayOf(127, 0, 0, 1),
                0x01.toByte() to byteArrayOf(10, 0, 0, 1),
                0x01.toByte() to byteArrayOf(172.toByte(), 16, 0, 1),
                0x01.toByte() to byteArrayOf(192.toByte(), 168.toByte(), 1, 1),
                0x01.toByte() to byteArrayOf(169.toByte(), 254.toByte(), 169.toByte(), 254.toByte()),
                0x04.toByte() to InetAddress.getByName("::1").address,
                0x04.toByte() to InetAddress.getByName("fe80::1").address,
                0x04.toByte() to InetAddress.getByName("fd00::1").address
            )
            for ((atyp, addrBytes) in socksTargets) {
                Socket("127.0.0.1", proxyPort).use { client ->
                    val inp = client.getInputStream()
                    val out = client.getOutputStream()
                    out.write(byteArrayOf(0x05, 0x01, 0x00))
                    out.flush()
                    assertEquals(0x05, inp.read())
                    assertEquals(0x00, inp.read())

                    val req = ByteArray(4 + addrBytes.size + 2)
                    req[0] = 0x05
                    req[1] = 0x01
                    req[2] = 0x00
                    req[3] = atyp
                    System.arraycopy(addrBytes, 0, req, 4, addrBytes.size)
                    req[4 + addrBytes.size] = 0x00
                    req[5 + addrBytes.size] = 0x50 // port 80
                    out.write(req)
                    out.flush()

                    val reply = ByteArray(10)
                    readFully(inp, reply)
                    assertEquals(0x05, reply[0].toInt() and 0xFF)
                    assertEquals(0x02, reply[1].toInt() and 0xFF)
                }
            }
        } finally {
            proxy.stop()
        }
    }

    @Test
    fun testPostDnsRebindingSsrfBlockedAcrossAllPorts() {
        val rebindIps = listOf(
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "::1",
            "fe80::1",
            "fd00::1"
        )
        var currentIdx = 0
        val proxy = EmbeddedProxyServer(
            context = null,
            port = 0,
            outboundAddressResolver = { _, host ->
                arrayOf(InetAddress.getByAddress(host, InetAddress.getByName(rebindIps[currentIdx]).address))
            },
            allowLoopbackClients = true
        )
        assertTrue(proxy.start())
        try {
            for (idx in rebindIps.indices) {
                currentIdx = idx
                Socket("127.0.0.1", proxy.actualPort).use { client ->
                    val out = client.getOutputStream()
                    val inp = client.getInputStream()
                    out.write("CONNECT rebind.example.test:8080 HTTP/1.1\r\nHost: rebind.example.test:8080\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
                    out.flush()
                    val status = readLine(inp).orEmpty()
                    assertTrue("Expected post-DNS 403 for ${rebindIps[idx]}, got: $status", status.contains("403"))
                }
            }
        } finally {
            proxy.stop()
        }
    }

    @Test
    fun testUpgradeRequestsRejectedOnRawProxySockets() {
        val mockServer = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
        val mockPort = mockServer.localPort
        val upstreamTouched = CountDownLatch(1)
        val serverThread = Thread {
            try {
                mockServer.accept().use {
                    upstreamTouched.countDown()
                }
            } catch (_: Exception) {
            }
        }
        serverThread.isDaemon = true
        serverThread.start()

        val proxy = newRelayTestProxy(mockPort)
        assertTrue(proxy.start())
        try {
            // 1. Forward HTTP with Connection: Upgrade + Upgrade: websocket must be rejected with 403 without hitting upstream
            Socket("127.0.0.1", proxy.actualPort).use { client ->
                val out = client.getOutputStream()
                val inp = client.getInputStream()
                val req = "GET http://relay.example.test:$mockPort/ws HTTP/1.1\r\n" +
                    "Host: relay.example.test:$mockPort\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Upgrade: websocket\r\n\r\n"
                out.write(req.toByteArray(StandardCharsets.US_ASCII))
                out.flush()
                val status = readLine(inp).orEmpty()
                assertTrue("Expected 403 Forbidden for Upgrade request, got: $status", status.contains("403"))
            }

            // 2. Standalone Upgrade: h2c header without Connection: Upgrade must also be rejected
            Socket("127.0.0.1", proxy.actualPort).use { client ->
                val out = client.getOutputStream()
                val inp = client.getInputStream()
                val req = "GET http://relay.example.test:$mockPort/ HTTP/1.1\r\n" +
                    "Host: relay.example.test:$mockPort\r\n" +
                    "Upgrade: h2c\r\n\r\n"
                out.write(req.toByteArray(StandardCharsets.US_ASCII))
                out.flush()
                val status = readLine(inp).orEmpty()
                assertTrue("Expected 403 Forbidden for Upgrade: h2c, got: $status", status.contains("403"))
            }

            // 3. Proxy-Connection: Upgrade must also be rejected
            Socket("127.0.0.1", proxy.actualPort).use { client ->
                val out = client.getOutputStream()
                val inp = client.getInputStream()
                val req = "GET http://relay.example.test:$mockPort/ HTTP/1.1\r\n" +
                    "Host: relay.example.test:$mockPort\r\n" +
                    "Proxy-Connection: Upgrade\r\n\r\n"
                out.write(req.toByteArray(StandardCharsets.US_ASCII))
                out.flush()
                val status = readLine(inp).orEmpty()
                assertTrue("Expected 403 Forbidden for Proxy-Connection: Upgrade, got: $status", status.contains("403"))
            }

            // 4. Bare CR smuggling of Upgrade / Proxy-Authorization must be rejected with 400 Bad Request
            for (smuggled in listOf(
                "GET http://relay.example.test:$mockPort/ HTTP/1.1\rUpgrade: websocket\r\nHost: relay.example.test:$mockPort\r\n\r\n",
                "GET http://relay.example.test:$mockPort/ HTTP/1.1\r\nHost: relay.example.test:$mockPort\r\nX-Foo: 1\rUpgrade: websocket\r\n\r\n",
                "GET http://relay.example.test:$mockPort/ HTTP/1.1\r\nHost: relay.example.test:$mockPort\r\nX-Foo: 1\rProxy-Authorization: Basic secret\r\n\r\n"
            )) {
                Socket("127.0.0.1", proxy.actualPort).use { client ->
                    val out = client.getOutputStream()
                    val inp = client.getInputStream()
                    out.write(smuggled.toByteArray(StandardCharsets.US_ASCII))
                    out.flush()
                    val status = readLine(inp).orEmpty()
                    assertTrue("Expected 400 Bad Request for bare-CR header smuggling, got: $status", status.contains("400"))
                }
            }

            // 5. Explicit :0 port in forward HTTP URI must be rejected with 403 (not coerced to port 80)
            Socket("127.0.0.1", proxy.actualPort).use { client ->
                val out = client.getOutputStream()
                val inp = client.getInputStream()
                val req = "GET http://relay.example.test:0/ HTTP/1.1\r\nHost: relay.example.test:0\r\n\r\n"
                out.write(req.toByteArray(StandardCharsets.US_ASCII))
                out.flush()
                val status = readLine(inp).orEmpty()
                assertTrue("Expected 403 Forbidden for explicit :0 port, got: $status", status.contains("403"))
            }

            assertFalse("Rejected Upgrade/smuggled requests must not dial upstream server", upstreamTouched.await(250, TimeUnit.MILLISECONDS))
        } finally {
            proxy.stop()
            mockServer.close()
        }
    }

    @Test
    fun testAdditionalEdgeBlockedTargetsAndHeaderHelpers() {
        assertFalse(EmbeddedProxyServer.isTargetSafe("64:ff9b:1::1", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("64:ff9b::127.0.0.1", 80))
        assertFalse(EmbeddedProxyServer.isTargetSafe("foo.localdomain", 80))
        assertTrue(EmbeddedProxyServer.hasInvalidHttpHeaderSyntax("GET / HTTP/1.1\r\nX-A: 1\rUpgrade: ws\r\n\r\n"))
        assertFalse(EmbeddedProxyServer.hasInvalidHttpHeaderSyntax("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
        assertTrue(EmbeddedProxyServer.hasUpgradeHeader("GET / HTTP/1.1\rUpgrade: websocket\r\nHost: example.com\r\n\r\n"))
        assertTrue(EmbeddedProxyServer.hasUpgradeHeader("GET / HTTP/1.1\r\nProxy-Connection: keep-alive, Upgrade\r\n\r\n"))
    }

    @Test
    fun testExpandedSsrfAndHostnameBlocks() {
        val blockedTargets = listOf(
            "100.64.0.1",         // CGNAT RFC 6598
            "192.0.0.1",          // IETF protocol assignments
            "192.0.2.1",          // TEST-NET-1
            "192.88.99.1",        // 6to4 relay anycast
            "198.18.0.1",         // Benchmarking
            "198.51.100.1",       // TEST-NET-2
            "203.0.113.1",        // TEST-NET-3
            "2002::1",            // 6to4 IPv6
            "2001::1",            // Teredo
            "2001:2::1",          // Benchmarking / ORCHID
            "2001:db8::1",        // Documentation
            "100::1",             // Discard-only
            "router.home.arpa",
            "nas.lan",
            "metadata.goog",
            "metadata.google.internal"
        )
        for (target in blockedTargets) {
            assertFalse("Expected SSRF target $target to be blocked", EmbeddedProxyServer.isTargetSafe(target, 80))
        }

        val customSubnets = listOf(byteArrayOf(10, 99, 0, 0) to 16)
        assertFalse(
            "Instance target filter must block active custom P2P subnet",
            EmbeddedProxyServer.isTargetSafe("10.99.12.34", 80, customSubnets)
        )
    }

    @Test
    fun testDefaultDeniesLoopbackAndBindExceptionFallsBackToEphemeralPort() {
        val prodProxy = EmbeddedProxyServer(context = null, port = 0)
        assertTrue(prodProxy.start())
        try {
            Socket("127.0.0.1", prodProxy.actualPort).use { client ->
                client.soTimeout = 1000
                val denied = try {
                    val out = client.getOutputStream()
                    out.write("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
                    out.flush()
                    readLine(client.getInputStream()) == null
                } catch (_: java.net.SocketException) {
                    // Immediate server-side client.close() causes TCP RST when CONNECT bytes arrive
                    true
                }
                assertTrue("Loopback client must be denied when allowLoopbackClients=false", denied)
            }
        } finally {
            prodProxy.stop()
        }

        // Verify BindException fallback when desired port is already occupied on wildcard interface
        ServerSocket().use { occupier ->
            occupier.reuseAddress = false
            occupier.bind(InetSocketAddress(InetAddress.getByName("0.0.0.0"), 0), 5)
            val busyPort = occupier.localPort
            val fallbackProxy = EmbeddedProxyServer(context = null, port = busyPort, allowLoopbackClients = true)
            assertTrue("Proxy must bind ephemerally when desired port $busyPort is in use", fallbackProxy.start())
            try {
                assertTrue(fallbackProxy.actualPort > 0)
                assertTrue("Expected fallback port != $busyPort, got ${fallbackProxy.actualPort}", fallbackProxy.actualPort != busyPort)
            } finally {
                fallbackProxy.stop()
            }
        }
    }

    @Test
    fun testHttpForwardProxyRejectsRequestSmugglingFramingHeaders() {
        val mockServer = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
        val mockPort = mockServer.localPort
        val proxy = newRelayTestProxy(mockPort)
        assertTrue(proxy.start())

        try {
            val smugglingPayloads = listOf(
                // TE.CL request smuggling
                "POST http://relay.example.test:$mockPort/submit HTTP/1.1\r\n" +
                    "Host: relay.example.test:$mockPort\r\n" +
                    "Content-Length: 4\r\n" +
                    "Transfer-Encoding: chunked\r\n\r\n" +
                    "0\r\n\r\n",
                // Conflicting CL.CL request smuggling
                "POST http://relay.example.test:$mockPort/submit HTTP/1.1\r\n" +
                    "Host: relay.example.test:$mockPort\r\n" +
                    "Content-Length: 5\r\n" +
                    "Content-Length: 10\r\n\r\n" +
                    "hello",
                // Duplicate identical Content-Length
                "POST http://relay.example.test:$mockPort/submit HTTP/1.1\r\n" +
                    "Host: relay.example.test:$mockPort\r\n" +
                    "Content-Length: 5\r\n" +
                    "Content-Length: 5\r\n\r\n" +
                    "hello",
                // Negative / non-numeric Content-Length
                "POST http://relay.example.test:$mockPort/submit HTTP/1.1\r\n" +
                    "Host: relay.example.test:$mockPort\r\n" +
                    "Content-Length: -1\r\n\r\n"
            )

            for (payload in smugglingPayloads) {
                Socket("127.0.0.1", proxy.actualPort).use { client ->
                    client.soTimeout = 2000
                    client.getOutputStream().apply {
                        write(payload.toByteArray(StandardCharsets.US_ASCII))
                        flush()
                    }
                    val status = readLine(client.getInputStream()).orEmpty()
                    assertTrue("Expected 400 Bad Request for smuggling payload, got: $status", status.contains("400 Bad Request"))
                }
            }
        } finally {
            proxy.stop()
            mockServer.close()
        }
    }

    private fun readFully(inp: InputStream, buf: ByteArray) {
        var offset = 0
        while (offset < buf.size) {
            val n = inp.read(buf, offset, buf.size - offset)
            if (n == -1) throw java.io.EOFException("Premature EOF")
            offset += n
        }
    }

    private fun readLine(inp: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = inp.read()
            if (b == -1) return if (sb.isEmpty()) null else sb.toString()
            val c = b.toChar()
            if (c == '\n') {
                return sb.toString().trimEnd('\r')
            }
            sb.append(c)
        }
    }
}
