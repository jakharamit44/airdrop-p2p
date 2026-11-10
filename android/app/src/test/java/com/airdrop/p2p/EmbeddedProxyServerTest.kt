package com.airdrop.p2p

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class EmbeddedProxyServerTest {

    @Test
    fun testClientIpWhitelist() {
        assertTrue(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("127.0.0.1")))
        assertTrue(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("::1")))
        assertTrue(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("192.168.49.1")))
        assertTrue(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("192.168.49.100")))
        assertTrue(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("::ffff:192.168.49.50")))

        assertFalse(EmbeddedProxyServer.isClientAllowed(null))
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("192.168.1.1")))
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("10.0.0.1")))
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("172.16.0.5")))
        assertFalse(EmbeddedProxyServer.isClientAllowed(InetAddress.getByName("8.8.8.8")))
    }

    @Test
    fun testIsTargetSafe() {
        assertTrue(EmbeddedProxyServer.isTargetSafe("example.com", 443))
        assertTrue(EmbeddedProxyServer.isTargetSafe("1.1.1.1", 80))
        assertTrue(EmbeddedProxyServer.isTargetSafe("127.0.0.1", 8080))
        assertTrue(EmbeddedProxyServer.isTargetSafe("127.0.0.2", 8080))

        // Blocked SSRF loopback to local AirDrop or proxy daemon across all loopback variants
        assertFalse(EmbeddedProxyServer.isTargetSafe("127.0.0.1", 8771))
        assertFalse(EmbeddedProxyServer.isTargetSafe("127.0.0.2", 8771))
        assertFalse(EmbeddedProxyServer.isTargetSafe("127.1", 8771))
        assertFalse(EmbeddedProxyServer.isTargetSafe("0.0.0.0", 8771))
        assertFalse(EmbeddedProxyServer.isTargetSafe("0", 8771))
        assertFalse(EmbeddedProxyServer.isTargetSafe("::1", 8771))
        assertFalse(EmbeddedProxyServer.isTargetSafe("::", 8771))
        assertFalse(EmbeddedProxyServer.isTargetSafe("::ffff:127.0.0.1", 8771))
        assertFalse(EmbeddedProxyServer.isTargetSafe("localhost", 1080))
        assertFalse(EmbeddedProxyServer.isTargetSafe("localhost.", 1080))
        assertFalse(EmbeddedProxyServer.isTargetSafe("192.168.49.1", 8771))
        assertFalse(EmbeddedProxyServer.isTargetSafe("192.168.49.1", 1080))
        assertFalse(EmbeddedProxyServer.isTargetSafe("::ffff:192.168.49.1", 1080))

        // Invalid ports
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

        val proxy = EmbeddedProxyServer(context = null, port = 0)
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

            // Step 2: SOCKS5 connect to 127.0.0.1:mockPort
            val portHi = (mockPort shr 8) and 0xFF
            val portLo = mockPort and 0xFF
            val connectReq = byteArrayOf(
                0x05, 0x01, 0x00, 0x01,
                127, 0, 0, 1,
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

        val proxy = EmbeddedProxyServer(context = null, port = 0)
        assertTrue(proxy.start())
        val proxyPort = proxy.actualPort

        try {
            val client = Socket("127.0.0.1", proxyPort)
            val clientIn = client.getInputStream()
            val clientOut = client.getOutputStream()

            val req = "CONNECT 127.0.0.1:$mockPort HTTP/1.1\r\nHost: 127.0.0.1:$mockPort\r\n\r\n"
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

        val proxy = EmbeddedProxyServer(context = null, port = 0)
        assertTrue(proxy.start())

        try {
            val client = Socket("127.0.0.1", proxy.actualPort)
            val clientIn = client.getInputStream()
            val clientOut = client.getOutputStream()

            // Standard HTTP forward proxy request
            val req = "GET http://127.0.0.1:$mockPort/index.html HTTP/1.1\r\nHost: 127.0.0.1:$mockPort\r\nUser-Agent: curl/8.0\r\n\r\n"
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
        } finally {
            proxy.stop()
            mockServer.close()
        }
    }

    @Test
    fun testHttpConnectHeaderTooLarge() {
        val proxy = EmbeddedProxyServer(context = null, port = 0)
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
        val proxy = EmbeddedProxyServer(context = null, port = 0)
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
        val proxy = EmbeddedProxyServer(context = null, port = 0)
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
        val raw = "GET http://example.com/test HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: Keep-Alive\r\nConnection: keep-alive\r\nUser-Agent: curl/8.0\r\n\r\n"
        val rewritten = EmbeddedProxyServer.rewriteForwardHttpHeaders("GET", "/test", "HTTP/1.1", raw)
        assertTrue(rewritten.startsWith("GET /test HTTP/1.1\r\n"))
        assertFalse(rewritten.contains("Proxy-Connection", ignoreCase = true))
        assertFalse(rewritten.contains("keep-alive", ignoreCase = true))
        assertTrue(rewritten.contains("Connection: close\r\n"))
        assertTrue(rewritten.endsWith("\r\n\r\n"))

        val upgradeRaw = "GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        val upgradeRewritten = EmbeddedProxyServer.rewriteForwardHttpHeaders("GET", "/ws", "HTTP/1.1", upgradeRaw)
        assertTrue(upgradeRewritten.contains("Connection: Upgrade\r\n"))
        assertFalse(upgradeRewritten.contains("Connection: close"))
    }

    @Test
    fun testForwardTargetAndAuthorityParsingEdgeCases() {
        val proxy = EmbeddedProxyServer(context = null, port = 0)

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
        val proxy = EmbeddedProxyServer(context = null, port = 0)
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

        val proxy = EmbeddedProxyServer(context = null, port = 0)
        assertTrue(proxy.start())

        try {
            Socket("127.0.0.1", proxy.actualPort).use { client ->
                val inp = client.getInputStream()
                val out = client.getOutputStream()
                val req = "POST http://127.0.0.1:$mockPort/submit?a=1|2 HTTP/1.1\r\nHost: 127.0.0.1:$mockPort\r\nProxy-Connection: keep-alive\r\nContent-Length: ${reqBodyPayload.length}\r\n\r\n$reqBodyPayload"
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
