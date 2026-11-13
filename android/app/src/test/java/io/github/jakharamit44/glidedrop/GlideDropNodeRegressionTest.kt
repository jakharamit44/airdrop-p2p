package io.github.jakharamit44.glidedrop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import java.io.IOException
import java.io.EOFException
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import org.junit.Assert.assertTrue
import org.junit.Test

class GlideDropNodeRegressionTest {
    // ---- Task 3.5: W2P2 v3 handshake security ----
    private val pub1Der = java.util.Base64.getDecoder().decode(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUVw9brnjlrkE0/7Kf1T9zQzB6Ze/N13KUVrQpsO0A19FNr46UPMY+/mlR1kCoiFQK+8NV+CMU7LMClbxfZ+TVA=="
    )
    private fun fixedPriv(): java.security.PrivateKey {
        val s = java.math.BigInteger(1, ByteArray(32) { (it + 33).toByte() })
        val params = java.security.AlgorithmParameters.getInstance("EC")
        params.init(java.security.spec.ECGenParameterSpec("secp256r1"))
        val spec = params.getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        return java.security.KeyFactory.getInstance("EC").generatePrivate(java.security.spec.ECPrivateKeySpec(s, spec))
    }
    private val fpA = "aa".repeat(32)
    private val fpB = "bb".repeat(32)
    private val sid = ByteArray(16) { (it + 1).toByte() }
    private val respPubStub = ByteArray(91) { 0x42 }

    @Test
    fun hkdfMatchesRfc5869TestCase1() {
        val ikm = ByteArray(22) { 0x0b }
        val salt = ByteArray(13) { it.toByte() }
        val info = ByteArray(10) { (0xf0 + it).toByte() }
        val okm = GlideDropNode.hkdfSha256(ikm, salt, info, 42)
        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            GlideDropNode.bytesToHex(okm)
        )
    }

    @Test
    fun w2p2V3MaterialMatchesSwiftVector() {
        val m = GlideDropNode.deriveW2p2SessionMaterial(fixedPriv(), pub1Der, sid, pub1Der, respPubStub, fpA, fpB)
        assertEquals("/UapwvsyFihK9p7CgynCYS3jGftS09bUXvMf27AKBQE=", java.util.Base64.getEncoder().encodeToString(m.sessionKey))
        assertEquals("8ea5f9f4940b8095d52e539e0b1a8d57bca6d6e9eafd4f34180a7d2dd6f1a161", m.token)
        assertEquals("551 971", m.verificationCode)
    }

    @Test
    fun w2p2V3KeysAreSeparatedAndBoundToInputs() {
        val base = GlideDropNode.deriveW2p2SessionMaterial(fixedPriv(), pub1Der, sid, pub1Der, respPubStub, fpA, fpB)
        assertFalse(base.sessionKey.contentEquals(GlideDropNode.hexToBytesOrNull(base.token)))
        val tamperedFp = GlideDropNode.deriveW2p2SessionMaterial(fixedPriv(), pub1Der, sid, pub1Der, respPubStub, fpA, "bc".repeat(32))
        val tamperedPub = GlideDropNode.deriveW2p2SessionMaterial(fixedPriv(), pub1Der, sid, pub1Der, respPubStub.copyOf().also { it[5] = 0 }, fpA, fpB)
        val otherSid = GlideDropNode.deriveW2p2SessionMaterial(fixedPriv(), pub1Der, ByteArray(16) { 9 }, pub1Der, respPubStub, fpA, fpB)
        for (t in listOf(tamperedFp, tamperedPub, otherSid)) {
            assertFalse(base.token == t.token)
            assertFalse(base.sessionKey.contentEquals(t.sessionKey))
        }
        assertTrue(Regex("\\d{3} \\d{3}").matches(base.verificationCode))
    }

    @Test
    fun w2p2BothSidesDeriveSameMaterial() {
        val a = GlideDropNode.generateEphemeralEcdhKeyPair()
        val b = GlideDropNode.generateEphemeralEcdhKeyPair()
        val fromA = GlideDropNode.deriveW2p2SessionMaterial(a.privateKey, b.publicKey.encoded, sid, a.publicKey.encoded, b.publicKey.encoded, fpA, fpB)
        val fromB = GlideDropNode.deriveW2p2SessionMaterial(b.privateKey, a.publicKey.encoded, sid, a.publicKey.encoded, b.publicKey.encoded, fpA, fpB)
        assertTrue(fromA.sessionKey.contentEquals(fromB.sessionKey))
        assertEquals(fromA.token, fromB.token)
        assertEquals(fromA.verificationCode, fromB.verificationCode)
    }

    @Test
    fun w2p2RequestVersioning() {
        val v3 = GlideDropNode.parseW2p2Request("\t3\tPUB\t${fpA}\t" + "0102030405060708090a0b0c0d0e0f10")
        assertEquals(3, v3.version)
        assertEquals("PUB", v3.pubB64)
        assertEquals(16, v3.sessionId?.size)
        assertTrue(GlideDropNode.parseW2p2Request("\t2\tPUB\t$fpA").version < GlideDropNode.W2P2_PROTOCOL_VERSION)
        assertTrue(GlideDropNode.parseW2p2Request("\tPUB\t$fpA").version < GlideDropNode.W2P2_PROTOCOL_VERSION)
        assertTrue(GlideDropNode.isW2p2UpdateRequiredReply("NO\tUPDATE\t3"))
        assertFalse(GlideDropNode.isW2p2UpdateRequiredReply("NO"))
    }

    @Test
    fun w2p2RateLimiterAndGattOffsetAndConnectionCap() {
        val lim = GlideDropNode.Companion.SlidingWindowLimiter(2, 1_000L)
        assertTrue(lim.tryAcquire(0)); assertTrue(lim.tryAcquire(10)); assertFalse(lim.tryAcquire(20))
        assertTrue(lim.tryAcquire(1_500))
        val v = byteArrayOf(1, 2, 3, 4)
        assertEquals(listOf<Byte>(3, 4), GlideDropNode.gattReadSlice(v, 2)!!.toList())
        assertEquals(0, GlideDropNode.gattReadSlice(v, 4)!!.size)
        assertEquals(null, GlideDropNode.gattReadSlice(v, 5))
        assertTrue(GlideDropNode.MAX_CONCURRENT_L2CAP_CONNECTIONS in 1..8)
        assertTrue(GlideDropNode.L2CAP_PREAUTH_IDLE_TIMEOUT_MS in 5_000L..60_000L)
        // Consent windows must fit inside the Mac's 25 s per-reply wait.
        assertTrue(GlideDropNode.W2P2_CONSENT_WINDOW_MS < 25_000L)
    }

    @Test
    fun completeArchiveCannotHideTruncatedHttpFramingFromCodecValidation() {
        val archive = ByteArrayOutputStream().also { out ->
            GlideDropCodec.writeDvzipCpio(listOf(GlideDropCodec.OutgoingEntry("file.txt", 4L) { "data".byteInputStream() }), out)
        }.toByteArray()
        val chunked = ByteArrayOutputStream().apply {
            write("${archive.size.toString(16)}\r\n".toByteArray())
            write(archive)
            write("\r\n0\r\n".toByteArray())
        }.toByteArray()
        val cases = listOf(
            archive to mapOf("content-length" to (archive.size + 1).toString()),
            chunked to mapOf("transfer-encoding" to "chunked")
        )
        for ((wire, headers) in cases) {
            val dir = Files.createTempDirectory("node-truncated-http").toFile()
            try {
                try {
                    GlideDropCodec.extractDvzipCpio(GlideDropNode.openHttpBodyStream(wire.inputStream(), headers), dir)
                    fail("A complete CPIO archive must not bypass incomplete HTTP framing")
                } catch (_: IOException) {
                    assertTrue("No extracted file may be committed", dir.listFiles().orEmpty().isEmpty())
                }
            } finally {
                dir.deleteRecursively()
            }
        }
    }

    @Test
    fun outgoingNamesMatchMetadataAndArchiveWithoutDroppingDuplicates() {
        val rawNames = listOf("folder/.report.txt", "C:\\root\\report.txt", ". . doc.txt", "a".repeat(239) + " tail")
        val payloads = rawNames.indices.map { "payload-$it".toByteArray() }
        val rawEntries = rawNames.mapIndexed { i, name ->
            GlideDropCodec.OutgoingEntry(name, payloads[i].size.toLong(), 42L) { payloads[i].inputStream() }
        }
        val prepared = GlideDropNode.prepareOutgoingFiles(rawEntries)
        val names = listOf("report.txt", "report.txt", "doc.txt", "a".repeat(239))
        assertEquals(names, prepared.entries.map { it.name })
        assertEquals(rawNames, rawEntries.map { it.name })
        assertEquals(names, prepared.metadata.map { it["FileName"] })
        assertEquals(names.map { "./$it" }, prepared.metadata.map { it["FileBomPath"] })
        assertEquals(listOf(42L, 42L, 42L, 42L), prepared.entries.map { it.mtimeSec })
        val metadata = GlideDropCodec.decodeBplistDict(GlideDropCodec.encodeBplist(mapOf("Files" to prepared.metadata)))
        val out = ByteArrayOutputStream()
        GlideDropCodec.writeDvzipCpio(prepared.entries, out)
        val dir = Files.createTempDirectory("node-normalized-names").toFile()
        try {
            val received = GlideDropCodec.extractDvzipCpio(out.toByteArray().inputStream(), dir,
                approvedFiles = GlideDropNode.approvedReceiveFiles(metadata))
            assertEquals(4, received.size)
            assertEquals(payloads.map { String(it) }, received.map { it.readText() })
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun publicationCopyStopsOnCancellationWithoutWritingRemainingBytes() {
        var cancelled = false
        val target = object : ByteArrayOutputStream() {
            override fun write(b: ByteArray, off: Int, len: Int) {
                super.write(b, off, len)
                cancelled = true
            }
        }
        try {
            GlideDropNode.copyForPublication(ByteArray(2_000_000).inputStream(), target,
                checkActive = { if (cancelled) throw IOException("cancelled") })
            fail("Cancellation must prevent successful publication")
        } catch (e: IOException) {
            assertEquals("cancelled", e.message)
            assertTrue(target.size() in 1 until 2_000_000)
        }
    }

    @Test
    fun publicationCopyRechecksCancellationAfterEof() {
        var cancelled = false
        val source = object : ByteArrayInputStream(ByteArray(0)) {
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                cancelled = true
                return -1
            }
        }
        try {
            GlideDropNode.copyForPublication(source, ByteArrayOutputStream(),
                checkActive = { if (cancelled) throw IOException("cancelled at EOF") })
            fail("Cancellation during the final read must not be acknowledged")
        } catch (e: IOException) {
            assertEquals("cancelled at EOF", e.message)
        }
    }

    @Test
    fun publicationCopyReportsRealBytesWithoutClosingBorrowedStreams() {
        var sourceClosed = false
        var targetClosed = false
        val source = object : ByteArrayInputStream("published".toByteArray()) {
            override fun close() { sourceClosed = true }
        }
        val target = object : ByteArrayOutputStream() {
            override fun close() { targetClosed = true }
        }
        val progress = ArrayList<Long>()
        GlideDropNode.copyForPublication(source, target, checkActive = {}, onProgress = { progress.add(it) })
        assertEquals("published", target.toString("UTF-8"))
        assertEquals(listOf(9L), progress)
        assertFalse(sourceClosed)
        assertFalse(targetClosed)
        target.write('!'.code)
        assertEquals("published!", target.toString("UTF-8"))
    }

    @Test
    fun fixedLengthBodyRejectsShortEofForSingleByteAndBulkReads() {
        for (bulk in listOf(false, true)) {
            val body = GlideDropNode.openHttpBodyStream(ByteArrayInputStream(byteArrayOf(1, 2)), mapOf("content-length" to "3"))
            try {
                if (bulk) body.readBytes() else while (body.read() != -1) {}
                fail("Short fixed-length body must throw EOFException")
            } catch (_: EOFException) {
            }
        }
    }

    @Test
    fun fixedLengthBodyStopsAtItsBoundaryAndHonorsZeroLengthReads() {
        val source = ByteArrayInputStream("abcNEXT".toByteArray())
        val body = GlideDropNode.openHttpBodyStream(source, mapOf("content-length" to "3"))
        assertEquals("abc", String(body.readBytes()))
        assertEquals(0, body.read(ByteArray(1), 0, 0))
        assertEquals(-1, body.read())
        assertEquals("NEXT", String(source.readBytes()))
    }

    @Test
    fun zeroChunkRequiresCompleteCrlfTerminatedTrailerSection() {
        for (wire in listOf("0", "0\r\n", "0\r\nX-Test: yes\r\n", "0\r\n\r", "0\r\n\n", "0\n\r\n")) {
            try {
                GlideDropNode.openHttpBodyStream(ByteArrayInputStream(wire.toByteArray()), mapOf("transfer-encoding" to "chunked")).readBytes()
                fail("Incomplete/malformed chunk terminator accepted: ${wire.toByteArray().toList()}")
            } catch (_: IOException) {
            }
        }
    }

    @Test
    fun chunkTrailersHaveAggregateCountAndByteLimits() {
        val blocks = listOf(
            (1..65).joinToString("") { "X-$it: v\r\n" },
            (1..5).joinToString("") { "X-$it: ${"v".repeat(4000)}\r\n" }
        )
        for (trailers in blocks) {
            try {
                GlideDropNode.openHttpBodyStream(ByteArrayInputStream("0\r\n${trailers}\r\n".toByteArray()), mapOf("transfer-encoding" to "chunked")).readBytes()
                fail("Oversized trailer section accepted")
            } catch (e: GlideDropNode.HttpFramingException) {
                assertEquals(431, e.statusCode)
            }
        }
    }

    @Test
    fun chunkTrailersRequireValidHeaderSyntaxAndCannotChangeFramingOrAuth() {
        for (trailer in listOf("not-a-header", " Bad: folded", "Content-Length: 0", "Transfer-Encoding: chunked", "X-GlideDrop-Token: forged")) {
            try {
                GlideDropNode.openHttpBodyStream(ByteArrayInputStream("0\r\n$trailer\r\n\r\n".toByteArray()), mapOf("transfer-encoding" to "chunked")).readBytes()
                fail("Invalid/forbidden trailer accepted: $trailer")
            } catch (e: GlideDropNode.HttpFramingException) {
                assertEquals(400, e.statusCode)
            }
        }
    }

    @Test
    fun validChunkTrailersDoNotConsumeFollowingMessage() {
        val source = ByteArrayInputStream("1\r\nx\r\n0\r\nX-Checksum: value\r\n\r\nNEXT".toByteArray())
        val body = GlideDropNode.openHttpBodyStream(source, mapOf("transfer-encoding" to "chunked"))
        assertEquals("x", String(body.readBytes()))
        assertEquals(-1, body.read())
        assertEquals("NEXT", String(source.readBytes()))
    }

    @Test
    fun socketAdmissionRequiresTheActualGroupOwnerLocalAddress() {
        val subnets = listOf(GlideDropNode.parseCidr("192.168.73.0/24")!!)
        assertTrue(GlideDropNode.isReceiverEndpointAllowed("192.168.73.42", "192.168.73.1", "192.168.73.1", subnets))
        assertFalse(GlideDropNode.isReceiverEndpointAllowed("192.168.73.42", "192.168.73.2", "192.168.73.1", subnets))
        assertFalse(GlideDropNode.isReceiverEndpointAllowed("192.168.73.42", "192.168.73.1", "", subnets))
    }

    @Test
    fun failedP2pBindingNeverConnectsUsingTheDefaultRoute() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            Socket().use { socket ->
                try {
                    GlideDropNode.connectWithP2pBinding(socket, InetSocketAddress(server.inetAddress, server.localPort)) {
                        throw IOException("P2P network lost")
                    }
                    fail("Binding failure must abort connection")
                } catch (e: IOException) {
                    assertEquals("P2P network lost", e.message)
                    assertFalse(socket.isConnected)
                }
            }
        }
    }

    @Test
    fun approvedManifestPreservesDuplicateNamesAndUnknownSizes() {
        val manifest = GlideDropNode.approvedReceiveFiles(mapOf("Files" to listOf(
            mapOf("FileName" to "note.txt", "FileSize" to 4L),
            mapOf("FileName" to "note.txt")
        )))
        assertEquals(listOf(GlideDropCodec.ApprovedFile("note.txt", 4L), GlideDropCodec.ApprovedFile("note.txt")), manifest)
        assertTrue(GlideDropNode.approvedReceiveFiles(emptyMap()).isEmpty())
    }

    @Test
    fun invalidOrOverflowingApprovedSizesAreRejectedBeforeConsent() {
        for (files in listOf(
            listOf(mapOf("FileName" to "bad.txt", "FileSize" to -1L)),
            listOf(mapOf("FileSize" to 1L)),
            listOf(mapOf("FileName" to "bad.txt", "FileSize" to "100")),
            listOf(mapOf("FileName" to "a", "FileSize" to Long.MAX_VALUE), mapOf("FileName" to "b", "FileSize" to 1L))
        )) {
            try {
                GlideDropNode.approvedReceiveFiles(mapOf("Files" to files))
                fail("Invalid approved manifest must fail: $files")
            } catch (_: IOException) {
                // Rejected before a misleading consent prompt or archive extraction.
            }
        }
    }

    @Test
    fun liveBleTokenNeverAuthorizesAnUnrelatedLanClient() {
        val subnets = listOf(GlideDropNode.parseCidr("192.168.73.0/24")!!)
        for (ip in listOf("192.168.1.42", "10.2.3.4", "172.20.1.4", "fd12:3456::42")) {
            assertFalse(ip, GlideDropNode.isReceiverRequestClientAllowed(ip, subnets, hasActiveSessionToken = true))
        }
    }

    @Test
    fun tokenCannotReplaceMissingOsResolvedP2pSubnet() {
        assertFalse(GlideDropNode.isReceiverRequestClientAllowed("192.168.73.42", hasActiveSessionToken = true))
    }

    @Test
    fun activeDynamicP2pClientsStillPassAddressAdmission() {
        val subnets = listOf(GlideDropNode.parseCidr("192.168.73.128/25")!!)
        assertTrue(GlideDropNode.isReceiverRequestClientAllowed("192.168.73.200", subnets))
        assertFalse(GlideDropNode.isReceiverRequestClientAllowed("192.168.73.10", subnets, hasActiveSessionToken = true))
    }

    @Test
    fun receiverNeverAcceptsLoopbackOrMappedLoopbackInProduction() {
        val subnets = listOf(GlideDropNode.parseCidr("192.168.73.0/24")!!)
        for (ip in listOf("127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::")) {
            assertFalse(ip, GlideDropNode.isReceiverRequestClientAllowed(ip, subnets, hasActiveSessionToken = true))
        }
    }
}
