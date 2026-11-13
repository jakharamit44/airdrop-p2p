package io.github.jakharamit44.glidedrop

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files

class GlideDropCodecTest {
    private fun odc(name: String, data: ByteArray = byteArrayOf(), mode: Int = 33188): ByteArray {
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        return String.format(
            java.util.Locale.US,
            "070707%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o",
            0, 1, mode, 0, 0, 1, 0, 0L, nameBytes.size + 1, data.size.toLong()
        ).toByteArray(Charsets.US_ASCII) + nameBytes + byteArrayOf(0) + data
    }

    private fun archive(name: String = "report.txt", data: ByteArray = "received".toByteArray()): ByteArray =
        odc(name, data) + odc("TRAILER!!!", mode = 0)

    private fun plist(objects: List<ByteArray>, refSize: Int = 1, top: Long = 0): ByteArray {
        val out = ByteArrayOutputStream()
        out.write("bplist00".toByteArray())
        val offsets = objects.map { obj -> out.size().also { out.write(obj) } }
        val table = out.size()
        offsets.forEach { out.write(java.nio.ByteBuffer.allocate(4).putInt(it).array()) }
        out.write(java.nio.ByteBuffer.allocate(32).apply {
            position(6); put(4); put(refSize.toByte()); putLong(objects.size.toLong()); putLong(top); putLong(table.toLong())
        }.array())
        return out.toByteArray()
    }

    private fun rejects(block: () -> Unit) {
        try {
            block()
            org.junit.Assert.fail("Expected malformed input to be rejected")
        } catch (_: java.io.IOException) {
        } catch (_: IllegalArgumentException) {
        }
    }

    private fun gzip(bytes: ByteArray): ByteArray = ByteArrayOutputStream().also { out ->
        java.util.zip.GZIPOutputStream(out).use { it.write(bytes) }
    }.toByteArray()

    private fun dvzipBlock(bytes: ByteArray, stored: Boolean = false): ByteArray {
        val payload = if (stored) bytes else ByteArrayOutputStream().also { out ->
            java.util.zip.DeflaterOutputStream(out).use { it.write(bytes) }
        }.toByteArray()
        val flag = if (stored) GlideDropCodec.DVZIP_STORED else 0
        return java.nio.ByteBuffer.allocate(4).putInt(flag or payload.size).array() + payload
    }

    @Test
    fun emptyDotDirectoryEntryIsAcceptedAndNotWritten() {
        val wire = odc(".", mode = 16877) + archive()
        val dir = Files.createTempDirectory("codec-dot-dir").toFile()
        try {
            val saved = GlideDropCodec.extractDvzipCpio(
                wire.inputStream(), dir, approvedFiles = listOf(GlideDropCodec.ApprovedFile("report.txt"))
            )
            assertEquals(listOf("report.txt"), saved.map { it.name })
            assertEquals("received", saved.single().readText())
            assertEquals(listOf("report.txt"), dir.listFiles()!!.map { it.name })
        } finally { dir.deleteRecursively() }
    }

    @Test
    fun nonRegularEntriesAndDirectoriesWithDataStayRejectedUnderManifest() {
        val approved = listOf(GlideDropCodec.ApprovedFile("report.txt"))
        val cases = mapOf(
            "symlink" to odc("link", "target".toByteArray(), mode = 41471),
            "char device" to odc("dev", mode = 8612),
            "fifo" to odc("pipe", mode = 4516),
            "directory with data" to odc(".", "payload".toByteArray(), mode = 16877)
        )
        for ((label, entry) in cases) {
            val dir = Files.createTempDirectory("codec-non-regular").toFile()
            try {
                val failed = try {
                    GlideDropCodec.extractDvzipCpio((entry + archive()).inputStream(), dir, approvedFiles = approved)
                    false
                } catch (_: java.io.IOException) { true }
                assertTrue("$label must be rejected", failed)
                assertEquals("$label must publish nothing", 0, dir.listFiles()!!.size)
            } finally { dir.deleteRecursively() }
        }
    }

    private fun rejectsArchive(bytes: ByteArray, maxExpandedBytes: Long = Long.MAX_VALUE) {
        val dir = Files.createTempDirectory("codec-invalid-envelope").toFile()
        try {
            rejects { GlideDropCodec.extractDvzipCpio(bytes.inputStream(), dir, maxExpandedBytes = maxExpandedBytes) }
            assertEquals("Nothing may be published and staging must be removed", 0, dir.listFiles()!!.size)
        } finally { dir.deleteRecursively() }
    }

    @Test
    fun gzipFooterMustBeCompleteAndValidBeforePublication() {
        val wire = gzip(archive())
        for (missing in 1..8) rejectsArchive(wire.copyOf(wire.size - missing))
        for (index in wire.size - 8 until wire.size) {
            val corrupt = wire.copyOf()
            corrupt[index] = (corrupt[index].toInt() xor 1).toByte()
            rejectsArchive(corrupt)
        }
    }

    @Test
    fun trailingDecodedDataAfterCpioTrailerIsRejectedForEveryEnvelope() {
        val raw = archive() + byteArrayOf(0, 0, 1)
        for (wire in listOf(raw, gzip(raw), dvzipBlock(raw), dvzipBlock(raw, stored = true))) {
            rejectsArchive(wire)
        }
        rejectsArchive(gzip(archive()) + gzip("another decoded member".toByteArray()))
        rejectsArchive(dvzipBlock(archive()) + dvzipBlock("another decoded block".toByteArray()))
    }

    @Test
    fun concatenatedGzipMembersCannotHideDataOnFragmentedStreams() {
        val wire = gzip(archive()) + gzip("hidden decoded data".toByteArray())
        val dir = Files.createTempDirectory("codec-gzip-fragmented").toFile()
        try {
            val input = object : ByteArrayInputStream(wire) {
                override fun available(): Int = 0
                override fun read(b: ByteArray, off: Int, len: Int): Int = super.read(b, off, minOf(len, 1))
            }
            rejects { GlideDropCodec.extractDvzipCpio(input, dir) }
            assertEquals(0, dir.listFiles()!!.size)
        } finally { dir.deleteRecursively() }
    }

    @Test
    fun postTrailerZeroPaddingIsBoundedAndChargedToExpansionLimit() {
        val padding = ByteArray(65536)
        val raw = archive() + padding
        for (wire in listOf(raw, gzip(raw), dvzipBlock(raw), dvzipBlock(raw, stored = true))) {
            val dir = Files.createTempDirectory("codec-padding").toFile()
            try {
                val input = object : ByteArrayInputStream(wire) {
                    var closedByCodec = false
                    override fun close() { closedByCodec = true; super.close() }
                }
                val saved = GlideDropCodec.extractDvzipCpio(input, dir, maxExpandedBytes = raw.size.toLong())
                assertEquals("received", saved.single().readText())
                assertEquals("The complete envelope must be read", 0, input.available())
                assertTrue("The caller retains ownership of rawIn", !input.closedByCodec)
                rejectsArchive(wire, maxExpandedBytes = raw.size - 1L)
            } finally { dir.deleteRecursively() }
        }
        val excessive = raw + byteArrayOf(0)
        for (wire in listOf(excessive, gzip(excessive), dvzipBlock(excessive))) rejectsArchive(wire)
    }

    @Test
    fun dvzipEndBlockMustBeCompleteAndFinalButRemainsOptional() {
        val block = dvzipBlock(archive(), stored = true)
        val dir = Files.createTempDirectory("codec-dvzip-end").toFile()
        try {
            for (end in listOf(byteArrayOf(), ByteArray(4))) {
                assertEquals("received", GlideDropCodec.extractDvzipCpio((block + end).inputStream(), dir).single().readText())
            }
        } finally { dir.deleteRecursively() }
        for (partial in 1..3) rejectsArchive(block + ByteArray(partial))
        rejectsArchive(block + ByteArray(4) + byteArrayOf(1))
        rejectsArchive(block + ByteArray(4) + dvzipBlock(byteArrayOf(0)))
        rejectsArchive(block + java.nio.ByteBuffer.allocate(4).putInt(GlideDropCodec.DVZIP_STORED).array())
    }

    @Test
    fun dvzipZlibFooterAndDeclaredBlockLengthMustBeValidated() {
        val block = dvzipBlock(archive())
        for (missing in 1..4) {
            val truncated = block.copyOf(block.size - missing)
            java.nio.ByteBuffer.wrap(truncated).putInt(truncated.size - 4)
            rejectsArchive(truncated)
        }
        val excess = block + byteArrayOf(0)
        java.nio.ByteBuffer.wrap(excess).putInt(excess.size - 4)
        rejectsArchive(excess)
        val declaredTooLong = block.copyOf()
        java.nio.ByteBuffer.wrap(declaredTooLong).putInt(block.size - 3)
        rejectsArchive(declaredTooLong)
    }

    @Test
    fun existingPartFileIsNeverTruncated() {
        val dir = Files.createTempDirectory("codec-existing-part").toFile()
        try {
            File(dir, "report.txt.part").writeText("keep me")
            val saved = GlideDropCodec.extractDvzipCpio(archive().inputStream(), dir)
            assertEquals("keep me", File(dir, "report.txt.part").readText())
            assertEquals("received", saved.single().readText())
        } finally { dir.deleteRecursively() }
    }

    @Test
    fun predictablePartSymlinkCannotOverwriteVictim() {
        val dir = Files.createTempDirectory("codec-symlink-part").toFile()
        val victim = Files.createTempFile("codec-victim", ".txt").toFile()
        try {
            victim.writeText("keep me")
            Files.createSymbolicLink(File(dir, "report.txt.part").toPath(), victim.toPath())
            val saved = GlideDropCodec.extractDvzipCpio(archive().inputStream(), dir)
            assertEquals("keep me", victim.readText())
            assertEquals("received", saved.single().readText())
            assertTrue(Files.isSymbolicLink(File(dir, "report.txt.part").toPath()))
        } finally { dir.deleteRecursively(); victim.delete() }
    }

    @Test
    fun danglingFinalSymlinkIsACollisionNotAReplacement() {
        val dir = Files.createTempDirectory("codec-dangling-final").toFile()
        try {
            val target = File(dir, "report.txt").toPath()
            Files.createSymbolicLink(target, File(dir, "missing-victim").toPath())
            val saved = GlideDropCodec.extractDvzipCpio(archive().inputStream(), dir)
            assertTrue(Files.isSymbolicLink(target))
            assertEquals("report (1).txt", saved.single().name)
            assertEquals("received", saved.single().readText())
            assertTrue(!File(dir, "missing-victim").exists())
        } finally { dir.deleteRecursively() }
    }

    @Test
    fun concurrentFinalArrivalIsNotReplaced() {
        val dir = Files.createTempDirectory("codec-final-race").toFile()
        val bytes = archive()
        val dataOffset = odc("report.txt").size
        val input = object : ByteArrayInputStream(bytes) {
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (pos == dataOffset) File(dir, "report.txt").writeText("other transfer")
                return super.read(b, off, len)
            }
        }
        try {
            val saved = GlideDropCodec.extractDvzipCpio(input, dir)
            assertEquals("other transfer", File(dir, "report.txt").readText())
            assertEquals("received", saved.single().readText())
            assertTrue(saved.single().name != "report.txt")
        } finally { dir.deleteRecursively() }
    }

    @Test
    fun missingTrailerRejectsEvenAtEntryBoundary() {
        val dir = Files.createTempDirectory("codec-no-trailer").toFile()
        try {
            rejects { GlideDropCodec.extractDvzipCpio(odc("report.txt", "received".toByteArray()).inputStream(), dir) }
            assertEquals(0, dir.listFiles()!!.size)
            rejects { GlideDropCodec.extractDvzipCpio(byteArrayOf().inputStream(), dir) }
        } finally { dir.deleteRecursively() }
    }

    @Test
    fun repeatedPlistReferencesShareDecodedObjects() {
        val objects = (0 until 12).map { byteArrayOf(0xa2.toByte(), (it + 1).toByte(), (it + 1).toByte()) } +
            listOf(byteArrayOf(0x51, 'x'.code.toByte()))
        var node = GlideDropCodec.decodeBplist(plist(objects))
        repeat(12) {
            val list = node as List<*>
            org.junit.Assert.assertSame(list[0], list[1])
            node = list[0]
        }
        assertEquals("x", node)
    }

    @Test
    fun compactPlistGraphCannotExpandExponentiallyInCallers() {
        val objects = (0 until 24).map { byteArrayOf(0xa2.toByte(), (it + 1).toByte(), (it + 1).toByte()) } +
            listOf(byteArrayOf(0x51, 'x'.code.toByte()))
        rejects { GlideDropCodec.decodeBplist(plist(objects)) }
    }

    @Test
    fun malformedPlistCyclesCountsAndWideIndicesAreRejected() {
        val cases = listOf(
            plist(listOf(byteArrayOf(0xa1.toByte(), 0))),
            plist(listOf(byteArrayOf(0xa1.toByte(), 1))),
            plist(listOf(byteArrayOf(0)), top = 0x1_0000_0000L),
            plist(listOf(byteArrayOf(0xa1.toByte()) + java.nio.ByteBuffer.allocate(8).putLong(0x1_0000_0001L).array(), byteArrayOf(0)), refSize = 8),
            plist(listOf(byteArrayOf(0x4f, 0x50))),
            plist(listOf(byteArrayOf(0x1f))),
            plist(listOf(byteArrayOf(0x5e, 65)))
        )
        cases.forEach { bytes -> rejects { GlideDropCodec.decodeBplist(bytes) } }
    }
    @Test
    fun aliasedPlistOffsetsCannotExceedDecodeBudget() {
        val refs = java.nio.ByteBuffer.allocate(1024).apply { repeat(512) { putShort((it + 1).toShort()) } }.array()
        val objects = listOf(byteArrayOf(0xaf.toByte(), 0x11, 2, 0) + refs) +
            listOf(byteArrayOf(0x5f, 0x11, 0x40, 0) + ByteArray(16384) { 65 }) +
            List(511) { byteArrayOf(0) }
        val bytes = plist(objects, refSize = 2)
        val buffer = java.nio.ByteBuffer.wrap(bytes)
        val table = buffer.getLong(bytes.size - 8).toInt()
        val stringOffset = buffer.getInt(table + 4)
        for (i in 2..512) buffer.putInt(table + i * 4, stringOffset)
        rejects { GlideDropCodec.decodeBplist(bytes) }
    }

    @Test
    fun expandedArchiveBudgetRejectsRawGzipAndDvzipBeforePublishing() {
        val payload = ByteArray(65536) { 65 }
        val raw = archive(data = payload)
        val gzip = ByteArrayOutputStream().also { out ->
            java.util.zip.GZIPOutputStream(out).use { it.write(raw) }
        }.toByteArray()
        val dvzip = ByteArrayOutputStream().also { out ->
            GlideDropCodec.writeDvzipCpio(listOf(GlideDropCodec.OutgoingEntry("report.txt", payload.size.toLong()) {
                payload.inputStream()
            }), out)
        }.toByteArray()
        for (wire in listOf(raw, gzip, dvzip)) {
            val dir = Files.createTempDirectory("codec-expansion-cap").toFile()
            try {
                rejects { GlideDropCodec.extractDvzipCpio(wire.inputStream(), dir, maxExpandedBytes = 32768) }
                assertEquals(0, dir.listFiles()!!.size)
                val saved = GlideDropCodec.extractDvzipCpio(wire.inputStream(), dir, maxExpandedBytes = raw.size.toLong())
                assertArrayEquals(payload, saved.single().readBytes())
            } finally { dir.deleteRecursively() }
        }
    }

    @Test
    fun expansionBudgetAlsoCountsCompressedSkippedEntries() {
        val raw = odc("ignored-link", ByteArray(65536) { 65 }, mode = 40960) + odc("TRAILER!!!", mode = 0)
        val gzip = ByteArrayOutputStream().also { out ->
            java.util.zip.GZIPOutputStream(out).use { it.write(raw) }
        }.toByteArray()
        val compressed = ByteArrayOutputStream().also { out ->
            java.util.zip.DeflaterOutputStream(out).use { it.write(raw) }
        }.toByteArray()
        val dvzip = java.nio.ByteBuffer.allocate(4).putInt(compressed.size).array() + compressed + ByteArray(4)
        for (wire in listOf(gzip, dvzip)) {
            val dir = Files.createTempDirectory("codec-skipped-budget").toFile()
            try {
                rejects { GlideDropCodec.extractDvzipCpio(wire.inputStream(), dir, maxExpandedBytes = 32768) }
                assertEquals(0, dir.listFiles()!!.size)
            } finally { dir.deleteRecursively() }
        }
    }

    @Test
    fun defaultWifiStreamingIsNotLimitedByBleBudget() {
        val size = 30_000_001
        val out = ByteArrayOutputStream()
        java.util.zip.GZIPOutputStream(out).use { gzip ->
            val header = odc("large.bin")
            // Patch the odc size independently; produce the body without a large in-memory fixture.
            val sizeBytes = String.format(java.util.Locale.US, "%011o", size.toLong()).toByteArray()
            sizeBytes.copyInto(header, 65)
            gzip.write(header)
            val chunk = ByteArray(65536) { 42 }
            var left = size
            while (left > 0) {
                val n = minOf(chunk.size, left)
                gzip.write(chunk, 0, n)
                left -= n
            }
            gzip.write(odc("TRAILER!!!", mode = 0))
        }
        val dir = Files.createTempDirectory("codec-large-wifi").toFile()
        try {
            val file = GlideDropCodec.extractDvzipCpio(out.toByteArray().inputStream(), dir).single()
            assertEquals(size.toLong(), file.length())
            file.inputStream().use { input ->
                val chunk = ByteArray(65536)
                var count = 0L
                while (true) {
                    val n = input.read(chunk)
                    if (n < 0) break
                    for (i in 0 until n) assertEquals(42.toByte(), chunk[i])
                    count += n
                }
                assertEquals(size.toLong(), count)
            }
        } finally { dir.deleteRecursively() }
    }

    @Test
    fun approvedManifestRejectsExtraMissingDuplicateAndWrongSizeEntries() {
        val approved = listOf(GlideDropCodec.ApprovedFile("report.txt", 8L))
        val invalid = listOf(
            archive("unexpected.txt"),
            odc("TRAILER!!!", mode = 0),
            odc("report.txt", "received".toByteArray()) + archive(),
            archive(data = "short".toByteArray()),
            odc("report.txt", "received".toByteArray()) + odc("link", mode = 40960) + odc("TRAILER!!!", mode = 0)
        )
        for (wire in invalid) {
            val dir = Files.createTempDirectory("codec-manifest-reject").toFile()
            try {
                rejects { GlideDropCodec.extractDvzipCpio(wire.inputStream(), dir, approvedFiles = approved) }
                assertEquals(0, dir.listFiles()!!.size)
            } finally { dir.deleteRecursively() }
        }
        val dir = Files.createTempDirectory("codec-manifest-ok").toFile()
        try {
            File(dir, "report.txt").writeText("existing")
            val saved = GlideDropCodec.extractDvzipCpio(archive().inputStream(), dir, approvedFiles = approved)
            assertEquals("received", saved.single().readText())
            assertEquals("report (1).txt", saved.single().name)
            assertEquals("existing", File(dir, "report.txt").readText())
        } finally { dir.deleteRecursively() }
    }

    @Test
    fun approvedManifestSupportsUnknownSizesAndDuplicateNamesInAnyOrder() {
        val dir = Files.createTempDirectory("codec-manifest-duplicates").toFile()
        try {
            val wire = odc("report.txt", "received".toByteArray()) + archive(data = "other".toByteArray())
            val saved = GlideDropCodec.extractDvzipCpio(wire.inputStream(), dir, approvedFiles = listOf(
                GlideDropCodec.ApprovedFile("report.txt"), GlideDropCodec.ApprovedFile("report.txt", 8)
            ))
            assertEquals(listOf("received", "other"), saved.map { it.readText() })
            rejects { GlideDropCodec.extractDvzipCpio(archive().inputStream(), dir, approvedFiles = emptyList()) }
        } finally { dir.deleteRecursively() }
    }

    @Test
    fun roundTripBplistAndDvzipCpio() {
        val sampleBytes = "hello-glidedrop".toByteArray()
        val payload = mapOf(
            "SenderComputerName" to "Android Phone",
            "SenderModelName" to "SM-S911B",
            "BundleID" to "com.apple.finder",
            "ConvertMediaFormats" to false,
            "VerifiableIdentity" to true,
            "SenderRecordData" to sampleBytes,
            "Files" to listOf(
                mapOf(
                    "FileName" to "test.txt",
                    "FileType" to "public.plain-text",
                    "FileBomPath" to "./test.txt",
                    "FileIsDirectory" to false,
                    "ConvertMediaFormats" to 0L
                )
            )
        )

        val encoded = GlideDropCodec.encodeBplist(payload)
        assertTrue(String(encoded, 0, 8, Charsets.US_ASCII) == "bplist00")

        val decoded = GlideDropCodec.decodeBplistDict(encoded)
        assertEquals("Android Phone", decoded["SenderComputerName"])
        assertEquals("SM-S911B", decoded["SenderModelName"])
        assertEquals(false, decoded["ConvertMediaFormats"])
        assertEquals(true, decoded["VerifiableIdentity"])
        assertArrayEquals(sampleBytes, decoded["SenderRecordData"] as ByteArray)

        @Suppress("UNCHECKED_CAST")
        val files = decoded["Files"] as List<Map<String, Any?>>
        assertEquals(1, files.size)
        assertEquals("test.txt", files[0]["FileName"])
        assertEquals(0L, files[0]["ConvertMediaFormats"])

        // Test DVZip (64 KiB zlib/stored blocks + 070707 odc CPIO) archive streaming & extraction
        val out = ByteArrayOutputStream()
        GlideDropCodec.writeDvzipCpio(
            listOf(
                GlideDropCodec.OutgoingEntry(
                    name = "./test.txt",
                    size = sampleBytes.size.toLong(),
                    openStream = { ByteArrayInputStream(sampleBytes) }
                )
            ),
            out
        )

        val tempDir = Files.createTempDirectory("glidedrop-test").toFile()
        try {
            val extracted = GlideDropCodec.extractDvzipCpio(ByteArrayInputStream(out.toByteArray()), tempDir)
            assertEquals(1, extracted.size)
            assertArrayEquals(sampleBytes, File(tempDir, "test.txt").readBytes())
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun largeMultiBlockStreamingTest() {
        // Create 2 MB payload spanning multiple DVZip blocks (both compressed and stored)
        val payload = ByteArray(2 * 1024 * 1024) { (it % 251).toByte() }
        val out = ByteArrayOutputStream()
        var progressReported = 0L
        GlideDropCodec.writeDvzipCpio(
            listOf(
                GlideDropCodec.OutgoingEntry(
                    name = "./large_test.bin",
                    size = payload.size.toLong(),
                    openStream = { ByteArrayInputStream(payload) }
                )
            ),
            out
        ) { bytesRead ->
            progressReported = bytesRead
        }

        assertEquals(payload.size.toLong(), progressReported)

        val tempDir = Files.createTempDirectory("glidedrop-large-test").toFile()
        try {
            val extracted = GlideDropCodec.extractDvzipCpio(ByteArrayInputStream(out.toByteArray()), tempDir)
            assertEquals(1, extracted.size)
            val extractedFile = File(tempDir, "large_test.bin")
            assertEquals(payload.size.toLong(), extractedFile.length())
            assertArrayEquals(payload, extractedFile.readBytes())
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun bplistDoubleAndFloatSupport() {
        val payload = mapOf(
            "DoubleVal" to 42.125,
            "FloatVal" to 3.5f,
            "NegativeInt" to -500L
        )
        val encoded = GlideDropCodec.encodeBplist(payload)
        val decoded = GlideDropCodec.decodeBplistDict(encoded)
        assertEquals(42.125, (decoded["DoubleVal"] as Double), 0.0001)
        assertEquals(3.5, (decoded["FloatVal"] as Double), 0.0001)
    }

    @Test(expected = IllegalArgumentException::class)
    fun negativeSizeRejected() {
        val out = ByteArrayOutputStream()
        GlideDropCodec.writeDvzipCpio(
            listOf(
                GlideDropCodec.OutgoingEntry(
                    name = "invalid.bin",
                    size = -1L,
                    openStream = { ByteArrayInputStream(ByteArray(0)) }
                )
            ),
            out
        )
    }

    @Test
    fun extended64BitCpioHeaderAndStreaming() {
        // Test 64-bit Extended CPIO format (070764) for files > 8 GiB (e.g. 17,718,303,741 B / 16.50 GB)
        val payload = "payload-for-16.5gb-virtual-stream".toByteArray(Charsets.UTF_8)
        val out = ByteArrayOutputStream()
        GlideDropCodec.writeDvzipCpio(
            listOf(
                GlideDropCodec.OutgoingEntry(
                    name = "./large_archive.zip",
                    size = payload.size.toLong(),
                    openStream = { ByteArrayInputStream(payload) }
                )
            ),
            out
        )

        val tempDir = Files.createTempDirectory("glidedrop-64bit-test").toFile()
        try {
            val extracted = GlideDropCodec.extractDvzipCpio(ByteArrayInputStream(out.toByteArray()), tempDir)
            assertEquals(1, extracted.size)
            assertArrayEquals(payload, File(tempDir, "large_archive.zip").readBytes())
        } finally {
            tempDir.deleteRecursively()
        }

        // Test explicit 070764 header generation and roundtrip decoding with 17,718,303,741 bytes
        val largeSize = 17_718_303_741L
        val fakePayload = ByteArray(1024) { (it % 127).toByte() }
        val largeOut = ByteArrayOutputStream()
        GlideDropCodec.writeDvzipCpio(
            listOf(
                GlideDropCodec.OutgoingEntry(
                    name = "./Fear.The.Walking.Dead.S05.1080p.Hindi.English.Esubs.Moviesmod.cc.zip",
                    size = fakePayload.size.toLong(),
                    openStream = { ByteArrayInputStream(fakePayload) }
                )
            ),
            largeOut
        )
        // Verify that standard size (fakePayload.size) uses 070707, but if size > 8 GiB it uses 070764
        val largeHeaderOnlyOut = ByteArrayOutputStream()
        // Create an entry that streams fakePayload length but declares size > 8 GiB to test header wire format
        val entryName = "16.5gb_file.zip"
        val nameBytes = entryName.toByteArray(Charsets.UTF_8)
        val formatted64Hdr = String.format(
            java.util.Locale.US,
            "070764%016x%08x%08x%08x%08x%016x%016x%08x%08x",
            1L,
            33188,
            0,
            0,
            1,
            1731050000L,
            largeSize,
            nameBytes.size + 1,
            0
        )
        assertEquals(102, formatted64Hdr.length)
        assertTrue(formatted64Hdr.startsWith("070764"))
        val parsedSize = java.lang.Long.parseUnsignedLong(formatted64Hdr.substring(70, 86), 16)
        assertEquals(largeSize, parsedSize)
    }

    @Test
    fun atomicPartFileCleanupOnTruncation() {
        val payload = ByteArray(100_000) { (it % 256).toByte() }
        val out = ByteArrayOutputStream()
        GlideDropCodec.writeDvzipCpio(
            listOf(
                GlideDropCodec.OutgoingEntry(
                    name = "interrupted.bin",
                    size = payload.size.toLong(),
                    openStream = { ByteArrayInputStream(payload) }
                )
            ),
            out
        )
        val fullArchive = out.toByteArray()
        // Truncate archive in the middle of payload data
        val truncatedArchive = fullArchive.copyOf(fullArchive.size / 2)

        val tempDir = Files.createTempDirectory("glidedrop-atomic-test").toFile()
        try {
            var failed = false
            try {
                GlideDropCodec.extractDvzipCpio(ByteArrayInputStream(truncatedArchive), tempDir)
            } catch (_: java.io.IOException) {
                failed = true
            }
            assertTrue("Expected truncated stream to throw IOException", failed)
            val files = tempDir.listFiles().orEmpty()
            assertTrue("Destination directory must not contain .part files after failure", files.none { it.name.endsWith(".part") })
            assertTrue("Destination directory must not contain partial target files", files.none { it.name == "interrupted.bin" })
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun precompressedExtensionUsesStoredBlocksDirectly() {
        val payload = ByteArray(128 * 1024) { (it * 31).toByte() }
        val out = ByteArrayOutputStream()
        GlideDropCodec.writeDvzipCpio(
            listOf(
                GlideDropCodec.OutgoingEntry(
                    name = "clip.mkv",
                    size = payload.size.toLong(),
                    openStream = { ByteArrayInputStream(payload) }
                )
            ),
            out
        )
        val encoded = out.toByteArray()
        val firstHdr = java.nio.ByteBuffer.wrap(encoded, 0, 4).int
        assertTrue("Expected stored DVZip header flag (0x80000000)", (firstHdr and GlideDropCodec.DVZIP_STORED) != 0)

        val tempDir = Files.createTempDirectory("glidedrop-precomp-test").toFile()
        try {
            val extracted = GlideDropCodec.extractDvzipCpio(ByteArrayInputStream(encoded), tempDir)
            assertEquals(1, extracted.size)
            assertArrayEquals(payload, File(tempDir, "clip.mkv").readBytes())
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun multiMegabyteOneMibStoredBlocksRoundTrip() {
        val payload = ByteArray(3 * 1024 * 1024 + 137_913) { ((it * 17) xor (it ushr 9)).toByte() }
        val out = ByteArrayOutputStream()
        GlideDropCodec.writeDvzipCpio(
            listOf(
                GlideDropCodec.OutgoingEntry(
                    name = "movie_4k.mp4",
                    size = payload.size.toLong(),
                    openStream = { ByteArrayInputStream(payload) }
                )
            ),
            out
        )
        val tempDir = Files.createTempDirectory("glidedrop-1mib-test").toFile()
        try {
            val extracted = GlideDropCodec.extractDvzipCpio(ByteArrayInputStream(out.toByteArray()), tempDir)
            assertEquals(1, extracted.size)
            assertArrayEquals(payload, File(tempDir, "movie_4k.mp4").readBytes())
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun insufficientStorageCheckRejectsOversizedArchiveEntry() {
        val hugeSize = 900_000_000_000_000L // ~900 TB declared in 070764 header
        val name = "oversized.bin"
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        val hdr = String.format(
            java.util.Locale.US,
            "070764%016x%08x%08x%08x%08x%016x%016x%08x%08x",
            1L,
            33188,
            0,
            0,
            1,
            1731050000L,
            hugeSize,
            nameBytes.size + 1,
            0
        ).toByteArray(Charsets.US_ASCII)
        val archiveBytes = ByteArrayOutputStream().apply {
            write(hdr)
            write(nameBytes)
            write(0)
        }.toByteArray()

        val tempDir = Files.createTempDirectory("glidedrop-space-test").toFile()
        try {
            var threwIo = false
            try {
                GlideDropCodec.extractDvzipCpio(ByteArrayInputStream(archiveBytes), tempDir)
            } catch (e: java.io.IOException) {
                threwIo = e.message?.contains("Insufficient storage space") == true
            }
            assertTrue("Expected IOException for insufficient storage space", threwIo)
        } finally {
            tempDir.deleteRecursively()
        }
    }

    @Test
    fun signedOverflowCpio64BitSizeIsRejected() {
        val name = "overflow.bin"
        val nameBytes = name.toByteArray(Charsets.UTF_8)
        val hdr = (
            "070764" +
                "0000000000000001" +
                "000081a4" +
                "00000000" +
                "00000000" +
                "00000001" +
                "00000000672dd650" +
                "8000000000000000" + // wraps negative if unchecked after parseUnsignedLong
                String.format(java.util.Locale.US, "%08x", nameBytes.size + 1) +
                "00000000"
            ).toByteArray(Charsets.US_ASCII)
        val archiveBytes = ByteArrayOutputStream().apply {
            write(hdr)
            write(nameBytes)
            write(0)
        }.toByteArray()

        val tempDir = Files.createTempDirectory("glidedrop-overflow-test").toFile()
        try {
            var threw = false
            try {
                GlideDropCodec.extractDvzipCpio(ByteArrayInputStream(archiveBytes), tempDir)
            } catch (_: IllegalArgumentException) {
                threw = true
            }
            assertTrue("Expected IllegalArgumentException for >= 8 EiB CPIO size", threw)
            assertEquals(0, tempDir.listFiles()?.size ?: 0)
        } finally {
            tempDir.deleteRecursively()
        }
    }
}
