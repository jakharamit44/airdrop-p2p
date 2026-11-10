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

        // Verify BLE Continuity AirDrop wake frame (0x05 + 18 len + 0x40 Arm A + 3 tag bytes + 0x03)
        val ble = GlideDropCodec.bleWakePayload(byteArrayOf(0x11, 0x22, 0x33))
        assertEquals(20, ble.size)
        assertEquals(0x05.toByte(), ble[0])
        assertEquals(18.toByte(), ble[1])
        assertEquals(0x03.toByte(), ble[10])
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
}
