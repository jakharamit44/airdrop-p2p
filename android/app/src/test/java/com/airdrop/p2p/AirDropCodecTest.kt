package com.airdrop.p2p

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files

class AirDropCodecTest {
    @Test
    fun roundTripBplistAndDvzipCpio() {
        val sampleBytes = "hello-airdrop-p2p".toByteArray()
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

        val encoded = AirDropCodec.encodeBplist(payload)
        assertTrue(String(encoded, 0, 8, Charsets.US_ASCII) == "bplist00")

        val decoded = AirDropCodec.decodeBplistDict(encoded)
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
        AirDropCodec.writeDvzipCpio(
            listOf(
                AirDropCodec.OutgoingEntry(
                    name = "./test.txt",
                    size = sampleBytes.size.toLong(),
                    openStream = { ByteArrayInputStream(sampleBytes) }
                )
            ),
            out
        )

        val tempDir = Files.createTempDirectory("airdrop-test").toFile()
        try {
            val extracted = AirDropCodec.extractDvzipCpio(ByteArrayInputStream(out.toByteArray()), tempDir)
            assertEquals(1, extracted.size)
            assertArrayEquals(sampleBytes, File(tempDir, "test.txt").readBytes())
        } finally {
            tempDir.deleteRecursively()
        }

        // Verify BLE Continuity AirDrop wake frame (0x05 + 18 len + 0x40 Arm A + 3 tag bytes + 0x03)
        val ble = AirDropCodec.bleWakePayload(byteArrayOf(0x11, 0x22, 0x33))
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
        AirDropCodec.writeDvzipCpio(
            listOf(
                AirDropCodec.OutgoingEntry(
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

        val tempDir = Files.createTempDirectory("airdrop-large-test").toFile()
        try {
            val extracted = AirDropCodec.extractDvzipCpio(ByteArrayInputStream(out.toByteArray()), tempDir)
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
        val encoded = AirDropCodec.encodeBplist(payload)
        val decoded = AirDropCodec.decodeBplistDict(encoded)
        assertEquals(42.125, (decoded["DoubleVal"] as Double), 0.0001)
        assertEquals(3.5, (decoded["FloatVal"] as Double), 0.0001)
    }

    @Test(expected = IllegalArgumentException::class)
    fun odcSizeLimitEnforced() {
        val out = ByteArrayOutputStream()
        AirDropCodec.writeDvzipCpio(
            listOf(
                AirDropCodec.OutgoingEntry(
                    name = "giant.bin",
                    size = 9_000_000_000L,
                    openStream = { ByteArrayInputStream(ByteArray(0)) }
                )
            ),
            out
        )
    }
}
