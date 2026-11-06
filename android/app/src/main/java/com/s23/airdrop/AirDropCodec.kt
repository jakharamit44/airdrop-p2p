package com.s23.airdrop

import java.io.BufferedOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.zip.Deflater
import java.util.zip.GZIPInputStream
import java.util.zip.Inflater

/**
 * AirDrop wire codecs ported from netmojo-systems/omdrop-plugin:
 * 1. Apple binary plist (bplist00) encoder/decoder for /Discover and /Ask
 * 2. DVZip + CPIO (070707 odc / 070701 newc) streaming archive encoder/decoder for /Upload
 * 3. Apple Continuity BLE (0x004C, type 0x05) wake payload
 */
object AirDropCodec {

    const val DVZIP_BLOCK_BYTES = 65536
    const val DVZIP_STORED = 0x80000000.toInt()
    const val DEVICE_SUPPORT_FLAGS = 111611L

    val MEDIA_CAPABILITIES_BYTES: ByteArray =
        """{"SupportsAdjustmentBaseResources":true,"Version":3,"Codecs":{"hvc1":{"Profiles":{"VTIsHDRAllowedOnDevice":true,"VTSupportedProfiles":[1,2,3,4],"VTDoViIsHardwareAccelerated":true,"VTDoViSupportedLevels":["01","02","03","04","05","06","07","08","09"],"VTPerProfileSupport":{"3":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"1":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"4":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"2":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186}},"VTDoViSupportedProfiles":["05","08"]}},"CodecSupport":{"VTIsHDRAllowedOnDevice":true,"VTCodecSupportDict":{"apcs":{"VTIsHardwareAccelerated":true},"hvc1":{"VTIsHDRAllowedOnDevice":true,"VTPerProfileSupport":{"3":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"1":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"4":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"2":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186}},"VTSupportedProfiles":[1,2,3,4]},"apcn":{"VTIsHardwareAccelerated":true},"apch":{"VTIsHardwareAccelerated":true},"apco":{"VTIsHardwareAccelerated":true},"ap4x":{"VTIsHardwareAccelerated":true},"ap4h":{"VTIsHardwareAccelerated":true}}}},"ContainerFormats":{"public.heif-standard":{"HeifSubtypes":["public.avci","public.avif","public.heic","public.heics","public.heif"]}},"Vendor":{"com.apple":{"LivePhotoFormatVersion":"1","AssetBundleFormatVersion":"1"}}}"""
            .toByteArray(StandardCharsets.UTF_8)

    /** Continuity AirDrop (type 0x05) Arm A (OS 26+) BLE manufacturer data for company 0x004C. */
    fun bleWakePayload(tag3Bytes: ByteArray): ByteArray {
        require(tag3Bytes.size == 3)
        val out = ByteArray(20)
        out[0] = 0x05 // Continuity type: AirDrop
        out[1] = 0x12 // Length: 18 bytes
        out[2] = 0x40 // Arm A (OS 26+)
        out[3] = tag3Bytes[0]
        out[4] = tag3Bytes[1]
        out[5] = tag3Bytes[2]
        // bytes 6..9 = 0x00
        out[10] = 0x03
        // bytes 11..18 = 4 x 2-byte contact hashes (zeros for Everyone mode)
        // byte 19 = 0x00
        return out
    }

    fun utiForName(name: String): String {
        val dot = name.lastIndexOf('.')
        if (dot <= 0) return "public.data"
        return when (name.substring(dot).lowercase()) {
            ".jpg", ".jpeg" -> "public.jpeg"
            ".png" -> "public.png"
            ".heic" -> "public.heic"
            ".mov" -> "com.apple.quicktime-movie"
            ".mp4" -> "public.mpeg-4"
            ".pdf" -> "com.adobe.pdf"
            ".txt" -> "public.plain-text"
            else -> "public.data"
        }
    }

    fun safeFileName(rawPath: String): String {
        val base = rawPath.replace('\\', '/').substringAfterLast('/').trim()
        val cleaned = base.replace(Regex("[\\x00-\\x1f\\x7f-\\x9f/\\\\]"), "_")
            .trimStart('.')
        return cleaned.ifEmpty { "airdrop_file" }.take(240)
    }

    // =========================================================================
    // Apple Binary Plist (bplist00) Encoder & Decoder
    // =========================================================================

    fun encodeBplist(root: Any?): ByteArray {
        val objects = ArrayList<Any?>()
        fun collect(node: Any?): Int {
            val idx = objects.size
            objects.add(null) // reserve slot in pre-order
            when (node) {
                is Map<*, *> -> {
                    val sorted = node.entries
                        .map { it.key.toString() to it.value }
                        .sortedBy { it.first }
                    val keyRefs = IntArray(sorted.size)
                    val valRefs = IntArray(sorted.size)
                    for (i in sorted.indices) keyRefs[i] = collect(sorted[i].first)
                    for (i in sorted.indices) valRefs[i] = collect(sorted[i].second)
                    objects[idx] = Pair(keyRefs, valRefs)
                }
                is List<*> -> {
                    val refs = IntArray(node.size) { collect(node[it]) }
                    objects[idx] = refs
                }
                else -> objects[idx] = node
            }
            return idx
        }
        collect(root)

        val refSize = when {
            objects.size < 256 -> 1
            objects.size < 65536 -> 2
            else -> 4
        }
        val out = ByteArrayOutputStream()
        out.write("bplist00".toByteArray(StandardCharsets.US_ASCII))

        fun writeIntSized(v: Long, nBytes: Int) {
            for (shift in (nBytes - 1) downTo 0) {
                out.write(((v ushr (shift * 8)) and 0xFF).toInt())
            }
        }

        fun writeHeaderWithLen(markerHighNibble: Int, len: Int) {
            if (len < 15) {
                out.write((markerHighNibble shl 4) or len)
            } else {
                out.write((markerHighNibble shl 4) or 0x0F)
                when {
                    len < 256 -> {
                        out.write(0x10)
                        out.write(len)
                    }
                    len < 65536 -> {
                        out.write(0x11)
                        writeIntSized(len.toLong(), 2)
                    }
                    else -> {
                        out.write(0x12)
                        writeIntSized(len.toLong(), 4)
                    }
                }
            }
        }

        val offsets = IntArray(objects.size)
        for (i in objects.indices) {
            offsets[i] = out.size()
            when (val obj = objects[i]) {
                null -> out.write(0x00)
                false -> out.write(0x08)
                true -> out.write(0x09)
                is Number -> {
                    val v = obj.toLong()
                    when {
                        v in 0..255 -> {
                            out.write(0x10)
                            out.write(v.toInt())
                        }
                        v in 0..65535 -> {
                            out.write(0x11)
                            writeIntSized(v, 2)
                        }
                        v in 0..0xFFFFFFFFL -> {
                            out.write(0x12)
                            writeIntSized(v, 4)
                        }
                        else -> {
                            out.write(0x13)
                            writeIntSized(v, 8)
                        }
                    }
                }
                is ByteArray -> {
                    writeHeaderWithLen(0x4, obj.size)
                    out.write(obj)
                }
                is String -> {
                    val isAscii = obj.all { it.code in 1..127 }
                    if (isAscii) {
                        val bytes = obj.toByteArray(StandardCharsets.US_ASCII)
                        writeHeaderWithLen(0x5, bytes.size)
                        out.write(bytes)
                    } else {
                        writeHeaderWithLen(0x6, obj.length)
                        val bytes = obj.toByteArray(StandardCharsets.UTF_16BE)
                        out.write(bytes)
                    }
                }
                is IntArray -> {
                    writeHeaderWithLen(0xA, obj.size)
                    for (r in obj) writeIntSized(r.toLong(), refSize)
                }
                is Pair<*, *> -> {
                    val keyRefs = obj.first as IntArray
                    val valRefs = obj.second as IntArray
                    writeHeaderWithLen(0xD, keyRefs.size)
                    for (r in keyRefs) writeIntSized(r.toLong(), refSize)
                    for (r in valRefs) writeIntSized(r.toLong(), refSize)
                }
                else -> throw IllegalArgumentException("Unsupported plist type: ${obj::class}")
            }
        }

        val offsetTableStart = out.size()
        val maxOffset = offsets.maxOrNull() ?: 0
        val offsetSize = when {
            maxOffset < 256 -> 1
            maxOffset < 65536 -> 2
            else -> 4
        }
        for (off in offsets) {
            writeIntSized(off.toLong(), offsetSize)
        }

        // 32-byte trailer
        val trailer = ByteBuffer.allocate(32)
        trailer.position(6)
        trailer.put(offsetSize.toByte())
        trailer.put(refSize.toByte())
        trailer.putLong(objects.size.toLong())
        trailer.putLong(0L) // top object index = 0
        trailer.putLong(offsetTableStart.toLong())
        out.write(trailer.array())
        return out.toByteArray()
    }

    @Suppress("UNCHECKED_CAST")
    fun decodeBplistDict(bytes: ByteArray): Map<String, Any?> =
        (decodeBplist(bytes) as? Map<String, Any?>) ?: emptyMap()

    fun decodeBplist(bytes: ByteArray): Any? {
        require(bytes.size >= 40 && String(bytes, 0, 8, StandardCharsets.US_ASCII) == "bplist00") {
            "Not a valid binary plist"
        }
        val trailer = ByteBuffer.wrap(bytes, bytes.size - 26, 26)
        val offsetSize = trailer.get().toInt() and 0xFF
        val refSize = trailer.get().toInt() and 0xFF
        val numObjects = trailer.long.toInt()
        val topObject = trailer.long.toInt()
        val offsetTableOffset = trailer.long.toInt()
        require(offsetSize in 1..8 && refSize in 1..8 && numObjects in 1..65536) {
            "Invalid bplist trailer"
        }

        fun readUint(pos: Int, len: Int): Long {
            var v = 0L
            for (i in 0 until len) {
                v = (v shl 8) or (bytes[pos + i].toLong() and 0xFF)
            }
            return v
        }

        val offsets = IntArray(numObjects) { i ->
            readUint(offsetTableOffset + i * offsetSize, offsetSize).toInt()
        }

        fun parseAt(objIdx: Int, depth: Int): Any? {
            if (depth > 32 || objIdx !in 0 until numObjects) return null
            var pos = offsets[objIdx]
            val marker = bytes[pos++].toInt() and 0xFF
            val high = (marker ushr 4) and 0x0F
            val low = marker and 0x0F

            fun readCount(): Int {
                if (low != 0x0F) return low
                val intMarker = bytes[pos++].toInt() and 0xFF
                val intBytes = 1 shl (intMarker and 0x0F)
                val count = readUint(pos, intBytes).toInt()
                pos += intBytes
                return count
            }

            return when (high) {
                0x0 -> when (low) {
                    0x8 -> false
                    0x9 -> true
                    else -> null
                }
                0x1 -> {
                    val nBytes = 1 shl low
                    readUint(pos, nBytes)
                }
                0x2 -> {
                    val nBytes = 1 shl low
                    if (nBytes == 4) ByteBuffer.wrap(bytes, pos, 4).float.toDouble()
                    else ByteBuffer.wrap(bytes, pos, 8).double
                }
                0x4 -> {
                    val len = readCount()
                    bytes.copyOfRange(pos, pos + len)
                }
                0x5 -> {
                    val len = readCount()
                    String(bytes, pos, len, StandardCharsets.US_ASCII)
                }
                0x6 -> {
                    val chars = readCount()
                    String(bytes, pos, chars * 2, StandardCharsets.UTF_16BE)
                }
                0xA -> {
                    val count = readCount()
                    List(count) { i ->
                        val ref = readUint(pos + i * refSize, refSize).toInt()
                        parseAt(ref, depth + 1)
                    }
                }
                0xD -> {
                    val count = readCount()
                    val map = LinkedHashMap<String, Any?>(count)
                    val valStart = pos + count * refSize
                    for (i in 0 until count) {
                        val kRef = readUint(pos + i * refSize, refSize).toInt()
                        val vRef = readUint(valStart + i * refSize, refSize).toInt()
                        val key = parseAt(kRef, depth + 1)?.toString() ?: continue
                        map[key] = parseAt(vRef, depth + 1)
                    }
                    map
                }
                else -> null
            }
        }

        return parseAt(topObject, 0)
    }

    // =========================================================================
    // DVZip + CPIO (070707 odc / 070701 newc) Streaming Archive
    // =========================================================================

    data class OutgoingEntry(
        val name: String,
        val size: Long,
        val mtimeSec: Long = System.currentTimeMillis() / 1000L,
        val openStream: () -> InputStream
    )

    /**
     * Streams files as a 070707 (odc) CPIO archive inside 64 KiB DVZip blocks
     * (4-byte big-endian block header + zlib or stored payload), matching sharingd.
     * Uses stored blocks for payloads >= 1 MiB to maximize 5 GHz Wi-Fi Direct throughput
     * with near-zero memory and CPU overhead.
     */
    fun writeDvzipCpio(
        entries: List<OutgoingEntry>,
        rawOut: OutputStream,
        onProgress: ((Long) -> Unit)? = null
    ) {
        val totalSize = entries.sumOf { it.size }
        val useStoredBlocks = totalSize >= 1_048_576L
        val dvzipOut = object : OutputStream() {
            private val blockBuf = ByteArray(DVZIP_BLOCK_BYTES)
            private var blockLen = 0
            private val compBuf = if (useStoredBlocks) ByteArray(0) else ByteArray(DVZIP_BLOCK_BYTES + 1024)
            private val hdrBytes = ByteArray(4)

            private fun writeHdr(value: Int) {
                hdrBytes[0] = (value ushr 24).toByte()
                hdrBytes[1] = (value ushr 16).toByte()
                hdrBytes[2] = (value ushr 8).toByte()
                hdrBytes[3] = value.toByte()
                rawOut.write(hdrBytes)
            }

            override fun write(b: Int) {
                blockBuf[blockLen++] = b.toByte()
                if (blockLen == DVZIP_BLOCK_BYTES) emitBlock()
            }

            override fun write(b: ByteArray, off: Int, len: Int) {
                var offset = off
                var remaining = len
                while (remaining > 0) {
                    val room = DVZIP_BLOCK_BYTES - blockLen
                    val take = minOf(remaining, room)
                    System.arraycopy(b, offset, blockBuf, blockLen, take)
                    blockLen += take
                    offset += take
                    remaining -= take
                    if (blockLen == DVZIP_BLOCK_BYTES) emitBlock()
                }
            }

            fun emitBlock() {
                if (blockLen == 0) return
                if (useStoredBlocks) {
                    writeHdr(DVZIP_STORED or blockLen)
                    rawOut.write(blockBuf, 0, blockLen)
                    blockLen = 0
                    return
                }
                val deflater = Deflater(1, false) // fast zlib header
                deflater.setInput(blockBuf, 0, blockLen)
                deflater.finish()
                var compLen = 0
                while (!deflater.finished() && compLen < compBuf.size) {
                    val n = deflater.deflate(compBuf, compLen, compBuf.size - compLen)
                    if (n == 0 && !deflater.finished()) {
                        compLen = blockLen + 1
                        break
                    }
                    compLen += n
                }
                deflater.end()

                if (compLen in 1 until blockLen) {
                    writeHdr(compLen)
                    rawOut.write(compBuf, 0, compLen)
                } else {
                    writeHdr(DVZIP_STORED or blockLen)
                    rawOut.write(blockBuf, 0, blockLen)
                }
                blockLen = 0
            }

            override fun close() {
                emitBlock()
                rawOut.flush()
            }
        }

        fun writeOdcHeader(
            ino: Int,
            mode: Int,
            mtime: Long,
            nameBytes: ByteArray,
            fileSize: Long
        ) {
            val header = String.format(
                java.util.Locale.US,
                "070707%06o%06o%06o%06o%06o%06o%06o%011o%06o%011o",
                0,
                ino and 0x3FFFF,
                mode and 0x3FFFF,
                0,
                0,
                1,
                0,
                mtime.coerceAtLeast(0),
                nameBytes.size + 1,
                fileSize
            )
            dvzipOut.write(header.toByteArray(StandardCharsets.US_ASCII))
            dvzipOut.write(nameBytes)
            dvzipOut.write(0)
        }

        val buf = ByteArray(262144)
        var ino = 1
        var cumulativeRead = 0L
        for (entry in entries) {
            val safeName = safeFileName(entry.name)
            val nameBytes = safeName.toByteArray(StandardCharsets.UTF_8)
            writeOdcHeader(
                ino = ino++,
                mode = 33188, // 0100644 regular file
                mtime = entry.mtimeSec,
                nameBytes = nameBytes,
                fileSize = entry.size
            )
            var written = 0L
            entry.openStream().use { inp ->
                while (written < entry.size) {
                    val want = minOf(buf.size.toLong(), entry.size - written).toInt()
                    val n = inp.read(buf, 0, want)
                    if (n <= 0) throw EOFException("Short read on ${entry.name}")
                    dvzipOut.write(buf, 0, n)
                    written += n
                    cumulativeRead += n
                    onProgress?.invoke(cumulativeRead)
                }
            }
        }
        // CPIO TRAILER!!!
        writeOdcHeader(
            ino = 0,
            mode = 0,
            mtime = 0,
            nameBytes = "TRAILER!!!".toByteArray(StandardCharsets.US_ASCII),
            fileSize = 0
        )
        dvzipOut.close()
    }

    /**
     * Decodes a DVZip or Gzip stream containing a 070707 (odc) or 070701/070702 (newc)
     * CPIO archive and extracts regular files into destDir.
     */
    fun extractDvzipCpio(rawIn: InputStream, destDir: File): List<File> {
        destDir.mkdirs()
        val cpioStream = openDvzipOrGzipStream(rawIn)
        val saved = ArrayList<File>()
        val ioBuf = ByteArray(262144)

        fun readExact(inp: InputStream, dst: ByteArray, len: Int = dst.size): Int {
            var off = 0
            while (off < len) {
                val n = inp.read(dst, off, len - off)
                if (n <= 0) break
                off += n
            }
            return off
        }

        while (true) {
            val magicBuf = ByteArray(6)
            val m = readExact(cpioStream, magicBuf, 6)
            if (m == 0) break
            if (m < 6) throw EOFException("Truncated CPIO magic")
            val magic = String(magicBuf, StandardCharsets.US_ASCII)

            val mode: Int
            val nameSize: Int
            val fileSize: Long
            val isNewc: Boolean

            when (magic) {
                "070707" -> {
                    val hdr = ByteArray(70)
                    if (readExact(cpioStream, hdr, 70) < 70) throw EOFException("Truncated odc header")
                    val hStr = String(hdr, StandardCharsets.US_ASCII)
                    mode = hStr.substring(12, 18).toInt(8)
                    nameSize = hStr.substring(53, 59).toInt(8)
                    fileSize = hStr.substring(59, 70).toLong(8)
                    isNewc = false
                }
                "070701", "070702" -> {
                    val hdr = ByteArray(104)
                    if (readExact(cpioStream, hdr, 104) < 104) throw EOFException("Truncated newc header")
                    val hStr = String(hdr, StandardCharsets.US_ASCII)
                    mode = hStr.substring(8, 16).toInt(16)
                    fileSize = hStr.substring(48, 56).toLong(16)
                    nameSize = hStr.substring(88, 96).toInt(16)
                    isNewc = true
                }
                else -> throw IllegalArgumentException("Invalid CPIO magic: $magic")
            }

            require(nameSize in 1..4097) { "Invalid CPIO name size: $nameSize" }
            val nameBuf = ByteArray(nameSize)
            if (readExact(cpioStream, nameBuf, nameSize) < nameSize) {
                throw EOFException("Truncated CPIO entry name")
            }
            val rawName = String(nameBuf, 0, nameSize - 1, StandardCharsets.UTF_8)
            if (isNewc) {
                val hdrPad = (4 - ((110 + nameSize) % 4)) % 4
                if (hdrPad > 0) readExact(cpioStream, ByteArray(hdrPad), hdrPad)
            }
            if (rawName == "TRAILER!!!") break

            val isRegularFile = (mode and 61440) == 32768 // (mode & 0170000) == 0100000
            if (isRegularFile) {
                val baseName = safeFileName(rawName)
                var outFile = File(destDir, baseName)
                if (!outFile.canonicalPath.startsWith(destDir.canonicalPath)) {
                    throw SecurityException("CPIO path traversal detected: $rawName")
                }
                var suffix = 1
                while (outFile.exists()) {
                    val dot = baseName.lastIndexOf('.')
                    outFile = if (dot > 0) {
                        File(destDir, "${baseName.substring(0, dot)} ($suffix)${baseName.substring(dot)}")
                    } else {
                        File(destDir, "$baseName ($suffix)")
                    }
                    suffix++
                }
                BufferedOutputStream(FileOutputStream(outFile), 262144).use { fos ->
                    var left = fileSize
                    while (left > 0) {
                        val want = minOf(ioBuf.size.toLong(), left).toInt()
                        val n = cpioStream.read(ioBuf, 0, want)
                        if (n <= 0) throw EOFException("Truncated CPIO file data for $baseName")
                        fos.write(ioBuf, 0, n)
                        left -= n
                    }
                    fos.flush()
                }
                saved.add(outFile)
            } else {
                var left = fileSize
                while (left > 0) {
                    val want = minOf(ioBuf.size.toLong(), left).toInt()
                    val n = cpioStream.read(ioBuf, 0, want)
                    if (n <= 0) throw EOFException("Truncated CPIO non-file entry")
                    left -= n
                }
            }

            if (isNewc) {
                val dataPad = ((4 - (fileSize % 4)) % 4).toInt()
                if (dataPad > 0) readExact(cpioStream, ByteArray(dataPad), dataPad)
            }
        }
        return saved
    }

    private fun openDvzipOrGzipStream(rawIn: InputStream): InputStream {
        val prefix = ByteArray(2)
        var got = 0
        while (got < 2) {
            val n = rawIn.read(prefix, got, 2 - got)
            if (n <= 0) break
            got += n
        }
        if (got == 0) return ByteArrayInputStream(ByteArray(0))
        val combined = java.io.SequenceInputStream(ByteArrayInputStream(prefix, 0, got), rawIn)
        if (got == 2 && prefix[0] == 0x1f.toByte() && prefix[1] == 0x8b.toByte()) {
            return GZIPInputStream(combined)
        }
        return object : InputStream() {
            private var storedLeft = 0
            private var compLeft = 0
            private var inflater: Inflater? = null
            private val inBuf = ByteArray(65536)
            private val oneByte = ByteArray(1)
            private var eof = false

            override fun read(): Int {
                val n = read(oneByte, 0, 1)
                return if (n <= 0) -1 else (oneByte[0].toInt() and 0xFF)
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (len == 0) return 0
                while (!eof) {
                    if (storedLeft > 0) {
                        val want = minOf(len, storedLeft)
                        val n = combined.read(b, off, want)
                        if (n <= 0) throw EOFException("Truncated DVZip stored block")
                        storedLeft -= n
                        return n
                    }
                    val inf = inflater
                    if (inf != null) {
                        val produced = inf.inflate(b, off, len)
                        if (produced > 0) {
                            if (inf.finished()) {
                                inf.end()
                                inflater = null
                            }
                            return produced
                        }
                        if (inf.finished()) {
                            inf.end()
                            inflater = null
                            continue
                        }
                        if (inf.needsInput()) {
                            if (compLeft <= 0) throw EOFException("Truncated DVZip zlib block")
                            val want = minOf(inBuf.size, compLeft)
                            val n = combined.read(inBuf, 0, want)
                            if (n <= 0) throw EOFException("Truncated DVZip compressed bytes")
                            compLeft -= n
                            inf.setInput(inBuf, 0, n)
                            continue
                        }
                    }

                    // Read next 4-byte DVZip block header
                    val hdr = ByteArray(4)
                    var hRead = 0
                    while (hRead < 4) {
                        val n = combined.read(hdr, hRead, 4 - hRead)
                        if (n <= 0) break
                        hRead += n
                    }
                    if (hRead == 0) {
                        eof = true
                        return -1
                    }
                    if (hRead < 4) throw EOFException("Truncated DVZip block header ($hRead bytes)")
                    val v = ByteBuffer.wrap(hdr).int
                    val blockLen = v and 0x7FFFFFFF
                    if ((v and DVZIP_STORED) != 0) {
                        storedLeft = blockLen
                    } else {
                        compLeft = blockLen
                        inflater = Inflater(false)
                    }
                }
                return -1
            }
        }
    }
}
