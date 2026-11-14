package io.github.jakharamit44.glidedrop

import android.content.Context
import android.os.StatFs
import android.os.storage.StorageManager
import java.io.BufferedOutputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.FileAlreadyExistsException
import java.nio.file.FileSystemException
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption
import java.util.zip.Deflater
import java.util.zip.GZIPInputStream
import java.util.zip.Inflater

/**
 * GlideDrop wire codecs (compatible with Apple bplist00 & DVZip/CPIO):
 * 1. Binary plist (bplist00) encoder/decoder for /Discover and /Ask
 * 2. DVZip + CPIO (070707 odc / 070701 newc / 070764 64-bit) streaming archive encoder/decoder for /Upload
 */
object GlideDropCodec {

    const val DVZIP_BLOCK_BYTES = 65536
    const val DVZIP_STORED_BLOCK_BYTES = 1_048_576
    const val DVZIP_STORED = 0x80000000.toInt()
    const val DEVICE_SUPPORT_FLAGS = 111611L

    private val PRECOMPRESSED_EXTENSIONS = setOf(
        "mkv", "mp4", "mov", "avi", "webm", "m4v", "ts",
        "jpg", "jpeg", "png", "webp", "heic", "heif", "gif",
        "mp3", "m4a", "aac", "flac", "ogg", "opus",
        "zip", "gz", "tgz", "bz2", "xz", "zst", "7z", "rar",
        "apk", "aab", "ipa", "dmg", "pkg", "pdf", "docx", "xlsx", "pptx"
    )

    val MEDIA_CAPABILITIES_BYTES: ByteArray =
        """{"SupportsAdjustmentBaseResources":true,"Version":3,"Codecs":{"hvc1":{"Profiles":{"VTIsHDRAllowedOnDevice":true,"VTSupportedProfiles":[1,2,3,4],"VTDoViIsHardwareAccelerated":true,"VTDoViSupportedLevels":["01","02","03","04","05","06","07","08","09"],"VTPerProfileSupport":{"3":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"1":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"4":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"2":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186}},"VTDoViSupportedProfiles":["05","08"]}},"CodecSupport":{"VTIsHDRAllowedOnDevice":true,"VTCodecSupportDict":{"apcs":{"VTIsHardwareAccelerated":true},"hvc1":{"VTIsHDRAllowedOnDevice":true,"VTPerProfileSupport":{"3":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"1":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"4":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186},"2":{"VTMaxPlaybackLevel":186,"VTIsHardwareAccelerated":true,"VTMaxDecodeLevel":186}},"VTSupportedProfiles":[1,2,3,4]},"apcn":{"VTIsHardwareAccelerated":true},"apch":{"VTIsHardwareAccelerated":true},"apco":{"VTIsHardwareAccelerated":true},"ap4x":{"VTIsHardwareAccelerated":true},"ap4h":{"VTIsHardwareAccelerated":true}}}},"ContainerFormats":{"public.heif-standard":{"HeifSubtypes":["public.avci","public.avif","public.heic","public.heics","public.heif"]}},"Vendor":{"com.apple":{"LivePhotoFormatVersion":"1","AssetBundleFormatVersion":"1"}}}"""
            .toByteArray(StandardCharsets.UTF_8)

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
        return cleaned.ifEmpty { "glidedrop_file" }.take(240)
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
                is Double -> {
                    out.write(0x23)
                    writeIntSized(java.lang.Double.doubleToRawLongBits(obj), 8)
                }
                is Float -> {
                    out.write(0x22)
                    writeIntSized(java.lang.Float.floatToRawIntBits(obj).toLong() and 0xFFFFFFFFL, 4)
                }
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
        val trailerStart = bytes.size - 32
        val trailer = ByteBuffer.wrap(bytes, bytes.size - 26, 26)
        val offsetSize = trailer.get().toInt() and 0xFF
        val refSize = trailer.get().toInt() and 0xFF
        val objectCount = trailer.long
        val rootIndex = trailer.long
        val tableOffset = trailer.long
        require(offsetSize in 1..8 && refSize in 1..8 && objectCount in 1..65536L) {
            "Invalid bplist trailer"
        }
        require(rootIndex in 0 until objectCount && tableOffset in 8L..trailerStart.toLong()) {
            "Invalid bplist root or offset table"
        }
        require(objectCount * offsetSize <= trailerStart - tableOffset) { "Truncated bplist offset table" }
        val numObjects = objectCount.toInt()
        val table = tableOffset.toInt()

        fun readUint(pos: Int, len: Int, end: Int): Long {
            require(len in 1..8 && pos >= 8 && pos.toLong() + len <= end) { "Truncated bplist value" }
            var v = 0L
            for (i in 0 until len) v = (v shl 8) or (bytes[pos + i].toLong() and 0xFF)
            return v
        }
        fun index(value: Long, end: Int): Int {
            require(value >= 0 && value < end.toLong()) { "Invalid bplist index or length" }
            return value.toInt()
        }
        val offsets = IntArray(numObjects) { i ->
            index(readUint(table + i * offsetSize, offsetSize, trailerStart), table).also {
                require(it >= 8) { "Invalid bplist object offset" }
            }
        }
        val memo = arrayOfNulls<Any?>(numObjects)
        val state = ByteArray(numObjects)
        val heights = IntArray(numObjects)
        val expansionCosts = LongArray(numObjects) { 1L }
        val maxCost = 4L * 1024 * 1024
        // Bound both materialized decoding and logical expansion by downstream consumers.
        var budget = maxCost
        fun charge(amount: Long) {
            require(amount >= 0 && amount <= budget) { "Bplist decode budget exceeded" }
            budget -= amount
        }
        fun parseAt(objIdx: Int, depth: Int): Any? {
            require(depth <= 32 && state[objIdx] != 1.toByte()) { "Bplist cycle or excessive depth" }
            if (state[objIdx] == 2.toByte()) {
                require(depth + heights[objIdx] <= 32) { "Bplist excessive depth" }
                return memo[objIdx]
            }
            state[objIdx] = 1
            charge(1)
            var pos = offsets[objIdx]
            val marker = bytes[pos++].toInt() and 0xFF
            val high = marker ushr 4
            val low = marker and 0x0F
            fun readCount(): Int {
                if (low != 15) return low
                require(pos < table) { "Missing bplist length" }
                val intMarker = bytes[pos++].toInt() and 0xFF
                require(intMarker in 0x10..0x13) { "Invalid bplist length marker" }
                val width = 1 shl (intMarker and 15)
                val count = readUint(pos, width, table)
                pos += width
                return index(count, Int.MAX_VALUE)
            }
            fun span(count: Int, width: Int): Int {
                val length = count.toLong() * width
                require(pos.toLong() + length <= table) { "Truncated bplist object" }
                charge(length)
                require(expansionCosts[objIdx] <= maxCost - length) { "Bplist expansion budget exceeded" }
                expansionCosts[objIdx] += length
                return length.toInt()
            }
            fun child(refPos: Int): Any? {
                val ref = index(readUint(refPos, refSize, table), numObjects)
                val value = parseAt(ref, depth + 1)
                require(expansionCosts[objIdx] <= maxCost - expansionCosts[ref]) { "Bplist expansion budget exceeded" }
                expansionCosts[objIdx] += expansionCosts[ref]
                heights[objIdx] = maxOf(heights[objIdx], 1 + heights[ref])
                return value
            }
            val value: Any? = when (high) {
                0 -> when (low) {
                    0 -> null
                    8 -> false
                    9 -> true
                    else -> throw IllegalArgumentException("Unsupported bplist simple value")
                }
                1 -> {
                    require(low <= 3) { "Unsupported bplist integer width" }
                    readUint(pos, 1 shl low, table)
                }
                2 -> {
                    require(low == 2 || low == 3) { "Invalid bplist real width" }
                    span(1, 1 shl low)
                    if (low == 2) ByteBuffer.wrap(bytes, pos, 4).float.toDouble()
                    else ByteBuffer.wrap(bytes, pos, 8).double
                }
                4, 5, 6 -> {
                    val length = span(readCount(), if (high == 6) 2 else 1)
                    when (high) {
                        4 -> bytes.copyOfRange(pos, pos + length)
                        5 -> String(bytes, pos, length, StandardCharsets.US_ASCII)
                        else -> String(bytes, pos, length, StandardCharsets.UTF_16BE)
                    }
                }
                10 -> {
                    val count = readCount()
                    span(count, refSize)
                    List(count) { child(pos + it * refSize) }
                }
                13 -> {
                    val count = readCount()
                    span(count, 2 * refSize)
                    val map = LinkedHashMap<String, Any?>(count)
                    for (i in 0 until count) {
                        val key = child(pos + i * refSize)
                        require(key is String && !map.containsKey(key)) { "Invalid or duplicate bplist dictionary key" }
                        map[key] = child(pos + (count + i) * refSize)
                    }
                    map
                }
                else -> throw IllegalArgumentException("Unsupported bplist object type: $high")
            }
            memo[objIdx] = value
            state[objIdx] = 2
            return value
        }
        return parseAt(rootIndex.toInt(), 0)
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
        val allPrecompressed = entries.isNotEmpty() && entries.all {
            it.name.substringAfterLast('.', "").lowercase(java.util.Locale.US) in PRECOMPRESSED_EXTENSIONS
        }
        val useStoredBlocks = totalSize >= 1_048_576L || allPrecompressed
        val smallBufCap = if (useStoredBlocks) 4096 else DVZIP_BLOCK_BYTES
        val dvzipOut = object : OutputStream() {
            private val blockBuf = ByteArray(smallBufCap)
            private var blockLen = 0
            private val compBuf = if (useStoredBlocks) ByteArray(0) else ByteArray(DVZIP_BLOCK_BYTES + 1024)
            private val hdrBytes = ByteArray(4)
            private val deflater = if (!useStoredBlocks) Deflater(1, false) else null

            private fun writeHdr(value: Int) {
                hdrBytes[0] = (value ushr 24).toByte()
                hdrBytes[1] = (value ushr 16).toByte()
                hdrBytes[2] = (value ushr 8).toByte()
                hdrBytes[3] = value.toByte()
                rawOut.write(hdrBytes)
            }

            override fun write(b: Int) {
                blockBuf[blockLen++] = b.toByte()
                if (blockLen == smallBufCap) emitBlock()
            }

            override fun write(b: ByteArray, off: Int, len: Int) {
                if (useStoredBlocks && len >= smallBufCap) {
                    emitBlock()
                    var offset = off
                    var remaining = len
                    while (remaining > 0) {
                        val chunk = minOf(remaining, DVZIP_STORED_BLOCK_BYTES)
                        writeHdr(DVZIP_STORED or chunk)
                        rawOut.write(b, offset, chunk)
                        offset += chunk
                        remaining -= chunk
                    }
                    return
                }
                var offset = off
                var remaining = len
                while (remaining > 0) {
                    val room = smallBufCap - blockLen
                    val take = minOf(remaining, room)
                    System.arraycopy(b, offset, blockBuf, blockLen, take)
                    blockLen += take
                    offset += take
                    remaining -= take
                    if (blockLen == smallBufCap) emitBlock()
                }
            }

            fun emitBlock() {
                if (blockLen == 0) return
                if (useStoredBlocks || deflater == null) {
                    writeHdr(DVZIP_STORED or blockLen)
                    rawOut.write(blockBuf, 0, blockLen)
                    blockLen = 0
                    return
                }
                deflater.reset()
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
                deflater?.end()
                rawOut.flush()
            }
        }

        fun writeCpioHeader(
            ino: Int,
            mode: Int,
            mtime: Long,
            nameBytes: ByteArray,
            fileSize: Long
        ) {
            require(fileSize >= 0L) { "Negative file size: $fileSize" }
            if (fileSize <= 0x1FFFFFFFFL) {
                // POSIX odc 070707 format (76-byte header, backwards-compatible for files <= 8 GiB)
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
            } else {
                // Extended 64-bit CPIO 070764 format (102-byte header, unconstrained 64-bit size for >= 8 GiB, 16.5 GB, 50 GB+)
                val header = String.format(
                    java.util.Locale.US,
                    "070764%016x%08x%08x%08x%08x%016x%016x%08x%08x",
                    ino.toLong() and 0xFFFFFFFFL,
                    mode and 0xFFFFFF,
                    0, // uid
                    0, // gid
                    1, // nlink
                    mtime.coerceAtLeast(0),
                    fileSize,
                    nameBytes.size + 1,
                    0  // check
                )
                dvzipOut.write(header.toByteArray(StandardCharsets.US_ASCII))
                dvzipOut.write(nameBytes)
                dvzipOut.write(0)
            }
        }

        val buf = ByteArray(if (useStoredBlocks) DVZIP_STORED_BLOCK_BYTES else 262144)
        var ino = 1
        var cumulativeRead = 0L
        for (entry in entries) {
            val safeName = safeFileName(entry.name)
            val nameBytes = safeName.toByteArray(StandardCharsets.UTF_8)
            writeCpioHeader(
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
        writeCpioHeader(
            ino = 0,
            mode = 0,
            mtime = 0,
            nameBytes = "TRAILER!!!".toByteArray(StandardCharsets.US_ASCII),
            fileSize = 0
        )
        dvzipOut.close()
    }

    internal fun availableStorageBytes(destDir: File, context: Context?): Long {
        if (context != null) {
            val allocatable = runCatching {
                val sm = context.getSystemService(StorageManager::class.java) ?: return@runCatching null
                val uuid = sm.getUuidForPath(destDir)
                sm.getAllocatableBytes(uuid)
            }.getOrNull()
            if (allocatable != null) return allocatable
        }
        val statBytes = runCatching { StatFs(destDir.absolutePath).availableBytes }.getOrNull()
        if (statBytes != null) return statBytes
        return Files.getFileStore(destDir.toPath()).usableSpace
    }

    private const val MAX_CPIO_TRAILING_PADDING_BYTES = 65536

    data class ApprovedFile(val name: String, val size: Long? = null)

    data class StreamedEntrySpec(
        val name: String,
        val sizeBytes: Long
    )

    /**
     * Streams validated regular CPIO entries directly to caller-provided output streams.
     * Validates all CPIO headers/sizes, approved-file manifests, expansion bounds, TRAILER!!!,
     * trailing padding, and DVZip/gzip EOF/footers before returning. On any error or
     * cancellation, [onRollbackEntry] is invoked for every entry handle opened so far.
     */
    fun <T> extractDvzipCpioStreaming(
        rawIn: InputStream,
        maxExpandedBytes: Long = Long.MAX_VALUE,
        availableStorageBytes: (() -> Long)? = null,
        approvedFiles: List<ApprovedFile>? = null,
        checkCancelled: (() -> Unit)? = null,
        openEntryOutput: (StreamedEntrySpec) -> Pair<T, OutputStream>,
        onRollbackEntry: (T) -> Unit = {}
    ): List<T> {
        require(maxExpandedBytes >= 0) { "Negative expansion limit" }
        val remaining = approvedFiles?.map {
            require(it.size == null || it.size >= 0) { "Negative approved file size" }
            it.copy(name = safeFileName(it.name))
        }?.groupingBy { it }?.eachCount()?.toMutableMap()
        val openedHandles = ArrayList<T>()
        val ioBuf = ByteArray(DVZIP_STORED_BLOCK_BYTES)
        // Release decoder resources without closing the caller-owned HTTP/BLE stream.
        val borrowed = object : java.io.FilterInputStream(rawIn) {
            override fun close() = Unit
        }
        try {
            openDvzipOrGzipStream(borrowed).use { decoded ->
                val cpioStream = object : InputStream() {
                    var expanded = 0L
                    override fun read(): Int {
                        val b = ByteArray(1)
                        return if (read(b, 0, 1) < 0) -1 else b[0].toInt() and 255
                    }
                    override fun read(b: ByteArray, off: Int, len: Int): Int {
                        if (len == 0) return 0
                        if (expanded >= maxExpandedBytes) {
                            // Permit an EOF probe at the exact cap, including footer/checksum validation.
                            if (decoded.read() < 0) return -1
                            throw IOException("Expanded archive exceeds limit: $maxExpandedBytes")
                        }
                        val n = decoded.read(b, off, minOf(len.toLong(), maxExpandedBytes - expanded).toInt())
                        if (n > 0) expanded += n
                        return n
                    }
                }

                fun readExact(inp: InputStream, dst: ByteArray, len: Int = dst.size): Int {
                    var off = 0
                    while (off < len) {
                        checkCancelled?.invoke()
                        val n = inp.read(dst, off, len - off)
                        if (n <= 0) break
                        off += n
                    }
                    return off
                }

                while (true) {
                    checkCancelled?.invoke()
                    val magicBuf = ByteArray(6)
                    val m = readExact(cpioStream, magicBuf, 6)
                    if (m == 0) throw EOFException("Missing CPIO trailer")
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
                        "070764" -> {
                            val hdr = ByteArray(96)
                            if (readExact(cpioStream, hdr, 96) < 96) throw EOFException("Truncated 070764 header")
                            val hStr = String(hdr, StandardCharsets.US_ASCII)
                            mode = hStr.substring(16, 24).toInt(16)
                            fileSize = java.lang.Long.parseUnsignedLong(hStr.substring(64, 80), 16)
                            nameSize = hStr.substring(80, 88).toInt(16)
                            isNewc = false
                        }
                        else -> throw IllegalArgumentException("Invalid CPIO magic: $magic")
                    }

                    require(fileSize >= 0L) { "Invalid negative CPIO file size: $fileSize" }
                    require(nameSize in 1..4097) { "Invalid CPIO name size: $nameSize" }
                    val nameBuf = ByteArray(nameSize)
                    if (readExact(cpioStream, nameBuf, nameSize) < nameSize) {
                        throw EOFException("Truncated CPIO entry name")
                    }
                    require(nameBuf.indexOf(0.toByte()) == nameSize - 1) {
                        "Invalid CPIO name terminator"
                    }
                    val rawName = String(nameBuf, 0, nameSize - 1, StandardCharsets.UTF_8)
                    if (isNewc) {
                        val hdrPad = (4 - ((110 + nameSize) % 4)) % 4
                        if (hdrPad > 0 && readExact(cpioStream, ByteArray(hdrPad), hdrPad) != hdrPad) {
                            throw EOFException("Truncated CPIO header padding")
                        }
                    }
                    if (rawName == "TRAILER!!!") {
                        require(fileSize == 0L) { "Invalid CPIO trailer size" }
                        break
                    }

                    val isRegularFile = (mode and 61440) == 32768 // (mode & 0170000) == 0100000
                    if (isRegularFile) {
                        val baseName = safeFileName(rawName)
                        if (remaining != null) {
                            // Consume exact sizes before unknown sizes so duplicate names are order-independent.
                            val exact = ApprovedFile(baseName, fileSize)
                            val match = if (remaining.containsKey(exact)) exact else ApprovedFile(baseName)
                            val count = remaining[match]
                                ?: throw IOException("CPIO entry is not in approved manifest: $baseName ($fileSize bytes)")
                            if (count == 1) remaining.remove(match) else remaining[match] = count - 1
                        }
                        if (fileSize > maxExpandedBytes - cpioStream.expanded) {
                            throw IOException("Expanded archive exceeds limit: $maxExpandedBytes")
                        }
                        if (availableStorageBytes != null) {
                            val availableBytes = availableStorageBytes.invoke()
                            if (availableBytes < fileSize) {
                                throw IOException("Insufficient storage space for $baseName: required $fileSize B, available $availableBytes B")
                            }
                        }
                        checkCancelled?.invoke()
                        val (handle, outStream) = openEntryOutput(StreamedEntrySpec(baseName, fileSize))
                        openedHandles.add(handle)
                        outStream.use { fos ->
                            var left = fileSize
                            while (left > 0) {
                                checkCancelled?.invoke()
                                val want = minOf(ioBuf.size.toLong(), left).toInt()
                                val n = cpioStream.read(ioBuf, 0, want)
                                if (n <= 0) throw EOFException("Truncated CPIO file data for $baseName")
                                checkCancelled?.invoke()
                                fos.write(ioBuf, 0, n)
                                left -= n
                            }
                            checkCancelled?.invoke()
                            fos.flush()
                        }
                    } else {
                        // Senders (macOS sharingd and GlideDrop for Mac) emit an empty "." root
                        // directory entry before files. Empty directories are never materialised
                        // (output is flattened), so they are safe; any other non-regular entry
                        // (symlink, device, FIFO, or a directory carrying data) stays rejected.
                        val isEmptyDirectory = (mode and 61440) == 16384 && fileSize == 0L
                        if (remaining != null && !isEmptyDirectory) {
                            throw IOException("Non-regular CPIO entry is not approved: $rawName")
                        }
                        var left = fileSize
                        while (left > 0) {
                            checkCancelled?.invoke()
                            val want = minOf(ioBuf.size.toLong(), left).toInt()
                            val n = cpioStream.read(ioBuf, 0, want)
                            if (n <= 0) throw EOFException("Truncated CPIO non-file entry")
                            left -= n
                        }
                    }

                    if (isNewc) {
                        val dataPad = ((4 - (fileSize % 4)) % 4).toInt()
                        if (dataPad > 0 && readExact(cpioStream, ByteArray(dataPad), dataPad) != dataPad) {
                            throw EOFException("Truncated CPIO data padding")
                        }
                    }
                }
                // Reaching TRAILER!!! alone does not validate a gzip/zlib footer or later DVZip blocks.
                var padding = 0
                while (true) {
                    checkCancelled?.invoke()
                    val n = cpioStream.read(ioBuf, 0, minOf(ioBuf.size, MAX_CPIO_TRAILING_PADDING_BYTES - padding + 1))
                    if (n < 0) break
                    padding += n
                    if (padding > MAX_CPIO_TRAILING_PADDING_BYTES) throw IOException("Excessive CPIO trailing padding")
                    for (i in 0 until n) {
                        if (ioBuf[i] != 0.toByte()) throw IOException("Non-zero data after CPIO trailer")
                    }
                }
            }
            if (!remaining.isNullOrEmpty()) throw IOException("CPIO archive is missing approved files")
            checkCancelled?.invoke()
            return openedHandles
        } catch (t: Throwable) {
            for (handle in openedHandles) {
                runCatching { onRollbackEntry(handle) }
            }
            throw t
        }
    }

    /**
     * Extracts regular files only after a complete CPIO archive has been validated.
     * BLE callers must set [maxExpandedBytes] to a transport-specific cap; Wi-Fi streams
     * remain unrestricted by default. The cap includes headers, skipped entries and padding.
     * After TRAILER!!!, only up to 64 KiB of zero padding is allowed. Decoder EOF and
     * compressed-stream checksums/framing are validated before any files are published.
     * Pass the user-approved [approvedFiles] to enforce the exact flattened names/counts
     * and known sizes; null sizes support peers that omit FileSize. An empty list denies files.
     * The caller owns rawIn and must provide a trusted destination directory.
     */
    fun extractDvzipCpio(
        rawIn: InputStream,
        destDir: File,
        context: Context? = null,
        maxExpandedBytes: Long = Long.MAX_VALUE,
        approvedFiles: List<ApprovedFile>? = null
    ): List<File> {
        destDir.mkdirs()
        val destination = destDir.canonicalFile
        val staging = Files.createTempDirectory(destination.toPath(), ".glidedrop-")
        val saved = ArrayList<File>()
        try {
            var entryIdx = 0
            val pending = extractDvzipCpioStreaming(
                rawIn = rawIn,
                maxExpandedBytes = maxExpandedBytes,
                availableStorageBytes = { availableStorageBytes(destination, context) },
                approvedFiles = approvedFiles,
                openEntryOutput = { spec ->
                    val partFile = staging.resolve("${entryIdx++}.part").toFile()
                    val out = BufferedOutputStream(
                        Files.newOutputStream(
                            partFile.toPath(),
                            StandardOpenOption.CREATE_NEW,
                            StandardOpenOption.WRITE,
                            LinkOption.NOFOLLOW_LINKS
                        ),
                        DVZIP_STORED_BLOCK_BYTES
                    )
                    (partFile to spec.name) to out
                },
                onRollbackEntry = { (partFile, _) -> partFile.delete() }
            )
            for ((partFile, baseName) in pending) {
                var suffix = 0
                while (true) {
                    val dot = baseName.lastIndexOf('.')
                    val name = when {
                        suffix == 0 -> baseName
                        dot > 0 -> "${baseName.substring(0, dot)} ($suffix)${baseName.substring(dot)}"
                        else -> "$baseName ($suffix)"
                    }
                    val target = File(destination, name)
                    try {
                        publishNoReplace(partFile, target)
                        saved.add(target)
                        break
                    } catch (_: FileAlreadyExistsException) {
                        suffix++
                    }
                }
            }
            return saved
        } finally {
            staging.toFile().deleteRecursively()
        }
    }

    private fun publishNoReplace(staged: File, target: File) {
        try {
            // A hard link is atomic and fails if *any* target entry already exists, including a dangling symlink.
            Files.createLink(target.toPath(), staged.toPath())
            return
        } catch (e: FileAlreadyExistsException) {
            throw e
        } catch (_: UnsupportedOperationException) {
            // Emulated Android external storage may not support hard links.
        } catch (_: FileSystemException) {
            // Fall back to exclusive creation, never a check-then-replacing rename.
        }
        val output = Files.newOutputStream(
            target.toPath(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS
        )
        try {
            output.use { out -> staged.inputStream().use { it.copyTo(out, DVZIP_STORED_BLOCK_BYTES) } }
        } catch (e: Exception) {
            target.delete()
            throw e
        }
    }

    private fun openDvzipOrGzipStream(rawIn: InputStream): InputStream {
        val prefix = ByteArray(6)
        var got = 0
        while (got < 6) {
            val n = rawIn.read(prefix, got, 6 - got)
            if (n <= 0) break
            got += n
        }
        if (got == 0) return ByteArrayInputStream(ByteArray(0))
        val combined = java.io.SequenceInputStream(ByteArrayInputStream(prefix, 0, got), rawIn)
        if (got >= 2 && prefix[0] == 0x1f.toByte() && prefix[1] == 0x8b.toByte()) {
            return GZIPInputStream(combined, 65536)
        }
        if (got == 6) {
            val magic6 = String(prefix, 0, 6, StandardCharsets.US_ASCII)
            if (magic6 == "070707" || magic6 == "070701" || magic6 == "070702" || magic6 == "070764") {
                return combined
            }
        }
        return object : InputStream() {
            private var storedLeft = 0
            private var compLeft = 0
            private var inflater: Inflater? = null
            private val inBuf = ByteArray(65536)
            private val oneByte = ByteArray(1)
            private var eof = false

            private fun finishCompressedBlock(inf: Inflater) {
                if (inf.remaining != 0 || compLeft != 0) throw IOException("DVZip compressed block length mismatch")
                inf.end()
                inflater = null
            }

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
                        if (inf.needsDictionary()) {
                            throw IOException("Zlib preset dictionary not supported in DVZip")
                        }
                        val produced = try {
                            inf.inflate(b, off, len)
                        } catch (e: java.util.zip.DataFormatException) {
                            throw IOException("Invalid DVZip zlib block", e)
                        }
                        if (produced > 0) {
                            if (inf.finished()) finishCompressedBlock(inf)
                            return produced
                        }
                        if (inf.finished()) {
                            finishCompressedBlock(inf)
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
                    if (v == 0) {
                        if (combined.read() >= 0) throw IOException("Data after DVZip end block")
                        eof = true
                        return -1
                    }
                    val blockLen = v and 0x7FFFFFFF
                    if (blockLen == 0) throw IOException("Empty DVZip data block")
                    if ((v and DVZIP_STORED) != 0) {
                        storedLeft = blockLen
                    } else {
                        compLeft = blockLen
                        inflater = Inflater(false)
                    }
                }
                return -1
            }

            override fun close() {
                runCatching { inflater?.end() }
                inflater = null
                combined.close()
                super.close()
            }
        }
    }
}
