package com.flashguard.engine.core

import com.flashguard.engine.compression.Compression
import com.flashguard.engine.container.ArchiveImport
import com.flashguard.engine.container.SquashFsReader
import com.flashguard.engine.fs.VirtualFs
import com.flashguard.engine.util.Bin
import com.flashguard.engine.util.Hex
import com.flashguard.engine.util.Limits
import com.flashguard.engine.util.ProgressSink
import com.flashguard.engine.util.Text

/** Everything we managed to pull out of an image, plus what we could not. */
class UnpackResult(
    val vfs: VirtualFs,
    val notes: MutableList<String> = ArrayList(),
    val importedFiles: Int = 0,
    val unsupported: MutableList<String> = ArrayList(),
) {
    val usable: Boolean get() = importedFiles > 0

    /**
     * True only when the engine actually got *inside* the image (at least one object beyond the
     * virtual root was materialised).
     *
     * Every hardware-matrix row that reasons about the image's *content* - "ships no wireless
     * drivers", "has no USB support", "is not signed", "coverage: 100%" - is only evidence when
     * this is true. On an opaque payload (raw blob, vendor-encrypted file, UBI/UBIFS rootfs) the
     * absence of a module name is *absence of evidence*, and the honest verdict is "could not
     * check", never "not present".
     */
    val inspected: Boolean get() = importedFiles > 0 && vfs.fileCount > 1

    /** One line explaining why nothing could be read - null when the image was readable. */
    fun opaqueReason(): String? = if (inspected) null
    else unsupported.firstOrNull() ?: notes.lastOrNull { it.startsWith("Nothing extractable") }
}

/**
 * Turns a firmware blob into a virtual root filesystem by following containers and compression
 * layers, then mines the result for the facts the emulator, the hardware matrix and the report need.
 */
class FirmwareUnpacker(
    private val bytes: ByteArray,
    private val identity: ImageIdentity,
    private val progress: ProgressSink = ProgressSink.NONE,
) {
    private val vfs = VirtualFs()
    private val notes = ArrayList<String>()
    private val unsupported = ArrayList<String>()

    /**
     * [probe] marks a blob found by the deep scan (a guess at an offset inside an unrecognised
     * header). A probe that turns out not to be a valid stream is a dead end, not a limitation of
     * the image, so its failures are reported as notes instead of "unsupported" entries.
     */
    private class Job(val data: ByteArray, val origin: String, val depth: Int, val probe: Boolean = false)

    fun unpack(): UnpackResult {
        var imported = 0
        val queue = ArrayDeque<Job>()
        queue.add(Job(bytes, "primary image", 0))

        // Pre-seed nested regions discovered by the identifier (vendor header + payload layouts).
        for (layer in identity.layers.flatMap { it.flattenTree() }) {
            if (layer.offset <= 0) continue
            if (layer.format == ImageFormat.RAW || layer.format == ImageFormat.TPLINK_IMG0) continue
            var length = layer.length
            if (length <= 0) {
                // Sweep finds (no length). Recover a usable bound: SquashFS carries its
                // bytes_used in the superblock; stream formats (gzip/xz/...) run to EOF and
                // the decoder stops at the stream end anyway.
                length = when (layer.format) {
                    ImageFormat.SQUASHFS -> {
                        val off = layer.offset.toInt()
                        if (off + 48 <= bytes.size) {
                            val bu = Bin.u64le(bytes, off + 40)
                            if (bu in 1..(bytes.size - off).toLong()) bu else (bytes.size - off).toLong()
                        } else (bytes.size - off).toLong()
                    }
                    else -> (bytes.size - layer.offset).toLong()
                }
            }
            val start = layer.offset.toInt()
            val end = minOf(bytes.size.toLong(), layer.offset + length).toInt()
            if (end - start < 64) continue
            queue.add(Job(bytes.copyOfRange(start, end), "layer @0x${start.toString(16)} (${layer.format.label})", 1))
        }

        var steps = 0
        while (queue.isNotEmpty() && steps++ < 24) {
            val job = queue.removeFirst()
            if (job.depth > Limits.MAX_LAYER_DEPTH) {
                notes.add("Stopped at nesting depth ${Limits.MAX_LAYER_DEPTH} (${job.origin})")
                continue
            }
            progress.onProgress(20 + minOf(steps * 6, 50), "Unpacking ${job.origin}")
            imported += handleBlob(job, queue)
            if (vfs.storedBytes >= Limits.MAX_EXTRACT_BYTES) {
                notes.add("Extraction budget (${Hex.humanBytes(Limits.MAX_EXTRACT_BYTES)}) reached - remaining files were not kept")
                break
            }
        }

        if (imported == 0 && vfs.fileCount <= 1) {
            notes.add("Nothing extractable: the image is a flat blob (bootloader/whole-flash dump) or uses an unsupported container")
            unsupported.add(
                "Nothing inside this image could be unpacked: no recognised container, filesystem, archive or compression stream was found"
            )
        }
        notes.addAll(vfs.fileCount.let { listOf("Virtual rootfs: ${vfs.humanSummary()}") })
        if (vfs.truncated) unsupported.add("File count limit hit - the rootfs listing is partial")
        return UnpackResult(vfs, notes, imported, unsupported)
    }

    /** Returns how many filesystem objects were imported from this blob. */
    private fun handleBlob(job: Job, queue: ArrayDeque<Job>): Int {
        val data = job.data
        if (data.size < 8) return 0

        // 1) structured vendor containers first (they are not compression layers)
        when (FirmwareIdentifier.detectAt(data, 0)?.first) {
            ImageFormat.TRX -> {
                val parts = trxSegments(data)
                if (parts.size > 1) {
                    notes.add("TRX split into ${parts.size - 1} segments (${job.origin})")
                    for (i in 0 until parts.size - 1) {
                        val chunk = data.copyOfRange(parts[i], parts[i + 1])
                        if (chunk.size > 64) queue.add(Job(chunk, "${job.origin} TRX segment ${i + 1}", job.depth + 1))
                    }
                }
            }
            ImageFormat.UBOOT_LEGACY -> {
                // size@12 is valid for both real U-Boot (image_header_t) and the compat layout.
                // Compression must be sniffed from the payload: real uImage headers have no comp
                // field, and reading byte 31 (the old code path) lands in ih_name on real images.
                val size = Bin.u32be(data, 12)
                if (size in 1 until (data.size - 64 + 1).toLong().toInt()) {
                    val payload = data.copyOfRange(64, minOf(data.size, 64 + size.toInt()))
                    val decoded = Compression.decode(payload)
                    when {
                        decoded != null -> {
                            notes.add("uImage payload decompressed (${decoded.kind.label}, ${Hex.humanBytes(decoded.bytes.size)})")
                            queue.add(Job(decoded.bytes, "${job.origin} uImage payload", job.depth + 1))
                        }
                        Bin.u8(payload, 0) == 0x7F && payload.size > 4 &&
                            payload[1].toInt() and 0xFF == 0x45 && payload[2].toInt() and 0xFF == 0x4C &&
                            payload[3].toInt() and 0xFF == 0x46 ->
                            unsupported.add("uImage payload is a raw (uncompressed) ELF kernel - no rootfs to extract")
                        else -> unsupported.add("uImage payload is not a recognised compressed stream (${job.origin})")
                    }
                }
            }
            ImageFormat.UBI, ImageFormat.UBIFS, ImageFormat.JFFS2, ImageFormat.EXT -> {
                unsupported.add("${job.origin}: ${identity.primary.label} cannot be unpacked statically - the rootfs needs a mount (UBIFS/JFFS2/ext4)")
                return 0
            }
            ImageFormat.TPLINK_IMG0 -> {
                return unpackTpLinkImg0VxWorks(data, job.origin)
            }
            ImageFormat.TPLINK_SIGNED -> {
                unsupported.add("${job.origin}: vendor-signed/encrypted TP-Link image - payload cannot be inspected")
                return 0
            }
            else -> Unit
        }

        // 2) squashfs
        if (SquashFsReader.sniff(data)) {
            val reader = SquashFsReader(data)
            if (reader.parse()) {
                if (!reader.superBlock.decodable) {
                    unsupported.add("SquashFS uses ${reader.superBlock.compressorName} - listing unavailable on-device")
                    return 0
                }
                val entries = reader.toArchiveEntries()
                val n = ArchiveImport.importInto(vfs, entries)
                notes.add("SquashFS (${reader.superBlock.compressorName}): $n objects imported (${job.origin})")
                notes.add(reader.diagnostics)
                return n
            }
        }

        // 3) archives
        val archive = ArchiveImport.detect(data)
        if (archive != null) {
            val entries = archive.entries(data)
            val n = ArchiveImport.importInto(vfs, entries)
            notes.add("${archive.name} archive: $n objects imported (${job.origin})")
            // OpenWrt sysupgrade tars carry CONTROL metadata describing the exact target device.
            if (archive.name == "tar" && vfs.exists("/CONTROL")) {
                notes.add("OpenWrt sysupgrade package detected (CONTROL directory present)")
            }
            return n
        }

        // 4) plain compression layer
        val kind = Compression.sniff(data)
        if (kind != null) {
            if (!kind.decodable) {
                if (job.probe) notes.add("Deep-scan candidate ${job.origin} is a ${kind.label} this build cannot decompress - ignored")
                else unsupported.add("${kind.label} container cannot be decompressed on-device (${job.origin})")
                return 0
            }
            val decoded = Compression.decode(data)
            if (decoded != null && decoded.bytes.size > 16) {
                notes.add("${kind.label} decompressed: ${Hex.humanBytes(decoded.bytes.size)} (${job.origin})")
                queue.add(Job(decoded.bytes, "${job.origin} > ${kind.label}", job.depth + 1))
                return 0
            }
            // A mis-detected magic inside binary data is not a property of the firmware.
            if (job.probe) notes.add("Deep-scan candidate ${job.origin} was not a valid ${kind.label} stream - ignored")
            else unsupported.add("${kind.label} stream could not be decoded (${job.origin})")
            return 0
        }

        // 5) last resort: a vendor header the identifier could not parse, possibly followed by a
        //    payload we *can* read. Sweep the blob for a known payload and hand it back to the
        //    pipeline - this is what opens "Raw/unknown binary" vendor images whose header is
        //    proprietary but whose kernel/rootfs is a plain gzip/lzma/squashfs/tar stream.
        val hits = deepScan(data, job, queue)
        if (hits == 0) {
            notes.add(
                "Nothing recognisable in this blob (${job.origin}): no container, filesystem, archive or compression stream - " +
                    "the payload is likely encrypted, proprietary, or not a firmware image at all"
            )
        }
        return 0
    }

    /**
     * Sweeps [data] for payloads at *any* offset (not just the header the parser knows about).
     * Only streams we can actually decode are queued; a candidate that fails to decode is recorded
     * as a note, never as an "unsupported feature" of the image, so deep-scan noise cannot leak
     * into the report as a limitation of the file.
     */
    private fun deepScan(data: ByteArray, job: Job, queue: ArrayDeque<Job>): Int {
        if (data.size < 256) return 0
        val limit = minOf(data.size, DEEP_SCAN_BYTES)
        var hits = 0

        fun queueHit(at: Int, label: String) {
            notes.add("Deep scan: $label found at 0x${at.toString(16)} behind an unrecognised header (${job.origin})")
            queue.add(Job(data.copyOfRange(at, data.size), "${job.origin} $label @0x${at.toString(16)}", job.depth + 1, probe = true))
            hits++
        }

        for (m in DEEP_MAGICS) {
            if (hits >= MAX_DEEP_HITS) break
            var from = 16
            while (hits < MAX_DEEP_HITS) {
                val idx = Bin.indexOf(data, m.bytes, from)
                if (idx < 0 || idx >= limit) break
                from = idx + 1
                if (idx < 16) continue
                // SquashFS only counts when the superblock version really is 4, otherwise the four
                // magic bytes were a coincidence in binary data.
                if (m.format == ImageFormat.SQUASHFS && (idx + 30 > data.size || Bin.u16le(data, idx + 28) != 4)) continue
                // gzip needs the method byte and a sane flag byte: the 2-byte magic alone turns up
                // in random data far too often (1 in 65536 bytes).
                if (m.format == ImageFormat.GZIP &&
                    (idx + 4 > data.size || Bin.u8(data, idx + 2) != 0x08 || (Bin.u8(data, idx + 3) and 0xE0) != 0)
                ) continue
                if (m.format == ImageFormat.BZIP2 && (idx + 4 > data.size || Bin.u8(data, idx + 3) !in '1'.code..'9'.code)) continue
                queueHit(idx, m.label)
            }
        }

        // A tar archive whose 512-byte header starts after a vendor header: "ustar" sits at
        // start + 257. Validate the size field so random "ustar" strings cannot match.
        var from = 0
        while (hits < MAX_DEEP_HITS) {
            val idx = Bin.indexOfAscii(data, "ustar", from)
            if (idx < 0 || idx >= limit) break
            from = idx + 1
            val start = idx - 257
            if (start < 16) continue
            val sizeField = Bin.ascii(data, start + 124, 11).trim { it == ' ' || it == '\u0000' }
            if (sizeField.isEmpty() || sizeField.any { it < '0' || it > '7' }) continue
            queueHit(start, "tar archive")
        }
        return hits
    }

    /**
     * Payloads the deep scan looks for anywhere in a blob, most-readable first. Filesystems come
     * before compression streams because a squashfs/cpio find *is* the rootfs, while a compression
     * find only moves the search one layer deeper.
     */
    private val DEEP_MAGICS = listOf(
        DeepMagic("hsqs".toByteArray(Charsets.ISO_8859_1), ImageFormat.SQUASHFS, "SquashFS (little-endian)"),
        DeepMagic("sqsh".toByteArray(Charsets.ISO_8859_1), ImageFormat.SQUASHFS, "SquashFS (big-endian)"),
        DeepMagic("070701".toByteArray(Charsets.ISO_8859_1), ImageFormat.CPIO, "cpio newc archive"),
        DeepMagic(byteArrayOf(0x1F, 0x8B.toByte()), ImageFormat.GZIP, "gzip stream"),
        DeepMagic(byteArrayOf(0xFD.toByte(), 0x37, 0x7A, 0x58, 0x5A, 0x00), ImageFormat.XZ, "xz stream"),
        DeepMagic(byteArrayOf(0x42, 0x5A, 0x68), ImageFormat.BZIP2, "bzip2 stream"),
        DeepMagic(byteArrayOf(0x28, 0xB5.toByte(), 0x2F, 0xFD.toByte()), ImageFormat.ZSTD, "zstd stream"),
        DeepMagic(byteArrayOf(0x04, 0x22, 0x4D, 0x18), ImageFormat.LZ4, "lz4 stream"),
        DeepMagic(byteArrayOf(0x89.toByte(), 0x4C, 0x5A, 0x4F), ImageFormat.LZO, "lzo stream"),
    )

    private class DeepMagic(val bytes: ByteArray, val format: ImageFormat, val label: String)

    /**
     * Extracts the Wind River web-management store used by the official TP-Link TL-WR720N v2
     * IMG0/VxWorks firmware. This is not a Linux rootfs: VxWorks packs the admin UI as 48-byte
     * records pointing at per-file LZMA-alone streams. Pulling those pages into /www lets the app
     * identify and preview the stock web UI instead of treating the official 2 MB image as opaque.
     */
    private fun unpackTpLinkImg0VxWorks(data: ByteArray, origin: String): Int {
        val storeBase = findWr720nStoreBase(data)
        if (storeBase < 0) {
            unsupported.add("$origin: TP-Link IMG0/VxWorks image recognised, but no supported Wind River web store was found")
            return 0
        }

        var imported = 0
        val lzmaMagic = byteArrayOf(0x5A, 0x00, 0x00, 0x80.toByte(), 0x00) // props 0x5A + 8 MiB dictionary
        val firstRecord = 0x40
        val dataArea = 0x24A0
        val stride = 48
        val nameLen = 40
        var pos = firstRecord
        while (pos + stride <= dataArea && storeBase + pos + stride <= data.size && imported < Limits.MAX_FILES) {
            val rawName = data.copyOfRange(storeBase + pos, storeBase + pos + nameLen)
            var nul = -1
            for (i in rawName.indices) {
                if (rawName[i] == 0.toByte()) {
                    nul = i
                    break
                }
            }
            val nameBytes = rawName.copyOfRange(0, if (nul >= 0) nul else rawName.size)
            if (nameBytes.isEmpty() || nameBytes.any { c -> (c.toInt() and 0xFF) !in 0x20..0x7E }) break
            val name = String(nameBytes, Charsets.ISO_8859_1)
            val size = Bin.u32be(data, storeBase + pos + nameLen).toInt()
            val relOff = Bin.u32be(data, storeBase + pos + nameLen + 4).toInt()
            val streamStart = storeBase + relOff + 20
            if (size <= 0 || streamStart < 0 || streamStart + 13 > data.size || streamStart + size > data.size) break
            if (!startsWith(data, streamStart, lzmaMagic)) break

            val decoded = Compression.decodeAs(data, Compression.Kind.LZMA, streamStart, Limits.MAX_INFLATE_BYTES)
            if (decoded == null) {
                unsupported.add("$origin: Wind River web file '$name' uses LZMA, but this build could not decode it")
                pos += stride
                continue
            }
            val safeName = name.replace('\\', '_').replace('/', '_')
            if (vfs.addFile("/www/$safeName", decoded.bytes, decoded.bytes.size.toLong(), source = "TP-Link IMG0 Wind River web store")) {
                imported++
            }
            pos += stride
        }

        // Record the two large VxWorks LZMA code images as boot artifacts without keeping their
        // bytes in RAM. This makes the boot-chain report show that a kernel/OS payload exists.
        addVxWorksCodeMarkers(data)

        if (imported > 0) {
            notes.add("TP-Link IMG0/VxWorks web store: $imported files imported from 0x${storeBase.toString(16)}")
        } else {
            unsupported.add("$origin: TP-Link IMG0/VxWorks web store found, but no files could be decoded")
        }
        return imported
    }

    private fun findWr720nStoreBase(data: ByteArray): Int {
        val magic = byteArrayOf(0x5F, 0xA9.toByte(), 0x1A, 0xB1.toByte())
        var from = 0
        while (from >= 0) {
            val idx = Bin.indexOf(data, magic, from)
            if (idx < 0) return -1
            if (looksLikeWr720nStore(data, idx)) return idx
            from = idx + 1
        }
        return -1
    }

    private fun looksLikeWr720nStore(data: ByteArray, base: Int): Boolean {
        val firstRecord = 0x40
        val nameLen = 40
        if (base + firstRecord + 48 > data.size) return false
        val name = data.copyOfRange(base + firstRecord, base + firstRecord + nameLen).takeWhile { it.toInt() != 0 }
        if (name.isEmpty() || name.any { c -> (c.toInt() and 0xFF) !in 0x20..0x7E }) return false
        val size = Bin.u32be(data, base + firstRecord + nameLen).toInt()
        val relOff = Bin.u32be(data, base + firstRecord + nameLen + 4).toInt()
        val streamStart = base + relOff + 20
        return size > 13 && streamStart + 5 <= data.size &&
            data[streamStart] == 0x5A.toByte() && data[streamStart + 1] == 0x00.toByte() &&
            data[streamStart + 2] == 0x00.toByte() && data[streamStart + 3] == 0x80.toByte() && data[streamStart + 4] == 0x00.toByte()
    }

    private fun startsWith(data: ByteArray, offset: Int, magic: ByteArray): Boolean {
        if (offset < 0 || offset + magic.size > data.size) return false
        for (i in magic.indices) if (data[offset + i] != magic[i]) return false
        return true
    }

    private fun indexOfByte(data: ByteArray, needle: Byte, from: Int): Int {
        var i = maxOf(0, from)
        while (i < data.size) {
            if (data[i] == needle) return i
            i++
        }
        return -1
    }

    private fun addVxWorksCodeMarkers(data: ByteArray) {
        val lzmaHeaders = ArrayList<Pair<Int, Long>>()
        var from = 0
        while (lzmaHeaders.size < 2 && from + 13 <= data.size) {
            val idx = indexOfByte(data, 0x6E.toByte(), from)
            if (idx < 0 || idx + 13 > data.size) break
            val dict = Bin.u32le(data, idx + 1)
            val usize = Bin.u64le(data, idx + 5)
            if (dict == 0x800000L && usize in 128 * 1024L..16 * 1024 * 1024L) {
                lzmaHeaders.add(idx to usize)
            }
            from = idx + 1
        }
        for ((i, h) in lzmaHeaders.withIndex()) {
            val (off, usize) = h
            vfs.addFile(
                "/boot/vxworks-kernel-image-${i + 1}.lzma",
                content = null,
                size = usize,
                source = "TP-Link IMG0 VxWorks LZMA stream @0x${off.toString(16)}",
            )
        }
    }

    private companion object {
        /** How much of a blob the deep scan sweeps (phone-friendly: no 4 GB dumps). */
        const val DEEP_SCAN_BYTES = 64 * 1024 * 1024

        /** At most this many payload candidates per blob, so one noisy file cannot flood the queue. */
        const val MAX_DEEP_HITS = 4
    }

    private fun trxSegments(data: ByteArray): List<Int> {
        val len = Bin.u32le(data, 4)
        val offsets = ArrayList<Int>()
        offsets.add(28)
        for (i in 0 until 3) {
            val o = Bin.u32le(data, 16 + i * 4)
            if (o in 28 until data.size.toLong()) offsets.add(o.toInt())
        }
        val end = if (len in 28 until data.size.toLong()) len.toInt() else data.size
        offsets.add(end)
        return offsets.distinct().sorted()
    }

    private fun compName(c: Int): String = when (c) {
        1 -> "gzip"; 2 -> "bzip2"; 3 -> "lzma"; 4 -> "lzo"; 5 -> "lz4"; 6 -> "zstd"; else -> "compression #$c"
    }
}

/**
 * Facts mined out of the extracted rootfs. These drive the emulator (what to run), the hardware
 * matrix (what the image needs) and the report (what the user reads).
 */
class FirmwareFacts(
    val distro: String? = null,
    val target: String? = null,
    val arch: String? = null,
    val kernelVersion: String? = null,
    val deviceModelHint: String? = null,
    val packages: List<String> = emptyList(),
    val kernelModules: List<String> = emptyList(),
    val wirelessDrivers: List<String> = emptyList(),
    val switchDrivers: List<String> = emptyList(),
    val usbSupported: Boolean = false,
    val vpnSupported: Boolean = false,
    val initScripts: List<String> = emptyList(),
    val configFiles: Map<String, String> = emptyMap(),
    val users: List<String> = emptyList(),
    val passwordHashCount: Int = 0,
    val webRoot: String? = null,
    val loginPages: List<String> = emptyList(),
    val webHandlers: List<String> = emptyList(),
    val nvramDefaults: Map<String, String> = emptyMap(),
    val rootfsUncompressed: Long = 0,
    val firmwareVersion: String? = null,
    val requiredFlashMb: Double? = null,
    /** SoC family names found inside the extracted rootfs (board info, banners, preinit). */
    val socHints: List<String> = emptyList(),
    val notes: List<String> = emptyList(),
) {
    companion object {
        fun extract(vfs: VirtualFs, identity: ImageIdentity): FirmwareFacts {
            val notes = ArrayList<String>()
            val configFiles = LinkedHashMap<String, String>()
            for (p in listOf(
                "/etc/openwrt_release", "/etc/openwrt_version", "/usr/lib/os-release", "/etc/os-release",
                "/etc/banner", "/etc/motd", "/etc/issue", "/etc/version", "/etc/opkg/distfeeds.conf",
                "/etc/config/system", "/tmp/sysinfo/model", "/proc/version", "/etc/device_info",
            )) {
                vfs.readText(p, 8192)?.let { configFiles[p] = it }
            }

            var distro: String? = null
            var target: String? = null
            var arch: String? = null
            var version: String? = null
            val isTpLinkImg0 = identity.primary == ImageFormat.TPLINK_IMG0
            val isWr720nImg0 = isTpLinkImg0 && (identity.model?.contains("WR720N", true) == true || identity.archHints.any { it.contains("ar9331", true) })
            if (isTpLinkImg0) {
                distro = "TP-Link VxWorks"
                target = if (isWr720nImg0) "atheros/ar9331" else "vxworks"
                arch = "mips"
                version = identity.version
                notes.add("TP-Link IMG0/VxWorks stock firmware metadata inferred from the container")
            }
            configFiles["/etc/openwrt_release"]?.let { t ->
                distro = Regex("DISTRIB_ID='?([^'\n]+)").find(t)?.groupValues?.get(1)?.trim()
                version = Regex("DISTRIB_RELEASE='?([^'\n]+)").find(t)?.groupValues?.get(1)?.trim()
                target = Regex("DISTRIB_TARGET='?([^'\n]+)").find(t)?.groupValues?.get(1)?.trim()
                arch = Regex("DISTRIB_ARCH='?([^'\n]+)").find(t)?.groupValues?.get(1)?.trim()
                notes.add("OpenWrt release metadata found")
            }
            configFiles["/usr/lib/os-release"]?.let { t ->
                distro = distro ?: Regex("^NAME=\"?([^\"\n]+)").find(t)?.groupValues?.get(1)
                version = version ?: Regex("^VERSION=\"?([^\"\n]+)").find(t)?.groupValues?.get(1)
            }
            configFiles["/etc/banner"]?.let { t ->
                Regex("OpenWrt\\s+([\\w.\\-]+)").find(t)?.let {
                    distro = distro ?: "OpenWrt"
                    version = version ?: it.groupValues[1]
                }
                Regex("(\\w[\\w\\-]*\\d[\\w\\-]*),?\\s*(?:Target|Platform)").find(t)?.let {
                    target = target ?: it.groupValues[1]
                }
                notes.add("Banner present - the image is at least a real rootfs")
            }
            configFiles["/tmp/sysinfo/model"]?.let { notes.add("sysinfo model: ${Text.truncate(it.trim(), 60)}") }

            // kernel version + modules
            val kernelVersion = if (isTpLinkImg0) {
                identity.version?.let { "VxWorks $it" } ?: "VxWorks"
            } else {
                vfs.findByContains("/etc/modules/")
                    .firstOrNull()
                    ?.let { null }
                    ?: Regex("Linux version\\s+([\\d.\\w\\-+]+)").find(identity.evidence.joinToString(" "))?.groupValues?.get(1)
            }

            val modules = vfs.findByContains("/modules/")
                .filter { it.path.endsWith(".ko") }
                .map { Text.baseName(it.path).removeSuffix(".ko") }
                .distinct()
                .take(400)

            val wirelessDrivers = if (isWr720nImg0) {
                listOf("Atheros AR9331 VxWorks monolithic wireless driver")
            } else {
                modules.filter {
                    it.contains("ath") || it.contains("mt7") || it.contains("mt76") || it.contains("rt2") ||
                        it.contains("rtl") || it.contains("brcm") || it.contains("mac80211") || it.contains("cfg80211") ||
                        it.contains("iwl") || it.contains("carl9170") || it.contains("rt2800") ||
                        it == "wl" || it.startsWith("wl-") || it.contains("b43") || it == "broadcom-wl"
                }
            }
            val switchDrivers = modules.filter {
                it.contains("switch") || it.contains("dsa") || it.contains("mvsw") || it.contains("rtl83") || it.contains("mt7530")
            }
            val usbSupported = modules.any { it.startsWith("usb") || it.contains("xhci") || it.contains("ehci") || it.contains("usb-storage") } ||
                vfs.exists("/sys/bus/usb")
            val vpnSupported = modules.any { it.contains("wireguard") || it.contains("tun") || it.contains("openvpn") || it.contains("pptp") || it.contains("l2tp") } ||
                vfs.findByContains("/usr/sbin/openvpn").isNotEmpty()

            // packages (opkg status file or installed db)
            val packages = ArrayList<String>()
            vfs.readText("/usr/lib/opkg/status", 2 * 1024 * 1024)?.let { t ->
                var count = 0
                for (line in t.lineSequence()) {
                    if (line.startsWith("Package: ")) {
                        packages.add(line.removePrefix("Package: ").trim())
                        if (++count > 1500) break
                    }
                }
                if (packages.isNotEmpty()) notes.add("${packages.size} installed packages found in opkg status")
            }

            val initScripts = (vfs.allFiles().filter { it.path.startsWith("/etc/init.d/") }.map { it.path } +
                vfs.allFiles().filter { it.path.startsWith("/etc/rc.d/") }.map { it.path })
                .distinct()

            val users = ArrayList<String>()
            var hashCount = 0
            vfs.readText("/etc/passwd", 65536)?.let { t ->
                for (line in t.lineSequence()) {
                    val u = line.substringBefore(':')
                    if (u.isNotBlank() && !u.startsWith("#")) users.add(u)
                }
            }
            vfs.readText("/etc/shadow", 65536)?.let { t ->
                hashCount = t.lineSequence().count { it.split(':').getOrNull(1)?.let { h -> h.isNotBlank() && h != "*" && h != "!" } == true }
            }

            val webRoots = vfs.findWebRoots()
            val webRoot = webRoots.firstOrNull()
            val loginPages = webRoots.flatMap { root ->
                vfs.list(root).filter { e ->
                    val n = e.name.lowercase()
                    n.startsWith("login") || n.startsWith("index") && n.contains("login") || n.contains("auth")
                }.map { it.path }
            }.distinct()
            val webHandlers = vfs.allFiles()
                .filter { e ->
                    val p = e.path.lowercase()
                    (p.contains("/cgi-bin/") || p.contains("/cgi/")) &&
                        (p.endsWith(".cgi") || p.endsWith(".lua") || p.endsWith(".sh") || p.endsWith(".asp") || p.endsWith(".php") || e.executable)
                }
                .map { it.path }
                .distinct()

            // Broadcom/vendor defaults live in nvram txt files
            val nvram = LinkedHashMap<String, String>()
            for (f in vfs.allFiles().filter { it.name.startsWith("nvram") || it.name.endsWith(".nvram") || it.name == "defaults" }) {
                val txt = vfs.readText(f.path, 512 * 1024) ?: continue
                for (line in txt.lineSequence()) {
                    val parts = line.trim().split("=", limit = 2)
                    if (parts.size == 2 && parts[0].isNotBlank()) nvram[parts[0].trim()] = parts[1].trim()
                    if (nvram.size > 4000) break
                }
            }

            // SoC family evidence: board-info files, banners and preinit scripts name the chip.
            // Bounded scan: at most 160 small text files, 8 KB each - the chip name, when present,
            // is almost always in /etc or /tmp/sysinfo. Binary collisions with a 6-char SoC token
            // are negligible, and unknown families simply yield no hint (the row stays unverified).
            val socHints = ArrayList<String>()
            fun harvestSoc(text: String) {
                SocFamilies.fromText(text)?.let { if (it.name !in socHints) socHints.add(it.name) }
            }
            configFiles.values.forEach { harvestSoc(it) }
            if (isWr720nImg0 && "Atheros AR9331" !in socHints) socHints.add("Atheros AR9331")
            var socScanned = 0
            for (f in vfs.allFiles()) {
                if (socScanned >= 160) break
                if (f.size !in 8..16384) continue
                socScanned++
                vfs.readText(f.path, 8192)?.let { harvestSoc(it) }
            }
            if (socHints.isNotEmpty()) notes.add("SoC markers in rootfs: " + socHints.joinToString(", "))

            val rootfsSize = vfs.allFiles().sumOf { it.size }
            val requiredFlashMb = when {
                isTpLinkImg0 -> identity.totalSize / (1024.0 * 1024.0)
                rootfsSize > 0 -> rootfsSize / (1024.0 * 1024.0) * 1.15
                else -> null
            }

            return FirmwareFacts(
                distro = distro,
                target = target,
                arch = arch,
                kernelVersion = kernelVersion,
                deviceModelHint = identity.model,
                packages = packages.distinct().take(400),
                kernelModules = modules,
                wirelessDrivers = wirelessDrivers.distinct(),
                switchDrivers = switchDrivers.distinct(),
                usbSupported = usbSupported,
                vpnSupported = vpnSupported,
                initScripts = initScripts.take(300),
                configFiles = configFiles,
                users = users.distinct().take(60),
                passwordHashCount = hashCount,
                webRoot = webRoot,
                loginPages = loginPages,
                webHandlers = webHandlers.take(400),
                nvramDefaults = nvram,
                rootfsUncompressed = rootfsSize,
                firmwareVersion = version ?: identity.version,
                requiredFlashMb = requiredFlashMb,
                socHints = socHints,
                notes = notes,
            )
        }
    }
}
