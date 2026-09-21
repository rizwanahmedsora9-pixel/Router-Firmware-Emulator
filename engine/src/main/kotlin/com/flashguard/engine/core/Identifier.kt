package com.flashguard.engine.core

import com.flashguard.engine.compression.Compression
import com.flashguard.engine.container.SquashFsReader
import com.flashguard.engine.util.Bin
import com.flashguard.engine.util.Digests
import com.flashguard.engine.util.Entropy
import com.flashguard.engine.util.Hex
import com.flashguard.engine.util.ProgressSink
import com.flashguard.engine.util.Strings
import com.flashguard.engine.util.Text
import com.flashguard.engine.util.Limits

/**
 * Recognises "any router firmware file" without unpacking it: magic sniffing, vendor/model/version
 * extraction and a recursive layer tree. Everything here is read-only and bounded.
 */
object FirmwareIdentifier {

    private data class Magic(
        val bytes: ByteArray,
        val format: ImageFormat,
        val label: String,
        val atZeroOnly: Boolean = false,
    )

    private val MAGICS: List<Magic> = listOf(
        Magic(byteArrayOf(0x1F, 0x8B.toByte()), ImageFormat.GZIP, "gzip stream"),
        Magic(byteArrayOf(0xFD.toByte(), 0x37, 0x7A, 0x58, 0x5A, 0x00), ImageFormat.XZ, "xz stream"),
        Magic(byteArrayOf(0x42, 0x5A, 0x68), ImageFormat.BZIP2, "bzip2 stream"),
        Magic(byteArrayOf(0x28, 0xB5.toByte(), 0x2F, 0xFD.toByte()), ImageFormat.ZSTD, "zstd stream"),
        Magic(byteArrayOf(0x04, 0x22, 0x4D, 0x18), ImageFormat.LZ4, "lz4 stream (LE)"),
        Magic(byteArrayOf(0x89.toByte(), 0x4C, 0x5A, 0x4F), ImageFormat.LZO, "lzo stream"),
        Magic("hsqs".toByteArray(Charsets.ISO_8859_1), ImageFormat.SQUASHFS, "SquashFS 4.0 (little endian)"),
        Magic("sqsh".toByteArray(Charsets.ISO_8859_1), ImageFormat.SQUASHFS, "SquashFS (big endian)"),
        Magic(byteArrayOf(0x45, 0x3D, 0xCD.toByte(), 0x28), ImageFormat.CRAMFS, "CramFS"),
        Magic("UBI#".toByteArray(Charsets.ISO_8859_1), ImageFormat.UBI, "UBI image (NAND)"),
        Magic(byteArrayOf(0x31, 0x18, 0x10, 0x06), ImageFormat.UBIFS, "UBIFS filesystem"),
        Magic(byteArrayOf(0x85.toByte(), 0x19), ImageFormat.JFFS2, "JFFS2 filesystem (big endian)"),
        Magic(byteArrayOf(0x19, 0x85.toByte()), ImageFormat.JFFS2, "JFFS2 filesystem (little endian)"),
        Magic(byteArrayOf(0xD0.toByte(), 0x0D, 0xFE.toByte(), 0xED.toByte()), ImageFormat.UBOOT_FIT, "U-Boot FIT / device tree blob"),
        Magic(byteArrayOf(0x27, 0x05, 0x19, 0x56), ImageFormat.UBOOT_LEGACY, "U-Boot legacy uImage"),
        Magic("HDR0".toByteArray(Charsets.ISO_8859_1), ImageFormat.TRX, "TRX (Broadcom/DD-WRT)"),
        Magic(byteArrayOf(0x2A, 0x23, 0x24, 0x5E), ImageFormat.NETGEAR_CHK, "Netgear CHK"),
        Magic("SHRS".toByteArray(Charsets.ISO_8859_1), ImageFormat.DLINK_SHR, "D-Link image"),
        Magic(byteArrayOf(0x01, 0x00, 0x00, 0x00), ImageFormat.TPLINK_BIN, "TP-Link firmware header", atZeroOnly = true),
        Magic("PK\u0003\u0004".toByteArray(Charsets.ISO_8859_1), ImageFormat.ZIP, "ZIP archive"),
        Magic(byteArrayOf(0x7F, 0x45, 0x4C, 0x46), ImageFormat.ELF, "ELF binary"),
        Magic("070701".toByteArray(Charsets.ISO_8859_1), ImageFormat.CPIO, "cpio newc archive", atZeroOnly = true),
        Magic("070707".toByteArray(Charsets.ISO_8859_1), ImageFormat.CPIO, "cpio oldc archive", atZeroOnly = true),
        Magic("070702".toByteArray(Charsets.ISO_8859_1), ImageFormat.CPIO, "cpio crc archive", atZeroOnly = true),
    )

    /** Offsets where vendor headers commonly stash the real payload. */
    private val CANDIDATE_OFFSETS = intArrayOf(0, 0x20, 0x40, 0x100, 0x200, 0x300, 0x400, 0x600, 0x800, 0x1000, 0x2000, 0x4000, 0x10000, 0x20000, 0x40000)

    private val VERSION_REGEXES = listOf(
        Regex("""(?:FW|Firmware|version|Version|VERSION)[^0-9A-Za-z]{0,4}(\d+\.\d+(?:\.\d+)*(?:\s*Build\s*[\w.]+)?)"""),
        Regex("""(\d+\.\d+\.\d+\s+Build\s+\d+\s*Rel\.?\s*\d*\w*)"""),
        Regex("""(\d+\.\d+\.\d+\s+\(\w+\))"""),
        Regex("""OpenWrt\s+([\d.]+(?:\.\d+)*(?:-rc\d+)?|SNAPSHOT)"""),
        Regex("""DD-WRT\s+(v?[\d.]+(?:-r\d+)?)"""),
        Regex("""(v\d+\.\d+\.\d+(?:\.\d+)*)"""),
    )

    private val MODEL_REGEXES = listOf(
        Regex("""\b(Archer\s?[A-Z]{1,3}\d{2,4}[A-Z]?(?:\s?V\d)?)\b"""),
        Regex("""\b(TL-[A-Z]{2}\d{3,4}[A-Z]?(?:\s?V\d+(?:\.\d+)?)?)\b"""),
        Regex("""\b(TL-WR\d{3,4}N(?:D)?(?:\s?V\d+)?)\b"""),
        Regex("""\b(R(?:6|7|8|9)\d{3,4}(?:v\d)?)\b"""),
        Regex("""\b(WNDR\d{4}(?:v\d)?)\b"""),
        Regex("""\b(EX\d{4})\b"""),
        Regex("""\b(DIR-\d{3,4}[A-Z]?(?:\s?Rev\.[A-Z]\d)?)\b"""),
        Regex("""\b(DSL-\d{3,4}[A-Z]?)\b"""),
        Regex("""\b(RT-[A-Z]{1,2}\d{2,4}[A-Z]{0,2}(?:\s?(?:v\d|PRO|Plus))?)\b"""),
        Regex("""\b(Mi\s?Router\s?\d[A-Z]?(?:\s?Gigabit)?)\b"""),
        Regex("""\b(R\d{4}[AG]?)\b"""),
        Regex("""\b(EA\d{4})\b"""),
        Regex("""\b(F9K\d{4})\b"""),
        Regex("""\b(model|Model|MODEL|board|BOARD|hw_id|HW_ID|product_name)[=:\s]+([A-Za-z0-9_\-./ ]{3,32})"""),
        Regex("""\b(AC\d{3,4}[A-Z]?(?:\s?Pro)?)\b"""),
    )

    fun identify(bytes: ByteArray, fileName: String = "", progress: ProgressSink = ProgressSink.NONE): ImageIdentity {
        val evidence = ArrayList<String>()
        val layers = ArrayList<Layer>()
        val archHints = LinkedHashSet<String>()

        if (bytes.isEmpty()) {
            return ImageIdentity(
                ImageFormat.EMPTY, Vendor.UNKNOWN, null, null, emptyList(), 100,
                listOf("File is empty (0 bytes)"), emptyList(), 0, Digests.sha256(bytes),
            )
        }

        progress.onProgress(3, "Hashing image (SHA-256)")
        val sha = Digests.sha256(bytes)
        progress.onProgress(8, "Sniffing container formats")

        val primary = detectAt(bytes, 0, evidence)?.first ?: ImageFormat.RAW
        if (primary == ImageFormat.RAW) {
            evidence.add("No known firmware magic at offset 0 - treating as opaque flash image")
        }

        // Structured vendor headers get parsed for extra fields.
        when (primary) {
            ImageFormat.TRX -> parseTrx(bytes, layers, evidence, archHints)
            ImageFormat.UBOOT_LEGACY -> parseUImage(bytes, 0, layers, evidence, archHints)
            ImageFormat.UBOOT_FIT -> {
                parseFdt(bytes, 0, layers, evidence, archHints)
            }
            ImageFormat.NETGEAR_CHK -> parseChk(bytes, layers, evidence)
            ImageFormat.TPLINK_BIN -> parseTpLink(bytes, layers, evidence, archHints)
            ImageFormat.SQUASHFS -> {
                val sb = SquashFsReader(bytes)
                if (sb.parse()) {
                    evidence.add(sb.describe())
                    if (!sb.superBlock.decodable) archHints.add("unsupported-compressor:${sb.superBlock.compressorName}")
                }
            }
            ImageFormat.UBI -> parseUbi(bytes, layers, evidence, archHints)
            ImageFormat.EXT -> Unit
            else -> Unit
        }

        progress.onProgress(14, "Scanning for nested containers")
        scanInnerImages(bytes, layers, evidence, archHints)

        val textSample = sampleStrings(bytes, if (bytes.size > 8 * 1024 * 1024) 4 * 1024 * 1024 else bytes.size)
        val vendorGuess = Vendor.guessFromText(fileName + "\n" + textSample)
        var vendor = vendorGuess?.first ?: Vendor.UNKNOWN
        vendorGuess?.let { evidence.add("Vendor string '${it.second}' found in image/filename") }

        // Structured evidence beats string evidence.
        vendor = refineVendorFromStructure(bytes, primary, vendor, evidence)

        val model = guessModel(textSample) ?: guessModel(fileName)
        val version = Strings.findFirst(textSample, VERSION_REGEXES)
        model?.let { evidence.add("Model string: $it") }
        version?.let { evidence.add("Version string: $it") }

        if (primary == ImageFormat.UBOOT_LEGACY) archHints.add("u-boot")
        val entropy = Entropy.of(bytes.copyOf(minOf(bytes.size, 512 * 1024)))
        evidence.add("Entropy ${String.format(java.util.Locale.US, "%.2f", entropy)} bits/byte over first ${Hex.humanBytes(minOf(bytes.size, 512 * 1024))}")
        if (entropy > 7.6 && primary != ImageFormat.SQUASHFS) {
            evidence.add("Very high entropy - payload may be encrypted or signed by the vendor")
        }

        val confidence = computeConfidence(primary, vendor, model, version, layers.size)
        return ImageIdentity(
            primary = primary,
            vendor = vendor,
            model = model,
            version = version,
            archHints = archHints.toList(),
            confidence = confidence,
            evidence = evidence,
            layers = layers,
            totalSize = bytes.size.toLong(),
            sha256 = sha,
        )
    }

    // ------------------------------------------------------------------ magic detection

    /** Returns the detected format and how many bytes the magic consumed. */
    fun detectAt(data: ByteArray, offset: Int, evidence: MutableList<String>? = null): Pair<ImageFormat, Int>? {
        if (offset >= data.size) return null
        // tar needs the ustar check rather than a fixed magic
        if (offset + 512 <= data.size && Bin.ascii(data, offset + 257, 5) == "ustar") {
            evidence?.add("tar (ustar) header at 0x${offset.toString(16)}")
            return ImageFormat.TAR to 512
        }
        for (m in MAGICS) {
            if (m.atZeroOnly && offset != 0) continue
            if (offset + m.bytes.size > data.size) continue
            var ok = true
            for (i in m.bytes.indices) {
                if (data[offset + i] != m.bytes[i]) {
                    ok = false
                    break
                }
            }
            if (ok) {
                if (m.format == ImageFormat.SQUASHFS) {
                    val ver = if (offset + 30 <= data.size) Bin.u16le(data, offset + 28) else 0
                    if (ver != 4) {
                        evidence?.add("SquashFS-like magic but version $ver - not parsed")
                        continue
                    }
                }
                evidence?.add("${m.label} at 0x${offset.toString(16)}")
                return m.format to m.bytes.size
            }
        }
        // ext2/3/4 superblock magic lives at 0x438
        if (offset + 0x43A <= data.size && Bin.u16le(data, offset + 0x438) == 0xEF53) {
            evidence?.add("ext2/3/4 superblock at 0x${offset.toString(16)}")
            return ImageFormat.EXT to 1024
        }
        // lzma-alone heuristic (property byte 0x5D + plausible dictionary size)
        if (offset + 13 <= data.size && Bin.u8(data, offset) == 0x5D) {
            val dict = Bin.u32le(data, offset + 1)
            if (dict in 0x1000..0x40000000L) {
                evidence?.add("lzma-alone stream at 0x${offset.toString(16)}")
                return ImageFormat.LZMA to 13
            }
        }
        return null
    }

    // ------------------------------------------------------------------ structure parsers

    private fun parseTrx(data: ByteArray, layers: MutableList<Layer>, evidence: MutableList<String>, archHints: MutableSet<String>) {
        if (data.size < 28) return
        val len = Bin.u32le(data, 4)
        val crc = Bin.u32le(data, 8)
        val flags = Bin.u32le(data, 12)
        val offsets = LongArray(3) { Bin.u32le(data, 16 + it * 4) }
        evidence.add(
            "TRX header: length ${Hex.humanBytes(len)}, crc32 0x${crc.toString(16)}, " +
                "flags 0x${flags.toString(16)}" + if (flags and 0x1 != 0L) " (version 2, 3rd partition present)" else ""
        )
        val boundaries = ArrayList<Long>()
        boundaries.add(28)
        for (o in offsets) if (o in 28 until data.size.toLong()) boundaries.add(o)
        boundaries.add(minOf(len, data.size.toLong()).let { if (it < 28) data.size.toLong() else it })
        boundaries.sort()
        val names = arrayOf("kernel", "rootfs", "3rd partition", "tail")
        for (i in 0 until boundaries.size - 1) {
            val start = boundaries[i].toInt()
            val end = boundaries[i + 1].toInt()
            if (end - start < 16) continue
            val inner = ArrayList<Layer>()
            val sub = data.copyOfRange(start, end)
            val det = detectAt(sub, 0, null)
            if (det != null) {
                inner.add(Layer(det.first, det.first.label, start.toLong(), (end - start).toLong()))
            }
            val name = names.getOrElse(i) { "segment $i" }
            layers.add(
                Layer(
                    ImageFormat.RAW,
                    "TRX $name (0x${start.toString(16)}-0x${end.toString(16)})",
                    start.toLong(),
                    (end - start).toLong(),
                    detail = "TRX segment ${i + 1}",
                    children = inner,
                )
            )
            if (inner.isNotEmpty() && inner[0].format == ImageFormat.UBOOT_LEGACY) {
                parseUImage(sub, start, layers, evidence, archHints)
            }
        }
    }

    private fun parseUImage(data: ByteArray, base: Int, layers: MutableList<Layer>, evidence: MutableList<String>, archHints: MutableSet<String>) {
        if (base + 64 > data.size) return
        val size = Bin.u32be(data, base + 12)
        val load = Bin.u32be(data, base + 16)
        val entry = Bin.u32be(data, base + 20)
        val os = Bin.u8(data, base + 28)
        val arch = Bin.u8(data, base + 29)
        val type = Bin.u8(data, base + 30)
        val comp = Bin.u8(data, base + 31)
        val name = Bin.cstr(data, base + 32, 32)
        val archName = when (arch) {
            2 -> "ARM"; 3 -> "x86"; 5 -> "MIPS"; 7 -> "PowerPC"; 22 -> "ARM64"; 26 -> "RISC-V"
            8 -> "M68K"; 20 -> "IA64"; 21 -> "NIOS2"; 25 -> "SH"; 16 -> "PPC64"
            else -> "arch#$arch"
        }
        val compName = when (comp) {
            0 -> "none"; 1 -> "gzip"; 2 -> "bzip2"; 3 -> "lzma"; 4 -> "lzo"; 5 -> "lz4"; 6 -> "zstd"
            else -> "comp#$comp"
        }
        val typeName = when (type) {
            1 -> "standalone"; 2 -> "kernel"; 3 -> "ramdisk"; 4 -> "multi"; 5 -> "firmware"; 6 -> "script"; 7 -> "filesystem"
            else -> "type#$type"
        }
        val osName = when (os) {
            5 -> "Linux"; 9 -> "OpenBSD"; 17 -> "RTEMS"; 14 -> "VxWorks"; 4 -> "NetBSD"; else -> "os#$os"
        }
        evidence.add(
            "U-Boot uImage '$name': $osName/$archName/$typeName compressed=$compName, " +
                "load 0x${load.toString(16)}, entry 0x${entry.toString(16)}, payload ${Hex.humanBytes(size)}"
        )
        if (archName != "arch#$arch") archHints.add(archName.lowercase())
        archHints.add("u-boot-load:0x${load.toString(16)}")
        val payloadStart = base + 64
        val payloadEnd = minOf(data.size, payloadStart + size.toInt())
        val children = ArrayList<Layer>()
        if (payloadEnd > payloadStart) {
            val sub = data.copyOfRange(payloadStart, payloadEnd)
            val kind = Compression.sniff(sub)
            if (kind != null) {
                children.add(Layer(kindToFormat(kind), "uImage payload: ${kind.label}", payloadStart.toLong(), (payloadEnd - payloadStart).toLong()))
                if (kind.decodable && sub.size < 24 * 1024 * 1024) {
                    val dec = Compression.decodeAs(sub, kind)
                    if (dec != null && dec.bytes.size >= 4) {
                        val linux = Bin.indexOfAscii(dec.bytes, "Linux version ")
                        if (linux >= 0) {
                            val ver = Bin.cstr(dec.bytes, linux + 14, 80)
                            evidence.add("Kernel banner: ${Text.truncate(ver, 90)}")
                            if (ver.contains("mips", true)) archHints.add("mips")
                            if (ver.contains("arm", true)) archHints.add("arm")
                            if (ver.contains("aarch64", true)) archHints.add("aarch64")
                        }
                        val machine = Bin.indexOfAscii(dec.bytes, "Machine")
                        if (machine >= 0) evidence.add("Kernel machine: ${Bin.cstr(dec.bytes, machine, 64)}")
                    }
                }
            }
        }
        layers.add(
            Layer(
                ImageFormat.UBOOT_LEGACY,
                "uImage '$name' ($archName $typeName",
                base.toLong(),
                (payloadEnd - base).toLong(),
                detail = "$compName payload, load 0x${load.toString(16)}",
                children = children,
            )
        )
    }

    /** Device tree / FIT: collect model + compatible strings (the best arch evidence there is). */
    private fun parseFdt(data: ByteArray, base: Int, layers: MutableList<Layer>, evidence: MutableList<String>, archHints: MutableSet<String>) {
        if (base + 40 > data.size) return
        val totalsize = Bin.u32be(data, base + 4)
        val offStruct = Bin.u32be(data, base + 8)
        val offStrings = Bin.u32be(data, base + 12)
        val sizeStrings = Bin.u32be(data, base + 32)
        val stringsBlob = if (offStrings + sizeStrings <= data.size) data.copyOfRange(offStrings.toInt(), (offStrings + sizeStrings).toInt()) else ByteArray(0)
        val stringList = Strings.extract(stringsBlob, 3, 400).map { it.second }
        val compatibles = stringList.filter { it.contains(',') && (it.contains("arm") || it.contains("mips") || it.contains("mediatek") || it.contains("qca") || it.contains("broadcom") || it.contains("atheros") || it.contains("marvell") || it.contains("rockchip") || it.contains("allwinner") || it.contains("realtek") || it.contains("lantiq") || it.contains("intel") || it.contains("qualcomm") || it.contains("ralink") || it.contains("espressif") || it.contains("star") || it.contains("siflower")) }
        val model = stringList.firstOrNull { it.contains("Router", true) || it.contains("AP", true) && it.length < 40 }
        evidence.add("FDT blob: total ${Hex.humanBytes(totalsize)}, ${stringList.size} strings")
        if (compatibles.isNotEmpty()) {
            evidence.add("Device-tree compatible: " + compatibles.take(6).joinToString(", "))
            archHints.addAll(compatibles.take(6).map { it.lowercase() })
        }
        model?.let { evidence.add("FDT model: $it") }
        // walk the structure block for /model and /compatible properties
        walkFdt(data, base + offStruct.toInt(), stringsBlob, evidence, archHints)
        layers.add(
            Layer(
                ImageFormat.UBOOT_FIT,
                if (stringList.any { it == "kernel" || it == "fdt" || it == "ramdisk" }) "U-Boot FIT image" else "Device tree blob",
                base.toLong(),
                minOf(totalsize, (data.size - base).toLong()),
                detail = compatibles.take(3).joinToString(", "),
            )
        )
    }

    private fun walkFdt(data: ByteArray, structStart: Int, stringsBlob: ByteArray, evidence: MutableList<String>, archHints: MutableSet<String>) {
        var p = structStart
        var depth = 0
        var guard = 0
        val names = ArrayList<String>()
        while (p + 4 <= data.size && guard++ < 20000) {
            val token = Bin.u32be(data, p).toInt()
            p += 4
            when (token) {
                1 -> { // BEGIN_NODE
                    val end = run {
                        var q = p
                        while (q < data.size && data[q].toInt() != 0) q++
                        q
                    }
                    val nodeName = String(data, p, maxOf(0, end - p), Charsets.ISO_8859_1)
                    p = ((end + 4) / 4) * 4
                    depth++
                    if (nodeName.isNotBlank() && depth <= 3) names.add(nodeName)
                }
                2 -> depth--
                3 -> { // PROP
                    if (p + 8 > data.size) break
                    val len = Bin.u32be(data, p).toInt()
                    val nameOff = Bin.u32be(data, p + 4).toInt()
                    val dataStart = p + 8
                    val propName = if (nameOff in stringsBlob.indices) {
                        var q = nameOff
                        while (q < stringsBlob.size && stringsBlob[q].toInt() != 0) q++
                        String(stringsBlob, nameOff, q - nameOff, Charsets.ISO_8859_1)
                    } else ""
                    if ((propName == "compatible" || propName == "model") && len in 1..512 && dataStart + len <= data.size) {
                        val value = String(data, dataStart, len, Charsets.ISO_8859_1).trimEnd('\u0000')
                        evidence.add("FDT $propName = ${Text.truncate(value.replace('\u0000', ' '), 120)}")
                        value.split('\u0000').forEach { archHints.add(it.trim().lowercase()) }
                    }
                    p = ((dataStart + len + 3) / 4) * 4
                }
                4 -> Unit // NOP
                9 -> return // END
                else -> return
            }
        }
        if (names.isNotEmpty()) evidence.add("FDT nodes: " + names.take(8).joinToString("/"))
    }

    private fun parseChk(data: ByteArray, layers: MutableList<Layer>, evidence: MutableList<String>) {
        if (data.size < 32) return
        val headerSize = Bin.u32be(data, 4)
        val kernelSize = Bin.u32be(data, 16)
        val rootfsSize = Bin.u32be(data, 20)
        evidence.add("Netgear CHK header: header ${Hex.humanBytes(headerSize)}, kernel ${Hex.humanBytes(kernelSize)}, rootfs ${Hex.humanBytes(rootfsSize)}")
        val candidateStart = headerSize.toInt()
        if (candidateStart in 32 until data.size) {
            val name = Bin.cstr(data, candidateStart, 64)
            if (name.isNotEmpty()) evidence.add("CHK payload name: ${Text.truncate(name, 60)}")
        }
        layers.add(Layer(ImageFormat.NETGEAR_CHK, "CHK container", 0, minOf(headerSize, data.size.toLong()), detail = "kernel + rootfs sections follow"))
    }

    private fun parseTpLink(data: ByteArray, layers: MutableList<Layer>, evidence: MutableList<String>, archHints: MutableSet<String>) {
        val vendor = Bin.cstr(data, 4, 24)
        val version = Bin.cstr(data, 28, 24)
        val hwId = Bin.cstr(data, 52, 24)
        val hwRev = Bin.cstr(data, 76, 24)
        evidence.add("TP-Link header: vendor='$vendor' version='$version' hw_id='$hwId' hw_rev='$hwRev'")
        if (hwId.isNotBlank()) archHints.add("hw-id:$hwId")
        layers.add(Layer(ImageFormat.TPLINK_BIN, "TP-Link header (0x0-0x100)", 0, 256, detail = "$hwId $hwRev v$version"))
    }

    private fun parseUbi(data: ByteArray, layers: MutableList<Layer>, evidence: MutableList<String>, archHints: MutableSet<String>) {
        if (data.size < 64) return
        val version = Bin.u8(data, 4)
        val vidHdrOffset = Bin.u32be(data, 8)
        val dataOffset = Bin.u32be(data, 12)
        val imageSeq = Bin.u32be(data, 16)
        val lebSize = Bin.u32be(data, 24)
        evidence.add(
            "UBI image v$version: erase-block (LEB) ${Hex.humanBytes(lebSize)}, vid header @ 0x${vidHdrOffset.toString(16)}, " +
                "data @ 0x${dataOffset.toString(16)}, sequence $imageSeq"
        )
        evidence.add("NAND/UBI images cannot be statically emulated on-device: the rootfs is inside UBIFS")
        archHints.add("ubi")
        layers.add(Layer(ImageFormat.UBI, "UBI container", 0, minOf(data.size.toLong(), lebSize * 4), detail = "LEB size ${Hex.humanBytes(lebSize)}"))
    }

    private fun refineVendorFromStructure(data: ByteArray, primary: ImageFormat, current: Vendor, evidence: MutableList<String>): Vendor {
        val text = sampleStrings(data, minOf(data.size, 2 * 1024 * 1024))
        val structural = when {
            text.contains("OpenWrt", true) -> Vendor.OPENWRT
            text.contains("DD-WRT", true) -> Vendor.DDWRT
            text.contains("ASUSWRT", true) || text.contains("asuswrt", true) -> Vendor.ASUS
            text.contains("Netgear", true) && primary == ImageFormat.NETGEAR_CHK -> Vendor.NETGEAR
            text.contains("TP-Link", true) && primary == ImageFormat.TPLINK_BIN -> Vendor.TP_LINK
            text.contains("D-Link", true) || text.contains("DLink", true) -> Vendor.DLINK
            text.contains("MikroTik", true) || text.contains("RouterOS", true) -> Vendor.MIKROTIK
            else -> null
        }
        return if (structural != null && structural != current) {
            evidence.add("Structure indicates ${structural.display} (overrides weak string match)")
            structural
        } else current
    }

    /** Generic nested-container discovery: finds every known magic inside the image. */
    private fun scanInnerImages(
        data: ByteArray,
        layers: MutableList<Layer>,
        evidence: MutableList<String>,
        archHints: MutableSet<String>,
        maxFindings: Int = 24,
    ) {
        val limit = minOf(data.size, 96 * 1024 * 1024)
        var found = 0
        // Fixed candidate offsets first (vendor headers), then a full magic sweep.
        for (off in CANDIDATE_OFFSETS) {
            if (found >= maxFindings) break
            if (off == 0 || off >= limit) continue
            val det = detectAt(data, off, null) ?: continue
            if (det.first == ImageFormat.RAW) continue
            evidence.add("Nested ${det.first.label} at 0x${off.toString(16)}")
            val length = when (det.first) {
                ImageFormat.SQUASHFS -> if (off + 48 <= data.size) Bin.u64le(data, off + 40).coerceAtLeast(0) else 0
                else -> 0
            }
            layers.add(Layer(det.first, "nested ${det.first.label} @ 0x${off.toString(16)}", off.toLong(), if (length > 0) length else -1, detail = "found by offset probe"))
            found++
            if (det.first == ImageFormat.UBOOT_LEGACY) parseUImage(data, off, layers, evidence, archHints)
            if (det.first == ImageFormat.UBOOT_FIT) parseFdt(data, off, layers, evidence, archHints)
            if (det.first == ImageFormat.TRX) parseTrx(data.copyOfRange(off, data.size), layers, evidence, archHints)
        }
        // Sweep: search each distinctive magic once, limit work on huge files.
        val sweepLimit = minOf(limit, 8 * 1024 * 1024)
        val searchEnd = if (limit > sweepLimit) sweepLimit else limit
        for (m in MAGICS.filter { it.format in setOf(ImageFormat.SQUASHFS, ImageFormat.CRAMFS, ImageFormat.NETGEAR_CHK, ImageFormat.TPLINK_BIN, ImageFormat.TRX, ImageFormat.UBOOT_LEGACY) }) {
            if (found >= maxFindings) break
            var from = 0
            var perMagic = 0
            while (perMagic < 3) {
                val idx = Bin.indexOf(data, m.bytes, from)
                if (idx < 0 || idx >= searchEnd) break
                from = idx + 1
                if (CANDIDATE_OFFSETS.contains(idx)) continue
                if (idx == 0) continue
                // verify squashfs version when relevant
                if (m.format == ImageFormat.SQUASHFS && (idx + 30 > data.size || Bin.u16le(data, idx + 28) != 4)) continue
                evidence.add("${m.label} at 0x${idx.toString(16)} (sweep)")
                layers.add(Layer(m.format, "${m.label} @ 0x${idx.toString(16)}", idx.toLong(), -1, detail = "found by magic sweep"))
                found++
                perMagic++
                if (m.format == ImageFormat.UBOOT_LEGACY && idx + 64 < data.size) parseUImage(data, idx, layers, evidence, archHints)
            }
        }
        if (layers.isEmpty()) evidence.add("No nested container found by probing - image looks like a single flat blob")
    }

    private fun kindToFormat(kind: Compression.Kind): ImageFormat = when (kind) {
        Compression.Kind.GZIP -> ImageFormat.GZIP
        Compression.Kind.XZ -> ImageFormat.XZ
        Compression.Kind.LZMA, Compression.Kind.LZMA_SQUASHFS -> ImageFormat.LZMA
        Compression.Kind.BZIP2 -> ImageFormat.BZIP2
        Compression.Kind.ZSTD -> ImageFormat.ZSTD
        Compression.Kind.LZ4 -> ImageFormat.LZ4
        Compression.Kind.LZO -> ImageFormat.LZO
        Compression.Kind.ZLIB -> ImageFormat.RAW
        Compression.Kind.NONE -> ImageFormat.RAW
    }

    // ------------------------------------------------------------------ text mining

    private fun sampleStrings(data: ByteArray, length: Int): String {
        val sb = StringBuilder()
        // Sample beginning, middle, end - headers and banners hide in all three.
        val chunk = minOf(length / 3, 2 * 1024 * 1024)
        val regions = listOf(0, maxOf(0, data.size / 2 - chunk / 2), maxOf(0, data.size - chunk))
        for (start in regions) {
            if (start >= data.size) continue
            val end = minOf(data.size, start + chunk)
            val strs = Strings.extract(data, 4, 3000, offset = start, length = end - start)
            for ((_, s) in strs) {
                sb.append(s).append('\n')
                if (sb.length > 512 * 1024) break
            }
            if (sb.length > 512 * 1024) break
        }
        return sb.toString()
    }

    private fun guessModel(text: String): String? {
        for (r in MODEL_REGEXES) {
            val m = r.find(text) ?: continue
            val candidate = if (m.groupValues.size >= 3 && m.groupValues[2].isNotBlank()) m.groupValues[2] else m.value
            val cleaned = candidate.trim().trim(',', ';', '"', '\'')
            if (cleaned.length in 3..40 && cleaned.any { it.isDigit() }) return cleaned
        }
        return null
    }

    private fun computeConfidence(
        primary: ImageFormat,
        vendor: Vendor,
        model: String?,
        version: String?,
        layers: Int,
    ): Int {
        var score = 30
        if (primary != ImageFormat.RAW) score += 25
        if (vendor != Vendor.UNKNOWN) score += 15
        if (model != null) score += 15
        if (version != null) score += 8
        score += minOf(layers, 4) * 2
        return minOf(score, 98)
    }

    /** Exposed for the UI: a one-line "what is this" answer. */
    fun describeQuickly(identity: ImageIdentity): String = identity.summary()
}
