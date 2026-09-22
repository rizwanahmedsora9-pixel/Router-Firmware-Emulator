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

    private class Job(val data: ByteArray, val origin: String, val depth: Int)

    fun unpack(): UnpackResult {
        var imported = 0
        val queue = ArrayDeque<Job>()
        queue.add(Job(bytes, "primary image", 0))

        // Pre-seed nested regions discovered by the identifier (vendor header + payload layouts).
        for (layer in identity.layers.flatMap { it.flattenTree() }) {
            if (layer.offset <= 0) continue
            if (layer.format == ImageFormat.RAW) continue
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
                unsupported.add("${kind.label} container cannot be decompressed on-device (${job.origin})")
                return 0
            }
            val decoded = Compression.decode(data)
            if (decoded != null && decoded.bytes.size > 16) {
                notes.add("${kind.label} decompressed: ${Hex.humanBytes(decoded.bytes.size)} (${job.origin})")
                queue.add(Job(decoded.bytes, "${job.origin} > ${kind.label}", job.depth + 1))
                return 0
            }
            unsupported.add("${kind.label} stream could not be decoded (${job.origin})")
            return 0
        }

        // 5) last resort: byte scan for an embedded filesystem inside a vendor header
        for (magic in listOf("hsqs", "070701")) {
            val idx = Bin.indexOfAscii(data, magic, 64)
            if (idx > 0) {
                val chunk = data.copyOfRange(idx, data.size)
                notes.add("Found embedded $magic payload at 0x${idx.toString(16)} (${job.origin})")
                queue.add(Job(chunk, "${job.origin} embedded @0x${idx.toString(16)}", job.depth + 1))
                return 0
            }
        }
        return 0
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
            val kernelVersion = vfs.findByContains("/etc/modules/")
                .firstOrNull()
                ?.let { null }
                ?: Regex("Linux version\\s+([\\d.\\w\\-+]+)").find(identity.evidence.joinToString(" "))?.groupValues?.get(1)

            val modules = vfs.findByContains("/modules/")
                .filter { it.path.endsWith(".ko") }
                .map { Text.baseName(it.path).removeSuffix(".ko") }
                .distinct()
                .take(400)

            val wirelessDrivers = modules.filter {
                it.contains("ath") || it.contains("mt7") || it.contains("mt76") || it.contains("rt2") ||
                    it.contains("rtl") || it.contains("brcm") || it.contains("mac80211") || it.contains("cfg80211") ||
                    it.contains("iwl") || it.contains("carl9170") || it.contains("rt2800") ||
                    it == "wl" || it.startsWith("wl-") || it.contains("b43") || it == "broadcom-wl"
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
            var socScanned = 0
            for (f in vfs.allFiles()) {
                if (socScanned >= 160) break
                if (f.size !in 8..16384) continue
                socScanned++
                vfs.readText(f.path, 8192)?.let { harvestSoc(it) }
            }
            if (socHints.isNotEmpty()) notes.add("SoC markers in rootfs: " + socHints.joinToString(", "))

            val rootfsSize = vfs.allFiles().sumOf { it.size }
            val requiredFlashMb = if (rootfsSize > 0) rootfsSize / (1024.0 * 1024.0) * 1.15 else null

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
