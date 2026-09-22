package com.flashguard.engine.core

/**
 * Everything the engine reports is made of these types, so the Android UI, the JSON export and
 * the self-test corpus all speak the same language.
 */

/** A firmware container/format the engine recognises. */
enum class ImageFormat(
    val label: String,
    /** true when the engine can unpack it into a virtual filesystem. */
    val unpackable: Boolean,
    val notes: String = "",
) {
    TRX("TRX / HDR0 (Broadcom, DD-WRT, some TP-Link)", true, "4-byte magic, then offsets and CRC32"),
    UBOOT_LEGACY("U-Boot legacy uImage", true, "0x27051956 header, optional gzip/LZMA payload"),
    UBOOT_FIT("U-Boot FIT image (dtb)", true, "FDT blob listing kernel/rootfs sub-images"),
    UBOOT_SCRIPT("U-Boot script image", false),
    NETGEAR_CHK("Netgear CHK (2A23245E)", true, "HEADER + kernel + squashfs/rootfs"),
    TPLINK_BIN("TP-Link firmware .bin", true, "header + bootloader/kernel/rootfs sections"),
    TPLINK_SIGNED("TP-Link signed/encrypted image", false, "Newer models wrap the payload in a vendor signature"),
    DLINK_SHR("D-Link SHRS/image", true),
    SERCOMM("Sercomm package", true),
    OPENWRT_SYSUPGRADE("OpenWrt sysupgrade tar", true, "kernel + root + CONTROL metadata"),
    OPENWRT_METADATA("OpenWrt .metadata / .json", false),
    TAR("tar archive", true),
    CPIO("cpio archive", true),
    ZIP("ZIP archive", true),
    SQUASHFS("SquashFS filesystem", true),
    CRAMFS("CramFS filesystem", true),
    EXT("ext2/3/4 filesystem", false, "Superblock readable, extraction not implemented"),
    JFFS2("JFFS2 filesystem", false, "Common on raw MTD flash dumps"),
    UBI("UBI image (UBI#)", false, "UBI volume table only; UBIFS payload not unpacked"),
    UBIFS("UBIFS filesystem", false, "Needs UBI volume context; not unpacked on-device"),
    GZIP("gzip stream", true),
    XZ("xz stream", true),
    LZMA("lzma alone stream", true),
    BZIP2("bzip2 stream", false, "Detected but not decompressed on-device"),
    ZSTD("zstd stream", false, "Detected but not decompressed on-device"),
    LZ4("lz4 stream", false, "Detected but not decompressed on-device"),
    LZO("lzo stream", false, "Detected but not decompressed on-device"),
    DT_BLOB("Device tree blob (DTB)", false),
    ELF("ELF executable/object", false),
    RAW("Raw/unknown binary", false, "No magic matched; treated as an opaque flash image"),
    EMPTY("Empty file", false);

    companion object {
        fun ofLabelOrNull(s: String): ImageFormat? = entries.firstOrNull { it.label == s }
    }
}

/** Vendor families we can name with reasonable confidence. */
enum class Vendor(val display: String, val slugs: List<String>) {
    TP_LINK("TP-Link", listOf("tp-link", "tplink", "tplinkrouter")),
    NETGEAR("Netgear", listOf("netgear")),
    DLINK("D-Link", listOf("d-link", "dlink")),
    ASUS("ASUS", listOf("asus", "asuswrt")),
    LINKSYS("Linksys", listOf("linksys")),
    OPENWRT("OpenWrt / LEDE", listOf("openwrt", "lede")),
    DDWRT("DD-WRT", listOf("dd-wrt", "ddwrt")),
    XIAOMI("Xiaomi / MiWiFi", listOf("xiaomi", "miwifi", "mi router")),
    MERCUSYS("Mercusys", listOf("mercusys")),
    TOTOLINK("TOTOLINK", listOf("totolink")),
    TENDA("Tenda", listOf("tenda")),
    UBIQUITI("Ubiquiti / AirOS", listOf("ubiquiti", "airos", "unifi", "ubnt")),
    GLINET("GL.iNet", listOf("gl.inet", "glinet", "gl-")),
    HUAWEI("Huawei", listOf("huawei")),
    ZTE("ZTE", listOf("zte")),
    NETIS("Netis", listOf("netis")),
    TRENDNET("TRENDnet", listOf("trendnet")),
    BUFFALO("Buffalo", listOf("buffalo")),
    MIKROTIK("MikroTik", listOf("mikrotik", "routeros")),
    UNKNOWN("Unknown vendor", emptyList());

    companion object {
        fun guessFromText(text: String): Pair<Vendor, String>? {
            val low = text.lowercase()
            var best: Pair<Vendor, String>? = null
            for (v in entries) {
                for (slug in v.slugs) {
                    val idx = low.indexOf(slug)
                    if (idx < 0) continue
                    // Short slugs must stand on their own: "zte" inside random flash bytes (or
                    // inside a longer word) is not evidence of a ZTE image.
                    if (slug.length < 6 && !isStandalone(low, idx, slug.length)) continue
                    val candidate = v to slug
                    if (best == null || slug.length > (best.second.length)) best = candidate
                }
            }
            return best
        }

        private fun isStandalone(text: String, index: Int, length: Int): Boolean {
            fun boundary(c: Char) = !c.isLetterOrDigit()
            val beforeOk = index == 0 || boundary(text[index - 1])
            val afterOk = index + length >= text.length || boundary(text[index + length])
            return beforeOk && afterOk
        }
    }
}

/** One layer of the container nesting tree (tar -> gzip -> squashfs -> ...). */
data class Layer(
    val format: ImageFormat,
    val label: String,
    val offset: Long,
    val length: Long,
    val detail: String = "",
    val children: List<Layer> = emptyList(),
) {
    fun flattenTree(into: MutableList<Layer> = ArrayList()): List<Layer> {
        into.add(this)
        for (c in children) c.flattenTree(into)
        return into
    }
}

/** What the identifier concluded about an image. */
data class ImageIdentity(
    val primary: ImageFormat,
    val vendor: Vendor,
    val model: String?,
    val version: String?,
    val archHints: List<String>,
    val confidence: Int,
    val evidence: List<String>,
    val layers: List<Layer>,
    val totalSize: Long,
    val sha256: String,
) {
    fun summary(): String = buildString {
        append(primary.label)
        if (vendor != Vendor.UNKNOWN) append(" | ").append(vendor.display)
        model?.let { append(" | ").append(it) }
        version?.let { append(" | v").append(it) }
    }
}

enum class FindingLevel { INFO, OK, WARN, ERROR }

/** A single observation: used for scan findings, emulation notes and the hardware matrix. */
data class Finding(
    val id: String,
    val title: String,
    val detail: String,
    val level: FindingLevel = FindingLevel.INFO,
    val evidence: String? = null,
    val category: String = "general",
)

/** Verdict per hardware feature (drives the red marking the user asked for). */
enum class FeatureVerdict(val display: String, val rank: Int) {
    COMPATIBLE("Compatible", 0),
    UNVERIFIED("Unverified (needs a real boot test)", 1),
    PARTIAL("Partial - works with caveats", 2),
    INCOMPATIBLE("HARDWARE INCOMPATIBLE", 3),
    MISSING("Not present in this image", 4),
    ;

    val isRed: Boolean get() = this == INCOMPATIBLE
}

/** One row of the compatibility table. */
data class HardwareFeature(
    val feature: String,
    val imageWants: String,
    val deviceHas: String,
    val verdict: FeatureVerdict,
    val why: String,
    val mitigation: String? = null,
)

/** Result of running the image's init logic inside the sandboxed simulator. */
data class EmulationResult(
    val bootLog: List<String>,
    val stages: List<BootStage>,
    val services: List<SimService>,
    val filesCreated: List<String>,
    val interfaces: List<String>,
    val variables: Map<String, String>,
    val commandsRun: Int,
    val unsupportedCommands: Map<String, Int>,
    val webRoot: String?,
    val loginPage: String?,
    val elapsedMs: Long,
    val truncated: Boolean,
    val notes: List<String>,
) {
    fun reachedInit(): Boolean = stages.any { it.name == BootStageNames.INIT && it.ok }
    fun reachedWebUi(): Boolean = stages.any { it.name == BootStageNames.WEBUI && it.ok }
}

data class BootStage(val name: String, val ok: Boolean, val detail: String)

object BootStageNames {
    const val HEADER = "Bootloader header"
    const val KERNEL = "Kernel image"
    const val ROOTFS = "Root filesystem"
    const val INIT = "init / rc scripts executed"
    const val NETWORK = "Network services"
    const val WEBUI = "Web UI / httpd started"
}

/** A service the emulated firmware tried to start, with the port it listens on. */
data class SimService(
    val name: String,
    val command: String,
    val port: Int?,
    val simulated: Boolean,
    val detail: String = "",
)

/** Overall report assembled for one firmware image + one target device. */
data class EngineReport(
    val identity: ImageIdentity,
    val findings: List<Finding>,
    val emulation: EmulationResult?,
    val features: List<HardwareFeature>,
    val device: DeviceProfile,
    val riskScore: Int,
    val verdict: RiskVerdict,
    val nextSteps: List<String>,
    val generatedAt: Long = System.currentTimeMillis(),
) {
    fun redFlags(): List<HardwareFeature> = features.filter { it.verdict.isRed }
    fun scanFindings(): List<Finding> = findings
}

enum class RiskVerdict(val display: String, val level: FindingLevel) {
    SAFE_TO_FLASH_AFTER_BACKUP("Looks flashable - take a full backup first", FindingLevel.OK),
    NEEDS_MANUAL_REVIEW("Needs manual review before flashing", FindingLevel.WARN),
    DO_NOT_FLASH("DO NOT FLASH - hardware mismatch detected", FindingLevel.ERROR),
    UNKNOWN("Not enough information", FindingLevel.INFO),
}

/** Hardware profile of a target router (built-in DB or entered by the user). */
data class DeviceProfile(
    val id: String,
    val brand: String,
    val model: String,
    val revision: String = "",
    val soc: String,
    val cpuFamily: CpuFamily,
    val cpuCores: Int,
    val cpuMhz: Int,
    val ramMb: Int,
    val flashMb: Int,
    val flashLayout: String,
    val bootloader: String,
    /** NOR, NAND, eMMC or SD - the single most important detail before flashing. */
    val flashType: String = "NOR",
    /** Known recovery method that can un-brick this model. */
    val recovery: String = "unknown",
    val wifiChips: List<String>,
    val extraFeatures: List<String> = emptyList(),
    val usb: Boolean = false,
    val ethernetPorts: Int = 0,
    val gigabit: Boolean = false,
    val requiresSignedFirmware: Boolean = false,
    val openwrtSupport: String = "unknown",
    val stockLogin: String = "unknown",
    val notes: String = "",
    val isCustom: Boolean = false,
) {
    val display: String get() = listOf(brand, model, revision).filter { it.isNotBlank() }.joinToString(" ")
}

enum class CpuFamily(val display: String, val kernelArchKeywords: List<String>) {
    // Bare "mips" is deliberately NOT a keyword: it is endian-ambiguous (uImage arch code 5
    // covers both mips and mipsel), so it yields a PARTIAL row rather than a green one.
    MIPS_BE("MIPS big-endian (mips/ar71xx-family)", listOf("mipseb", "ar71xx", "ath79", "ar9344", "qca")),
    MIPSEL("MIPS little-endian (mipsel/ramips)", listOf("mipsel", "ramips", "mt7620", "mt7621", "rt305x", "mt76x8")),
    ARM_LE("ARM 32-bit (armv7)", listOf("arm", "armv7", "armhf", "cortex-a7", "cortex-a9")),
    AARCH64("ARM 64-bit (arm64/aarch64)", listOf("aarch64", "arm64", "cortex-a53", "cortex-a55")),
    X86("x86/x86_64", listOf("x86", "i386", "i686", "x86_64", "amd64")),
    RISCV("RISC-V", listOf("riscv", "rv64")),
    UNKNOWN("Unknown", emptyList()),
}

/** Router-side stability probe results (test the *live* router before/after a flash). */
data class ProbeResult(
    val host: String,
    val reachable: Boolean,
    val webServer: String?,
    val loginPageFound: Boolean,
    val loginFormFields: List<String>,
    val authScheme: String,
    val serverHeader: String?,
    val cookies: List<String>,
    val defaultCredsTried: List<String>,
    val defaultCredsWorked: String?,
    val afterLoginFeatures: List<ProbeFeature>,
    val latencyMs: List<Long>,
    val errors: Int,
    val requests: Int,
    val stable: Boolean,
    val notes: List<String>,
) {
    val p50: Long get() = latencyMs.sorted().let { if (it.isEmpty()) 0 else it[it.size / 2] }
    val p95: Long get() = latencyMs.sorted().let { if (it.isEmpty()) 0 else it[(it.size * 95) / 100] }
}

data class ProbeFeature(val name: String, val path: String, val status: Int, val bytes: Int, val ms: Long)
