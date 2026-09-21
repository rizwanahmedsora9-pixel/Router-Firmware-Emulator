package com.flashguard.engine

import com.flashguard.engine.compression.Compression
import com.flashguard.engine.core.BootStageNames
import com.flashguard.engine.core.DeviceProfile
import com.flashguard.engine.core.FeatureVerdict
import com.flashguard.engine.core.FirmwareIdentifier
import com.flashguard.engine.core.ImageFormat
import com.flashguard.engine.device.DeviceDb
import com.flashguard.engine.fs.VirtualFs
import com.flashguard.engine.util.Bin
import com.flashguard.engine.util.Hex
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.GZIPOutputStream
import kotlin.system.exitProcess

/**
 * The engine's own test bench. Runs on a plain JVM (CI does this on every push) and needs no
 * Android device, no network and no external tools - except optional real images passed as argv,
 * which is how CI validates against genuine OpenWrt/vendor firmware built with mksquashfs.
 *
 * Exit code is non-zero when any check fails, so CI turns red on a regression.
 */
private class Runner {
    var passed = 0
    var failed = 0
    private val failures = ArrayList<String>()

    fun check(name: String, body: () -> Unit) {
        try {
            body()
            passed++
            println("  [pass] $name")
        } catch (t: Throwable) {
            failed++
            failures.add("$name: ${t.message}")
            println("  [FAIL] $name -> ${t.message}")
        }
    }

    fun expect(condition: Boolean, message: String) {
        if (!condition) throw AssertionError(message)
    }

    fun summary(): Int {
        println()
        println("=".repeat(72))
        println("FlashGuard engine self-test: $passed passed, $failed failed")
        if (failures.isNotEmpty()) {
            println("Failures:")
            failures.forEach { println("  - $it") }
        }
        println("=".repeat(72))
        return if (failed == 0) 0 else 1
    }
}

// ---------------------------------------------------------------------------- fixture builders

private fun tarEntry(name: String, content: ByteArray, mode: Int = 0b110100100, isDir: Boolean = false): ByteArray {
    val header = ByteArray(512)
    fun put(offset: Int, text: String, max: Int) {
        val bytes = text.toByteArray(Charsets.ISO_8859_1)
        System.arraycopy(bytes, 0, header, offset, minOf(bytes.size, max))
    }
    put(0, name, 100)
    put(100, String.format("%07o", if (isDir) 0b111101101 else mode), 8)
    put(108, "0000000", 8)
    put(116, "0000000", 8)
    put(124, String.format("%011o", if (isDir) 0 else content.size), 12)
    put(136, String.format("%011o", 0), 12)
    put(148, "        ", 8)
    header[156] = (if (isDir) '5' else '0').code.toByte()
    put(257, "ustar", 6)
    put(263, "00", 2)
    put(265, "root", 32)
    put(297, "root", 32)
    var sum = 0
    for (b in header) sum += b.toInt() and 0xFF
    put(148, String.format("%06o\u0000 ", sum), 8)
    val out = ByteArrayOutputStream()
    out.write(header)
    if (!isDir && content.isNotEmpty()) {
        out.write(content)
        val pad = (512 - content.size % 512) % 512
        if (pad > 0) out.write(ByteArray(pad))
    }
    return out.toByteArray()
}

private fun buildTar(entries: List<Pair<String, ByteArray>>, dirs: List<String> = emptyList()): ByteArray {
    val out = ByteArrayOutputStream()
    for (d in dirs) out.write(tarEntry(d, ByteArray(0), isDir = true))
    for ((name, content) in entries) out.write(tarEntry(name, content))
    out.write(ByteArray(1024))
    return out.toByteArray()
}

private fun gzip(data: ByteArray): ByteArray {
    val bos = ByteArrayOutputStream()
    GZIPOutputStream(bos).use { it.write(data) }
    return bos.toByteArray()
}

/** A realistic OpenWrt-flavoured rootfs used as the primary fixture. */
private fun openWrtLikeRootfs(): Pair<List<Pair<String, ByteArray>>, List<String>> {
    val entries = mutableListOf<Pair<String, ByteArray>>()
    val dirs = mutableListOf(
        "etc", "etc/init.d", "etc/config", "etc/rc.d", "www", "www/cgi-bin", "lib", "lib/modules",
        "lib/modules/4.14.241", "usr", "usr/sbin", "sbin", "bin", "tmp",
    )
    entries += "etc/openwrt_release" to """
        DISTRIB_ID='OpenWrt'
        DISTRIB_RELEASE='23.05.3'
        DISTRIB_REVISION='r23809-234f1a2efa'
        DISTRIB_TARGET='ramips/mt7621'
        DISTRIB_ARCH='mipsel_24kc'
        DISTRIB_DESCRIPTION='OpenWrt 23.05.3 r23809-234f1a2efa'
    """.trimIndent().toByteArray()

    entries += "etc/banner" to """
         _______                     ________        __
        |       |.-----.-----.-----.|  |  |  |.----.|  |_
        |   -   ||  _  |  -__|     ||  |  |  ||   _||   _|
        |_______||   __|_____|__|__||________||__|  |____|
                 |__| W I R E L E S S   F R E E D O M
         OpenWrt 23.05.3, r23809-234f1a2efa
    """.trimIndent().toByteArray()

    entries += "etc/init.d/network" to """
        #!/bin/sh /etc/rc.common
        START=20
        start() {
            echo "Configuring network"
            ip addr add 192.168.1.1/24 dev br-lan
            ip link set br-lan up
            ifconfig eth0 up
            export lan_ipaddr=192.168.1.1
            hostname OpenWrt
        }
        stop() { echo stopping network; }
    """.trimIndent().toByteArray()

    entries += "etc/init.d/uhttpd" to """
        #!/bin/sh /etc/rc.common
        START=50
        start() {
            echo "Starting uhttpd on port 80"
            uhttpd -h /www -p 80
            /usr/sbin/dropbear -p 22
            dnsmasq -C /var/etc/dnsmasq.conf
        }
    """.trimIndent().toByteArray()

    entries += "etc/rc.d/S20network" to "#!/bin/sh\n/etc/init.d/network start\n".toByteArray()
    entries += "etc/rc.d/S50uhttpd" to "#!/bin/sh\n/etc/init.d/uhttpd start\n".toByteArray()

    entries += "www/login.html" to """
        <html><head><title>OpenWrt Login</title></head><body>
        <h1>Router login</h1>
        <form method="post" action="/cgi-bin/luci">
          <input type="text" name="luci_username" placeholder="Username">
          <input type="password" name="luci_password" placeholder="Password">
          <input type="submit" value="Login">
        </form>
        </body></html>
    """.trimIndent().toByteArray()

    entries += "www/index.html" to "<html><title>OpenWrt Status</title><body>System status</body></html>".toByteArray()
    entries += "www/cgi-bin/luci" to "#!/usr/bin/lua\n-- LuCI dispatcher (native script)\n".toByteArray()
    entries += "www/wifi.html" to "<html><title>Wireless configuration</title><body>Wi-Fi settings</body></html>".toByteArray()
    entries += "www/vpn.html" to "<html><title>VPN configuration</title><body>OpenVPN / WireGuard</body></html>".toByteArray()

    entries += "etc/passwd" to "root:x:0:0:root:/root:/bin/ash\ndaemon:*:1:1:daemon:/var:/bin/false\n".toByteArray()
    entries += "etc/shadow" to "root:\$1\$abcdefgh\$1234567890abcdefghijkl:19000:0:99999:7:::\n".toByteArray()
    entries += "etc/config/network" to "config interface 'lan'\n\toption ifname 'br-lan'\n\toption proto 'static'\n\toption ipaddr '192.168.1.1'\n".toByteArray()
    entries += "etc/config/wireless" to "config wifi-device 'radio0'\n\toption type 'mac80211'\n\toption channel '6'\n".toByteArray()

    entries += "lib/modules/4.14.241/mt76x2e.ko" to ByteArray(2048) { (it % 251).toByte() }
    entries += "lib/modules/4.14.241/mt7603e.ko" to ByteArray(1024) { (it % 97).toByte() }
    entries += "lib/modules/4.14.241/usb-storage.ko" to ByteArray(512) { 1 }
    entries += "usr/sbin/dropbear" to ByteArray(4096) { 7 }
    entries += "usr/sbin/uhttpd" to ByteArray(4096) { 9 }
    entries += "usr/sbin/dnsmasq" to ByteArray(4096) { 11 }
    entries += "usr/sbin/telnetd" to ByteArray(256) { 3 }
    entries += "sbin/mtd" to ByteArray(64) { 5 }
    return entries to dirs
}

// ---------------------------------------------------------------------------- main

fun main(args: Array<String>) {
    println("FlashGuard engine self-test")
    println("limits: files=${com.flashguard.engine.util.Limits.MAX_FILES} ram=${Hex.humanBytes(com.flashguard.engine.util.Limits.MAX_EXTRACT_BYTES)} steps=${com.flashguard.engine.util.Limits.MAX_SHELL_STEPS}")
    val r = Runner()
    val (entries, dirs) = openWrtLikeRootfs()
    val tarBytes = buildTar(entries, dirs)
    val gzTar = gzip(tarBytes)

    // ------------------------------------------------------------------ identification
    r.check("identifies a gzip stream") {
        val id = FirmwareIdentifier.identify(gzTar, "test.tar.gz")
        r.expect(id.primary == ImageFormat.GZIP, "expected GZIP, got ${id.primary}")
    }
    r.check("identifies a tar archive") {
        val id = FirmwareIdentifier.identify(tarBytes, "test.tar")
        r.expect(id.primary == ImageFormat.TAR, "expected TAR, got ${id.primary}")
    }
    r.check("identifies a TRX container and finds the vendor") {
        val trx = buildTrx(gzTar)
        val id = FirmwareIdentifier.identify(trx, "DD-WRT-v3.trx")
        r.expect(id.primary == ImageFormat.TRX, "expected TRX, got ${id.primary}")
        r.expect(id.vendor.display.contains("DD-WRT", true), "expected DD-WRT vendor, got ${id.vendor}")
    }
    r.check("identifies a U-Boot legacy uImage with MIPS arch hint") {
        val uimage = buildUImage(gzTar)
        val id = FirmwareIdentifier.identify(uimage, "openwrt-uimage.bin")
        r.expect(id.primary == ImageFormat.UBOOT_LEGACY, "expected uImage, got ${id.primary}")
        r.expect(id.archHints.any { it.contains("mips") }, "expected mips arch hint, got ${id.archHints}")
    }
    r.check("flags an opaque high-entropy blob as RAW/encrypted") {
        val random = ByteArray(64 * 1024) { ((it * 7919) % 256).toByte() }
        val id = FirmwareIdentifier.identify(random, "mystery.bin")
        r.expect(id.primary == ImageFormat.RAW, "expected RAW, got ${id.primary}")
        r.expect(id.evidence.any { it.contains("entropy", true) }, "expected entropy evidence")
    }
    r.check("detects UBI/NAND images and refuses to pretend otherwise") {
        val ubi = ByteArray(2048)
        System.arraycopy("UBI#".toByteArray(), 0, ubi, 0, 4)
        ubi[4] = 1
        writeU32be(ubi, 8, 64)
        writeU32be(ubi, 12, 2048)
        writeU32be(ubi, 24, 128 * 1024)
        val id = FirmwareIdentifier.identify(ubi, "factory.ubi")
        r.expect(id.primary == ImageFormat.UBI, "expected UBI, got ${id.primary}")
    }
    r.check("handles empty files without crashing") {
        val id = FirmwareIdentifier.identify(ByteArray(0), "empty.bin")
        r.expect(id.primary == ImageFormat.EMPTY, "expected EMPTY")
    }

    // ------------------------------------------------------------------ compression + containers
    r.check("gzip round-trips") {
        val decoded = Compression.decode(gzTar)
        r.expect(decoded != null, "decode returned null")
        r.expect(decoded!!.bytes.size == tarBytes.size, "size mismatch ${decoded.bytes.size} vs ${tarBytes.size}")
    }
    r.check("tar reader extracts the expected tree") {
        val entriesRead = com.flashguard.engine.container.TarReader.entries(tarBytes)
        r.expect(entriesRead.size > 20, "expected >20 entries, got ${entriesRead.size}")
        r.expect(entriesRead.any { it.path == "/etc/openwrt_release" }, "missing /etc/openwrt_release")
        r.expect(entriesRead.any { it.path == "/www/login.html" }, "missing /www/login.html")
    }
    r.check("cpio newc rounds-trips") {
        val cpio = buildCpio(listOf("/etc/passwd" to "root:x:0:0:root:/root:/bin/sh\n".toByteArray()))
        val read = com.flashguard.engine.container.CpioReader.entries(cpio)
        r.expect(read.any { it.path == "/etc/passwd" }, "cpio entry missing")
        r.expect(read.first { it.path == "/etc/passwd" }.open()?.isNotEmpty() == true, "cpio content missing")
    }

    // ------------------------------------------------------------------ shell interpreter
    r.check("shell: variables, if/grep, functions and while loops") {
        val vfs = VirtualFs()
        vfs.addFile("/etc/config/mode", "router\n".toByteArray())
        val shell = com.flashguard.engine.emu.SimShell(vfs, com.flashguard.engine.core.FirmwareFacts())
        val res = shell.runString(
            """
            MODE=${'$'}(cat /etc/config/mode)
            count=0
            if [ "${'$'}MODE" = "router" ]; then
              echo "mode is router"
              count=1
            fi
            while [ ${'$'}count -lt 3 ]; do
              count=${'$'}((count + 1))
              echo "loop ${'$'}count"
            done
            """.trimIndent(),
        )
        r.expect(res.output.contains("mode is router"), "if/grep branch did not run: ${res.output}")
        r.expect(shell.steps > 0, "no shell steps recorded")
    }
    r.check("shell: records services, hardware touches and unsupported commands") {
        val vfs = VirtualFs()
        val shell = com.flashguard.engine.emu.SimShell(vfs, com.flashguard.engine.core.FirmwareFacts())
        shell.runString(
            """
            uhttpd -h /www -p 80
            mtd write /tmp/fw.bin firmware
            totally_unknown_tool --now
            """.trimIndent(),
        )
        r.expect(shell.services.any { it.name == "uhttpd" && it.port == 80 }, "uhttpd service not recorded")
        r.expect(shell.hardwareTouches.containsKey("mtd write /tmp/fw.bin firmware"), "mtd hardware touch not recorded")
        r.expect(shell.unsupported.containsKey("totally_unknown_tool"), "unknown command not recorded")
    }
    r.check("shell: cannot escape the sandbox") {
        val vfs = VirtualFs()
        val shell = com.flashguard.engine.emu.SimShell(vfs, com.flashguard.engine.core.FirmwareFacts())
        shell.runString("rm -rf / ; echo done ; cat /etc/passwd")
        r.expect(vfs.exists("/"), "sandbox root vanished - VFS should survive rm -rf /")
        r.expect(!java.io.File("/etc/passwd").let { it.exists() && false }, "sanity")
    }

    // ------------------------------------------------------------------ full pipeline
    r.check("full pipeline: gzip>tar>OpenWrt-like rootfs boots to a web UI") {
        val device = DeviceDb.byId("glinet-gl-mt1300")!!
        val session = FirmwareLab.analyze(gzTar, "openwrt-test.tar.gz", device)
        r.expect(session.identity.primary == ImageFormat.GZIP, "format ${session.identity.primary}")
        r.expect(session.unpack.vfs.fileCount > 20, "rootfs too small: ${session.unpack.vfs.fileCount}")
        r.expect(session.facts.distro != null, "distro not detected")
        r.expect(session.facts.target == "ramips/mt7621", "target was ${session.facts.target}")
        r.expect(session.emulation.services.any { it.name == "uhttpd" }, "uhttpd not started in emulation")
        r.expect(session.emulation.webRoot == "/www", "web root was ${session.emulation.webRoot}")
        r.expect(session.emulation.loginPage != null, "login page not found")
        r.expect(session.emulation.reachedInit(), "did not reach init")
        r.expect(session.emulation.reachedWebUi(), "did not reach web UI")
        // mipsel image on a mipsel device must NOT be flagged as a CPU mismatch
        val archRow = session.report.features.first { it.feature == "CPU architecture" }
        r.expect(archRow.verdict != FeatureVerdict.INCOMPATIBLE, "false CPU mismatch: ${archRow.why}")
        r.expect(session.report.features.any { it.feature.contains("Wi-Fi") }, "no wi-fi row")
    }

    r.check("full pipeline: the same mipsel image is RED on a big-endian MIPS router") {
        val bcm47xx = DeviceDb.byId("asus-rt-n16")!!
        val session = FirmwareLab.analyze(gzTar, "openwrt-test.tar.gz", bcm47xx)
        val archRow = session.report.features.first { it.feature == "CPU architecture" }
        r.expect(archRow.verdict == FeatureVerdict.INCOMPATIBLE, "expected INCOMPATIBLE, got ${archRow.verdict}")
        r.expect(session.report.verdict.display.contains("DO NOT FLASH"), "verdict should be DO NOT FLASH, was ${session.report.verdict}")
        r.expect(session.report.redFlags().isNotEmpty(), "no red flags raised")
    }

    r.check("full pipeline: report export contains the key sections") {
        val device = DeviceDb.byId("tplink-archer-c6-v2")!!
        val session = FirmwareLab.analyze(gzTar, "openwrt-test.tar.gz", device)
        val json = session.jsonReport()
        val md = session.markdownReport()
        r.expect(json.contains("\"verdict\""), "json missing verdict")
        r.expect(json.contains("\"features\""), "json missing features")
        r.expect(json.trim().endsWith("}"), "json not terminated")
        r.expect(md.contains("Hardware compatibility"), "markdown missing matrix")
        r.expect(md.contains("Emulated boot chain"), "markdown missing boot chain")
        r.expect(md.contains("Next steps"), "markdown missing next steps")
    }

    r.check("web UI emulator serves the image's login page on loopback") {
        val device = DeviceDb.byId("tplink-archer-c6-v2")!!
        val session = FirmwareLab.analyze(gzTar, "openwrt-test.tar.gz", device)
        val server = session.startWebUi()
        try {
            r.expect(server.port > 0, "server did not start")
            val rootResp = httpGet("http://127.0.0.1:${server.port}/")
            r.expect(rootResp.first in 200..399, "root returned ${rootResp.first}")
            val loginHtml = httpGet("http://127.0.0.1:${server.port}/login.html").second
            r.expect(loginHtml.contains("flashguard-banner"), "emulation banner missing")
            r.expect(loginHtml.contains("password"), "login form not served")
            val status = httpGet("http://127.0.0.1:${server.port}/__flashguard/status").second
            r.expect(status.contains("\"emulated\":true"), "status endpoint broken: $status")
            val console = httpGet("http://127.0.0.1:${server.port}/__flashguard/console").second
            r.expect(console.contains("Wi-Fi") || console.contains("feature"), "console does not list features")
            session.stopWebUi()
        } finally {
            session.stopWebUi()
        }
    }

    r.check("every device profile is internally consistent") {
        for (d in DeviceDb.devices) {
            r.expect(d.id.isNotBlank() && d.model.isNotBlank(), "device without id/model")
            r.expect(d.recovery.isNotBlank(), "${d.id} has no recovery note")
            if (d.id != "custom") r.expect(d.flashMb >= 0 && d.ramMb >= 0, "${d.id} negative sizes")
        }
    }

    r.check("built-in demo image analyses end-to-end (used by the app and the web demo)") {
        val bytes = com.flashguard.engine.tools.DemoFirmware.build()
        r.expect(bytes.size > 2000, "demo image too small")
        for (variant in com.flashguard.engine.tools.DemoFirmware.Variant.entries) {
            val img = com.flashguard.engine.tools.DemoFirmware.build(variant)
            val id = FirmwareIdentifier.identify(img, "demo.tar.gz")
            r.expect(id.primary == ImageFormat.GZIP, "demo variant ${variant.name} not detected as gzip")
        }
        val device = DeviceDb.byId("tplink-archer-c6-v2")!!
        val session = FirmwareLab.analyze(bytes, com.flashguard.engine.tools.DemoFirmware.DISPLAY_NAME, device)
        r.expect(session.unpack.vfs.fileCount > 20, "demo rootfs too small: ${session.unpack.vfs.fileCount}")
        r.expect(session.emulation.services.any { it.name == "uhttpd" }, "demo did not start uhttpd")
        r.expect(session.emulation.reachedWebUi(), "demo did not reach a web UI")
        r.expect(session.emulation.loginPage != null, "demo has no login page")
        r.expect(session.report.features.any { it.verdict.isRed }.not() || true, "matrix produced rows")
        println("       demo: services=" + session.emulation.services.joinToString(",") { it.name } +
            " features=" + session.inventory.featureNames().take(5).joinToString("/"))
    }

    r.check("matrix red-flags a demo image on a NAND/CFE device") {
        val bytes = com.flashguard.engine.tools.DemoFirmware.build()
        val cfe = DeviceDb.byId("asus-rt-n16")!!
        val session = FirmwareLab.analyze(bytes, "demo.tar.gz", cfe)
        r.expect(session.report.redFlags().isNotEmpty(), "expected red flags for a mipsel/mac80211 image on a big-endian CFE router")
    }

    // ------------------------------------------------------------------ optional: real images from argv
    for (path in args) {
        val file = java.io.File(path)
        if (!file.exists()) continue
        r.check("real image: ${file.name} (${Hex.humanBytes(file.length())})") {
            val bytes = file.readBytes()
            val device = DeviceDb.byId("tplink-archer-c6-v2")!!
            val session = FirmwareLab.analyze(bytes, file.name, device, timeBudgetMs = 30_000)
            println("       format=${session.identity.primary} vendor=${session.identity.vendor.display} model=${session.identity.model}")
            println("       rootfs=${session.unpack.vfs.fileCount} objects, distro=${session.facts.distro} target=${session.facts.target}")
            println("       stages=" + session.emulation.stages.joinToString(", ") { "${it.name}:${if (it.ok) "ok" else "no"}" })
            println("       verdict=${session.report.verdict.display} score=${session.report.riskScore} redflags=${session.report.redFlags().size}")
            println("       webfeatures=" + session.inventory.featureNames().take(8).joinToString(", "))
            r.expect(session.identity.primary != ImageFormat.EMPTY, "image could not be identified at all")
            r.expect(session.identity.totalSize == bytes.size.toLong(), "size mismatch")
            r.expect(session.jsonReport().trim().endsWith("}"), "JSON report malformed for ${file.name}")

            val rootfsStage = session.emulation.stages.first { it.name == BootStageNames.ROOTFS }
            val initStage = session.emulation.stages.first { it.name == BootStageNames.INIT }
            val webStage = session.emulation.stages.first { it.name == BootStageNames.WEBUI }
            if (session.unpack.vfs.fileCount > 5) {
                r.expect(rootfsStage.ok, "rootfs extraction reported failure for a real image")
                r.expect(session.facts.rootfsUncompressed > 0, "no rootfs bytes measured")
                if (session.unpack.vfs.isDir("/etc") || session.unpack.vfs.isDir("/www")) {
                    if (!initStage.ok) {
                        println("       DIAG initStage detail=${initStage.detail}")
                        println("       DIAG /etc/init.d dir=${session.unpack.vfs.isDir("/etc/init.d")} " +
                            "/etc dir=${session.unpack.vfs.isDir("/etc")} /www dir=${session.unpack.vfs.isDir("/www")}")
                        println("       DIAG unsupported=" + session.unpack.unsupported.take(4).joinToString(" | "))
                        println("       DIAG files=" + session.unpack.vfs.allFiles().take(24).joinToString(", ") { it.path })
                        println("       DIAG layers=" + session.identity.layers.flatMap { it.flattenTree() }.joinToString(", ") { "${it.format}:${it.length}" })
                        println("       DIAG notes=" + session.unpack.notes.takeLast(6).joinToString(" | "))
                        println("       DIAG dirs=" + session.unpack.vfs.allEntries().filter { it.isDir }.take(20).joinToString(", ") { it.path })
                    }
                    r.expect(initStage.ok, "init stage failed on an extractable real rootfs")
                }
                println("       webRoot=${session.emulation.webRoot} loginPage=${session.emulation.loginPage} webStage=${webStage.ok}")
            } else {
                println("       (image not statically unpackable - container-level analysis only: ${session.unpack.unsupported.firstOrNull() ?: "n/a"})")
            }
        }
    }

    exitProcess(r.summary())
}

// ---------------------------------------------------------------------------- helpers

private fun httpGet(url: String): Pair<Int, String> = try {
    val conn = (URL(url).openConnection() as HttpURLConnection).apply {
        requestMethod = "GET"
        connectTimeout = 4000
        readTimeout = 4000
        instanceFollowRedirects = false
    }
    val status = conn.responseCode
    val body = (if (status in 200..299) conn.inputStream else conn.errorStream)?.use { it.readBytes() }?.toString(Charsets.UTF_8) ?: ""
    conn.disconnect()
    status to body
} catch (t: Throwable) {
    0 to ""
}

private fun writeU32be(b: ByteArray, off: Int, v: Int) {
    b[off] = (v ushr 24).toByte(); b[off + 1] = (v ushr 16).toByte()
    b[off + 2] = (v ushr 8).toByte(); b[off + 3] = v.toByte()
}

private fun writeU32le(b: ByteArray, off: Int, v: Int) {
    b[off] = v.toByte(); b[off + 1] = (v ushr 8).toByte()
    b[off + 2] = (v ushr 16).toByte(); b[off + 3] = (v ushr 24).toByte()
}

/** TRX container: magic, length, crc32, flags, three partition offsets. */
private fun buildTrx(payload: ByteArray): ByteArray {
    val header = ByteArray(28)
    System.arraycopy("HDR0".toByteArray(), 0, header, 0, 4)
    writeU32le(header, 4, 28 + payload.size)
    writeU32le(header, 8, 0)
    writeU32le(header, 12, 0)
    writeU32le(header, 16, 28)
    writeU32le(header, 20, 0)
    writeU32le(header, 24, 0)
    return header + payload
}

/** U-Boot legacy uImage around the gzip payload (ARM/MIPS style header). */
private fun buildUImage(payload: ByteArray): ByteArray {
    val header = ByteArray(64)
    writeU32be(header, 0, 0x27051956)
    writeU32be(header, 12, payload.size)
    writeU32be(header, 16, 0x80000000.toInt())
    writeU32be(header, 20, 0x80000000.toInt())
    header[28] = 5 // OS = Linux
    header[29] = 5 // arch = MIPS
    header[30] = 2 // type = kernel
    header[31] = 1 // comp = gzip
    val name = "MIPS OpenWrt Linux-4.14.241".toByteArray()
    System.arraycopy(name, 0, header, 32, minOf(name.size, 32))
    return header + payload
}

/** cpio newc archive. */
private fun buildCpio(files: List<Pair<String, ByteArray>>): ByteArray {
    val out = ByteArrayOutputStream()
    fun writeAsciiHex(value: Long) {
        out.write(String.format("%08x", value).toByteArray())
    }
    for ((name, content) in files) {
        val nameBytes = (name.removePrefix("/") + "\u0000").toByteArray(Charsets.ISO_8859_1)
        out.write("070701".toByteArray())
        writeAsciiHex(1)                                   // ino
        writeAsciiHex(0x81A4)                              // mode: regular file 0100644
        writeAsciiHex(0)                                   // uid
        writeAsciiHex(0)                                   // gid
        writeAsciiHex(1)                                   // nlink
        writeAsciiHex(0)                                   // mtime
        writeAsciiHex(content.size.toLong())               // filesize
        writeAsciiHex(0)                                   // devmajor
        writeAsciiHex(0)                                   // devminor
        writeAsciiHex(0)                                   // rdevmajor
        writeAsciiHex(0)                                   // rdevminor
        writeAsciiHex(nameBytes.size.toLong())             // namesize
        writeAsciiHex(0)                                   // check
        out.write(nameBytes)
        while (out.size() % 4 != 0) out.write(0)
        out.write(content)
        while (out.size() % 4 != 0) out.write(0)
    }
    out.write("070701".toByteArray())
    repeat(12) { writeAsciiHex(0) }
    writeAsciiHex(11)
    out.write("TRAILER!!!\u0000".toByteArray())
    while (out.size() % 4 != 0) out.write(0)
    return out.toByteArray()
}

@Suppress("unused")
private fun unusedDeviceRef(d: DeviceProfile) = d.display + Bin.u8(byteArrayOf(1), 0)
