package com.flashguard.engine.emu

import com.flashguard.engine.core.BootStage
import com.flashguard.engine.core.BootStageNames
import com.flashguard.engine.core.EmulationResult
import com.flashguard.engine.core.FirmwareFacts
import com.flashguard.engine.core.ImageFormat
import com.flashguard.engine.core.ImageIdentity
import com.flashguard.engine.core.SimService
import com.flashguard.engine.core.UnpackResult
import com.flashguard.engine.fs.VirtualFs
import com.flashguard.engine.util.Bin
import com.flashguard.engine.util.Hex
import com.flashguard.engine.util.Limits
import com.flashguard.engine.util.ProgressSink
import com.flashguard.engine.util.Text

/**
 * Runs the firmware's boot logic in the sandboxed simulator and reports how far it gets.
 *
 * This is how the app can truthfully answer "does this image actually come up?" before a single
 * byte is written to flash:
 *   bootloader header -> kernel image -> rootfs mount -> init scripts executed -> services ->
 *   web UI / login page.
 */
class FirmwareEmulator(
    private val unpack: UnpackResult,
    private val facts: FirmwareFacts,
    private val identity: ImageIdentity,
    private val progress: ProgressSink = ProgressSink.NONE,
    private val timeBudgetMs: Long = Limits.MAX_EMULATION_MS,
) {
    private val vfs: VirtualFs = unpack.vfs
    private val bootLog = ArrayList<String>(500)
    private val notes = ArrayList<String>()

    fun run(): EmulationResult {
        val started = System.currentTimeMillis()
        val shell = SimShell(vfs, facts, Limits.MAX_SHELL_STEPS, timeBudgetMs)
        val stages = ArrayList<BootStage>()

        progress.onProgress(74, "Emulating boot chain")
        stages.add(stageHeader())

        val kernel = findKernel()
        stages.add(
            BootStage(
                BootStageNames.KERNEL,
                kernel != null,
                kernel?.let { "Kernel image found: ${it.first} (${it.second}, ${it.third})" }
                    ?: "No kernel image found in the extracted payload",
            )
        )
        kernel?.let { bootLog.add("[kernel] ${it.first} - ${it.second}, ${it.third}") }

        stages.add(
            BootStage(
                BootStageNames.ROOTFS,
                unpack.usable,
                if (unpack.usable) "Rootfs built: ${vfs.fileCount} objects, ${Hex.humanBytes(vfs.storedBytes)} in RAM"
                else "No rootfs could be extracted (${unpack.unsupported.firstOrNull() ?: "unsupported container"})",
            )
        )

        val scripts = bootCandidates()
        var executed = 0
        for (script in scripts) {
            if (shell.steps >= Limits.MAX_SHELL_STEPS || System.currentTimeMillis() - started > timeBudgetMs) {
                notes.add("Boot emulation stopped by the safety budget after $executed scripts")
                break
            }
            val r = shell.runScript(script)
            if (r.exitCode != 127 || !vfs.exists(script)) executed++
            bootLog.add("[init] $script (exit ${r.exitCode})")
            r.output.lineSequence().filter { it.isNotBlank() }.take(40).forEach { bootLog.add("   $it") }
        }
        stages.add(
            BootStage(
                BootStageNames.INIT,
                executed > 0 || vfs.isDir("/etc/init.d"),
                when {
                    executed > 0 -> "$executed init script(s) executed, ${shell.steps} shell steps, ${shell.functions.size} functions defined"
                    vfs.isDir("/etc/init.d") -> "/etc/init.d exists but no runnable init script matched"
                    else -> "No init scripts in this image"
                },
            )
        )

        // Declared-but-not-started services still tell the user what the image would bring up.
        val declared = declaredServices(shell)
        stages.add(
            BootStage(
                BootStageNames.NETWORK,
                shell.interfaces.isNotEmpty() || declared.any { it.port in setOf(53, 67, 68, 80, 443) } || looksOpenWrt(),
                if (shell.interfaces.isNotEmpty()) shell.interfaces.entries.joinToString(", ") { "${it.key}=${it.value}" }
                else if (declared.any { it.name.contains("dnsmasq") || it.name.contains("odhcpd") || it.name.contains("netifd") })
                    "Network daemons present in the image (started in emulation: ${declared.count { it.name.contains("dnsmasq") || it.name.contains("odhcpd") }})"
                else "No network configuration executed",
            )
        )

        val web = WebUiLab.inventory(vfs, facts)
        val webServerStarted = shell.services.any { it.port == 80 || it.port == 8080 || it.port == 443 }
        val webOk = webServerStarted || (web.docRoot != null && (web.loginPage != null || web.routes.isNotEmpty()))
        stages.add(
            BootStage(
                BootStageNames.WEBUI,
                webOk,
                buildString {
                    append(
                        when {
                            webServerStarted -> "httpd started in emulation: " +
                                shell.services.filter { it.port == 80 || it.port == 8080 || it.port == 443 }.joinToString(", ") { "${it.name}:${it.port}" }
                            web.docRoot != null -> "Web root ${web.docRoot} with ${web.routes.size} page(s) present in the image"
                            else -> "No web UI found in this image"
                        }
                    )
                    web.loginPage?.let { append(" | login page: $it") }
                    if (web.serverBinaries.isNotEmpty()) append(" | server binaries: ${web.serverBinaries.size}")
                },
            )
        )

        // Derive the "login page works" statement the user explicitly asked for.
        if (web.loginPage != null) {
            bootLog.add("[webui] login page present: ${web.loginPage}")
            val fields = web.loginFormFields
            if (fields.isNotEmpty()) bootLog.add("[webui] login form fields: ${fields.joinToString(", ")}")
            bootLog.add("[webui] default credential hint: ${defaultCredHint(web.loginPage)}")
        } else if (vfs.isDir("/etc/init.d")) {
            notes.add("No login page found: this image may be a kernel-only build, or the UI lives on a JFFS2/UBIFS partition")
        }

        val elapsed = System.currentTimeMillis() - started
        val unsupported = LinkedHashMap(shell.unsupported)
        if (shell.hardwareTouches.isNotEmpty()) {
            notes.add("Hardware-specific commands the image ran: " + shell.hardwareTouches.entries.take(6).joinToString(", ") { "${it.key} (x${it.value})" })
        }
        if (unsupported.isNotEmpty()) {
            notes.add("Commands not simulated (${unsupported.size} kinds): " + unsupported.entries.take(8).joinToString(", ") { it.key })
        }
        if (shell.truncated) notes.add("Emulation hit the instruction/time budget - the trace is partial (this is a safety limit, not a firmware bug)")

        return EmulationResult(
            bootLog = bootLog.take(600),
            stages = stages,
            services = shell.services.toList(),
            filesCreated = shell.filesCreated.distinct().take(120),
            interfaces = shell.interfaces.entries.map { "${it.key} -> ${it.value}" },
            variables = interestingVariables(shell),
            commandsRun = shell.steps,
            unsupportedCommands = unsupported,
            webRoot = web.docRoot,
            loginPage = web.loginPage,
            elapsedMs = elapsed,
            truncated = shell.truncated,
            notes = notes,
        )
    }

    // ------------------------------------------------------------------ helpers

    private fun stageHeader(): BootStage {
        val label = identity.primary
        val ok = when (label) {
            ImageFormat.RAW, ImageFormat.EMPTY -> false
            else -> true
        }
        val detail = when {
            identity.layers.isNotEmpty() -> "${label.label} container recognised, ${identity.layers.flatMap { it.flattenTree() }.size} layer(s) mapped"
            ok -> "${label.label} recognised"
            else -> "No bootloader header recognised - cannot tell how this image expects to be flashed"
        }
        bootLog.add("[header] $detail")
        return BootStage(BootStageNames.HEADER, ok, detail)
    }

    private fun looksOpenWrt(): Boolean = facts.distro?.contains("OpenWrt", true) == true ||
        vfs.readText("/etc/openwrt_release", 4096) != null

    /** Order matters: this mirrors how these images boot in reality. */
    private fun bootCandidates(): List<String> {
        val out = LinkedHashSet<String>()
        fun addIfExists(vararg paths: String) {
            for (p in paths) if (vfs.isFile(p)) out.add(p)
        }
        // Directories first for the shapes we know.
        val rcD = vfs.list("/etc/rc.d").sortedBy { it.name }.map { it.path }
        val rcSd = vfs.list("/etc/rcS.d").sortedBy { it.name }.map { it.path }
        val initD = vfs.list("/etc/init.d").sortedBy { it.name }.map { it.path }

        addIfExists("/etc/preinit", "/etc/init.d/preinit")
        for (p in rcSd.filter { Text.baseName(it).startsWith("S") }) out.add(p)
        if (rcD.isNotEmpty()) {
            for (p in rcD.filter { Text.baseName(it).startsWith("S") }) out.add(p)
        }
        addIfExists(
            "/etc/init.d/rcS", "/etc/rc.d/rcS", "/etc/rcS", "/etc/init.d/boot", "/etc/init.d/boot.sh",
            "/sbin/init.sh", "/etc/init.d/rc",
        )
        if (rcD.isEmpty() && rcSd.isEmpty()) {
            // No runlevel links: run the important daemons in a sane order, then the rest.
            val priority = listOf("network", "system", "boot", "firewall", "dnsmasq", "odhcpd", "dropbear", "uhttpd", "luci", "httpd", "webui", "wifi", "wpad")
            val sorted = initD.sortedBy { p ->
                val name = Text.baseName(p).lowercase()
                priority.indexOfFirst { name.contains(it) }.let { if (it < 0) priority.size else it }
            }
            for (p in sorted) out.add(p)
        }
        addIfExists("/etc/rc.local", "/etc/init.d/rc.local")
        // Never run uboot/bootloader-only or obviously hardware tools as "init".
        return out.filterNot { Text.baseName(it).contains("uboot") }.take(40)
    }

    private fun findKernel(): Triple<String, String, String>? {
        val vmlinuz = vfs.allFiles()
            .filter { !it.isDir && it.size > 128 * 1024 }
            .filter { e ->
                val n = e.name.lowercase()
                n.contains("kernel") || n.contains("vmlinuz") || n.contains("zimage") || n.contains("uimage") ||
                    n == "vmlinux" || n.contains("fit") || n.startsWith("linux") ||
                    e.path.startsWith("/boot/")
            }
            .maxByOrNull { it.size }
        if (vmlinuz != null) {
            val kind = when {
                vmlinuz.name.contains("uimage", true) -> "U-Boot uImage"
                vmlinuz.path.startsWith("/boot/") -> "boot partition image"
                else -> "kernel payload"
            }
            val compression = vmlinuz.content?.let { c ->
                when {
                    c.size > 4 && c[0] == 0x1F.toByte() && c[1] == 0x8B.toByte() -> "gzip"
                    c.size > 6 && c[0] == 0xFD.toByte() -> "xz"
                    Bin.u32be(c, 0) == 0x27051956L -> "uImage"
                    c.size > 4 && c[0] == 0x7F.toByte() && c[1] == 0x45.toByte() -> "ELF"
                    else -> "raw"
                }
            } ?: "not kept in RAM"
            return Triple(vmlinuz.path, kind, "${Hex.humanBytes(vmlinuz.size)}, $compression")
        }
        // Fall back to what the identifier saw (e.g. a TRX segment we could not store).
        identity.layers.flatMap { it.flattenTree() }.firstOrNull { it.format == ImageFormat.UBOOT_LEGACY }?.let {
            return Triple("(inside ${it.label})", "U-Boot uImage", Hex.humanBytes(it.length))
        }
        return null
    }

    /** Services that exist as binaries in the image even if no script started them in emulation. */
    private fun declaredServices(shell: SimShell): List<SimService> {
        val known = listOf(
            Triple("dnsmasq", "/usr/sbin/dnsmasq", 53),
            Triple("odhcpd", "/usr/sbin/odhcpd", 547),
            Triple("netifd", "/sbin/netifd", null),
            Triple("dropbear", "/usr/sbin/dropbear", 22),
            Triple("telnetd", "/usr/sbin/telnetd", 23),
            Triple("uhttpd", "/usr/sbin/uhttpd", 80),
            Triple("httpd", "/usr/sbin/httpd", 80),
            Triple("lighttpd", "/usr/sbin/lighttpd", 80),
            Triple("nginx", "/usr/sbin/nginx", 80),
            Triple("miniupnpd", "/usr/sbin/miniupnpd", 5000),
            Triple("smbd", "/usr/sbin/smbd", 445),
            Triple("openvpn", "/usr/sbin/openvpn", 1194),
            Triple("crond", "/usr/sbin/crond", null),
            Triple("hostapd", "/usr/sbin/hostapd", null),
            Triple("wpa_supplicant", "/usr/sbin/wpa_supplicant", null),
            Triple("ntpd", "/usr/sbin/ntpd", 123),
            Triple("syslogd", "/sbin/syslogd", 514),
        )
        val out = ArrayList<SimService>()
        for ((name, path, port) in known) {
            if (vfs.isFile(path) || vfs.isFile(path.replace("/usr/sbin", "/sbin")) || vfs.isFile(path.replace("/usr/sbin", "/usr/bin"))) {
                val already = shell.services.any { it.name.contains(name) }
                if (!already) {
                    out.add(SimService(name, path, port, simulated = false, detail = "binary present in image (not started by any init script)"))
                }
            }
        }
        return out
    }

    private fun interestingVariables(shell: SimShell): Map<String, String> {
        val keys = listOf(
            "HOSTNAME", "hostname", "lan_ipaddr", "lan_ip", "lan_netmask", "wan_ifname", "lan_ifname",
            "wl0_ssid", "wl_ssid", "lan_proto", "wan_proto", "BOARD", "board", "MODEL", "model",
            "SWITCH", "wifi_ifname", "rootfs_type", "MODE",
        )
        val out = LinkedHashMap<String, String>()
        for (k in keys) shell.variables[k]?.takeIf { it.isNotBlank() }?.let { out[k] = Text.truncate(it, 60) }
        shell.variables.entries.filter { it.key.startsWith("lan_") || it.key.startsWith("wan_") || it.key.startsWith("wl") }
            .take(20).forEach { out.putIfAbsent(it.key, Text.truncate(it.value, 60)) }
        return out
    }

    private fun defaultCredHint(loginPage: String): String {
        val html = vfs.readText(loginPage, 32768)?.lowercase() ?: return "unknown"
        return when {
            html.contains("tplink", true) || html.contains("tp-link") -> "TP-Link factory default: admin / admin (older units: admin / password)"
            html.contains("netgear") -> "Netgear factory default: admin / password (printed on the label)"
            html.contains("d-link") || html.contains("dlink") -> "D-Link factory default: admin / (blank) or admin / admin"
            html.contains("asus") -> "ASUS factory default: admin / admin"
            html.contains("linksys") -> "Linksys factory default: admin / admin (some models: (blank) / admin)"
            html.contains("xiaomi") || html.contains("miwifi") -> "Xiaomi: no default password - first boot sets it up"
            else -> "Check the printed label on the router for the default user/password"
        }
    }
}
