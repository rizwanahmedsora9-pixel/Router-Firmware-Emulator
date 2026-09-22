package com.flashguard.engine.analysis

import com.flashguard.engine.core.Finding
import com.flashguard.engine.core.FindingLevel
import com.flashguard.engine.core.FirmwareFacts
import com.flashguard.engine.core.ImageFormat
import com.flashguard.engine.core.ImageIdentity
import com.flashguard.engine.core.UnpackResult
import com.flashguard.engine.fs.VirtualFs
import com.flashguard.engine.util.Bin
import com.flashguard.engine.util.Limits
import com.flashguard.engine.util.Text

/**
 * Static security and quality findings. These do not decide whether the image boots, but they are
 * frequently the reason a "custom firmware" turns a router into somebody's botnet node.
 */
object Heuristics {

    fun findings(identity: ImageIdentity, facts: FirmwareFacts, unpack: UnpackResult): List<Finding> {
        val out = ArrayList<Finding>()
        val vfs = unpack.vfs

        // ---------------------------------------------------------------- structural
        if (identity.primary == ImageFormat.EMPTY) {
            out.add(Finding("empty", "Empty file", "The selected file has no content.", FindingLevel.ERROR, category = "structure"))
        }
        if (identity.primary == ImageFormat.RAW && unpack.importedFiles == 0) {
            out.add(
                Finding(
                    "raw-image", "Unrecognised raw image",
                    "No known container or filesystem was found. This is usually a whole-flash dump or an encrypted vendor image.",
                    FindingLevel.WARN, category = "structure",
                )
            )
        }
        if (unpack.unsupported.isNotEmpty()) {
            out.add(
                Finding(
                    "partial-extraction", "Only partially inspectable on-device",
                    unpack.unsupported.joinToString(" | ").take(300),
                    FindingLevel.WARN, category = "structure",
                )
            )
        }
        if (identity.evidence.any { it.contains("encrypted", true) }) {
            out.add(
                Finding(
                    "encrypted", "Payload looks encrypted or signed",
                    "Entropy and structure suggest the vendor wrapped the firmware. Nothing inside could be verified.",
                    FindingLevel.WARN, category = "structure",
                )
            )
        }
        if (identity.layers.flatMap { it.flattenTree() }.any { it.format == ImageFormat.UBI }) {
            out.add(
                Finding(
                    "ubi", "NAND/UBI image",
                    "The rootfs lives inside UBIFS, which cannot be mounted statically on a phone. Only the container could be described.",
                    FindingLevel.WARN, category = "structure",
                )
            )
        }

        // ---------------------------------------------------------------- rootfs security
        if (unpack.usable) {
            // root account without a password?
            vfs.readText("/etc/passwd", 65536)?.let { passwd ->
                val lines = passwd.lineSequence().filter { it.isNotBlank() && !it.startsWith("#") }.toList()
                val rootLine = lines.firstOrNull { it.startsWith("root:") }
                if (rootLine != null) {
                    val hash = rootLine.split(':').getOrNull(1) ?: ""
                    if (hash.isBlank()) {
                        out.add(
                            Finding(
                                "root-nopass", "root has no password",
                                "/etc/passwd gives root an empty password field (${rootLine.take(40)}...).",
                                FindingLevel.ERROR, evidence = "/etc/passwd", category = "security",
                            )
                        )
                    }
                }
                lines.firstOrNull { it.startsWith("support:") }?.let {
                    out.add(
                        Finding(
                            "vendor-support-user", "Vendor 'support' account present",
                            "/etc/passwd contains a vendor support account: ${Text.truncate(it, 80)}",
                            FindingLevel.WARN, evidence = "/etc/passwd", category = "security",
                        )
                    )
                }
            }
            vfs.readText("/etc/shadow", 65536)?.let { shadow ->
                val emptyHashes = shadow.lineSequence().count { line ->
                    val h = line.split(':').getOrNull(1)?.trim() ?: return@count false
                    h.isBlank()
                }
                if (emptyHashes > 0) {
                    out.add(
                        Finding(
                            "empty-shadow", "$emptyHashes account(s) with an empty password hash",
                            "Anybody on the LAN could log in to those accounts without a password.",
                            FindingLevel.ERROR, evidence = "/etc/shadow", category = "security",
                        )
                    )
                }
            }

            // telnet / debug services enabled by default
            if (vfs.isFile("/usr/sbin/telnetd") || vfs.isFile("/sbin/telnetd") || vfs.isFile("/bin/telnetd")) {
                out.add(
                    Finding(
                        "telnetd", "telnet daemon shipped in the image",
                        "telnet sends credentials in cleartext. If an init script starts it, anyone sniffing the LAN sees the password.",
                        FindingLevel.WARN, evidence = "/usr/sbin/telnetd", category = "security",
                    )
                )
            }
            if (facts.packages.any { it.contains("wpad") || it.contains("hostapd") }) {
                out.add(
                    Finding(
                        "wps", "WPS-capable supplicant present",
                        "WPS is convenient but has known PIN attacks; verify it is off in the web UI.",
                        FindingLevel.INFO, category = "security",
                    )
                )
            }
            if (facts.users.any { it == "admin" } || facts.users.any { it == "guest" }) {
                out.add(
                    Finding(
                        "default-users", "Default service accounts found",
                        "Accounts in /etc/passwd: ${facts.users.take(8).joinToString(", ")}",
                        FindingLevel.INFO, evidence = "/etc/passwd", category = "security",
                    )
                )
            }

            // hardcoded credentials / keys
            val webRoots = vfs.findWebRoots()
            var hardcoded = 0
            var examples = ArrayList<String>()
            for (e in vfs.allFiles().take(Limits.MAX_FILES)) {
                val content = e.content ?: continue
                if (content.size > 512 * 1024) continue
                for (needle in HARDCODE_MARKERS) {
                    if (Bin.indexOfAscii(content, needle) >= 0) {
                        hardcoded++
                        if (examples.size < 4) examples.add("${needle.trim()} in ${e.path}")
                        break
                    }
                }
            }
            if (hardcoded > 0) {
                out.add(
                    Finding(
                        "hardcoded", "$hardcoded file(s) contain hardcoded credentials or keys",
                        examples.joinToString(" | "),
                        FindingLevel.WARN, category = "security",
                    )
                )
            }

            // world-writable web content
            val worldWritable = vfs.allFiles().count { (it.mode and 0b000000010) != 0 && webRoots.any { r -> it.path.startsWith(r) } }
            if (worldWritable > 0) {
                out.add(
                    Finding(
                        "web-world-writable", "$worldWritable web file(s) are world-writable",
                        "World-writable files in the document root can be replaced by any service on the box.",
                        FindingLevel.INFO, category = "security",
                    )
                )
            }

            // old kernel / busybox
            val banner = listOfNotNull(
                facts.configFiles["/etc/banner"], facts.configFiles["/etc/motd"], facts.configFiles["/etc/version"],
            ).joinToString(" ")
            val kernelVersion = Regex("Linux\\s+([0-9]+\\.[0-9]+)").find(identity.evidence.joinToString(" "))?.groupValues?.get(1)
                ?: Regex("([0-9]+\\.[0-9]+)\\.[0-9]+").find(banner)?.groupValues?.get(1)
            if (kernelVersion != null) {
                val major = kernelVersion.substringBefore('.').toIntOrNull() ?: 0
                val minor = kernelVersion.substringAfter('.').toIntOrNull() ?: 0
                if (major < 4 || (major == 4 && minor < 4)) {
                    out.add(
                        Finding(
                            "old-kernel", "Old kernel branch ($kernelVersion)",
                            "Kernels older than 4.4 no longer receive security fixes - common in abandoned vendor builds.",
                            FindingLevel.WARN, category = "security",
                        )
                    )
                }
            }

            // login page over plain HTTP
            val login = facts.loginPages.firstOrNull()
            if (login != null) {
                val html = vfs.readText(login, 65536) ?: ""
                if (!html.contains("csrf", true) && html.contains("<form", true)) {
                    out.add(
                        Finding(
                            "no-csrf", "Login form has no CSRF token",
                            "The login form in ${Text.baseName(login)} posts without a token, which enables cross-site request forgery from a malicious page on the LAN.",
                            FindingLevel.INFO, evidence = login, category = "security",
                        )
                    )
                }
                if (!html.contains("https", true)) {
                    out.add(
                        Finding(
                            "http-login", "Admin UI is plain HTTP",
                            "Credentials travel unencrypted on the LAN (this is normal for stock router UIs, but worth knowing).",
                            FindingLevel.INFO, evidence = login, category = "security",
                        )
                    )
                }
            }

            // plaintext wifi keys in config
            val wirelessCfg = vfs.readText("/etc/config/wireless", 65536) ?: facts.configFiles["/etc/config/wireless"]
            if (wirelessCfg != null && Regex("key\\s+'[^']+'").containsMatchIn(wirelessCfg)) {
                out.add(
                    Finding(
                        "plaintext-wifi", "Wi-Fi key stored in plaintext in the config",
                        "/etc/config/wireless contains a key= value (ucode stores it unencrypted).",
                        FindingLevel.INFO, evidence = "/etc/config/wireless", category = "security",
                    )
                )
            }

            // TR-069 remote management = vendor back channel
            if (facts.packages.any { it.contains("tr069") || it.contains("cwmp") } || vfs.findByContains("tr069").isNotEmpty()) {
                out.add(
                    Finding(
                        "tr069", "TR-069 / CWMP remote management present",
                        "The ISP (or anyone who compromises the ACS URL) can reconfigure this router remotely.",
                        FindingLevel.WARN, category = "security",
                    )
                )
            }
            if (worldWritable == 0 && hardcoded == 0) {
                out.add(
                    Finding(
                        "clean-scan", "No obvious hardcoded credentials found",
                        "The quick scan of ${vfs.fileCount} objects did not find embedded keys or default password strings.",
                        FindingLevel.OK, category = "security",
                    )
                )
            }
        }

        // ---------------------------------------------------------------- quality-of-life facts
        if (facts.distro != null) {
            out.add(
                Finding(
                    "distro", "Distribution: ${facts.distro} ${facts.firmwareVersion ?: ""}".trim(),
                    "Target ${facts.target ?: "n/a"} / arch ${facts.arch ?: "n/a"}",
                    FindingLevel.OK, category = "identity",
                )
            )
        }
        if (facts.packages.isNotEmpty()) {
            val luci = facts.packages.any { it.startsWith("luci") }
            out.add(
                Finding(
                    "packages", "${facts.packages.size} packages, LuCI web UI: ${if (luci) "yes" else "no"}",
                    facts.packages.take(12).joinToString(", "),
                    if (luci) FindingLevel.OK else FindingLevel.INFO, category = "identity",
                )
            )
        }
        if (vfs.fileCount > 0 && unpack.importedFiles > 0) {
            out.add(
                Finding(
                    "rootfs", "Rootfs: ${vfs.humanSummary()}",
                    "Extracted ${unpack.importedFiles} objects; biggest areas: " + biggestAreas(vfs).joinToString(", "),
                    FindingLevel.INFO, category = "structure",
                )
            )
        }
        return out
    }

    private val HARDCODE_MARKERS = listOf(
        "BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN PRIVATE KEY",
        "password=admin", "passwd=admin", "admin:admin", "root:root",
        "default_password", "backdoor", "telnetd -l /bin/sh",
    )

    private fun biggestAreas(vfs: VirtualFs): List<String> {
        val buckets = HashMap<String, Long>()
        for (e in vfs.allFiles()) {
            val top = e.path.split('/').filter { it.isNotBlank() }.take(2).joinToString("/")
            buckets[top] = (buckets[top] ?: 0) + e.size
        }
        return buckets.entries.sortedByDescending { it.value }.take(4)
            .map { "/${it.key} (${com.flashguard.engine.util.Hex.humanBytes(it.value)})" }
    }
}
