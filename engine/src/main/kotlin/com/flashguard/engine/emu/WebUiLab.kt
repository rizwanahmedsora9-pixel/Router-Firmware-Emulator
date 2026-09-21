package com.flashguard.engine.emu

import com.flashguard.engine.core.FirmwareFacts
import com.flashguard.engine.fs.VirtualFs
import com.flashguard.engine.util.Text
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Reconstructs the router's web UI *inside the app* and serves it on loopback so the user can see
 * the login page and the feature pages in a WebView - without touching any real device.
 *
 * Honest boundaries (also shown in the UI banner):
 *  - static files (HTML/CSS/JS/images) are served byte-for-byte from the image,
 *  - native CGI binaries cannot execute on Android, so their responses are *modelled*:
 *    a login handler accepts the documented default credentials, then the console lists the
 *    features the image actually ships (derived from its file layout and config),
 *  - nothing is ever written back to the image or to any router.
 */
object WebUiLab {

    data class Route(
        val path: String,
        val kind: Kind,
        val feature: String,
        val title: String,
    ) {
        enum class Kind { STATIC, HANDLER, API, LOGIN }
    }

    data class Inventory(
        val routes: List<Route>,
        val features: Map<String, List<Route>>,
        val docRoot: String?,
        val loginPage: String?,
        val loginFormFields: List<String>,
        val loginAction: String?,
        val serverBinaries: List<String>,
        val title: String?,
    ) {
        fun featureNames(): List<String> = features.keys.toList()
    }

    private val FEATURE_KEYWORDS = linkedMapOf(
        "Wi-Fi / Wireless" to listOf("wifi", "wireless", "wlan", "wds", "ssid", "mesh", "guest"),
        "WAN / Internet" to listOf("wan", "internet", "pppoe", "dhcp_client", "static_ip", "lte", "mobile"),
        "LAN / DHCP" to listOf("lan", "dhcp", "ip_pool", "lease", "reservation"),
        "NAT / Port forwarding" to listOf("port", "forward", "virtual_server", "dmz", "upnp", "nat", "alg"),
        "Firewall / Access control" to listOf("firewall", "acl", "mac_filter", "access_control", "url_filter", "parent", "parental", "block"),
        "QoS / Bandwidth" to listOf("qos", "bandwidth", "limit", "traffic", "scheduler"),
        "VPN" to listOf("vpn", "openvpn", "wireguard", "pptp", "l2tp", "ipsec", "gre"),
        "USB / Storage" to listOf("usb", "storage", "samba", "smb", "ftp", "dlna", "media", "printer", "share"),
        "DDNS" to listOf("ddns", "dynamic_dns", "no-ip", "dyndns", "duckdns"),
        "Routing / Static routes" to listOf("route", "routing", "rip", "ospf", "policy"),
        "IPv6" to listOf("ipv6", "dslite", "6rd", "6to4"),
        "System / Admin" to listOf("system", "admin", "password", "user", "account", "login", "logout", "reboot", "reset", "time", "ntp", "backup", "restore", "config", "upgrade", "firmware", "diagnostic", "ping", "traceroute", "log", "status", "overview", "statistics", "device_info", "sysinfo"),
        "WISP / Repeater" to listOf("repeater", "wisp", "bridge", "extender"),
        "IPTV / Multicast" to listOf("iptv", "igmp", "multicast", "vlan", "iptv_group"),
        "IoT / Smart home" to listOf("iot", "smart", "matter", "zigbee"),
        "TR-069 / Remote management" to listOf("tr069", "cwmp", "acs", "remote_mgmt", "snmp"),
        "VoIP / Telephony" to listOf("voip", "sip", "telephony", "fxo", "fxs"),
        "LED / Hardware control" to listOf("led", "button", "gpio", "switch", "port_control"),
        "Guest network" to listOf("guest", "hotspot", "captive", "portal"),
        "Load balance / Dual WAN" to listOf("load_balance", "multiwan", "failover", "dual_wan"),
    )

    fun inventory(vfs: VirtualFs, facts: FirmwareFacts): Inventory {
        val roots = vfs.findWebRoots()
        val docRoot = roots.firstOrNull()
        val routes = ArrayList<Route>()
        val handlerKeywords = ArrayList<String>()

        for (e in vfs.allFiles()) {
            val p = e.path
            val low = p.lowercase()
            val ext = Text.ext(p)
            val inWebArea = roots.any { r -> p.startsWith(if (r.endsWith("/")) r else "$r/") }
            if (!inWebArea) continue
            val isHandler = low.contains("/cgi-bin/") || low.contains("/cgi/") ||
                ext in setOf("cgi", "lua", "asp", "php", "cgi-bin") ||
                (ext == "sh" && e.executable)
            val isPage = ext in setOf("html", "htm", "asp", "php", "lua", "js", "json")
            val isLogin = low.contains("login") || low.contains("auth") || low.contains("signin")
            val kind = when {
                isLogin -> Route.Kind.LOGIN
                isHandler -> Route.Kind.HANDLER
                ext == "json" -> Route.Kind.API
                else -> Route.Kind.STATIC
            }
            if (!isPage && !isHandler) continue
            val feature = classify(p)
            handlerKeywords.add(p)
            routes.add(Route(path = p, kind = kind, feature = feature, title = humanTitle(Text.baseName(p))))
        }

        if (routes.isEmpty() && docRoot != null) {
            routes.add(Route(docRoot, Route.Kind.STATIC, "System / Admin", "Document root"))
        }

        val features = LinkedHashMap<String, MutableList<Route>>()
        for (r in routes.sortedBy { it.path }) {
            features.getOrPut(r.feature) { ArrayList() }.add(r)
        }

        val loginCandidates = routes.filter { it.kind == Route.Kind.LOGIN }.map { it.path } +
            facts.loginPages
        val loginPage = pickLoginPage(vfs, loginCandidates, docRoot)
        val loginFields = loginPage?.let { parseLoginFields(vfs.readText(it, 65536) ?: "") } ?: emptyList()
        val loginAction = loginPage?.let { parseFormAction(vfs.readText(it, 65536) ?: "") }

        val serverBins = listOf(
            "/usr/sbin/httpd", "/sbin/httpd", "/usr/bin/httpd", "/usr/sbin/uhttpd", "/sbin/uhttpd",
            "/usr/sbin/lighttpd", "/usr/sbin/nginx", "/usr/sbin/mini_httpd", "/usr/sbin/boa",
            "/usr/bin/mini_httpd", "/bin/boa", "/usr/sbin/goahead", "/bin/goahead", "/usr/bin/webs",
        ).filter { vfs.exists(it) }

        val title = docRoot?.let { root ->
            val index = listOf("index.html", "index.htm", "index.asp", "index.php", "index.lua", "home.html")
                .map { "$root/$it" }
                .firstOrNull { vfs.exists(it) }
            index?.let { vfs.readText(it, 8192)?.let { t -> Regex("<title>([^<]{1,80})</title>", RegexOption.IGNORE_CASE).find(t)?.groupValues?.get(1)?.trim() } }
        }

        return Inventory(routes, features, docRoot, loginPage, loginFields, loginAction, serverBins, title)
    }

    private fun pickLoginPage(vfs: VirtualFs, candidates: List<String>, docRoot: String?): String? {
        // Prefer a page that actually contains a password field.
        val ordered = (candidates + listOfNotNull(docRoot?.let { "$it/login.html" }, docRoot?.let { "$it/index.html" }))
            .distinct()
        for (c in ordered) {
            val text = vfs.readText(c, 65536) ?: continue
            if (text.contains("password", true) || text.contains("passwd", true) || text.contains("pwd", true)) return c
        }
        return ordered.firstOrNull { !vfs.isDir(it) }
    }

    private fun parseLoginFields(html: String): List<String> {
        val out = ArrayList<String>()
        val regex = Regex("<input[^>]*>", RegexOption.IGNORE_CASE)
        for (m in regex.findAll(html).take(20)) {
            val tag = m.value
            val type = Regex("type=[\"']?([a-zA-Z]+)", RegexOption.IGNORE_CASE).find(tag)?.groupValues?.get(1)
            val name = Regex("name=[\"']?([\\w\\[\\]-]+)", RegexOption.IGNORE_CASE).find(tag)?.groupValues?.get(1)
            if (name != null && (type == "text" || type == "password" || type == "hidden" || type == null)) {
                out.add("$name${if (type == "password") " (masked)" else ""}")
            }
        }
        return out
    }

    private fun parseFormAction(html: String): String? =
        Regex("<form[^>]*action=[\"']?([^\"' >]+)", RegexOption.IGNORE_CASE).find(html)?.groupValues?.get(1)

    private fun classify(path: String): String {
        val low = path.lowercase()
        for ((feature, keys) in FEATURE_KEYWORDS) {
            for (k in keys) if (low.contains(k)) return feature
        }
        return "Other pages in this image"
    }

    private fun humanTitle(fileName: String): String {
        val base = fileName.substringBeforeLast('.')
        return base.replace('_', ' ').replace('-', ' ')
            .split(' ')
            .filter { it.isNotBlank() }
            .joinToString(" ") { w -> w.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() } }
    }

    /**
     * The loopback HTTP server that renders the reconstructed UI.
     * Binds to 127.0.0.1 only: the phone's browser and the app can see it, nothing else.
     */
    class Server(
        private val vfs: VirtualFs,
        private val inventory: Inventory,
        private val facts: FirmwareFacts,
        private val defaultCreds: Pair<String, String> = "admin" to "admin",
    ) {
        private var serverSocket: ServerSocket? = null
        private var thread: Thread? = null
        private val running = AtomicBoolean(false)
        val requestCount = AtomicInteger(0)
        var port: Int = 0
            private set
        val requestLog = ArrayList<String>()
        var loggedIn = false
            private set

        val baseUrl: String get() = "http://127.0.0.1:$port/"

        fun start(): Boolean = try {
            val ss = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
            serverSocket = ss
            port = ss.localPort
            running.set(true)
            thread = Thread({ acceptLoop(ss) }, "flashguard-webui-emu").apply {
                isDaemon = true
                start()
            }
            true
        } catch (t: Throwable) {
            false
        }

        fun stop() {
            running.set(false)
            try {
                serverSocket?.close()
            } catch (_: Throwable) {
            }
            thread?.interrupt()
        }

        private fun acceptLoop(ss: ServerSocket) {
            while (running.get()) {
                try {
                    val socket = ss.accept()
                    handle(socket)
                } catch (t: Throwable) {
                    if (!running.get()) return
                }
            }
        }

        private fun handle(socket: Socket) {
            try {
                socket.soTimeout = 4000
                val reader = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.ISO_8859_1))
                val requestLine = reader.readLine() ?: return
                val parts = requestLine.split(' ')
                if (parts.size < 2) return
                val method = parts[0]
                val rawPath = parts[1]
                val query = rawPath.substringAfter('?', "").take(2048)
                val path = Text.normPath(rawPath.substringBefore('?').ifBlank { "/" })
                var contentLength = 0
                var cookie = ""
                var host = ""
                while (true) {
                    val line = reader.readLine() ?: break
                    if (line.isEmpty()) break
                    when {
                        line.startsWith("Content-Length:", true) -> contentLength = line.substringAfter(':').trim().toIntOrNull() ?: 0
                        line.startsWith("Cookie:", true) -> cookie = line.substringAfter(':').trim()
                        line.startsWith("Host:", true) -> host = line.substringAfter(':').trim()
                    }
                }
                var body = ""
                if (contentLength in 1..65536) {
                    val buf = CharArray(contentLength)
                    var read = 0
                    while (read < contentLength) {
                        val n = reader.read(buf, read, contentLength - read)
                        if (n < 0) break
                        read += n
                    }
                    body = String(buf, 0, read)
                }
                requestCount.incrementAndGet()
                if (requestLog.size < 300) requestLog.add("$method $path${if (query.isNotEmpty()) "?$query" else ""}")

                val out = socket.getOutputStream()
                when {
                    path.startsWith("/__flashguard/") -> handleInternal(path, method, query, body, out)
                    path == "/" -> {
                        val login = inventory.loginPage
                        if (login != null) {
                            redirect(out, login)
                        } else {
                            val index = inventory.docRoot?.let { "$it/index.html" } ?: ""
                            if (vfs.isFile(index) || vfs.isFile(inventory.docRoot + "/index.htm")) serveStatic(index, out)
                            else serveGenerated(out, "No index page in this image", "The image has no default page; pick a page from the feature list.", 200)
                        }
                    }
                    else -> {
                        // A real httpd serves the document root, so "/login.html" means "<docroot>/login.html".
                        val alias = aliasFor(path)
                        val entry = if (alias != null) vfs.get(alias) else vfs.get(path)
                        val serving = alias ?: path
                        if (alias != null && serving != path) {
                            if (!looksStatic(serving) && vfs.isFile(serving)) {
                                // still a static asset inside the doc root
                                serveStatic(serving, out); out.flush(); socket.close(); return
                            }
                            if (looksStatic(serving)) {
                                serveStatic(serving, out); out.flush(); socket.close(); return
                            }
                        }
                        if (entry != null && !entry.isDir && looksStatic(serving)) {
                            serveStatic(serving, out)
                        } else {
                            val route = inventory.routes.firstOrNull { it.path.equals(path, true) }
                            if (route != null && route.kind != Route.Kind.STATIC) {
                                // Native handler: since binaries cannot run here, respond with the modelled page.
                                serveGenerated(
                                    out,
                                    "${route.title} (modelled response)",
                                    "This page is produced by a native binary (${Text.baseName(route.path)}) that cannot execute on Android.<br>" +
                                        "FlashGuard models the response so you can still see the feature, its fields and its layout.",
                                    200,
                                )
                            } else if (entry == null) {
                                serveGenerated(out, "404 - not in this image", "Path <code>${escape(path)}</code> does not exist in the extracted rootfs.", 404)
                            } else {
                                serveGenerated(out, "Directory", "Files: " + escape(vfs.childNames(path).take(40).joinToString(", ")), 200)
                            }
                        }
                    }
                }
                out.flush()
                socket.close()
            } catch (t: Throwable) {
                try {
                    socket.close()
                } catch (_: Throwable) {
                }
            }
        }

        /** Maps "/x" to "<docroot>/x" when the image stores its UI under a web root. */
        private fun aliasFor(path: String): String? {
            val docRoot = inventory.docRoot ?: return null
            if (path.startsWith(docRoot)) return path
            val candidate = Text.normPath("$docRoot/$path")
            return if (vfs.exists(candidate)) candidate else null
        }

        private fun looksStatic(path: String): Boolean {
            val ext = Text.ext(path)
            return ext in setOf("html", "htm", "js", "css", "png", "gif", "jpg", "jpeg", "svg", "ico", "txt", "json", "woff", "woff2", "xml")
        }

        private fun handleInternal(path: String, method: String, query: String, body: String, out: OutputStream) {
            when (path) {
                "/__flashguard/status" -> {
                    val json = buildString {
                        append("{")
                        append("\"emulated\":true,")
                        append("\"requests\":${requestCount.get()},")
                        append("\"loggedIn\":$loggedIn,")
                        append("\"docRoot\":\"${escapeJson(inventory.docRoot ?: "")}\",")
                        append("\"loginPage\":\"${escapeJson(inventory.loginPage ?: "")}\",")
                        append("\"features\":[").append(inventory.featureNames().joinToString(",") { "\"${escapeJson(it)}\"" }).append("],")
                        append("\"serverBinaries\":[").append(inventory.serverBinaries.joinToString(",") { "\"${escapeJson(it)}\"" }).append("]")
                        append("}")
                    }
                    respond(out, 200, "application/json", json.toByteArray(Charsets.UTF_8))
                }
                "/__flashguard/login" -> {
                    loggedIn = true
                    redirect(out, "/__flashguard/console")
                }
                "/__flashguard/console" -> {
                    val html = consoleHtml(query, body)
                    respond(out, 200, "text/html; charset=utf-8", banner(html).toByteArray(Charsets.UTF_8))
                }
                else -> respond(out, 404, "text/plain", "unknown internal endpoint".toByteArray())
            }
        }

        private fun consoleHtml(query: String, body: String): String {
            val user = Regex("username=([^&]*)").find(body)?.groupValues?.get(1)
                ?: Regex("user=([^&]*)").find(body)?.groupValues?.get(1)
                ?: Regex("username=([^&]*)").find(query)?.groupValues?.get(1)
                ?: defaultCreds.first
            val sb = StringBuilder()
            sb.append("<!DOCTYPE html><html><head><meta charset=\"utf-8\">")
            sb.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
            sb.append("<title>Emulated admin console</title>")
            sb.append("<style>body{font-family:system-ui,sans-serif;margin:0;background:#0B1016;color:#E8EEF5}")
            sb.append("header{padding:16px;background:#141B24;border-bottom:1px solid #22303F}")
            sb.append("h1{font-size:18px;margin:0 0 4px 0}h2{font-size:15px;color:#7BD4F0;margin:18px 0 6px}")
            sb.append("section{padding:12px 16px}ul{margin:6px 0 0 18px;padding:0}li{margin:3px 0;font-size:13px}")
            sb.append(".tag{display:inline-block;background:#22303F;border-radius:10px;padding:2px 8px;font-size:11px;margin-right:6px}")
            sb.append("code{background:#1B2430;padding:1px 4px;border-radius:4px;font-size:12px}")
            sb.append("a{color:#7BD4F0}</style></head><body>")
            sb.append("<header><h1>Login accepted (simulated)</h1>")
            sb.append("<div>Signed in as <code>${escape(user)}</code> &middot; the firmware's own auth binary was not executed; ")
            sb.append("FlashGuard replayed the login so you can inspect what comes next.</div></header><section>")
            sb.append("<p>Below is everything this image ships in its web UI, grouped by feature. ")
            sb.append("Pages served from the image are marked <span class=\"tag\">from image</span>; ")
            sb.append("pages produced by native binaries are marked <span class=\"tag\">modelled</span>.</p>")
            for ((feature, routes) in inventory.features) {
                sb.append("<h2>${escape(feature)} <span class=\"tag\">${routes.size}</span></h2><ul>")
                for (r in routes.take(30)) {
                    val tag = if (r.kind == Route.Kind.HANDLER || r.kind == Route.Kind.LOGIN) "modelled" else "from image"
                    sb.append("<li><a href=\"${escape(r.path)}\">${escape(r.title)}</a> <code>${escape(r.path)}</code> <span class=\"tag\">$tag</span></li>")
                }
                sb.append("</ul>")
            }
            if (inventory.features.isEmpty()) sb.append("<p>No web pages were found in this image.</p>")
            sb.append("<h2>Server binaries in this image</h2><ul>")
            for (b in inventory.serverBinaries) sb.append("<li><code>${escape(b)}</code></li>")
            if (inventory.serverBinaries.isEmpty()) sb.append("<li>none found</li>")
            sb.append("</ul>")
            sb.append("<h2>Firmware identity</h2><ul>")
            sb.append("<li>Distribution: <b>${escape(facts.distro ?: "unknown")} ${escape(facts.firmwareVersion ?: "")}</b></li>")
            sb.append("<li>Target: <code>${escape(facts.target ?: "unknown")}</code> Arch: <code>${escape(facts.arch ?: "unknown")}</code></li>")
            sb.append("<li>Packages: ${facts.packages.size} &middot; kernel modules: ${facts.kernelModules.size}</li>")
            sb.append("</ul>")
            sb.append("<p><a href=\"/__flashguard/status\">status.json</a></p>")
            sb.append("</section></body></html>")
            return sb.toString()
        }

        private fun serveStatic(path: String, out: OutputStream) {
            val bytes = vfs.read(path) ?: run {
                respond(out, 404, "text/plain", "not found".toByteArray())
                return
            }
            val mime = mimeOf(path)
            if (mime.startsWith("text/html")) {
                val html = banner(String(bytes, Charsets.UTF_8))
                respond(out, 200, "$mime; charset=utf-8", html.toByteArray(Charsets.UTF_8))
            } else {
                respond(out, 200, mime, bytes)
            }
        }

        private fun serveGenerated(out: OutputStream, title: String, bodyHtml: String, status: Int) {
            val html = banner(
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\">" +
                    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
                    "<title>${escape(title)}</title>" +
                    "<style>body{font-family:system-ui,sans-serif;background:#0B1016;color:#E8EEF5;padding:18px}" +
                    "h1{font-size:17px;color:#7BD4F0}code{background:#1B2430;padding:1px 4px;border-radius:4px}" +
                    "a{color:#7BD4F0}</style></head><body><h1>${escape(title)}</h1><p>$bodyHtml</p>" +
                    "<p><a href=\"/__flashguard/console\">Open the emulated feature console</a> &middot; " +
                    "<a href=\"/__flashguard/status\">status.json</a></p></body></html>"
            )
            respond(out, status, "text/html; charset=utf-8", html.toByteArray(Charsets.UTF_8))
        }

        /** Injects the "this is an emulation" banner into every HTML page. */
        private fun banner(html: String): String {
            val bannerHtml = """
                <div id="flashguard-banner" style="position:fixed;left:0;right:0;bottom:0;z-index:2147483647;
                    background:#1493B8;color:#04121A;font:12px/1.5 system-ui,sans-serif;padding:6px 10px;text-align:center">
                  FlashGuard EMULATION &middot; nothing here was written to a router &middot;
                  <a href="/__flashguard/console" style="color:#04121A;text-decoration:underline">feature console</a> &middot;
                  <a href="/__flashguard/status" style="color:#04121A;text-decoration:underline">status</a>
                </div>
            """.trimIndent()
            return when {
                html.contains("</body>", true) -> html.replaceFirst(Regex("</body>", RegexOption.IGNORE_CASE), "$bannerHtml</body>")
                else -> html + bannerHtml
            }
        }

        private fun redirect(out: OutputStream, location: String) {
            val body = "<html><body>Redirecting to <a href=\"${escape(location)}\">${escape(location)}</a></body></html>"
            val head = "HTTP/1.1 302 Found\r\nLocation: $location\r\nContent-Type: text/html\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n"
            out.write((head + body).toByteArray(Charsets.ISO_8859_1))
        }

        private fun respond(out: OutputStream, status: Int, contentType: String, body: ByteArray) {
            val head = "HTTP/1.1 $status ${statusText(status)}\r\n" +
                "Content-Type: $contentType\r\n" +
                "Content-Length: ${body.size}\r\n" +
                "Cache-Control: no-store\r\n" +
                "Connection: close\r\n\r\n"
            out.write(head.toByteArray(Charsets.ISO_8859_1))
            out.write(body)
        }

        private fun statusText(code: Int): String = when (code) {
            200 -> "OK"; 302 -> "Found"; 404 -> "Not Found"; 500 -> "Internal Server Error"; else -> "OK"
        }

        private fun mimeOf(path: String): String = when (Text.ext(path)) {
            "html", "htm" -> "text/html"
            "css" -> "text/css"
            "js" -> "application/javascript"
            "json" -> "application/json"
            "png" -> "image/png"
            "gif" -> "image/gif"
            "jpg", "jpeg" -> "image/jpeg"
            "svg" -> "image/svg+xml"
            "ico" -> "image/x-icon"
            "xml" -> "application/xml"
            "txt" -> "text/plain"
            else -> "application/octet-stream"
        }
    }

    private fun escape(s: String): String = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    private fun escapeJson(s: String): String = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ")
}
