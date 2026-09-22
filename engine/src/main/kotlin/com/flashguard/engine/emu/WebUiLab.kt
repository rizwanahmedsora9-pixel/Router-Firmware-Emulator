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
 *    the server first challenges for the documented default credentials (HTTP Basic Auth,
 *    like a real router: the WebView shows the native username/password popup on boot),
 *    the firmware's own login form is validated against the same default, then the console
 *    lists the features the image actually ships (derived from its file layout and config),
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
            val baseName = Text.baseName(low)
            val isLogin = (baseName.startsWith("login") || low.contains("/login") || low.contains("auth") || low.contains("signin")) &&
                !baseName.startsWith("changelogin") && !baseName.contains("loginpwd")
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
     *
     * Like a real router, every page sits behind an HTTP Basic-Auth login: the first request
     * gets a 401 + `WWW-Authenticate` challenge, so the WebView (or any browser) shows the
     * familiar username/password popup. The documented factory default ([defaultCreds],
     * normally admin/admin) is what unlocks it - anything else keeps getting 401s.
     */
    class Server(
        private val vfs: VirtualFs,
        private val inventory: Inventory,
        private val facts: FirmwareFacts,
        private val defaultCreds: Pair<String, String> = "admin" to "admin",
        private val requireAuth: Boolean = true,
    ) {
        private var serverSocket: ServerSocket? = null
        private var thread: Thread? = null
        private val running = AtomicBoolean(false)
        val requestCount = AtomicInteger(0)
        val authFailures = AtomicInteger(0)
        var port: Int = 0
            private set
        val requestLog = ArrayList<String>()
        var loggedIn = false
            private set
        /** Last username that passed the login challenge (null until the first success). */
        var authUser: String? = null
            private set
        /** The `WWW-Authenticate` realm shown in the login popup - router-style, e.g. "TP-LINK Wireless Router". */
        val realm: String = authRealm()

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
                var authorization = ""
                while (true) {
                    val line = reader.readLine() ?: break
                    if (line.isEmpty()) break
                    when {
                        line.startsWith("Content-Length:", true) -> contentLength = line.substringAfter(':').trim().toIntOrNull() ?: 0
                        line.startsWith("Cookie:", true) -> cookie = line.substringAfter(':').trim()
                        line.startsWith("Host:", true) -> host = line.substringAfter(':').trim()
                        line.startsWith("Authorization:", true) -> authorization = line.substringAfter(':').trim().take(512)
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
                // Router-style login gate: no (valid) credentials -> 401 challenge -> the
                // browser/WebView shows its native username/password popup, exactly like a
                // real router does on first contact.
                val loginUser = checkAuth(authorization)
                if (requireAuth && loginUser == null) {
                    if (authorization.isNotBlank()) authFailures.incrementAndGet()
                    if (requestLog.isNotEmpty() && requestLog.size < 300) {
                        requestLog[requestLog.lastIndex] = requestLog.last() + " -> 401"
                    }
                    unauthorized(out)
                    out.flush()
                    socket.close()
                    return
                }
                if (loginUser != null) {
                    loggedIn = true
                    authUser = loginUser
                }
                when {
                    path.startsWith("/__flashguard/") -> handleInternal(path, method, query, body, out, loginUser)
                    path == "/" -> {
                        val login = inventory.loginPage
                        if (login != null) {
                            redirect(out, login)
                        } else {
                            val index = indexFile()
                            if (index != null) serveStatic(index, out)
                            else serveGenerated(out, "No index page in this image", "The image has no default page; pick a page from the feature list.", 200)
                        }
                    }
                    else -> {
                        // A real httpd serves the document root, so "/login.html" means "<docroot>/login.html".
                        val alias = aliasFor(path)
                        val entry = if (alias != null) vfs.get(alias) else vfs.get(path)
                        val serving = alias ?: path
                        if (alias != null && serving != path) {
                            if (looksStatic(serving)) {
                                serveStatic(serving, out, method, query, body); out.flush(); socket.close(); return
                            }
                            if (vfs.isFile(serving)) {
                                // Non-static object inside the doc root (CGI / script / handler):
                                // native code cannot run here, so model the response instead of
                                // leaking the raw script bytes.
                                val r = inventory.routes.firstOrNull { it.path.equals(serving, true) }
                                serveHandler(r, serving, method, query, body, out, loginUser)
                                out.flush(); socket.close(); return
                            }
                        }
                        if (entry != null && !entry.isDir && looksStatic(serving)) {
                            serveStatic(serving, out, method, query, body)
                        } else {
                            val route = inventory.routes.firstOrNull { it.path.equals(path, true) }
                            if (route != null && route.kind != Route.Kind.STATIC) {
                                serveHandler(route, path, method, query, body, out, loginUser)
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

        private fun indexFile(): String? {
            val docRoot = inventory.docRoot ?: return null
            val names = listOf("index.html", "index.htm", "index.asp", "index.php", "index.lua", "home.html")
            for (name in names) {
                val exact = Text.normPath("$docRoot/$name")
                if (vfs.isFile(exact)) return exact
                vfs.list(docRoot).firstOrNull { it.name.equals(name, ignoreCase = true) }?.let { return it.path }
            }
            return null
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

        private fun handleInternal(path: String, method: String, query: String, body: String, out: OutputStream, loginUser: String?) {
            when (path) {
                "/__flashguard/status" -> {
                    val json = buildString {
                        append("{")
                        append("\"emulated\":true,")
                        append("\"requests\":${requestCount.get()},")
                        append("\"loggedIn\":$loggedIn,")
                        append("\"authRequired\":$requireAuth,")
                        append("\"authFailures\":${authFailures.get()},")
                        append("\"realm\":\"${escapeJson(realm)}\",")
                        append("\"docRoot\":\"${escapeJson(inventory.docRoot ?: "")}\",")
                        append("\"loginPage\":\"${escapeJson(inventory.loginPage ?: "")}\",")
                        append("\"features\":[").append(inventory.featureNames().joinToString(",") { "\"${escapeJson(it)}\"" }).append("],")
                        append("\"serverBinaries\":[").append(inventory.serverBinaries.joinToString(",") { "\"${escapeJson(it)}\"" }).append("]")
                        append("}")
                    }
                    respond(out, 200, "application/json", json.toByteArray(Charsets.UTF_8))
                }
                "/__flashguard/login" -> {
                    // Reaching this endpoint already means the Basic-Auth challenge was passed.
                    loggedIn = true
                    redirect(out, "/__flashguard/console")
                }
                "/__flashguard/console" -> {
                    val html = consoleHtml(loginUser, query, body)
                    respond(out, 200, "text/html; charset=utf-8", banner(html).toByteArray(Charsets.UTF_8))
                }
                else -> respond(out, 404, "text/plain", "unknown internal endpoint".toByteArray())
            }
        }

        private fun consoleHtml(loginUser: String?, query: String, body: String): String {
            val user = loginUser
                ?: extractFormCreds(body, query).first?.ifBlank { null }
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
            sb.append("<header><h1>Emulated admin console</h1>")
            sb.append("<div>Signed in as <code>${escape(user)}</code> &middot; the firmware's own auth binary was not executed; ")
            sb.append("FlashGuard checked the documented default credentials so you can inspect what comes next.</div></header><section>")
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

        private fun serveStatic(path: String, out: OutputStream, method: String = "GET", query: String = "", body: String = "") {
            // Some firmwares POST the login form back to the login page itself: validate those
            // credentials like the real httpd would instead of silently ignoring the POST body.
            if (isLoginEndpoint(path, inventory.routes.firstOrNull { it.path.equals(path, true) })) {
                when (loginSubmissionVerdict(body, query)) {
                    true -> {
                        loggedIn = true
                        redirect(out, "/__flashguard/console")
                        return
                    }
                    false -> {
                        authFailures.incrementAndGet()
                        serveLoginFailed(out, path)
                        return
                    }
                    null -> { /* not a login submission: serve the page normally */ }
                }
            }
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

        /**
         * Modelled response for a native handler (CGI binary, Lua/ASP dispatcher ...).
         * When the request carries login-form fields for a login endpoint, the credentials
         * are actually checked against the documented default: correct -> admin console,
         * wrong -> a "login failed" page, just like the real firmware would answer.
         */
        private fun serveHandler(
            route: Route?,
            path: String,
            method: String,
            query: String,
            body: String,
            out: OutputStream,
            loginUser: String?,
        ) {
            if (isLoginEndpoint(path, route)) {
                when (loginSubmissionVerdict(body, query)) {
                    true -> {
                        loggedIn = true
                        redirect(out, "/__flashguard/console")
                        return
                    }
                    false -> {
                        authFailures.incrementAndGet()
                        serveLoginFailed(out, inventory.loginPage ?: "/")
                        return
                    }
                    null -> { /* not a login submission: fall through to the modelled page */ }
                }
            }
            val title = (route?.title ?: Text.baseName(path)) + " (modelled response)"
            val name = route?.let { Text.baseName(it.path) } ?: Text.baseName(path)
            serveGenerated(
                out,
                title,
                "This page is produced by a native binary (<code>${escape(name)}</code>) that cannot execute on Android.<br>" +
                    "FlashGuard models the response so you can still see the feature, its fields and its layout." +
                    (if (loginUser != null) "<br>Signed in as <code>${escape(loginUser)}</code>." else ""),
                200,
            )
        }

        private fun serveLoginFailed(out: OutputStream, backTo: String) {
            serveGenerated(
                out,
                "Login failed",
                "Wrong username or password (checked by the emulation, nothing was sent anywhere).<br>" +
                    "Factory default: <code>${escape(defaultCreds.first)}</code> / <code>${escape(defaultCreds.second)}</code>.<br>" +
                    "<a href=\"${escape(backTo)}\">Back to the login page</a>",
                200,
            )
        }

        // ------------------------------------------------------------ router-style login

        /** Returns the username when [authorization] carries the correct Basic credentials, else null. */
        private fun checkAuth(authorization: String): String? {
            if (authorization.isBlank()) return null
            val prefix = "Basic "
            if (!authorization.startsWith(prefix, ignoreCase = true)) return null
            val decoded = try {
                String(
                    java.util.Base64.getDecoder().decode(authorization.substring(prefix.length).trim()),
                    Charsets.ISO_8859_1,
                )
            } catch (t: Throwable) {
                return null
            }
            val user = decoded.substringBefore(':')
            val pass = if (decoded.contains(':')) decoded.substringAfter(':') else ""
            return if (user == defaultCreds.first && pass == defaultCreds.second) user else null
        }

        /** The 401 challenge that makes browsers/WebViews show the native login popup. */
        private fun unauthorized(out: OutputStream) {
            val html = banner(
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\">" +
                    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
                    "<title>401 Authorization required</title>" +
                    "<style>body{font-family:system-ui,sans-serif;background:#0B1016;color:#E8EEF5;padding:18px}" +
                    "h1{font-size:17px;color:#7BD4F0}code{background:#1B2430;padding:1px 4px;border-radius:4px}" +
                    "a{color:#7BD4F0}</style></head><body>" +
                    "<h1>401 - Authorization required</h1>" +
                    "<p>This emulated router requires a username and password, just like the real one.</p>" +
                    "<p>Factory default: <code>${escape(defaultCreds.first)}</code> / <code>${escape(defaultCreds.second)}</code></p>" +
                    "<p><a href=\"/\">Try again</a></p></body></html>"
            )
            respond(
                out, 401, "text/html; charset=utf-8", html.toByteArray(Charsets.UTF_8),
                listOf("WWW-Authenticate" to "Basic realm=\"${realm.replace("\"", "")}\""),
            )
        }

        /** Router-like realm for the login popup, derived from the image's own branding. */
        private fun authRealm(): String {
            val html = inventory.loginPage?.let { vfs.readText(it, 8192)?.lowercase() } ?: ""
            val hay = "${inventory.title ?: ""} ${facts.distro ?: ""} ${facts.target ?: ""} $html".lowercase()
            return when {
                hay.contains("tp-link") || hay.contains("tplink") -> "TP-LINK Wireless Router"
                hay.contains("netgear") -> "NETGEAR Router"
                hay.contains("d-link") || hay.contains("dlink") -> "D-Link Router"
                hay.contains("asus") -> "ASUS Wireless Router"
                hay.contains("linksys") -> "Linksys Router"
                hay.contains("xiaomi") || hay.contains("miwifi") || hay.contains("redmi") -> "Xiaomi Router"
                hay.contains("huawei") -> "HUAWEI Router"
                hay.contains("zte") -> "ZTE Router"
                hay.contains("fritz") -> "FRITZ!Box"
                hay.contains("openwrt") || hay.contains("luci") -> "OpenWrt Router"
                hay.contains("dd-wrt") || hay.contains("ddwrt") -> "DD-WRT Router"
                hay.contains("tomato") -> "Tomato Router"
                hay.contains("gargoyle") -> "Gargoyle Router"
                inventory.title?.isNotBlank() == true -> inventory.title!!.take(48)
                else -> "Router"
            }
        }

        /** True when the request carries the login form's action or looks like an auth endpoint. */
        private fun isLoginEndpoint(path: String, route: Route?): Boolean {
            if (route?.kind == Route.Kind.LOGIN) return true
            if (inventory.loginPage != null && Text.normPath(path).equals(Text.normPath(inventory.loginPage!!), true)) return true
            val low = path.lowercase()
            if (low.contains("login") || low.contains("auth") || low.contains("signin")) return true
            val action = inventory.loginAction?.lowercase()?.trim()?.trimStart('/') ?: return false
            if (action.isEmpty()) return false
            val bare = low.trimStart('/')
            return bare == action || bare.endsWith("/$action") || action.endsWith("/$bare")
        }

        private fun hasLoginFields(body: String, query: String): Boolean {
            val combined = "$body&$query".lowercase()
            return combined.contains("password") || combined.contains("passwd") ||
                combined.contains("pwd=") || combined.contains("pwd%") ||
                combined.contains("pass=") || combined.contains("pass%") ||
                combined.contains("luci_password")
        }

        /**
         * Judges a form submission to a login endpoint: true = default credentials, open the
         * console; false = recognisable credentials that do NOT match, show "login failed";
         * null = no recognisable login fields (plain page view, JSON body, settings POST ...),
         * so no verdict - serve the page normally instead of guessing.
         */
        private fun loginSubmissionVerdict(body: String, query: String): Boolean? {
            if (!hasLoginFields(body, query)) return null
            val (user, pass) = extractFormCreds(body, query)
            if (user == null && pass == null) return null
            if (user != null && user != defaultCreds.first) return false
            if (pass != null && pass != defaultCreds.second) return false
            return true
        }

        /** Pulls the most likely (username, password) pair out of a form submission. */
        private fun extractFormCreds(body: String, query: String): Pair<String?, String?> {
            val combined = "$body&$query"
            val userKeys = listOf(
                "luci_username", "username", "user_name", "login_name", "admin_name",
                "auth_user", "authuser", "loginuser", "userid", "user_id", "account",
                "login", "user", "name",
            )
            val passKeys = listOf(
                "luci_password", "login_password", "admin_password", "auth_pass",
                "password", "passwd", "pwd", "pass", "psk",
            )
            fun find(keys: List<String>): String? {
                for (k in keys) {
                    // Anchored on a parameter boundary so "pass" never matches "bypass=1".
                    val m = Regex("(?:^|[&?;])$k=([^&;]*)", RegexOption.IGNORE_CASE).find(combined) ?: continue
                    return urlDecode(m.groupValues[1])
                }
                return null
            }
            return find(userKeys) to find(passKeys)
        }

        private fun urlDecode(s: String): String = try {
            java.net.URLDecoder.decode(s.replace("+", "%20"), "UTF-8").trim().take(128)
        } catch (t: Throwable) {
            s.trim().take(128)
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

        private fun respond(
            out: OutputStream,
            status: Int,
            contentType: String,
            body: ByteArray,
            extraHeaders: List<Pair<String, String>> = emptyList(),
        ) {
            val head = buildString {
                append("HTTP/1.1 $status ${statusText(status)}\r\n")
                for ((k, v) in extraHeaders) append("$k: $v\r\n")
                append("Content-Type: $contentType\r\n")
                append("Content-Length: ${body.size}\r\n")
                append("Cache-Control: no-store\r\n")
                append("Connection: close\r\n\r\n")
            }
            out.write(head.toByteArray(Charsets.ISO_8859_1))
            out.write(body)
        }

        private fun statusText(code: Int): String = when (code) {
            200 -> "OK"; 302 -> "Found"; 401 -> "Unauthorized"; 404 -> "Not Found"; 500 -> "Internal Server Error"; else -> "OK"
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
