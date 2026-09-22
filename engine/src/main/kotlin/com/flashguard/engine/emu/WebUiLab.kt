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
        val loginModelled: Boolean = false,
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
                !baseName.startsWith("changelogin") && !baseName.contains("loginpwd") &&
                !isLoginErrorName(baseName)
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
        // Some images (e.g. TP-Link VxWorks builds) ship no static login form at all: the original
        // httpd generates it. For those, FlashGuard serves a modelled login form instead, and the
        // image's own "login incorrect" page is reused for wrong credentials.
        val loginFields = loginPage?.let { parseLoginFields(vfs.readText(it, 65536) ?: "") }
            ?: listOf("username", "password (masked)")
        val loginAction = loginPage?.let { parseFormAction(vfs.readText(it, 65536) ?: "") }
            ?: MODELLED_LOGIN_PATH

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

        return Inventory(
            routes, features, docRoot, loginPage, loginFields, loginAction, serverBins, title,
            loginModelled = loginPage == null,
        )
    }

    /** Path of the login form FlashGuard generates when the image has no static one. */
    const val MODELLED_LOGIN_PATH = "/__flashguard/login"

    /** Name fragments that identify error/logout pages, which must never be picked as login pages. */
    private val LOGIN_ERROR_NAME_HINTS = listOf(
        "autherror", "auth_error", "errorpage", "error", "fail", "denied", "expired", "expire", "logout", "401",
    )

    private fun isLoginErrorName(baseName: String): Boolean {
        val n = baseName.lowercase()
        return LOGIN_ERROR_NAME_HINTS.any { n.contains(it) }
    }

    private fun pickLoginPage(vfs: VirtualFs, candidates: List<String>, docRoot: String?): String? {
        // Only a page that actually renders a login form qualifies: it must contain a password
        // input (or a form plus password wording). Pages that merely mention "password" - like the
        // classic TP-Link "AuthError.htm" troubleshooting page - are NOT login pages; serving those
        // made the emulator open on "Username or Password is incorrect" instead of a login form.
        val ordered = (
            candidates + listOfNotNull(
                docRoot?.let { "$it/login.html" }, docRoot?.let { "$it/login.htm" },
                docRoot?.let { "$it/index.html" },
            )
            ).distinct()
        for (c in ordered) {
            val text = vfs.readText(c, 65536) ?: continue
            if (isLoginErrorName(Text.baseName(c))) continue
            if (looksLikeLoginForm(text)) return c
        }
        return null
    }

    private fun looksLikeLoginForm(html: String): Boolean {
        val mentionsPassword = html.contains("password", true) ||
            html.contains("passwd", true) || html.contains("pwd", true)
        if (!mentionsPassword) return false
        val passwordInput = Regex("<input[^>]*type\\s*=\\s*[\"']?password", RegexOption.IGNORE_CASE)
            .containsMatchIn(html)
        val anyForm = html.contains("<form", true)
        return passwordInput || anyForm
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

        /**
         * Optional sink for app-level logging of server lifecycle and login attempts
         * (never the password itself). Called from server threads; the sink must be thread-safe.
         */
        var eventSink: ((String) -> Unit)? = null

        private fun emit(message: String) {
            try {
                eventSink?.invoke(message)
            } catch (_: Throwable) {
            }
        }

        /** Thread-safe copy of the served-request log for the diagnostics report. */
        @Synchronized
        fun requestLogSnapshot(): List<String> = ArrayList(requestLog)

        /**
         * The URL path a browser must open first: the image's own login page if it has one,
         * otherwise the modelled login form FlashGuard generates for it.
         */
        val loginUrl: String
            get() = inventory.loginPage?.let { page ->
                val docRoot = inventory.docRoot
                if (docRoot != null && page.startsWith(if (docRoot.endsWith("/")) docRoot else "$docRoot/")) {
                    "/" + page.removePrefix(if (docRoot.endsWith("/")) docRoot else "$docRoot/")
                } else {
                    "/" + page.removePrefix("/")
                }
            } ?: MODELLED_LOGIN_PATH

        fun start(): Boolean = try {
            val ss = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
            serverSocket = ss
            port = ss.localPort
            running.set(true)
            thread = Thread({ acceptLoop(ss) }, "flashguard-webui-emu").apply {
                isDaemon = true
                start()
            }
            emit("web server started on 127.0.0.1:$port")
            true
        } catch (t: Throwable) {
            emit("web server failed to start: ${t.message ?: t.javaClass.simpleName}")
            false
        }

        fun stop() {
            running.set(false)
            try {
                serverSocket?.close()
            } catch (_: Throwable) {
            }
            thread?.interrupt()
            emit("web server stopped after $requestCount request(s)")
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
                    else -> {
                        // A real httpd serves the document root, so "/login.html" means "<docroot>/login.html".
                        val alias = aliasFor(path)
                        val serving = alias ?: path
                        val isLoginEntry = serving.equals(inventory.loginPage, true) ||
                            path.equals(inventory.loginPage, true)

                        // Like the real device, the admin UI sits behind the login: everything that
                        // is not the login page itself redirects there until credentials check out.
                        if (!loggedIn) {
                            if (method == "POST") {
                                // Before authentication every POST is treated as a login attempt,
                                // exactly as the router sees its login form submit.
                                tryLogin(body, query, out); out.flush(); socket.close(); return
                            }
                            if (!isLoginEntry) {
                                redirect(out, loginUrl); out.flush(); socket.close(); return
                            }
                        } else if (isLoginEntry && method == "GET") {
                            // Already authenticated: the device drops you on the main page.
                            redirect(out, "/"); out.flush(); socket.close(); return
                        }

                        if (path == "/") {
                            val index = indexFile()
                            if (index != null) serveStatic(index, out)
                            else serveGenerated(out, "No index page in this image", "The image has no default page; pick a page from the feature list.", 200)
                        } else {
                            val entry = if (alias != null) vfs.get(alias) else vfs.get(path)
                            if (entry != null && !entry.isDir && looksStatic(serving)) {
                                serveStatic(serving, out)
                            } else {
                                val route = inventory.routes.firstOrNull { it.path.equals(serving, true) || it.path.equals(path, true) }
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

        /**
         * Maps "/x" to "<docroot>/x" when the image stores its UI under a web root. Images that
         * flatten their web store into one directory (TP-Link VxWorks does this) still reference
         * "/userRpm/MenuRpm.htm" or "/images/top.jpg" from their pages, so as a last resort the
         * file is looked up by its base name.
         */
        private fun aliasFor(path: String): String? {
            val docRoot = inventory.docRoot ?: return null
            if (path.startsWith(docRoot)) return path
            val candidate = Text.normPath("$docRoot/$path")
            if (vfs.exists(candidate)) return candidate
            val base = Text.baseName(path)
            if (base.isEmpty() || base == "/") return null
            val underDocRoot = vfs.findByName(base).filter { it.path.startsWith(if (docRoot.endsWith("/")) docRoot else "$docRoot/") }
            return when {
                underDocRoot.isNotEmpty() -> underDocRoot.minByOrNull { it.path.count { c -> c == '/' } }?.path
                else -> vfs.findByName(base).firstOrNull()?.path
            }
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
                        append("\"loginModelled\":${inventory.loginModelled},")
                        append("\"loginUrl\":\"${escapeJson(loginUrl)}\",")
                        append("\"features\":[").append(inventory.featureNames().joinToString(",") { "\"${escapeJson(it)}\"" }).append("],")
                        append("\"serverBinaries\":[").append(inventory.serverBinaries.joinToString(",") { "\"${escapeJson(it)}\"" }).append("]")
                        append("}")
                    }
                    respond(out, 200, "application/json", json.toByteArray(Charsets.UTF_8))
                }
                MODELLED_LOGIN_PATH -> when {
                    method == "POST" || query.contains("username=") || query.contains("password=") -> tryLogin(body, query, out)
                    loggedIn -> redirect(out, "/")
                    else -> respond(out, 200, "text/html; charset=utf-8", modelledLoginHtml().toByteArray(Charsets.UTF_8))
                }
                "/__flashguard/logout" -> {
                    loggedIn = false
                    emit("logout requested")
                    redirect(out, loginUrl)
                }
                "/__flashguard/console" -> {
                    val html = consoleHtml(query, body)
                    respond(out, 200, "text/html; charset=utf-8", banner(html).toByteArray(Charsets.UTF_8))
                }
                else -> respond(out, 404, "text/plain", "unknown internal endpoint".toByteArray())
            }
        }

        /**
         * Validates submitted credentials against the documented factory defaults and plays the
         * same flow the real device does: success lands on the main page, failure shows the
         * image's own "login incorrect" page when it ships one.
         */
        private fun tryLogin(body: String, query: String, out: OutputStream) {
            val fields = parseFormPairs(body) + parseFormPairs(query)
            var user: String? = null
            var pass: String? = null
            for ((k, v) in fields) {
                val key = k.lowercase()
                // Vendor forms name their fields differently ("username", "luci_username", "loginPassword"...) -
                // match on the meaningful fragment instead of an exact list.
                if (user == null && key.contains("user") && !key.contains("pass")) user = v
                else if (pass == null && (key.contains("pass") || key.contains("pwd"))) pass = v
            }
            val ok = user == defaultCreds.first && pass == defaultCreds.second
            emit("login attempt user='${user ?: ""}' -> ${if (ok) "accepted" else "REJECTED (wrong username or password)"}")
            if (ok) {
                loggedIn = true
                redirect(out, "/")
            } else {
                serveAuthError(out)
            }
        }

        /** The image's own "login incorrect" page if it ships one, otherwise a generated one. */
        private fun serveAuthError(out: OutputStream) {
            val page = vfs.findByName("AuthError.htm").firstOrNull()?.path
                ?: vfs.allFiles().firstOrNull { isLoginErrorName(Text.baseName(it.path)) && Text.baseName(it.path).lowercase().contains("auth") && looksStatic(it.path) }?.path
            if (page != null) {
                val raw = vfs.readText(page, 131072) ?: ""
                val withBackLink = when {
                    raw.contains("</body>", true) -> raw.replaceFirst(
                        Regex("</body>", RegexOption.IGNORE_CASE),
                        "<p style=\"text-align:center;margin-top:2em\"><a href=\"$loginUrl\">&larr; Return to the login page</a></p></body>",
                    )
                    else -> raw + "<p><a href=\"$loginUrl\">&larr; Return to the login page</a></p>"
                }
                respond(out, 200, "text/html; charset=utf-8", banner(withBackLink).toByteArray(Charsets.UTF_8))
            } else {
                serveGenerated(
                    out,
                    "Login incorrect",
                    "The username or password is not correct. The documented factory default for this image is " +
                        "<code>${escape(defaultCreds.first)} / ${escape(defaultCreds.second)}</code>.<br>" +
                        "<a href=\"$loginUrl\">Return to the login page</a>.",
                    200,
                )
            }
        }

        /**
         * A login form generated by FlashGuard for images that ship their web UI without a static
         * login page (the original httpd produces one on the fly, which cannot run on Android).
         */
        private fun modelledLoginHtml(): String {
            val model = facts.deviceModelHint ?: inventory.title ?: "Router"
            val sb = StringBuilder()
            sb.append("<!DOCTYPE html><html><head><meta charset=\"utf-8\">")
            sb.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
            sb.append("<title>").append(escape(model)).append(" - Login</title>")
            sb.append("<style>")
            sb.append("body{font-family:Arial,Helvetica,sans-serif;background:#DCE6F1;margin:0}")
            sb.append(".topbar{background:#0068B1;color:#fff;padding:14px 20px;font-size:20px;font-weight:bold}")
            sb.append(".box{max-width:380px;margin:8% auto 0;background:#fff;border:1px solid #B9C6D6;border-radius:6px;padding:26px 30px 30px}")
            sb.append("h1{font-size:18px;color:#0068B1;margin:0 0 18px}")
            sb.append("label{display:block;font-size:13px;color:#333;margin:12px 0 4px}")
            sb.append("input.text{width:100%;box-sizing:border-box;padding:8px;border:1px solid #A9B7C6;border-radius:4px;font-size:14px}")
            sb.append(".btn{margin-top:18px;width:100%;background:#0068B1;border:none;color:#fff;padding:10px;font-size:15px;border-radius:4px;cursor:pointer}")
            sb.append(".note{font-size:11px;color:#666;line-height:1.6;margin-top:18px;border-top:1px solid #E4E9F0;padding-top:12px}")
            sb.append("code{background:#EEF3F8;padding:1px 4px;border-radius:3px}")
            sb.append("</style></head><body>")
            sb.append("<div class=\"topbar\">").append(escape(model)).append("</div>")
            sb.append("<div class=\"box\"><h1>Router administration login</h1>")
            sb.append("<form method=\"POST\" action=\"").append(MODELLED_LOGIN_PATH).append("\">")
            sb.append("<label for=\"username\">Username</label><input class=\"text\" id=\"username\" name=\"username\" type=\"text\" autocomplete=\"off\">")
            sb.append("<label for=\"password\">Password</label><input class=\"text\" id=\"password\" name=\"password\" type=\"password\">")
            sb.append("<input class=\"btn\" type=\"submit\" value=\"Login\">")
            sb.append("</form>")
            sb.append("<div class=\"note\">This firmware ships its web UI without a static login page (the router's HTTP server generates one). ")
            sb.append("FlashGuard reproduces that page and validates against the documented factory defaults: ")
            sb.append("<code>").append(escape(defaultCreds.first)).append("</code> / <code>").append(escape(defaultCreds.second)).append("</code>.")
            sb.append("</div></div></body></html>")
            return banner(sb.toString())
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
            sb.append("<p><a href=\"/__flashguard/status\">status.json</a> &middot; ")
            sb.append("<a href=\"/__flashguard/logout\">log out of the simulated session</a></p>")
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
                val html = String(bytes, Charsets.UTF_8)
                // The original httpd appends runtime data (var arrays) to these templates before
                // serving them; the binaries that do that cannot run on Android, so FlashGuard
                // injects modelled values to keep the pages readable.
                val withData = modelledDataScript(html)?.let { injectIntoHead(html, it) } ?: html
                respond(out, 200, "$mime; charset=utf-8", banner(withData).toByteArray(Charsets.UTF_8))
            } else {
                respond(out, 200, mime, bytes)
            }
        }

        /**
         * Builds a <script> block with the data variables a template expects but that only the
         * original CGI could provide (TP-Link's "*Para" arrays, the visible-menu list, traffic
         * counters). Returns null for pages that do not reference such data.
         */
        private fun modelledDataScript(html: String): String? {
            val defined = Regex("var\\s+(\\w+)").findAll(html).map { it.groupValues[1] }.toHashSet()
            val maxIndex = LinkedHashMap<String, Int>()
            val uses = Regex("([A-Za-z_]\\w*(?:Para|statistList|statistlist))\\s*\\[\\s*(\\d+)\\s*]")
            for (m in uses.findAll(html)) {
                val name = m.groupValues[1]
                if (name in defined) continue
                val idx = m.groupValues[2].toIntOrNull() ?: continue
                if (idx in 0..31) maxIndex[name] = maxOf(maxIndex[name] ?: -1, idx)
            }
            val sb = StringBuilder()
            var any = false
            for ((name, max) in maxIndex) {
                any = true
                sb.append("var ").append(name).append("=new Array(")
                    .append((0..max).joinToString(",") { modelledValue(name, it) }).append(");\n")
            }
            if (html.contains("menuInit(", true) && "visibleMenuList" !in defined) {
                menuPageIds()?.let { ids ->
                    if (ids.isNotEmpty()) {
                        any = true
                        sb.append("var visibleMenuList=new Array(")
                            .append(ids.joinToString(",") { "\"${escapeHtml(it)}\"" }).append(");\n")
                    }
                }
            }
            if (!any) return null
            return "<SCRIPT type=\"text/javascript\">\n" +
                "<!-- FlashGuard: modelled runtime data (the original httpd appends these values) -->\n" +
                sb.toString() + "</SCRIPT>\n"
        }

        /** Modelled values for the well-known slots of TP-Link status templates; others stay "-". */
        private fun modelledValue(varName: String, index: Int): String {
            val name = varName.lowercase()
            return when {
                name == "statistlist" -> "0"
                name == "lanpara" && index == 0 -> "\"${escapeHtml(modelledMac())}\""
                name == "lanpara" && index == 1 -> "\"192.168.0.1\""
                name == "lanpara" && index == 2 -> "\"255.255.255.0\""
                name == "statuspara" && index == 0 -> "\"1\""
                name == "statuspara" && index == 1 -> "\"1\""
                name == "statuspara" && index == 2 -> "\"0\""
                name == "statuspara" && index == 3 -> "\"10000\""
                name == "statuspara" && index == 4 -> "\"${(System.currentTimeMillis() / 1000) % 86_400L}\""
                name == "statuspara" && index == 5 -> "\"${escapeHtml(facts.firmwareVersion ?: "-")}\""
                name == "statuspara" && index == 6 -> "\"${escapeHtml(modelledHardwareVersion())}\""
                name == "wlanpara" && index == 0 -> "\"1\""
                name == "wlanpara" && index == 1 -> "\"${escapeHtml(modelledSsid())}\""
                else -> "\"-\""
            }
        }

        private fun modelledMac(): String {
            val seed = (facts.deviceModelHint ?: facts.distro ?: "router").hashCode()
            return (1..5).joinToString(":") { "%02X".format((seed shr (it * 5)) and 0xFF) }
                .let { "02:$it" } // 02 = locally administered, so it can never match a real device
        }

        private fun modelledSsid(): String {
            val hint = facts.deviceModelHint
            val prefix = if (hint != null && (hint.contains("TL-", true) || hint.contains("TP-", true))) "TP-LINK_" else "Router_"
            val seed = (hint ?: "router").hashCode() and 0xFFFF
            return prefix + "%04X".format(seed)
        }

        private fun modelledHardwareVersion(): String {
            val hint = facts.deviceModelHint ?: return "-"
            return Regex("v\\d+(?:\\.\\d+)?", RegexOption.IGNORE_CASE).find(hint)?.value ?: "-"
        }

        /**
         * The page ids the device's menu structure offers (parsed from the image's own menu.js);
         * used to fill `visibleMenuList`, which the original httpd appends to the menu frame.
         */
        private fun menuPageIds(): List<String>? {
            val menuJs = vfs.findByName("menu.js").firstOrNull() ?: return null
            val text = vfs.readText(menuJs.path, 262144) ?: return null
            val ids = LinkedHashSet<String>()
            for (m in Regex("\"([A-Za-z0-9_]{2,40})\"\\s*,\\s*-?\\d").findAll(text)) {
                val id = m.groupValues[1]
                if (id.endsWith("Rpm")) ids.add(id)
            }
            return ids.toList()
        }

        private fun injectIntoHead(html: String, script: String): String {
            val head = Regex("<head[^>]*>", RegexOption.IGNORE_CASE).find(html)
            return when {
                head != null -> html.substring(0, head.range.last + 1) + "\n" + script + html.substring(head.range.last + 1)
                else -> script + html
            }
        }

        /** Parses "a=1&b=2" bodies/query strings into decoded key/value pairs. */
        private fun parseFormPairs(raw: String): List<Pair<String, String>> {
            if (raw.isBlank()) return emptyList()
            return raw.split('&').take(32).mapNotNull { part ->
                if (part.isEmpty()) return@mapNotNull null
                val k = urlDecode(part.substringBefore('=', ""))
                val v = urlDecode(part.substringAfter('=', ""))
                if (k.isEmpty()) null else k to v
            }
        }

        private fun urlDecode(s: String): String {
            val bytes = ArrayList<Byte>(s.length)
            var i = 0
            while (i < s.length) {
                when (val c = s[i]) {
                    '+' -> { bytes.add(' '.code.toByte()); i++ }
                    '%' -> {
                        if (i + 2 < s.length) {
                            val hex = s.substring(i + 1, i + 3)
                            val v = hex.toIntOrNull(16)
                            if (v != null && v in 0..255) {
                                bytes.add(v.toByte()); i += 3
                            } else {
                                bytes.add(c.code.toByte()); i++
                            }
                        } else {
                            bytes.add(c.code.toByte()); i++
                        }
                    }
                    else -> { bytes.add(c.code.toByte()); i++ }
                }
            }
            return String(bytes.toByteArray(), Charsets.UTF_8)
        }

        private fun escapeHtml(s: String): String = escape(s)


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
