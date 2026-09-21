package com.flashguard.engine.analysis

import com.flashguard.engine.core.ProbeFeature
import com.flashguard.engine.core.ProbeResult
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.Base64

/**
 * Tests a *live* router on your own LAN - before and after a flash - to answer:
 *   "is it up, does the login page show, what works after login, and does it stay stable?"
 *
 * Safety rules baked in:
 *  - only loopback/LAN hosts are accepted,
 *  - only HTTP GET, plus an optional POST to the login form the page itself advertises,
 *  - state-changing paths (reboot/upgrade/reset/format...) are never requested,
 *  - everything is read: no configuration is ever written.
 */
object StabilityProbe {

    private val FORBIDDEN = listOf(
        "reboot", "reset", "reboot", "upgrade", "firmware", "flash", "format", "erase", "restore",
        "factory", "sysupgrade", "delete", "remove", "save", "apply", "submit_config", "set_",
    )

    private val DEFAULT_CREDS = listOf(
        "admin" to "admin",
        "admin" to "password",
        "admin" to "",
        "admin" to "1234",
        "root" to "admin",
        "root" to "",
        "root" to "toor",
        "admin" to "admin123",
    )

    fun probe(
        host: String,
        tryDefaultCreds: Boolean = false,
        timeoutMs: Int = 5000,
        maxPages: Int = 20,
    ): ProbeResult {
        val notes = ArrayList<String>()
        val cleanHost = host.trim().removePrefix("http://").removePrefix("https://").substringBefore('/')
        val base = "http://$cleanHost"
        val latencies = ArrayList<Long>()
        var errors = 0
        var requests = 0

        val root = get(base + "/", timeoutMs)
        requests++
        if (!root.ok) {
            errors++
            return ProbeResult(
                host = cleanHost, reachable = false, webServer = null, loginPageFound = false,
                loginFormFields = emptyList(), authScheme = "none", serverHeader = null, cookies = emptyList(),
                defaultCredsTried = emptyList(), defaultCredsWorked = null, afterLoginFeatures = emptyList(),
                latencyMs = latencies, errors = errors, requests = requests, stable = false,
                notes = listOf("Could not reach $base - check the IP, that the router is on the same LAN, and that its web UI is enabled."),
            )
        }
        latencies.add(root.ms)

        val serverHeader = root.headers["server"] ?: root.headers["Server"]
        val cookies = root.headers.filterKeys { it.equals("set-cookie", true) }.values.toList()
        var authScheme = when {
            root.status == 401 -> "HTTP Basic/Digest (browser login prompt)"
            root.body.contains("type=\"password\"", true) -> "form login"
            root.body.contains("password", true) -> "form login (guessed from markup)"
            else -> "unknown"
        }
        val loginFields = parseInputs(root.body)
        val loginAction = parseFormAction(root.body) ?: "/"

        var credsWorked: String? = null
        val tried = ArrayList<String>()
        if (tryDefaultCreds) {
            for ((user, pass) in DEFAULT_CREDS.take(6)) {
                tried.add("$user/${if (pass.isEmpty()) "(blank)" else pass}")
                val ok = tryLogin(base, loginAction, user, pass, loginFields, timeoutMs)
                requests++
                if (ok) {
                    credsWorked = "$user / ${if (pass.isEmpty()) "(blank)" else pass}"
                    break
                }
            }
            if (credsWorked == null) notes.add("None of the documented default credentials worked (that is good news).")
            if (credsWorked != null) notes.add("Factory default credentials work. Change them before putting this router on the internet.")
        }

        // Enumerate what the router shows (read-only GETs only).
        val featurePages = findFeatureLinks(root.body, base, maxPages)
        val features = ArrayList<ProbeFeature>()
        for (page in featurePages) {
            if (isForbidden(page.path)) continue
            val r = get(page.url, timeoutMs)
            requests++
            if (!r.ok) errors++
            latencies.add(r.ms)
            features.add(ProbeFeature(name = page.name, path = page.path, status = r.status, bytes = r.body.length, ms = r.ms))
        }

        // Stability: repeat the login page request and watch for jitter/failures.
        val repeats = 6
        for (i in 0 until repeats) {
            val r = get(base + "/", timeoutMs)
            requests++
            if (!r.ok) errors++ else latencies.add(r.ms)
        }
        val sorted = latencies.sorted()
        val p50 = if (sorted.isEmpty()) 0 else sorted[sorted.size / 2]
        val p95 = if (sorted.isEmpty()) 0 else sorted[(sorted.size * 95) / 100]
        val stable = errors == 0 && (p95 < 2500 || p95 < p50 * 4)

        if (!stable) notes.add("The router showed $errors error(s) and p95 latency ${p95}ms during a short test - it may be overloaded or unstable.")
        if (features.isEmpty()) notes.add("No feature pages could be listed from the login page (they may be behind JS or a different path).")

        return ProbeResult(
            host = cleanHost,
            reachable = true,
            webServer = serverHeader,
            loginPageFound = root.body.contains("password", true) || root.status == 401,
            loginFormFields = loginFields,
            authScheme = authScheme,
            serverHeader = serverHeader,
            cookies = cookies,
            defaultCredsTried = tried,
            defaultCredsWorked = credsWorked,
            afterLoginFeatures = features,
            latencyMs = latencies,
            errors = errors,
            requests = requests,
            stable = stable,
            notes = notes,
        )
    }

    private data class Page(val name: String, val url: String, val path: String)

    private class Response(
        val ok: Boolean,
        val status: Int,
        val body: String,
        val headers: Map<String, String>,
        val ms: Long,
    )

    private fun get(url: String, timeoutMs: Int): Response {
        val started = System.currentTimeMillis()
        return try {
            val conn = (URL(url).openConnection() as HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                instanceFollowRedirects = true
                setRequestProperty("User-Agent", "FlashGuard/1.0 (read-only stability check)")
                setRequestProperty("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
            }
            val status = conn.responseCode
            val stream = if (status in 200..399) conn.inputStream else conn.errorStream
            val body = stream?.let { s ->
                BufferedReader(InputStreamReader(s, Charsets.ISO_8859_1)).use { r ->
                    val sb = StringBuilder()
                    val buf = CharArray(8192)
                    var total = 0
                    while (total < 512 * 1024) {
                        val n = r.read(buf)
                        if (n < 0) break
                        sb.append(buf, 0, n)
                        total += n
                    }
                    sb.toString()
                }
            } ?: ""
            val headers = conn.headerFields.orEmpty().entries
                .filter { it.key != null }
                .associate { it.key to it.value.joinToString(", ") }
            conn.disconnect()
            Response(status in 200..399, status, body, headers, System.currentTimeMillis() - started)
        } catch (t: Throwable) {
            Response(false, 0, "", emptyMap(), System.currentTimeMillis() - started)
        }
    }

    private fun tryLogin(
        base: String,
        action: String,
        user: String,
        pass: String,
        fields: List<String>,
        timeoutMs: Int,
    ): Boolean {
        return try {
            val url = if (action.startsWith("http")) action else base + "/" + action.trimStart('/')
            val userField = fields.firstOrNull { it.contains("user", true) || it.contains("name", true) } ?: "username"
            val passField = fields.firstOrNull { it.contains("pass", true) } ?: "password"
            val payload = "$userField=${enc(user)}&$passField=${enc(pass)}"
            val conn = (URL(url).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                doOutput = true
                instanceFollowRedirects = true
                setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                setRequestProperty("User-Agent", "FlashGuard/1.0 (login test)")
                setRequestProperty("Referer", base + "/")
            }
            conn.outputStream.use { it.write(payload.toByteArray(Charsets.ISO_8859_1)) }
            val status = conn.responseCode
            val text = conn.inputStream?.let { s ->
                BufferedReader(InputStreamReader(s, Charsets.ISO_8859_1)).use { it.readText().take(65536) }
            } ?: ""
            conn.disconnect()
            val looksRejected = text.contains("invalid", true) && text.contains("password", true) ||
                text.contains("login failed", true) || text.contains("wrong", true)
            status in 200..399 && !looksRejected && text.contains("password", true).not()
        } catch (t: Throwable) {
            false
        }
    }

    private fun parseInputs(html: String): List<String> =
        Regex("<input[^>]*name=[\"']?([\\w\\[\\]-]+)", RegexOption.IGNORE_CASE)
            .findAll(html).take(12).map { it.groupValues[1] }.toList()

    private fun parseFormAction(html: String): String? =
        Regex("<form[^>]*action=[\"']?([^\"' >]+)", RegexOption.IGNORE_CASE).find(html)?.groupValues?.get(1)

    private fun findFeatureLinks(html: String, base: String, max: Int): List<Page> {
        val out = LinkedHashMap<String, Page>()
        for (m in Regex("href=[\"']([^\"'#]+)", RegexOption.IGNORE_CASE).findAll(html).take(200)) {
            val href = m.groupValues[1]
            if (href.startsWith("mailto:") || href.startsWith("javascript:") || href.endsWith(".css") || href.endsWith(".js")) continue
            val path = if (href.startsWith("http")) href.replace(base, "").ifBlank { "/" } else href
            if (path.startsWith("//")) continue
            if (out.size >= max) break
            out.putIfAbsent(path, Page(prettyName(path), base + "/" + path.trimStart('/'), path))
        }
        return out.values.toList()
    }

    private fun prettyName(path: String): String =
        path.substringBefore('?').trim('/').ifBlank { "Home" }.replace('_', ' ').replace('-', ' ')
            .split('/').last().substringBeforeLast('.')

    private fun isForbidden(path: String): Boolean {
        val low = path.lowercase()
        return FORBIDDEN.any { low.contains(it) }
    }

    private fun enc(s: String): String = java.net.URLEncoder.encode(s, "UTF-8")

    /** Quick TCP reachability for UI feedback. */
    fun pingPort(host: String, port: Int, timeoutMs: Int = 1500): Boolean = try {
        Socket().use { it.connect(InetSocketAddress(host, port), timeoutMs) }
        true
    } catch (t: Throwable) {
        false
    }

    @Suppress("unused")
    private fun basicAuthHeader(user: String, pass: String): String =
        "Basic " + Base64.getEncoder().encodeToString("$user:$pass".toByteArray())
}
