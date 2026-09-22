package com.flashguard.engine.analysis

import com.flashguard.engine.LabSession
import com.flashguard.engine.core.BootStageNames
import com.flashguard.engine.core.FeatureVerdict
import com.flashguard.engine.core.FindingLevel
import com.flashguard.engine.core.RiskVerdict
import com.flashguard.engine.util.Hex
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * One copyable text block with *everything* a safety test produced:
 * the safety report (verdict, matrix, findings), the complete emulation/boot logs, the full web UI
 * inventory, the emulated server request log, every extraction warning, and the live-router
 * watchdog results (each request with status and latency).
 *
 * It is meant to be pasted into a chat, an issue or an email when asking for help with a specific
 * firmware - self-contained, plain text, no tooling needed to read it.
 */
object Diagnostics {

    private const val RULE = "--------------------------------------------------------------"

    fun build(session: LabSession, serverLines: List<String>): String {
        val sb = StringBuilder(32768)
        val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US).apply {
            timeZone = java.util.TimeZone.getTimeZone("UTC")
        }.format(Date(System.currentTimeMillis()))

        sb.append("==============================================================\n")
        sb.append("FlashGuard FULL DIAGNOSTICS  (safety report + logs + watchdog)\n")
        sb.append("==============================================================\n")
        sb.append("Generated: $ts\n")
        sb.append("Firmware : ${session.fileName}\n")
        sb.append("Size     : ${Hex.humanBytes(session.identity.totalSize)}\n")
        sb.append("SHA-256  : ${session.identity.sha256}\n")
        sb.append("Tested against: ${session.report.device.display}\n")
        sb.append("Engine   : FlashGuard 1.0.0 (static emulation, nothing flashed)\n\n")

        // ------------------------------------------------------------- verdict
        sb.append("VERDICT\n$RULE\n")
        sb.append("${session.report.verdict.display}  (risk ${session.report.riskScore}/100)\n")
        val red = session.report.redFlags()
        if (red.isNotEmpty()) {
            sb.append("RED flags (${red.size}): ${red.joinToString(", ") { it.feature }}\n")
        } else {
            sb.append("No verified hardware mismatch. \n")
        }
        sb.append("\nNext steps:\n")
        session.report.nextSteps.forEachIndexed { i, s -> sb.append("  ${i + 1}. $s\n") }
        sb.append("\n")

        // ------------------------------------------------------------- boot chain
        sb.append("BOOT CHAIN (emulated)\n$RULE\n")
        for (s in session.emulation.stages) {
            sb.append("[${if (s.ok) " OK " else "FAIL"}] ${s.name}\n       ${s.detail}\n")
        }
        sb.append("\n")

        // ------------------------------------------------------------- full boot log
        sb.append("FULL BOOT LOG (${session.emulation.bootLog.size} lines)\n$RULE\n")
        if (session.emulation.bootLog.isEmpty()) sb.append("(no boot log produced)\n")
        for (line in session.emulation.bootLog) sb.append(line).append('\n')
        sb.append("\n")

        // ------------------------------------------------------------- emulation details
        val e = session.emulation
        sb.append("EMULATION DETAILS\n$RULE\n")
        sb.append("${e.commandsRun} shell step(s) in ${e.elapsedMs} ms, truncated: ${e.truncated}\n")
        if (e.services.isEmpty()) sb.append("Services: none detected\n")
        else {
            sb.append("Services:\n")
            for (s in e.services) sb.append("  - ${s.name}${s.port?.let { p -> " (port $p)" } ?: ""} <- ${s.command}\n")
        }
        if (e.interfaces.isNotEmpty()) sb.append("Interfaces: ${e.interfaces.joinToString("; ")}\n")
        if (e.variables.isNotEmpty()) {
            sb.append("Key variables:\n")
            for ((k, v) in e.variables) sb.append("  $k = $v\n")
        }
        if (e.filesCreated.isNotEmpty()) {
            sb.append("Files created in the sandbox (${e.filesCreated.size}):\n")
            for (f in e.filesCreated) sb.append("  $f\n")
        }
        if (e.unsupportedCommands.isNotEmpty()) {
            sb.append("Commands NOT simulated (${e.unsupportedCommands.values.sum()} call(s), ${e.unsupportedCommands.size} kinds):\n")
            for ((k, v) in e.unsupportedCommands.entries.sortedByDescending { it.value }) sb.append("  $k x$v\n")
        }
        if (e.notes.isNotEmpty()) {
            sb.append("Emulation notes:\n")
            for (n in e.notes) sb.append("  ! $n\n")
        }
        sb.append("\n")

        // ------------------------------------------------------------- web UI
        val inv = session.inventory
        sb.append("WEB UI IN IMAGE\n$RULE\n")
        sb.append("Document root : ${inv.docRoot ?: "none found"}\n")
        sb.append("Login page    : ${inv.loginPage ?: "none static (FlashGuard serves a modelled login form)"}\n")
        if (inv.loginModelled) sb.append("Login modelled: yes (the original httpd generates the page; factory default admin/admin)\n")
        sb.append("Login fields  : ${inv.loginFormFields.joinToString(", ").ifBlank { "-" }}\n")
        sb.append("Login action  : ${inv.loginAction ?: "-"}\n")
        inv.title?.let { sb.append("UI title      : $it\n") }
        if (inv.serverBinaries.isNotEmpty()) sb.append("Server binaries: ${inv.serverBinaries.joinToString(", ")}\n")
        sb.append("Pages: ${inv.routes.size} in ${inv.features.size} group(s)\n")
        for ((name, routes) in inv.features) {
            sb.append("  [$name]\n")
            for (r in routes) sb.append("    ${r.path}\n")
        }
        sb.append("\n")

        // ------------------------------------------------------------- live emulated server
        sb.append("EMULATED WEB SERVER (this session)\n$RULE\n")
        if (serverLines.isEmpty()) sb.append("(server not started)\n")
        else for (l in serverLines) sb.append(l).append('\n')
        sb.append("\n")

        // ------------------------------------------------------------- extraction
        sb.append("EXTRACTION / UNPACK\n$RULE\n")
        val u = session.unpack
        sb.append("${u.importedFiles} object(s) imported; ${u.vfs.humanSummary()}\n")
        if (u.vfs.truncated) sb.append("! extraction was TRUNCATED by safety limits (skipped ${u.vfs.skippedFiles} file(s))\n")
        if (u.vfs.blocked.isNotEmpty()) {
            sb.append("Oversized blobs not kept in RAM (${u.vfs.blocked.size}):\n")
            for (b in u.vfs.blocked) sb.append("  $b\n")
        }
        if (u.notes.isNotEmpty()) {
            sb.append("Unpacker notes:\n")
            for (n in u.notes) sb.append("  - $n\n")
        }
        if (u.unsupported.isNotEmpty()) {
            sb.append("Things that could NOT be decoded/read (${u.unsupported.size}) - these are the errors you may want to report:\n")
            for (x in u.unsupported.take(200)) sb.append("  x $x\n")
            if (u.unsupported.size > 200) sb.append("  ... ${u.unsupported.size - 200} more\n")
        }
        u.opaqueReason()?.let { sb.append("Opaque image: $it\n") }
        sb.append("\n")

        // ------------------------------------------------------------- identity layers
        sb.append("HOW THE FILE WAS IDENTIFIED\n$RULE\n")
        sb.append("${session.identity.summary()} (confidence ${session.identity.confidence}%)\n")
        for (ev in session.identity.evidence.take(20)) sb.append("  - $ev\n")
        val layers = session.identity.layers.flatMap { it.flattenTree() }
        if (layers.isNotEmpty()) {
            sb.append("Layers:\n")
            for (l in layers.take(40)) {
                sb.append("  @0x${l.offset.toString(16)} +${l.length} ${l.format.label}" +
                    (l.detail?.let { " - $it" } ?: "") + "\n")
            }
        }
        sb.append("\n")

        // ------------------------------------------------------------- facts
        val f = session.facts
        sb.append("FIRMWARE FACTS\n$RULE\n")
        sb.append("Distro: ${f.distro ?: "unknown"} ${f.firmwareVersion ?: ""}  target ${f.target ?: "-"}/${f.arch ?: "-"}")
        f.kernelVersion?.let { sb.append("  kernel $it") }
        sb.append('\n')
        sb.append("SoC hints: ${f.socHints.joinToString(", ").ifBlank { "-" }}\n")
        sb.append("Packages: ${f.packages.size}")
        if (f.packages.isNotEmpty()) sb.append(" -> ${f.packages.take(60).joinToString(", ")}" + if (f.packages.size > 60) " ... (+${f.packages.size - 60} more)" else "")
        sb.append('\n')
        sb.append("Kernel modules: ${f.kernelModules.size}")
        if (f.kernelModules.isNotEmpty()) sb.append(" -> ${f.kernelModules.take(40).joinToString(", ")}" + if (f.kernelModules.size > 40) " ... (+${f.kernelModules.size - 40} more)" else "")
        sb.append('\n')
        sb.append("Wireless drivers: ${f.wirelessDrivers.joinToString(", ").ifBlank { "-" }}\n")
        sb.append("Users in image: ${f.users.joinToString(", ").ifBlank { "-" }}  |  password hashes: ${f.passwordHashCount}\n")
        sb.append("Config files: ${f.configFiles.size}  |  init scripts: ${f.initScripts.size}  |  web handlers: ${f.webHandlers.size}\n")
        if (f.notes.isNotEmpty()) {
            sb.append("Facts notes:\n")
            for (n in f.notes) sb.append("  - $n\n")
        }
        sb.append("\n")

        // ------------------------------------------------------------- hardware matrix
        sb.append("HARDWARE COMPATIBILITY MATRIX (all rows)\n$RULE\n")
        for (row in session.report.features) {
            val mark = when {
                row.verdict.isRed -> "RED  "
                row.verdict == FeatureVerdict.COMPATIBLE -> "OK   "
                row.verdict == FeatureVerdict.PARTIAL -> "WARN "
                else -> "UNVER"
            }
            sb.append("[$mark] ${row.feature}: image=${row.imageWants} | device=${row.deviceHas}\n")
            sb.append("        why: ${row.why}\n")
            row.mitigation?.let { sb.append("        do: $it\n") }
        }
        sb.append("\n")

        // ------------------------------------------------------------- findings
        sb.append("SECURITY / QUALITY FINDINGS\n$RULE\n")
        val levels = listOf(FindingLevel.ERROR, FindingLevel.WARN, FindingLevel.INFO, FindingLevel.OK)
        var any = false
        for (level in levels) {
            val group = session.report.findings.filter { it.level == level }
            if (group.isEmpty()) continue
            any = true
            for (x in group) {
                sb.append("[${level.name}] ${x.title}\n        ${x.detail}\n")
                x.evidence?.let { sb.append("        evidence: $it\n") }
            }
        }
        if (!any) sb.append("(none)\n")
        sb.append("\n")

        // ------------------------------------------------------------- watchdog
        sb.append("WATCHDOG: LIVE ROUTER CHECK\n$RULE\n")
        val p = session.probeResult
        if (p == null) {
            sb.append("Not run yet. Use the 'Live test' tab to check a real router on your LAN\n")
            sb.append("(read-only: GETs plus an optional login attempt with factory defaults).\n")
        } else {
            sb.append("Host: ${p.host}\n")
            sb.append("Reachable: ${p.reachable}\n")
            if (p.reachable) {
                sb.append("Web server: ${p.webServer ?: "unknown"}\n")
                sb.append("Auth: ${p.authScheme}\n")
                sb.append("Login page found: ${p.loginPageFound}\n")
                if (p.loginFormFields.isNotEmpty()) sb.append("Login form fields: ${p.loginFormFields.joinToString(", ")}\n")
                if (p.cookies.isNotEmpty()) sb.append("Cookies: ${p.cookies.joinToString(" | ").take(300)}\n")
                if (p.defaultCredsTried.isNotEmpty()) {
                    sb.append("Default credentials tried: ${p.defaultCredsTried.joinToString(", ")}\n")
                    sb.append("Default credentials work: ${p.defaultCredsWorked ?: "no"}\n")
                }
                sb.append("Requests: ${p.requests}  |  Errors: ${p.errors}\n")
                sb.append("Latency p50: ${p.p50} ms  |  p95: ${p.p95} ms\n")
                sb.append("Stability verdict: ${if (p.stable) "STABLE" else "UNSTABLE"}\n")
                if (p.afterLoginFeatures.isNotEmpty()) {
                    sb.append("Pages answered (${p.afterLoginFeatures.size}):\n")
                    for (x in p.afterLoginFeatures) {
                        sb.append("  [${x.status}] ${x.name}  ${x.path}  (${x.bytes} B, ${x.ms} ms)\n")
                    }
                }
                if (p.latencyMs.isNotEmpty()) sb.append("All latency samples (ms): ${p.latencyMs.joinToString(", ")}\n")
                if (p.notes.isNotEmpty()) {
                    sb.append("Watchdog notes:\n")
                    for (n in p.notes) sb.append("  ! $n\n")
                }
                if (p.trace.isNotEmpty()) {
                    sb.append("Full request trace:\n")
                    for (t in p.trace) sb.append("  $t\n")
                }
            } else {
                for (n in p.notes) sb.append("! $n\n")
            }
        }
        sb.append("\n")

        // ------------------------------------------------------------- footer
        if (session.report.verdict == RiskVerdict.CANNOT_VERIFY) {
            sb.append("NOTE: verdict is CANNOT VERIFY - the image could not be unpacked, so treat every\n")
            sb.append("content-based row above as 'unknown', not as 'fine'.\n\n")
        }
        sb.append("End of FlashGuard diagnostics. Static emulation only - nothing was written to any router.\n")
        return sb.toString()
    }

    /** Wraps engine diagnostics + app-run log into one copyable bundle. */
    fun bundle(diagnostics: String, appLogText: String): String = buildString {
        append(diagnostics)
        append("\n\n==============================================================\n")
        append("APP RUN LOG (every event, warning and error from this app session)\n")
        append("==============================================================\n")
        append(appLogText.ifBlank { "(app log is empty)\n" })
    }
}
