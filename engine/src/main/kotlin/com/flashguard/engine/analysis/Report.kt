package com.flashguard.engine.analysis

import com.flashguard.engine.core.EngineReport
import com.flashguard.engine.core.EmulationResult
import com.flashguard.engine.core.FeatureVerdict
import com.flashguard.engine.core.FindingLevel
import com.flashguard.engine.core.FirmwareFacts
import com.flashguard.engine.core.HardwareFeature
import com.flashguard.engine.core.ProbeResult
import com.flashguard.engine.core.RiskVerdict
import com.flashguard.engine.emu.WebUiLab
import com.flashguard.engine.util.Hex
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Renders a report as JSON (for tooling) and Markdown (for humans / GitHub issues / copy-paste).
 */
object Report {

    fun toJson(
        report: EngineReport,
        facts: FirmwareFacts,
        inventory: WebUiLab.Inventory?,
        probe: ProbeResult? = null,
    ): String {
        val sb = StringBuilder(16384)
        sb.append("{\n")
        sb.append("  \"generatedAt\": \"${iso(report.generatedAt)}\",\n")
        sb.append("  \"engine\": {\"name\": \"FlashGuard\", \"version\": \"1.0.0\"},\n")
        sb.append("  \"image\": {\n")
        sb.append("    \"primaryFormat\": ${q(report.identity.primary.label)},\n")
        sb.append("    \"vendor\": ${q(report.identity.vendor.display)},\n")
        sb.append("    \"model\": ${q(report.identity.model ?: "")},\n")
        sb.append("    \"version\": ${q(report.identity.version ?: "")},\n")
        sb.append("    \"sizeBytes\": ${report.identity.totalSize},\n")
        sb.append("    \"sha256\": ${q(report.identity.sha256)},\n")
        sb.append("    \"confidence\": ${report.identity.confidence},\n")
        sb.append("    \"archHints\": ${arr(report.identity.archHints)},\n")
        sb.append("    \"evidence\": ${arr(report.identity.evidence)},\n")
        sb.append("    \"layers\": [\n")
        val flat = report.identity.layers.flatMap { it.flattenTree() }
        flat.forEachIndexed { i, l ->
            sb.append("      {\"format\": ${q(l.format.label)}, \"offset\": ${l.offset}, \"length\": ${l.length}, \"detail\": ${q(l.detail)}}")
            if (i < flat.size - 1) sb.append(',')
            sb.append('\n')
        }
        sb.append("    ]\n  },\n")

        sb.append("  \"firmwareFacts\": {\n")
        sb.append("    \"distro\": ${q(facts.distro ?: "")},\n")
        sb.append("    \"version\": ${q(facts.firmwareVersion ?: "")},\n")
        sb.append("    \"target\": ${q(facts.target ?: "")},\n")
        sb.append("    \"arch\": ${q(facts.arch ?: "")},\n")
        sb.append("    \"packageCount\": ${facts.packages.size},\n")
        sb.append("    \"kernelModuleCount\": ${facts.kernelModules.size},\n")
        sb.append("    \"wirelessDrivers\": ${arr(facts.wirelessDrivers)},\n")
        sb.append("    \"usbSupported\": ${facts.usbSupported},\n")
        sb.append("    \"vpnSupported\": ${facts.vpnSupported},\n")
        sb.append("    \"rootfsUncompressedBytes\": ${facts.rootfsUncompressed},\n")
        sb.append("    \"webRoot\": ${q(facts.webRoot ?: "")},\n")
        sb.append("    \"userCount\": ${facts.users.size},\n")
        sb.append("    \"passwordHashes\": ${facts.passwordHashCount}\n")
        sb.append("  },\n")

        sb.append("  \"device\": {\n")
        sb.append("    \"brand\": ${q(report.device.brand)},\n")
        sb.append("    \"model\": ${q(report.device.model)},\n")
        sb.append("    \"revision\": ${q(report.device.revision)},\n")
        sb.append("    \"soc\": ${q(report.device.soc)},\n")
        sb.append("    \"cpuFamily\": ${q(report.device.cpuFamily.display)},\n")
        sb.append("    \"ramMb\": ${report.device.ramMb},\n")
        sb.append("    \"flashMb\": ${report.device.flashMb},\n")
        sb.append("    \"flashType\": ${q(report.device.flashType)},\n")
        sb.append("    \"bootloader\": ${q(report.device.bootloader)},\n")
        sb.append("    \"recovery\": ${q(report.device.recovery)}\n")
        sb.append("  },\n")

        sb.append("  \"verdict\": {\n")
        sb.append("    \"summary\": ${q(report.verdict.display)},\n")
        sb.append("    \"riskScore\": ${report.riskScore},\n")
        sb.append("    \"redFlags\": ${report.redFlags().size},\n")
        // An unreadable image has zero red flags but is still not flashable on this evidence.
        sb.append("    \"verifiedMismatches\": ${report.redFlags().size},\n")
        sb.append("    \"inspectionFailed\": ${report.verdict == RiskVerdict.CANNOT_VERIFY},\n")
        sb.append("    \"nextSteps\": ${arr(report.nextSteps)}\n")
        sb.append("  },\n")

        sb.append("  \"features\": [\n")
        report.features.forEachIndexed { i, f ->
            sb.append("    {\"feature\": ${q(f.feature)}, \"image\": ${q(f.imageWants)}, \"device\": ${q(f.deviceHas)}, ")
            sb.append("\"verdict\": ${q(f.verdict.display)}, \"red\": ${f.verdict.isRed}, \"why\": ${q(f.why)}}")
            if (i < report.features.size - 1) sb.append(',')
            sb.append('\n')
        }
        sb.append("  ],\n")

        sb.append("  \"findings\": [\n")
        report.findings.forEachIndexed { i, f ->
            sb.append("    {\"id\": ${q(f.id)}, \"level\": ${q(f.level.name)}, \"title\": ${q(f.title)}, \"detail\": ${q(f.detail)}, \"category\": ${q(f.category)}}")
            if (i < report.findings.size - 1) sb.append(',')
            sb.append('\n')
        }
        sb.append("  ],\n")

        report.emulation?.let { e ->
            sb.append("  \"emulation\": {\n")
            sb.append("    \"reachedInit\": ${e.reachedInit()},\n")
            sb.append("    \"reachedWebUi\": ${e.reachedWebUi()},\n")
            sb.append("    \"commandsRun\": ${e.commandsRun},\n")
            sb.append("    \"elapsedMs\": ${e.elapsedMs},\n")
            sb.append("    \"truncated\": ${e.truncated},\n")
            sb.append("    \"stages\": [\n")
            e.stages.forEachIndexed { i, s ->
                sb.append("      {\"stage\": ${q(s.name)}, \"ok\": ${s.ok}, \"detail\": ${q(s.detail)}}")
                if (i < e.stages.size - 1) sb.append(',')
                sb.append('\n')
            }
            sb.append("    ],\n")
            sb.append("    \"services\": ${arr(e.services.map { "${it.name}${it.port?.let { p -> ":$p" } ?: ""}" })},\n")
            sb.append("    \"interfaces\": ${arr(e.interfaces)},\n")
            sb.append("    \"webRoot\": ${q(e.webRoot ?: "")},\n")
            sb.append("    \"loginPage\": ${q(e.loginPage ?: "")}\n")
            sb.append("  },\n")
        }

        inventory?.let { inv ->
            sb.append("  \"webUi\": {\n")
            sb.append("    \"docRoot\": ${q(inv.docRoot ?: "")},\n")
            sb.append("    \"loginPage\": ${q(inv.loginPage ?: "")},\n")
            sb.append("    \"loginFormFields\": ${arr(inv.loginFormFields)},\n")
            sb.append("    \"serverBinaries\": ${arr(inv.serverBinaries)},\n")
            sb.append("    \"featureCount\": ${inv.features.size},\n")
            sb.append("    \"features\": [\n")
            inv.features.entries.forEachIndexed { i, (name, routes) ->
                sb.append("      {\"name\": ${q(name)}, \"pages\": ${routes.size}, \"examples\": ${arr(routes.take(4).map { it.path })}}")
                if (i < inv.features.size - 1) sb.append(',')
                sb.append('\n')
            }
            sb.append("    ]\n  },\n")
        }

        probe?.let { p ->
            sb.append("  \"liveProbe\": {\n")
            sb.append("    \"host\": ${q(p.host)},\n")
            sb.append("    \"reachable\": ${p.reachable},\n")
            sb.append("    \"loginPageFound\": ${p.loginPageFound},\n")
            sb.append("    \"authScheme\": ${q(p.authScheme)},\n")
            sb.append("    \"defaultCredsWorked\": ${q(p.defaultCredsWorked ?: "")},\n")
            sb.append("    \"requests\": ${p.requests},\n")
            sb.append("    \"errors\": ${p.errors},\n")
            sb.append("    \"p50ms\": ${p.p50},\n")
            sb.append("    \"p95ms\": ${p.p95},\n")
            sb.append("    \"stable\": ${p.stable},\n")
            sb.append("    \"features\": ${arr(p.afterLoginFeatures.map { "${it.name} (${it.status})" })}\n")
            sb.append("  },\n")
        }

        sb.append("  \"disclaimer\": \"Static emulation only. Nothing was written to any router. Always keep a full flash backup and a recovery path.\"\n")
        sb.append("}\n")
        return sb.toString()
    }

    fun toMarkdown(
        report: EngineReport,
        facts: FirmwareFacts,
        inventory: WebUiLab.Inventory?,
        emulation: EmulationResult?,
        probe: ProbeResult? = null,
    ): String {
        val sb = StringBuilder(8192)
        sb.append("# FlashGuard report\n\n")
        sb.append("_Generated ${iso(report.generatedAt)} - static emulation only, nothing was flashed._\n\n")

        sb.append("## Image\n\n")
        sb.append("| | |\n|---|---|\n")
        sb.append("| Format | ${report.identity.primary.label} |\n")
        sb.append("| Vendor | ${report.identity.vendor.display} |\n")
        sb.append("| Model | ${report.identity.model ?: "-"} |\n")
        sb.append("| Version | ${report.identity.version ?: "-"} |\n")
        sb.append("| Size | ${Hex.humanBytes(report.identity.totalSize)} |\n")
        sb.append("| SHA-256 | `${report.identity.sha256}` |\n")
        sb.append("| Identification confidence | ${report.identity.confidence}% |\n")
        if (facts.distro != null || facts.target != null) {
            sb.append("| Distribution | ${facts.distro ?: "-"} ${facts.firmwareVersion ?: ""} |\n")
            sb.append("| Target / arch | ${facts.target ?: "-"} / ${facts.arch ?: "-"} |\n")
        }
        sb.append('\n')

        // Why the file was identified the way it was. Without this section a user sees
        // "Raw/unknown binary" and has no way to tell a truncated download from a vendor-encrypted
        // image - the evidence is what makes the report auditable instead of a black box.
        val evidence = report.identity.evidence
        if (evidence.isNotEmpty()) {
            sb.append("## How the file was identified\n\n")
            for (e in evidence.take(14)) sb.append("- $e\n")
            if (evidence.size > 14) sb.append("- ... ${evidence.size - 14} more observation(s)\n")
            sb.append('\n')
        }

        val red = report.redFlags()
        val unverified = report.features.count { it.verdict == FeatureVerdict.UNVERIFIED || it.verdict == FeatureVerdict.PARTIAL }
        sb.append("## Verdict: ${report.verdict.display}\n\n")
        sb.append("Risk score **${report.riskScore}/100** - ")
        if (red.isNotEmpty()) {
            sb.append("${red.size} hardware-incompatible feature(s): ${red.joinToString(", ") { it.feature }}.\n\n")
        } else {
            // Never let "0 hardware mismatch(es)" read like a green light when nothing could be read.
            sb.append("no verified hardware mismatch")
            if (unverified > 0) {
                sb.append("; $unverified check(s) could not be verified from the file's contents")
                if (report.verdict == RiskVerdict.CANNOT_VERIFY) sb.append(" because nothing inside it could be unpacked")
            }
            sb.append(".\n\n")
        }

        sb.append("## Hardware compatibility (red = do not flash)\n\n")
        sb.append("| Feature | Image | Your router | Result |\n|---|---|---|---|\n")
        for (f in report.features) {
            val mark = when {
                f.verdict.isRed -> "**RED - INCOMPATIBLE**"
                f.verdict == FeatureVerdict.COMPATIBLE -> "OK"
                f.verdict == FeatureVerdict.PARTIAL -> "caution"
                else -> "needs verification"
            }
            sb.append("| ${f.feature} | ${md(f.imageWants)} | ${md(f.deviceHas)} | $mark |\n")
        }
        sb.append('\n')
        // Red and caution rows always explain themselves; unverified rows only when they carry advice
        // (otherwise a report for an unreadable image would be nothing but boilerplate).
        val explained = report.features.filter {
            it.verdict.isRed || it.verdict == FeatureVerdict.PARTIAL ||
                (it.verdict == FeatureVerdict.UNVERIFIED && it.mitigation != null)
        }
        for (f in explained.take(10)) {
            sb.append("- **${f.feature}**: ${f.why}\n")
            f.mitigation?.let { sb.append("  - _What to do:_ $it\n") }
        }
        sb.append('\n')

        if (emulation != null) {
            sb.append("## Emulated boot chain\n\n")
            for (s in emulation.stages) {
                sb.append("- ${if (s.ok) "[x]" else "[ ]"} **${s.name}** - ${s.detail}\n")
            }
            sb.append("\n${emulation.commandsRun} shell steps in ${emulation.elapsedMs} ms; ${emulation.services.size} service(s) simulated.\n\n")
            if (emulation.services.isNotEmpty()) {
                sb.append("Services: ").append(emulation.services.take(12).joinToString(", ") { "${it.name}${it.port?.let { p -> ":$p" } ?: ""}" }).append("\n\n")
            }
            if (emulation.loginPage != null) {
                sb.append("Login page found in the image: `${emulation.loginPage}`\n\n")
            }
            if (emulation.unsupportedCommands.isNotEmpty()) {
                sb.append("Commands not simulated: ")
                    .append(emulation.unsupportedCommands.entries.take(10).joinToString(", ") { "${it.key} (${it.value}x)" })
                    .append("\n\n")
            }
        }

        inventory?.let { inv ->
            sb.append("## Features in the web UI (${inv.features.size} groups, ${inv.routes.size} pages)\n\n")
            for ((name, routes) in inv.features) {
                sb.append("- **$name** (${routes.size}): ").append(routes.take(5).joinToString(", ") { "`${it.path}`" }).append('\n')
            }
            sb.append('\n')
        }

        sb.append("## Findings\n\n")
        for (level in listOf(FindingLevel.ERROR, FindingLevel.WARN, FindingLevel.INFO, FindingLevel.OK)) {
            val group = report.findings.filter { it.level == level }
            if (group.isEmpty()) continue
            sb.append("**${level.name}**\n\n")
            for (f in group) sb.append("- ${f.title}: ${f.detail}\n")
            sb.append('\n')
        }

        probe?.let { p ->
            sb.append("## Live router check (${p.host})\n\n")
            sb.append("- Reachable: ${p.reachable}, web server: ${p.serverHeader ?: "unknown"}, auth: ${p.authScheme}\n")
            sb.append("- Login page found: ${p.loginPageFound}; default credentials worked: ${p.defaultCredsWorked ?: "no"}\n")
            sb.append("- ${p.requests} requests, ${p.errors} error(s); latency p50 ${p.p50} ms / p95 ${p.p95} ms -> ${if (p.stable) "STABLE" else "UNSTABLE"}\n")
            if (p.afterLoginFeatures.isNotEmpty()) {
                sb.append("- Features reachable after login: ").append(p.afterLoginFeatures.take(12).joinToString(", ") { it.name }).append('\n')
            }
            sb.append('\n')
        }

        sb.append("## Next steps\n\n")
        for ((i, step) in report.nextSteps.withIndex()) sb.append("${i + 1}. $step\n")
        sb.append("\n---\n\n")
        sb.append("Static emulation reproduces the firmware's own init/config logic in a sandbox; it cannot run ARM/MIPS native " +
            "binaries or touch real hardware. Treat hardware-specific verdicts as advisory evidence, keep a full flash backup, " +
            "and make sure a recovery path exists before you flash anything.\n")
        return sb.toString()
    }

    private fun md(s: String): String = s.replace("|", "\\|").replace("\n", " ")

    private fun q(s: String): String {
        val sb = StringBuilder(s.length + 2)
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> if (c.code < 0x20) sb.append("\\u%04x".format(c.code)) else sb.append(c)
            }
        }
        sb.append('"')
        return sb.toString()
    }

    private fun arr(items: List<String>): String = items.joinToString(", ", "[", "]") { q(it) }

    private fun iso(ts: Long): String =
        SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply { timeZone = java.util.TimeZone.getTimeZone("UTC") }.format(Date(ts))
}
