package com.flashguard.engine

import com.flashguard.engine.analysis.Diagnostics
import com.flashguard.engine.analysis.HardwareMatrix
import com.flashguard.engine.analysis.Heuristics
import com.flashguard.engine.analysis.Report
import com.flashguard.engine.core.DeviceProfile
import com.flashguard.engine.core.EngineReport
import com.flashguard.engine.core.EmulationResult
import com.flashguard.engine.core.FirmwareFacts
import com.flashguard.engine.core.FirmwareIdentifier
import com.flashguard.engine.core.FirmwareUnpacker
import com.flashguard.engine.core.ImageIdentity
import com.flashguard.engine.core.ProbeResult
import com.flashguard.engine.core.UnpackResult
import com.flashguard.engine.emu.FirmwareEmulator
import com.flashguard.engine.emu.WebUiLab
import com.flashguard.engine.util.Limits
import com.flashguard.engine.util.ProgressSink

/**
 * The single entry point the Android app talks to.
 *
 * Typical flow inside the app:
 *   1. user picks a firmware file + their router model,
 *   2. [FirmwareLab.analyze] identifies, unpacks, emulates and scores everything on-device,
 *   3. the UI shows the stages (identity -> rootfs -> init -> services -> web UI), the red/amber/green
 *      hardware matrix and the exported report,
 *   4. optionally [LabSession.startWebUi] serves the reconstructed login page into a WebView.
 */
object FirmwareLab {

    fun analyze(
        bytes: ByteArray,
        fileName: String,
        device: DeviceProfile,
        progress: ProgressSink = ProgressSink.NONE,
        timeBudgetMs: Long = Limits.MAX_EMULATION_MS,
    ): LabSession {
        progress.onProgress(2, "Starting analysis of ${fileName.ifBlank { "firmware" }}")

        val identity = FirmwareIdentifier.identify(bytes, fileName, progress)
        progress.onProgress(16, "Identified: ${identity.summary()}")

        val unpack = FirmwareUnpacker(bytes, identity, progress).unpack()
        progress.onProgress(70, "Rootfs: ${unpack.vfs.fileCount} objects")

        val facts = FirmwareFacts.extract(unpack.vfs, identity)
        val emulation = FirmwareEmulator(unpack, facts, identity, progress, timeBudgetMs).run()
        progress.onProgress(90, "Emulation finished: ${emulation.commandsRun} shell steps")

        val inventory = WebUiLab.inventory(unpack.vfs, facts)
        val features = HardwareMatrix.evaluate(identity, facts, unpack, emulation, device)
        val findings = Heuristics.findings(identity, facts, unpack)
        val score = HardwareMatrix.score(features)
        // "Nothing could be read" must not be reported as a hardware mismatch: the rows already say
        // "needs verification", and the verdict follows the same rule.
        val verdict = HardwareMatrix.verdict(features, unpack.inspected)
        val nextSteps = HardwareMatrix.nextSteps(features, device, emulation, unpack)

        val report = EngineReport(
            identity = identity,
            findings = findings,
            emulation = emulation,
            features = features,
            device = device,
            riskScore = score,
            verdict = verdict,
            nextSteps = nextSteps,
        )
        progress.onProgress(96, "Report ready: ${verdict.display}")
        return LabSession(fileName, identity, unpack, facts, emulation, inventory, report)
    }
}

/** Everything one analysis produced, plus the emulated web UI server handle. */
class LabSession(
    val fileName: String,
    val identity: ImageIdentity,
    val unpack: UnpackResult,
    val facts: FirmwareFacts,
    val emulation: EmulationResult,
    val inventory: WebUiLab.Inventory,
    val report: EngineReport,
) {
    private var server: WebUiLab.Server? = null
    var probeResult: ProbeResult? = null

    /** Serves the image's own web files byte-for-byte on loopback for the WebView (read-only static preview, no login). */
    fun startWebUi(defaultUser: String = "admin", defaultPass: String = "admin"): WebUiLab.Server {
        stopWebUi()
        val s = WebUiLab.Server(unpack.vfs, inventory, facts, defaultUser to defaultPass)
        s.eventSink = webUiEventSink
        return if (s.start()) {
            server = s
            s
        } else {
            s
        }
    }

    fun stopWebUi() {
        server?.stop()
        server = null
    }

    /**
     * App-level sink for static-preview web-server events (started/stopped).
     * Set by the app so the full run log also covers the preview server.
     */
    var webUiEventSink: ((String) -> Unit)? = null
        set(value) {
            field = value
            server?.eventSink = value
        }

    val webUiUrl: String? get() = server?.let { if (it.port > 0) it.baseUrl else null }

    val requestsServedByEmulator: Int get() = server?.requestCount?.get() ?: 0

    fun jsonReport(): String = Report.toJson(report, facts, inventory, probeResult)

    fun markdownReport(): String = Report.toMarkdown(report, facts, inventory, emulation, probeResult)

    /** Human one-liner for the summary card. */
    fun headline(): String = buildString {
        append(identity.primary.label)
        if (identity.model != null) append(" - ").append(identity.model)
        append(" | ").append(report.verdict.display)
    }

    /** Current state of the static-preview web server as report lines (empty when never started). */
    fun webServerStatusLines(): List<String> {
        val s = server ?: return emptyList()
        return buildList {
            add(if (s.port > 0) "Running: http://127.0.0.1:${s.port}/  (static preview, read-only, ${s.requestCount.get()} request(s) served)" else "Started but not listening")
            add("Entry URL: ${s.loginUrl}")
            val reqs = s.requestLogSnapshot()
            if (reqs.isEmpty()) add("No requests served yet.")
            else {
                add("Request log (${reqs.size} most recent):")
                for (r in reqs) add("  $r")
            }
        }
    }

    /**
     * The complete copyable diagnostics bundle: safety report + all logs + watchdog results.
     * The app appends its own run log on top (see [Diagnostics.bundle]).
     */
    fun diagnosticsText(): String = Diagnostics.build(this, webServerStatusLines())
}
