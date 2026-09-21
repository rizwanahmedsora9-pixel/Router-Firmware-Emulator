package com.flashguard.app

import android.app.Activity
import android.content.Intent
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.flashguard.app.databinding.ActivityMainBinding
import com.flashguard.engine.FirmwareLab
import com.flashguard.engine.LabSession
import com.flashguard.engine.analysis.StabilityProbe
import com.flashguard.engine.core.BootStageNames
import com.flashguard.engine.core.FindingLevel
import com.flashguard.engine.core.ProbeResult
import com.flashguard.engine.device.DeviceDb
import com.flashguard.engine.tools.DemoFirmware
import com.flashguard.engine.util.Hex
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * The dashboard: pick a firmware file, pick your router, then run the whole safety pipeline
 * (identify -> unpack -> emulate the boot logic -> compatibility matrix -> report) on-device.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var b: ActivityMainBinding
    private lateinit var prefs: Prefs
    private var busy = false

    private val pickFile = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri != null) loadFirmware(uri)
    }

    private val pickDevice = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) refreshDeviceUi()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)
        prefs = Prefs(this)

        LabHolder.device = LabHolder.device ?: prefs.loadedDevice()
        b.inputRouterIp.setText(prefs.routerIp)

        b.btnPickFile.setOnClickListener { pickFile.launch(arrayOf("*/*")) }
        b.btnPickDevice.setOnClickListener { pickDevice.launch(Intent(this, DevicePickerActivity::class.java)) }
        b.btnDemoFile.setOnClickListener { loadDemo() }
        b.btnAnalyze.setOnClickListener { runAnalysis() }
        b.btnOpenMatrix.setOnClickListener { startActivity(Intent(this, MatrixActivity::class.java)) }
        b.btnOpenEmulator.setOnClickListener { openEmulator(console = false) }
        b.btnStartEmulator.setOnClickListener { startEmulatorServer() }
        b.btnOpenEmulatorFull.setOnClickListener { openEmulator(console = false) }
        b.btnStopEmulator.setOnClickListener { stopEmulatorServer() }
        b.btnRunProbe.setOnClickListener { runProbe() }
        b.btnShareReport.setOnClickListener { openReport() }
        b.reportFormat.setOnCheckedChangeListener { _, _ -> renderReport() }
        b.bottomNav.setOnItemSelectedListener { item -> showSection(item.itemId); true }
        b.bottomNav.selectedItemId = R.id.tab_analyze

        refreshDeviceUi()
        showSection(R.id.tab_analyze)
        LabHolder.session?.let { renderResults(it) }
    }

    override fun onResume() {
        super.onResume()
        refreshDeviceUi()
    }

    override fun onDestroy() {
        super.onDestroy()
        // Keep the emulation server only while this screen exists.
        LabHolder.session?.stopWebUi()
    }

    // ------------------------------------------------------------------ sections

    private fun showSection(itemId: Int) {
        b.sectionAnalyze.visibility = if (itemId == R.id.tab_analyze) View.VISIBLE else View.GONE
        b.sectionDevice.visibility = if (itemId == R.id.tab_device) View.VISIBLE else View.GONE
        b.sectionEmulator.visibility = if (itemId == R.id.tab_emulator) View.VISIBLE else View.GONE
        b.sectionLive.visibility = if (itemId == R.id.tab_live) View.VISIBLE else View.GONE
        b.sectionReport.visibility = if (itemId == R.id.tab_report) View.VISIBLE else View.GONE
    }

    private fun refreshDeviceUi() {
        val device = LabHolder.device
        b.textDeviceChip.text = if (device == null) {
            "No router selected - open “My router”"
        } else {
            "Target: ${device.display}  |  ${device.cpuFamily.display}  |  ${device.flashMb} MB ${device.flashType}"
        }
        b.textDeviceName.text = device?.display ?: "Nothing selected"
        b.deviceSpecsContainer.removeAllViews()
        if (device == null) {
            addSpec("Pick your exact model (and revision) so FlashGuard can compare it with the image.")
        } else {
            addSpec("SoC: ${device.soc}")
            addSpec("CPU: ${device.cpuFamily.display}, ${device.cpuCores} core(s) @ ${device.cpuMhz} MHz")
            addSpec("RAM: ${device.ramMb} MB   Flash: ${device.flashMb} MB ${device.flashType}")
            addSpec("Layout: ${device.flashLayout}")
            addSpec("Bootloader: ${device.bootloader}")
            if (device.wifiChips.isNotEmpty()) addSpec("Wi-Fi: ${device.wifiChips.joinToString(", ")}")
            if (device.extraFeatures.isNotEmpty()) addSpec("Extra: ${device.extraFeatures.joinToString(", ")}")
            addSpec("OpenWrt support: ${device.openwrtSupport}")
            addSpec("Recovery: ${device.recovery}")
            if (device.notes.isNotBlank()) addSpec(device.notes)
            addSpec("Always confirm the revision printed on the router label before flashing.")
        }
        b.btnAnalyze.isEnabled = LabHolder.fileBytes != null && device != null && !busy
    }

    private fun addSpec(text: String) {
        val tv = TextView(this)
        tv.text = "• $text"
        tv.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
        tv.textSize = 12f
        val lp = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)
        lp.topMargin = dp(4)
        tv.layoutParams = lp
        b.deviceSpecsContainer.addView(tv)
    }

    private fun dp(v: Int): Int = (v * resources.displayMetrics.density).toInt()

    // ------------------------------------------------------------------ firmware loading

    private fun loadFirmware(uri: Uri) {
        lifecycleScope.launch {
            setBusy(true, "Reading firmware file…", 2)
            val result = withContext(Dispatchers.IO) {
                try {
                    val name = queryName(uri) ?: "firmware.bin"
                    val size = contentResolver.openAssetFileDescriptor(uri, "r")?.use { it.length } ?: -1L
                    if (size > MAX_FILE_BYTES) {
                        return@withContext Pair<String, ByteArray?>("TOO_BIG:$name:$size", null)
                    }
                    val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                    Pair(name, bytes)
                } catch (e: IOException) {
                    Pair("ERROR:${e.message}", null)
                }
            }
            setBusy(false)
            val (name, bytes) = result
            when {
                name.startsWith("TOO_BIG:") -> {
                    val parts = name.split(":")
                    toast("That file is ${parts.getOrNull(2)?.toLongOrNull()?.let { Hex.humanBytes(it) }} - larger than the ${Hex.humanBytes(MAX_FILE_BYTES)} in-app limit.")
                }
                bytes == null -> toast("Could not read that file (${name.removePrefix("ERROR:")})")
                bytes.isEmpty() -> toast("That file is empty.")
                else -> {
                    LabHolder.fileBytes = bytes
                    LabHolder.fileName = name
                    LabHolder.usingDemoImage = false
                    LabHolder.clearAnalysis()
                    b.textFileName.text = "$name\n${Hex.humanBytes(bytes.size.toLong())} - ready to test"
                    refreshDeviceUi()
                    toast("Loaded ${Hex.humanBytes(bytes.size.toLong())}. Now run the safety test.")
                }
            }
        }
    }

    private fun queryName(uri: Uri): String? {
        return try {
            contentResolver.query(uri, null, null, null, null)?.use { c ->
                val idx = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun loadDemo() {
        lifecycleScope.launch {
            setBusy(true, "Building the built-in demo image…", 4)
            val bytes = withContext(Dispatchers.Default) { DemoFirmware.build() }
            setBusy(false)
            LabHolder.fileBytes = bytes
            LabHolder.fileName = DemoFirmware.DISPLAY_NAME
            LabHolder.usingDemoImage = true
            LabHolder.clearAnalysis()
            b.textFileName.text = "${DemoFirmware.DISPLAY_NAME}\n${Hex.humanBytes(bytes.size.toLong())} - built-in demo (not a real router firmware)"
            refreshDeviceUi()
            toast("Demo image ready - it is synthetic, safe and shows the whole pipeline.")
        }
    }

    // ------------------------------------------------------------------ analysis

    private fun runAnalysis() {
        val bytes = LabHolder.fileBytes ?: return toast("Choose a firmware file first.")
        val device = LabHolder.device ?: return toast("Pick your router model first (tab: My router).")

        lifecycleScope.launch {
            setBusy(true, "Starting…", 0)
            LabHolder.session?.stopWebUi()
            LabHolder.session = null
            try {
                val session = withContext(Dispatchers.Default) {
                    FirmwareLab.analyze(bytes, LabHolder.fileName, device) { pct, message ->
                        runOnUiThread {
                            b.scanProgress.progress = pct
                            b.textProgress.text = message
                        }
                    }
                }
                LabHolder.session = session
                setBusy(false)
                renderResults(session)
                b.bottomNav.selectedItemId = R.id.tab_analyze
                toast(if (session.report.redFlags().isNotEmpty()) "Finished - RED flags found, read them before flashing." else "Finished - report ready.")
            } catch (t: Throwable) {
                setBusy(false)
                toast("Analysis failed: ${t.message ?: t.javaClass.simpleName}")
            }
        }
    }

    private fun setBusy(busyNow: Boolean, message: String = "", progress: Int = 0) {
        busy = busyNow
        b.progressBox.visibility = if (busyNow) View.VISIBLE else View.GONE
        b.btnAnalyze.isEnabled = !busyNow && LabHolder.fileBytes != null && LabHolder.device != null
        b.btnPickFile.isEnabled = !busyNow
        if (busyNow) {
            b.scanProgress.progress = progress
            b.textProgress.text = message
        }
    }

    private fun renderResults(session: LabSession) {
        b.verdictBanner.visibility = View.VISIBLE
        val red = session.report.redFlags().size
        b.textVerdict.text = "${session.report.verdict.display}   (risk ${session.report.riskScore}/100)"
        b.verdictBanner.setBackgroundResource(
            when {
                red > 0 -> R.drawable.bg_verdict_red
                session.report.riskScore > 15 -> R.drawable.bg_verdict_amber
                else -> R.drawable.bg_verdict_green
            }
        )
        b.textVerdictDetail.text = buildString {
            append("${red} hardware-incompatible feature(s), ")
            append("${session.report.features.size} checks, ")
            append("${session.unpack.vfs.fileCount} objects extracted")
            if (LabHolder.usingDemoImage) append("  •  built-in demo image")
        }
        b.textIdentity.text = buildString {
            append(session.identity.summary())
            append("\n")
            append("confidence ${session.identity.confidence}%  •  ${Hex.humanBytes(session.identity.totalSize)}  •  sha256 ${session.identity.sha256.take(16)}…")
            session.facts.distro?.let { append("\n$it ${session.facts.firmwareVersion ?: ""}  target ${session.facts.target ?: "-"} / ${session.facts.arch ?: "-"}") }
        }

        // boot chain
        b.stagesContainer.removeAllViews()
        for (stage in session.emulation.stages) {
            val tv = TextView(this)
            tv.text = "${if (stage.ok) "✔" else "✘"}  ${stage.name}\n${stage.detail}"
            tv.setTextColor(ContextCompat.getColor(this, if (stage.ok) R.color.ok_green else R.color.bad_red))
            tv.textSize = 12f
            tv.setPadding(0, dp(4), 0, dp(4))
            b.stagesContainer.addView(tv)
        }
        val extra = TextView(this)
        extra.text = "${session.emulation.commandsRun} shell steps in ${session.emulation.elapsedMs} ms  •  " +
            "${session.emulation.services.size} service(s) simulated  •  " +
            "web root ${session.emulation.webRoot ?: "n/a"}  •  login page ${session.emulation.loginPage ?: "not found"}"
        extra.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
        extra.textSize = 11f
        extra.setPadding(0, dp(6), 0, 0)
        b.stagesContainer.addView(extra)
        session.emulation.notes.take(4).forEach { note ->
            val tv = TextView(this)
            tv.text = "• $note"
            tv.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
            tv.textSize = 11f
            b.stagesContainer.addView(tv)
        }

        // findings
        b.findingsContainer.removeAllViews()
        for (f in session.report.findings.sortedByDescending { it.level.ordinal }.take(14)) {
            val tv = TextView(this)
            val mark = when (f.level) {
                FindingLevel.ERROR -> "✘"
                FindingLevel.WARN -> "!"
                FindingLevel.OK -> "✔"
                FindingLevel.INFO -> "i"
            }
            tv.text = "$mark  ${f.title}\n${f.detail}"
            tv.setTextColor(
                ContextCompat.getColor(
                    this,
                    when (f.level) {
                        FindingLevel.ERROR -> R.color.bad_red
                        FindingLevel.WARN -> R.color.warn_amber
                        FindingLevel.OK -> R.color.ok_green
                        FindingLevel.INFO -> R.color.text_secondary
                    },
                )
            )
            tv.textSize = 12f
            tv.setPadding(0, dp(4), 0, dp(4))
            b.findingsContainer.addView(tv)
        }

        b.btnOpenMatrix.isEnabled = true
        b.btnOpenEmulator.isEnabled = true
        b.btnStartEmulator.isEnabled = true
        b.btnStopEmulator.isEnabled = true
        b.btnOpenEmulatorFull.isEnabled = true

        // boot log
        b.textBootLog.text = session.emulation.bootLog.joinToString("\n").ifBlank { "No boot log produced." }
        b.textEmulatorStatus.text = "Ready. Web root: ${session.emulation.webRoot ?: "n/a"}, login page: ${session.emulation.loginPage ?: "not found"}."
        renderReport()
        refreshDeviceUi()
    }

    private fun renderReport() {
        val session = LabHolder.session ?: return
        val json = b.radioJson.isChecked
        b.textReport.text = if (json) {
            session.jsonReport()
        } else {
            session.markdownReport()
        }
    }

    // ------------------------------------------------------------------ emulator server

    private fun startEmulatorServer() {
        val session = LabHolder.session ?: return toast("Run the safety test first.")
        lifecycleScope.launch {
            val server = withContext(Dispatchers.IO) { session.startWebUi() }
            if (server.port <= 0) {
                toast("Could not start the loopback web server.")
                return@launch
            }
            b.textEmulatorStatus.text = "Running on ${server.baseUrl}\n" +
                "Doc root: ${session.inventory.docRoot ?: "n/a"}  •  login page: ${session.inventory.loginPage ?: "none"}\n" +
                "Features found: ${session.inventory.features.size} groups, ${session.inventory.routes.size} pages"
            b.btnOpenEmulatorFull.isEnabled = true
            toast("Emulated web UI is up (loopback only).")
        }
    }

    private fun stopEmulatorServer() {
        LabHolder.session?.stopWebUi()
        b.textEmulatorStatus.text = "Stopped."
    }

    private fun openEmulator(console: Boolean) {
        val session = LabHolder.session ?: return toast("Run the safety test first.")
        val server = session.startWebUi()
        if (server.port <= 0) return toast("Could not start the emulated web server.")
        startActivity(
            Intent(this, EmulatorActivity::class.java).apply {
                putExtra("console", console)
            }
        )
    }

    // ------------------------------------------------------------------ live probe

    private fun runProbe() {
        val host = b.inputRouterIp.text.toString().trim().ifBlank { "192.168.1.1" }
        prefs.routerIp = host
        val tryCreds = b.checkDefaultCreds.isChecked
        lifecycleScope.launch {
            b.probeBox.visibility = View.VISIBLE
            b.textProbeSummary.text = "Contacting $host (read-only)…"
            b.probeFeaturesContainer.removeAllViews()
            val result = withContext(Dispatchers.IO) { StabilityProbe.probe(host, tryDefaultCreds = tryCreds) }
            LabHolder.session?.probeResult = result
            renderProbe(result)
            renderReport()
        }
    }

    private fun renderProbe(p: ProbeResult) {
        b.probeBox.visibility = View.VISIBLE
        b.textProbeSummary.text = buildString {
            append(if (p.reachable) "Reachable" else "Not reachable")
            append("  •  server: ${p.serverHeader ?: "unknown"}")
            append("  •  auth: ${p.authScheme}")
            append("\nLogin page: ${if (p.loginPageFound) "found" else "not found"}")
            p.defaultCredsWorked?.let { append("  •  default credentials work: $it") }
            append("\n${p.requests} requests, ${p.errors} error(s), latency p50 ${p.p50} ms / p95 ${p.p95} ms")
            append("\nStability: ${if (p.stable) "STABLE ✔" else "UNSTABLE ✘"}")
            if (p.afterLoginFeatures.isNotEmpty()) append("\nFeatures answering: ${p.afterLoginFeatures.size}")
        }
        b.probeFeaturesContainer.removeAllViews()
        for (f in p.afterLoginFeatures.take(25)) {
            val tv = TextView(this)
            tv.text = "• ${f.name}  [${f.status}]  ${f.path}  (${f.bytes} B, ${f.ms} ms)"
            tv.setTextColor(ContextCompat.getColor(this, if (f.status in 200..399) R.color.ok_green else R.color.warn_amber))
            tv.textSize = 11f
            b.probeFeaturesContainer.addView(tv)
        }
        for (n in p.notes) {
            val tv = TextView(this)
            tv.text = "! $n"
            tv.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
            tv.textSize = 11f
            b.probeFeaturesContainer.addView(tv)
        }
    }

    private fun openReport() {
        if (LabHolder.session == null) return toast("Run the safety test first.")
        startActivity(Intent(this, ReportActivity::class.java))
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    companion object {
        /** Keeps a phone from trying to load a 500 MB SD-card image into RAM. */
        const val MAX_FILE_BYTES = 64L * 1024 * 1024
    }
}
