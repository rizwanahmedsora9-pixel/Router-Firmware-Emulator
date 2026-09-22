package com.flashguard.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.flashguard.app.databinding.ActivityDiagnosticsBinding
import com.flashguard.engine.analysis.Diagnostics

/**
 * One copyable bundle with everything: the safety check report (verdict, hardware matrix,
 * findings), the complete emulation/boot logs, the web UI inventory, the emulated server request
 * log, every extraction warning, the live-router watchdog results (each request with status and
 * latency) and the app run log including errors and crashes.
 *
 * Built for exactly one job: test a firmware, then hand a well-formed report to the developer.
 */
class DiagnosticsActivity : AppCompatActivity() {

    private lateinit var b: ActivityDiagnosticsBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityDiagnosticsBinding.inflate(layoutInflater)
        setContentView(b.root)
        AppLog.i("diag", "Diagnostics screen opened")
        refresh()

        b.btnRefresh.setOnClickListener { refresh() }
        b.btnCopy.setOnClickListener {
            val text = compose()
            (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                .setPrimaryClip(ClipData.newPlainText("FlashGuard diagnostics", text))
            AppLog.i("diag", "Diagnostics copied to clipboard (${text.length} chars)")
            Toast.makeText(this, "Full diagnostics copied (${text.length} chars). Paste it anywhere.", Toast.LENGTH_LONG).show()
        }
        b.btnShare.setOnClickListener {
            val text = compose()
            AppLog.i("diag", "Diagnostics shared (${text.length} chars)")
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_SUBJECT, "FlashGuard diagnostics - ${LabHolder.fileName.ifBlank { "no firmware" }}")
                putExtra(Intent.EXTRA_TEXT, text)
            }
            startActivity(Intent.createChooser(intent, "Share full diagnostics"))
        }
        b.btnClear.setOnClickListener {
            AppLog.clear()
            AppLog.i("diag", "Run log cleared by user")
            refresh()
        }
    }

    private fun refresh() {
        val text = compose()
        b.textDiagnostics.text = text
        b.textDiagSummary.text = buildString {
            append("Safety report + watchdog: ${LabHolder.session?.let { "ready" } ?: "no session yet"}")
            append("  •  run log: ${AppLog.size()} event(s)")
            LabHolder.session?.probeResult?.let { append("  •  watchdog: ${if (it.reachable) if (it.stable) "STABLE" else "UNSTABLE" else "unreachable"}") }
        }
    }

    private fun compose(): String {
        val report = LabHolder.session?.diagnosticsText()
            ?: "(No safety-test session yet. Load a firmware on the Analyze tab and run the safety test -\n" +
                "the full report, boot logs and watchdog results will be part of this bundle.)\n"
        return Diagnostics.bundle(report, AppLog.lastCrashNote(this) + AppLog.dump())
    }
}
