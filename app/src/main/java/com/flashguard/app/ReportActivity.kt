package com.flashguard.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.flashguard.app.databinding.ActivityReportBinding

/** Full report viewer: Markdown for humans, JSON for tooling, plus share/copy. */
class ReportActivity : AppCompatActivity() {

    private lateinit var b: ActivityReportBinding
    private var showingJson = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityReportBinding.inflate(layoutInflater)
        setContentView(b.root)
        if (LabHolder.session == null) {
            finish()
            return
        }
        render()
        b.btnToggleFormat.setOnClickListener {
            showingJson = !showingJson
            b.btnToggleFormat.text = if (showingJson) "Show Markdown" else "Show JSON"
            AppLog.i("report", "Report format switched to ${if (showingJson) "JSON" else "Markdown"}")
            render()
        }
        b.btnCopy.setOnClickListener {
            val text = body()
            (getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                .setPrimaryClip(ClipData.newPlainText("FlashGuard report", text))
            AppLog.i("report", "Report copied (${if (showingJson) "JSON" else "Markdown"}, ${text.length} chars)")
            Toast.makeText(this, "Report copied (${text.length} chars).", Toast.LENGTH_SHORT).show()
        }
        b.btnShare.setOnClickListener {
            val text = body()
            AppLog.i("report", "Report shared (${if (showingJson) "JSON" else "Markdown"}, ${text.length} chars)")
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_SUBJECT, "FlashGuard report - ${LabHolder.fileName}")
                putExtra(Intent.EXTRA_TEXT, text)
            }
            startActivity(Intent.createChooser(intent, "Share FlashGuard report"))
        }
        b.btnDiagnostics.setOnClickListener {
            startActivity(Intent(this, DiagnosticsActivity::class.java))
        }
    }

    private fun body(): String {
        val session = LabHolder.session ?: return ""
        return if (showingJson) session.jsonReport() else session.markdownReport()
    }

    private fun render() {
        b.textReportBody.text = body()
    }
}
