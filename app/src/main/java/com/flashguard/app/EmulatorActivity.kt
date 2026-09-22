package com.flashguard.app

import android.annotation.SuppressLint
import android.os.Bundle
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import com.flashguard.app.databinding.ActivityEmulatorBinding

/**
 * Shows the firmware's own web files (including its login page, when it ships a real HTML form)
 * served byte-for-byte from the loopback static-preview server.
 * All requests stay on 127.0.0.1: the WebView is blocked from reaching anything else.
 *
 * Honesty: there is no login step (static preview cannot authenticate), no invented data and no
 * modified pages. Handler URLs show a notice instead of a faked response.
 */
class EmulatorActivity : AppCompatActivity() {

    private lateinit var b: ActivityEmulatorBinding
    private lateinit var server: com.flashguard.engine.emu.WebUiLab.Server

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityEmulatorBinding.inflate(layoutInflater)
        setContentView(b.root)

        val session = LabHolder.session ?: run {
            finish()
            return
        }
        AppLog.i("emu-web", "Static preview screen opened (index=${intent.getBooleanExtra("console", false)})")
        server = session.startWebUi()
        if (server.port <= 0) {
            AppLog.e("emu-web", "Loopback preview server failed to start from the preview screen")
            b.textEmuStatus.text = "Could not start the loopback preview server."
            return
        }
        val base = server.baseUrl
        // The image's own login page when it ships a real HTML login form, otherwise the honest
        // file index. Nothing is ever invented here.
        val home = base + server.loginUrl.removePrefix("/")

        b.textEmuTitle.text = session.fileName.ifBlank { "Firmware web preview" }
        b.textEmuStatus.text = "Loopback ${server.baseUrl}  •  ${session.inventory.routes.size} pages in ${session.inventory.features.size} folders  •  read-only, no login"

        val web = b.webview
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = false
        web.settings.allowContentAccess = false
        web.settings.loadsImagesAutomatically = true
        web.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val host = request.url.host ?: return true
                // Only the preview server itself may be loaded - never a real network address.
                return if (host == "127.0.0.1" || host == "localhost") {
                    false
                } else {
                    AppLog.w("emu-web", "Blocked external navigation to $host (preview stays on this device)")
                    b.textEmuStatus.text = "Blocked external navigation to ${request.url.host} (preview stays on this device)."
                    true
                }
            }
        }
        b.btnEmuLogin.setOnClickListener {
            AppLog.i("emu-web", "Entry page reloaded ($home)")
            web.loadUrl(home)
        }
        b.btnEmuConsole.setOnClickListener { web.loadUrl(base + "__flashguard/index") }
        b.btnEmuReload.setOnClickListener { web.reload() }
        if (intent.getBooleanExtra("console", false)) {
            web.loadUrl(base + "__flashguard/index")
        } else {
            web.loadUrl(home)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // The server is owned by the session so the dashboard can keep serving it; only stop the WebView.
        b.webview.destroy()
    }
}
