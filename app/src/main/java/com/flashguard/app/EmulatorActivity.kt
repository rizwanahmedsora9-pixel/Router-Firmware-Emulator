package com.flashguard.app

import android.annotation.SuppressLint
import android.os.Bundle
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import com.flashguard.app.databinding.ActivityEmulatorBinding

/**
 * Shows the firmware's own web UI (including its login page) served from the loopback emulator.
 * All requests stay on 127.0.0.1: the WebView is blocked from reaching anything else.
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
        server = session.startWebUi()
        if (server.port <= 0) {
            b.textEmuStatus.text = "Could not start the loopback web server."
            return
        }
        val base = server.baseUrl
        // The image's own login page when it ships one; otherwise the modelled login form
        // FlashGuard generates (the original httpd's login page is a native binary here).
        val home = base + server.loginUrl.removePrefix("/")

        b.textEmuTitle.text = session.fileName.ifBlank { "Firmware web UI" }
        b.textEmuStatus.text = "Loopback ${server.baseUrl}  •  ${session.inventory.features.size} feature groups  •  ${session.inventory.routes.size} pages found"

        val web = b.webview
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.settings.allowFileAccess = false
        web.settings.allowContentAccess = false
        web.settings.loadsImagesAutomatically = true
        web.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val host = request.url.host ?: return true
                // Only the emulator itself may be loaded - never a real network address.
                return if (host == "127.0.0.1" || host == "localhost") {
                    false
                } else {
                    b.textEmuStatus.text = "Blocked external navigation to ${request.url.host} (emulation stays on this device)."
                    true
                }
            }
        }
        b.btnEmuLogin.setOnClickListener { web.loadUrl(home) }
        b.btnEmuConsole.setOnClickListener { web.loadUrl(base + "__flashguard/console") }
        b.btnEmuReload.setOnClickListener { web.reload() }
        if (intent.getBooleanExtra("console", false)) {
            web.loadUrl(base + "__flashguard/console")
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
