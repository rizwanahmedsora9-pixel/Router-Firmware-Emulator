package com.flashguard.app

import android.annotation.SuppressLint
import android.app.AlertDialog
import android.os.Bundle
import android.text.InputType
import android.webkit.HttpAuthHandler
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.webkit.WebViewDatabase
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.flashguard.app.databinding.ActivityEmulatorBinding

/**
 * Shows the firmware's own web UI (including its login page) served from the loopback emulator.
 * All requests stay on 127.0.0.1: the WebView is blocked from reaching anything else.
 *
 * Like a real router, the emulated UI asks for a username and password first: the server answers
 * the first request with a 401 challenge, and [onReceivedHttpAuthRequest] turns that into the
 * familiar native sign-in popup (factory default admin / admin).
 */
class EmulatorActivity : AppCompatActivity() {

    private lateinit var b: ActivityEmulatorBinding
    private lateinit var server: com.flashguard.engine.emu.WebUiLab.Server
    private var authDialog: AlertDialog? = null
    private var authAttempts = 0

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
        // Every boot asks again, like power-cycling a real router: drop any cached login.
        try {
            WebViewDatabase.getInstance(this).clearHttpAuthUsernamePassword()
        } catch (_: Throwable) {
        }
        val base = server.baseUrl
        val loginPath = session.inventory.loginPage?.removePrefix("/") ?: ""
        val home = base + loginPath

        b.textEmuTitle.text = session.fileName.ifBlank { "Firmware web UI" }
        b.textEmuStatus.text = "Loopback ${server.baseUrl}  •  router login admin / admin  •  " +
            "${session.inventory.features.size} feature groups  •  ${session.inventory.routes.size} pages found"

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

            /**
             * The router-style login popup: fired by the server's 401 challenge on boot and on
             * every "Login page" press (which logs out first). Wrong credentials make the
             * server challenge again, exactly like a real router.
             */
            override fun onReceivedHttpAuthRequest(view: WebView, handler: HttpAuthHandler, host: String, realm: String) {
                if (authDialog?.isShowing == true) {
                    // The popup is already up: fail this extra request instead of stacking
                    // dialogs or leaving the handler hanging.
                    handler.cancel()
                    return
                }
                authAttempts++
                val userInput = EditText(this@EmulatorActivity).apply {
                    hint = "Username"
                    inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                    setText("admin")
                }
                val passInput = EditText(this@EmulatorActivity).apply {
                    hint = "Password"
                    inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                }
                val layout = LinearLayout(this@EmulatorActivity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(48, 24, 48, 8)
                    addView(userInput)
                    addView(passInput)
                }
                val message = if (authAttempts > 1) {
                    "Wrong username or password. Try again (factory default admin / admin)."
                } else {
                    "\"$realm\" requires a username and password (factory default admin / admin)."
                }
                authDialog = AlertDialog.Builder(this@EmulatorActivity)
                    .setTitle("Sign in to the emulated router")
                    .setMessage(message)
                    .setView(layout)
                    .setCancelable(false)
                    .setPositiveButton("Sign in") { _, _ ->
                        handler.proceed(userInput.text.toString(), passInput.text.toString())
                    }
                    .setNegativeButton("Cancel") { _, _ ->
                        handler.cancel()
                        b.textEmuStatus.text = "Login cancelled - nothing was sent anywhere. Tap “Login page” to try again (admin / admin)."
                    }
                    .create()
                    .also { it.show() }
                passInput.requestFocus()
            }

            override fun onReceivedHttpError(view: WebView, request: WebResourceRequest, errorResponse: WebResourceResponse) {
                if (request.isForMainFrame && errorResponse.statusCode == 401) {
                    b.textEmuStatus.text = "The emulated router asked for a login and got none. Tap “Login page” to sign in (admin / admin)."
                }
            }
        }
        // "Login page" always starts from a logged-out state, so it replays the boot-time
        // popup on demand (handy for retrying or demonstrating the login).
        b.btnEmuLogin.setOnClickListener {
            try {
                WebViewDatabase.getInstance(this).clearHttpAuthUsernamePassword()
            } catch (_: Throwable) {
            }
            authAttempts = 0
            web.loadUrl(home)
            Toast.makeText(this, "Logged out - the router asks for the login again.", Toast.LENGTH_SHORT).show()
        }
        b.btnEmuConsole.setOnClickListener { web.loadUrl(base + "__flashguard/console") }
        b.btnEmuReload.setOnClickListener { web.reload() }
        if (intent.getBooleanExtra("console", false)) {
            web.loadUrl(base + "__flashguard/console")
        } else {
            web.loadUrl(home)
        }
    }

    override fun onDestroy() {
        try {
            authDialog?.dismiss()
        } catch (_: Throwable) {
        }
        authDialog = null
        super.onDestroy()
        // The server is owned by the session so the dashboard can keep serving it; only stop the WebView.
        try {
            b.webview.destroy()
        } catch (_: Throwable) {
        }
    }
}
