package com.flashguard.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.flashguard.app.databinding.ActivityLoginBinding

/**
 * The app's own login screen (the firmware's login page appears separately, inside the emulator).
 * It is a local convenience gate only: credentials never leave the device.
 */
class LoginActivity : AppCompatActivity() {

    private lateinit var b: ActivityLoginBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(b.root)
        val prefs = Prefs(this)
        b.inputUser.setText(prefs.lockUser)
        b.btnUnlock.setOnClickListener {
            val user = b.inputUser.text.toString().trim()
            val pass = b.inputPass.text.toString()
            if (user == prefs.lockUser && pass == prefs.lockPass) {
                AppLog.i("app-lock", "App unlocked")
                prefs.lockEnabled = true
                startActivity(Intent(this, MainActivity::class.java))
                finish()
            } else {
                AppLog.w("app-lock", "Failed app unlock attempt (user '$user')")
                b.textLoginError.visibility = View.VISIBLE
                b.textLoginError.text = "Wrong username or password. Default is admin / admin (change it any time from the dashboard)."
            }
        }
        b.btnSkip.setOnClickListener {
            AppLog.i("app-lock", "App lock disabled by user")
            prefs.lockEnabled = false
            startActivity(Intent(this, MainActivity::class.java))
            finish()
        }
    }
}
