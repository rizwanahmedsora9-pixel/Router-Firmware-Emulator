package com.flashguard.app

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

/** Temporary smoke-test activity; replaced by the real FlowGuard UI. */
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(TextView(this).apply {
            text = "FlashGuard scaffold OK"
            textSize = 18f
            setPadding(48, 96, 48, 48)
        })
    }
}
