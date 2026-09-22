package com.flashguard.app

import android.content.Context
import com.flashguard.engine.LabSession
import com.flashguard.engine.core.DeviceProfile
import com.flashguard.engine.device.DeviceDb

/**
 * In-memory state shared between the screens: the firmware being tested, the selected router and
 * the running emulation server. Everything is dropped when the process dies - by design, since a
 * firmware blob should not linger on disk unless the user exports a report.
 */
object LabHolder {
    var device: DeviceProfile? = null
    var fileName: String = ""
    var fileBytes: ByteArray? = null
    var session: LabSession? = null

    /** True when the currently held bytes are the built-in demo image, not a real firmware file. */
    var usingDemoImage: Boolean = false

    fun clearAnalysis() {
        if (session != null) AppLog.i("state", "Analysis session cleared (emulator server stopped)")
        session?.stopWebUi()
        session = null
    }

    fun clearAll() {
        clearAnalysis()
        fileBytes = null
        fileName = ""
        usingDemoImage = false
        AppLog.i("state", "Loaded firmware cleared")
    }

    val bytes: ByteArray? get() = fileBytes

    fun sizeText(): String = fileBytes?.let { com.flashguard.engine.util.Hex.humanBytes(it.size.toLong()) } ?: "-"
}

/** Small persisted preferences: app lock + last used router. */
class Prefs(context: Context) {
    private val sp = context.getSharedPreferences("flashguard", Context.MODE_PRIVATE)

    var lockEnabled: Boolean
        get() = sp.getBoolean("lock_enabled", true)
        set(v) = sp.edit().putBoolean("lock_enabled", v).apply()

    var lockUser: String
        get() = sp.getString("lock_user", "admin") ?: "admin"
        set(v) = sp.edit().putString("lock_user", v).apply()

    var lockPass: String
        get() = sp.getString("lock_pass", "admin") ?: "admin"
        set(v) = sp.edit().putString("lock_pass", v).apply()

    var lastDeviceId: String?
        get() = sp.getString("device_id", null)
        set(v) = sp.edit().putString("device_id", v).apply()

    var routerIp: String
        get() = sp.getString("router_ip", "192.168.1.1") ?: "192.168.1.1"
        set(v) = sp.edit().putString("router_ip", v).apply()

    /** Text of the last crash, kept so the diagnostics screen can show it after a restart. */
    var lastCrash: String?
        get() = sp.getString("last_crash", null)
        set(v) = sp.edit().putString("last_crash", v).apply()

    var lastCrashAt: Long
        get() = sp.getLong("last_crash_at", 0L)
        set(v) = sp.edit().putLong("last_crash_at", v).apply()

    fun loadedDevice(): DeviceProfile? = lastDeviceId?.let { DeviceDb.byId(it) }
}
