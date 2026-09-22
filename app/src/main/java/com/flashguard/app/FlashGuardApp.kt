package com.flashguard.app

import android.app.Application

/**
 * Installs the global crash recorder: any uncaught exception is written into the run log and into
 * preferences (the process dies right after), so the Diagnostics screen can show the user exactly
 * what happened even after a restart - and they can paste it into a bug report.
 */
class FlashGuardApp : Application() {

    override fun onCreate() {
        super.onCreate()
        AppLog.i("app", "FlashGuard starting (pid ${android.os.Process.myPid()})")
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                AppLog.e("crash", "UNCAUGHT exception on thread '${thread.name}'", throwable)
                val prefs = Prefs(this)
                prefs.lastCrash = "${throwable.javaClass.name}: ${throwable.message}\n" +
                    throwable.stackTraceToString().take(6000)
                prefs.lastCrashAt = System.currentTimeMillis()
            } catch (_: Throwable) {
                // Never let the recorder break the crash path.
            }
            previous?.uncaughtException(thread, throwable)
        }
    }
}
