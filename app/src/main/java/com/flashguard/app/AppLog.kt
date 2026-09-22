package com.flashguard.app

import android.content.Context
import java.text.SimpleDateFormat
import java.util.ArrayDeque
import java.util.Date
import java.util.Locale

/**
 * In-memory run log for everything the app does: firmware loads, analysis progress, emulation and
 * web-server events, live-check (watchdog) results, warnings, errors with stack traces and crashes.
 *
 * It exists so the user can copy ONE block of text (see DiagnosticsActivity) and send a complete,
 * well-formed bug report - no adb, no logcat knowledge required. The buffer is bounded; the oldest
 * lines drop first. Nothing in it ever leaves the device until the user copies/shares it.
 */
object AppLog {

    private const val MAX_ENTRIES = 6000
    private val entries = ArrayDeque<String>(MAX_ENTRIES)
    private val lock = Any()
    private val fmt = SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US)
    private var startedAt = System.currentTimeMillis()

    fun i(tag: String, message: String) = add("I", tag, message)
    fun w(tag: String, message: String) = add("W", tag, message)

    fun e(tag: String, message: String, t: Throwable? = null) {
        add("E", tag, buildString {
            append(message)
            t?.let { append(" -> ").append(it.javaClass.name).append(": ").append(it.message) }
        })
        t?.let { add("E", tag, it.stackTraceToString().take(6000)) }
    }

    private fun add(level: String, tag: String, message: String) {
        val ts = fmt.format(Date())
        val body = message.replace("\n", "\n    ")
        synchronized(lock) {
            entries.addLast("$ts $level/$tag: $body")
            while (entries.size > MAX_ENTRIES) entries.removeFirst()
        }
    }

    fun clear() = synchronized(lock) { entries.clear() }

    fun size(): Int = synchronized(lock) { entries.size }

    /** The whole log as one copyable block. */
    fun dump(): String = synchronized(lock) {
        buildString {
            append("Captured ${entries.size} event(s) since ${fmt.format(Date(startedAt))}.\n")
            for (line in entries) append(line).append('\n')
        }
    }

    /**
     * The crash recorded by the global handler, if the previous app run ended in one. Kept in
     * SharedPreferences because the process (and this object) dies with the crash.
     */
    fun lastCrashNote(context: Context): String {
        val prefs = Prefs(context)
        val crash = prefs.lastCrash ?: return ""
        val at = prefs.lastCrashAt
        val whenText = if (at > 0) fmt.format(Date(at)) else "unknown time"
        return buildString {
            append("!! PREVIOUS RUN ENDED IN A CRASH ($whenText) !!\n")
            append("    ").append(crash.replace("\n", "\n    ")).append('\n')
        }
    }
}
