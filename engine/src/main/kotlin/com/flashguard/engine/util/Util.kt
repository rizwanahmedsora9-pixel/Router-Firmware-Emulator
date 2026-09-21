package com.flashguard.engine.util

import java.nio.charset.Charset
import java.security.MessageDigest

/**
 * Hard safety limits. The engine runs on a phone, inside a sandbox, on untrusted vendor blobs,
 * so every loop that follows attacker-controlled data is bounded by one of these.
 */
object Limits {
    /** How deep we follow nested containers (tar -> gzip -> cpio -> ...). */
    const val MAX_LAYER_DEPTH = 6

    /** Total number of files we will materialise in the virtual rootfs. */
    const val MAX_FILES = 60_000

    /** Total bytes we will hold in the virtual rootfs (kernel blobs are hashed, not kept). */
    const val MAX_EXTRACT_BYTES = 48L * 1024 * 1024

    /** Single-file copy limit while extracting. */
    const val MAX_SINGLE_FILE = 32L * 1024 * 1024

    /** Maximum decompressed size allowed for one compression layer (zip-bomb guard). 1.5 GiB. */
    const val MAX_INFLATE_BYTES = 1536L * 1024 * 1024

    /** Instruction budget for the sandboxed shell interpreter. */
    const val MAX_SHELL_STEPS = 250_000

    /** Wall-clock budget for one emulated boot, milliseconds. */
    const val MAX_EMULATION_MS = 20_000L

    /** Loop-iteration budget inside the shell interpreter. */
    const val MAX_LOOP_ITERATIONS = 2_000

    /** Recursion depth for shell function calls / sourced scripts. */
    const val MAX_CALL_DEPTH = 32
}

/** Little/big-endian helpers over byte arrays. All bounds-checked by the caller's cursor. */
object Bin {
    fun u8(b: ByteArray, off: Int): Int = b[off].toInt() and 0xFF

    fun u16le(b: ByteArray, off: Int): Int = u8(b, off) or (u8(b, off + 1) shl 8)
    fun u16be(b: ByteArray, off: Int): Int = (u8(b, off) shl 8) or u8(b, off + 1)

    fun u32le(b: ByteArray, off: Int): Long =
        (u8(b, off).toLong()) or (u8(b, off + 1).toLong() shl 8) or
            (u8(b, off + 2).toLong() shl 16) or (u8(b, off + 3).toLong() shl 24)

    fun u32be(b: ByteArray, off: Int): Long =
        (u8(b, off).toLong() shl 24) or (u8(b, off + 1).toLong() shl 16) or
            (u8(b, off + 2).toLong() shl 8) or (u8(b, off + 3).toLong())

    fun u64le(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or u8(b, off + i).toLong()
        return v
    }

    fun u64be(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or u8(b, off + i).toLong()
        return v
    }

    /** Printable-ASCII view of a region; non-printables become '.'. */
    fun ascii(b: ByteArray, off: Int, len: Int): String {
        if (off < 0 || off >= b.size) return ""
        val end = minOf(b.size, off + len)
        val sb = StringBuilder(end - off)
        for (i in off until end) {
            val c = b[i].toInt() and 0xFF
            sb.append(if (c in 0x20..0x7E) c.toChar() else '.')
        }
        return sb.toString()
    }

    /** Trimmed, printable-only text (NUL padded strings typical for uImage names etc.). */
    fun cstr(b: ByteArray, off: Int, maxLen: Int = 64): String {
        val end = minOf(b.size, off + maxLen)
        var i = off
        val sb = StringBuilder()
        while (i < end) {
            val c = b[i].toInt() and 0xFF
            if (c == 0) break
            sb.append(if (c in 0x20..0x7E) c.toChar() else '.')
            i++
        }
        return sb.toString().trim()
    }

    fun indexOf(hay: ByteArray, needle: ByteArray, from: Int = 0): Int {
        if (needle.isEmpty() || hay.size < needle.size) return -1
        val start = maxOf(0, from)
        outer@ for (i in start..hay.size - needle.size) {
            for (j in needle.indices) {
                if (hay[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }

    fun indexOfAscii(hay: ByteArray, needle: String, from: Int = 0): Int =
        indexOf(hay, needle.toByteArray(Charsets.ISO_8859_1), from)

    fun containsAscii(hay: ByteArray, needle: String): Boolean = indexOfAscii(hay, needle) >= 0
}

/** Offset-addressable, bounds-safe view over a byte array (used for nested containers). */
class Slice(val data: ByteArray, val base: Long = 0L) {
    val size: Int get() = data.size
    fun u32le(off: Int): Long = if (off + 4 <= size) Bin.u32le(data, off) else -1L
    fun u32be(off: Int): Long = if (off + 4 <= size) Bin.u32be(data, off) else -1L
    fun u16le(off: Int): Int = if (off + 2 <= size) Bin.u16le(data, off) else -1
    fun u16be(off: Int): Int = if (off + 2 <= size) Bin.u16be(data, off) else -1
    fun u64le(off: Int): Long = if (off + 8 <= size) Bin.u64le(data, off) else -1L
    fun ascii(off: Int, len: Int): String =
        if (off in 0 until size) Bin.ascii(data, off, len) else ""

    fun copyRange(off: Int, len: Int): ByteArray {
        if (off < 0 || off >= size) return ByteArray(0)
        val end = minOf(size, off + maxOf(0, len))
        return data.copyOfRange(off, end)
    }

    fun sub(off: Int, len: Int): Slice {
        val c = copyRange(off, len)
        return Slice(c, base + off)
    }
}

object Hex {
    private val HEX = "0123456789abcdef".toCharArray()

    fun hex(b: ByteArray, off: Int = 0, len: Int = b.size): String {
        val end = minOf(b.size, off + len)
        val sb = StringBuilder((end - off) * 2)
        for (i in off until end) {
            val v = b[i].toInt() and 0xFF
            sb.append(HEX[v ushr 4]).append(HEX[v and 0x0F])
        }
        return sb.toString()
    }

    /** Classic xxd-style dump, capped at [maxLines]. */
    fun dump(b: ByteArray, offset: Int = 0, length: Int = 256, maxLines: Int = 16): String {
        val sb = StringBuilder()
        var line = 0
        var i = maxOf(0, offset)
        val end = minOf(b.size, offset + length)
        while (i < end && line < maxLines) {
            val chunkEnd = minOf(end, i + 16)
            val hexPart = StringBuilder()
            val asciiPart = StringBuilder()
            for (j in i until chunkEnd) {
                val v = b[j].toInt() and 0xFF
                hexPart.append(HEX[v ushr 4]).append(HEX[v and 0x0F]).append(' ')
                asciiPart.append(if (v in 0x20..0x7E) v.toChar() else '.')
            }
            sb.append(padHex(i.toString(16), 6)).append("  ")
            sb.append(hexPart.toString().padEnd(16 * 3 + 1))
            sb.append(asciiPart)
            sb.append('\n')
            i = chunkEnd
            line++
        }
        return sb.toString().trimEnd('\n')
    }

    private fun padHex(s: String, width: Int): String =
        if (s.length >= width) s else "0".repeat(width - s.length) + s

    fun humanBytes(n: Long): String {
        if (n < 1024) return "$n B"
        val units = arrayOf("KiB", "MiB", "GiB", "TiB")
        var v = n.toDouble() / 1024.0
        var idx = 0
        while (v >= 1024.0 && idx < units.size - 1) {
            v /= 1024.0
            idx++
        }
        return String.format(java.util.Locale.US, "%.2f %s", v, units[idx])
    }

    fun humanBytes(n: Int): String = humanBytes(n.toLong())
}

object Digests {
    fun md5(b: ByteArray): String = hash("MD5", b)
    fun sha256(b: ByteArray): String = hash("SHA-256", b)

    private fun hash(algo: String, b: ByteArray): String {
        val md = MessageDigest.getInstance(algo)
        return Hex.hex(md.digest(b))
    }
}

/** Entropy estimate in bits/byte (Shannon). Used to spot encrypted/compressed payloads. */
object Entropy {
    fun of(b: ByteArray): Double {
        if (b.isEmpty()) return 0.0
        val counts = IntArray(256)
        val step = if (b.size > 262_144) b.size / 262_144 else 1
        var sampled = 0
        var i = 0
        while (i < b.size) {
            counts[b[i].toInt() and 0xFF]++
            sampled++
            i += step
        }
        var h = 0.0
        for (c in counts) {
            if (c == 0) continue
            val p = c.toDouble() / sampled
            h -= p * (Math.log(p) / Math.log(2.0))
        }
        return h
    }
}

/** Extract printable ASCII (+ a little UTF-8-ish tolerance) strings, bounded. */
object Strings {
    fun extract(
        data: ByteArray,
        minLen: Int = 5,
        limit: Int = 4000,
        base: Long = 0L,
        charset: Charset = Charsets.ISO_8859_1,
        offset: Int = 0,
        length: Int = data.size,
    ): List<Pair<Long, String>> {
        val out = ArrayList<Pair<Long, String>>(minOf(limit, 512))
        val end = minOf(data.size, offset + length)
        val sb = StringBuilder()
        var start = -1
        var i = maxOf(0, offset)
        while (i < end && out.size < limit) {
            val c = data[i].toInt() and 0xFF
            val printable = c == 9 || (c in 0x20..0x7E) || c >= 0xA0
            if (printable) {
                if (start < 0) start = i
                sb.append(c.toChar())
            } else {
                if (sb.length >= minLen) out.add((base + start) to sb.toString())
                sb.setLength(0)
                start = -1
            }
            i++
        }
        if (sb.length >= minLen && out.size < limit) out.add((base + start) to sb.toString())
        return out
    }

    /** Version-ish / alphanumeric token search, e.g. "V1.0.3" or "3.0.0.4.380". */
    fun findFirst(text: String, patterns: List<Regex>): String? {
        for (p in patterns) {
            val m = p.find(text) ?: continue
            val g = m.groupValues.getOrNull(1) ?: m.value
            if (g.isNotBlank()) return m.value.trim()
        }
        return null
    }
}

/** Small helpers used all over the analyzers. */
object Text {
    fun slug(s: String): String =
        s.lowercase().replace(Regex("[^a-z0-9]+"), "-").trim('-').ifEmpty { "unknown" }

    fun truncate(s: String, max: Int): String =
        if (s.length <= max) s else s.take(max - 1) + "\u2026"

    fun normPath(p: String): String {
        var path = p.replace('\\', '/')
        while (path.contains("//")) path = path.replace("//", "/")
        if (!path.startsWith("/")) path = "/$path"
        // collapse ./ and ../ safely (no escaping above root)
        val parts = ArrayList<String>()
        for (seg in path.split('/')) {
            when (seg) {
                "", "." -> {}
                ".." -> if (parts.isNotEmpty()) parts.removeAt(parts.size - 1)
                else -> parts.add(seg)
            }
        }
        return "/" + parts.joinToString("/")
    }

    fun dirName(path: String): String {
        val i = path.lastIndexOf('/')
        return if (i <= 0) "/" else path.substring(0, i)
    }

    fun baseName(path: String): String = path.substringAfterLast('/')

    fun ext(path: String): String = path.substringAfterLast('.', "").lowercase()
}

/** Progress callback so the Android UI can show what the engine is chewing on. */
interface ProgressSink {
    fun onProgress(percent: Int, message: String)
    companion object {
        val NONE = object : ProgressSink {
            override fun onProgress(percent: Int, message: String) {}
        }
    }
}
