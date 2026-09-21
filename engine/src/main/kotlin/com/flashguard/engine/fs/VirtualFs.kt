package com.flashguard.engine.fs

import com.flashguard.engine.util.Hex
import com.flashguard.engine.util.Limits
import com.flashguard.engine.util.Text

/**
 * In-memory virtual filesystem built from whatever the engine could unpack.
 *
 * It is deliberately *not* a real filesystem: nothing is ever written to the phone's storage, and
 * the sandboxed shell can create/delete freely - a reboot of the emulator just drops the object.
 */
class VfsEntry(
    val path: String,
    var isDir: Boolean,
    var mode: Int = 0b110100100, // 0644
    var linkTarget: String? = null,
    var content: ByteArray? = null,
    var size: Long = 0,
    var contentStored: Boolean = true,
    val source: String = "",
) {
    val name: String get() = Text.baseName(path)
    val executable: Boolean get() = (mode and 0b001001001) != 0
    val isSymlink: Boolean get() = linkTarget != null

    fun sizeText(): String = if (isDir) "-" else if (!contentStored) "${Hex.humanBytes(size)} (not kept in RAM)"
    else Hex.humanBytes(size)

    fun modeString(): String {
        val sb = StringBuilder(10)
        sb.append(if (isDir) 'd' else if (isSymlink) 'l' else '-')
        val rwx = "rwx"
        for (shift in intArrayOf(6, 3, 0)) {
            for (bit in 0 until 3) {
                val set = (mode shr (shift + 2 - bit)) and 1 == 1
                sb.append(if (set) rwx[bit] else '-')
            }
        }
        return sb.toString()
    }
}

class VirtualFs(
    private val maxBytes: Long = Limits.MAX_EXTRACT_BYTES,
    private val maxFiles: Int = Limits.MAX_FILES,
    private val keepFileLimit: Long = 4L * 1024 * 1024,
) {
    private val entries = LinkedHashMap<String, VfsEntry>()
    var truncated: Boolean = false
        private set
    var storedBytes: Long = 0L
        private set
    var skippedFiles: Int = 0
        private set

    init {
        entries["/"] = VfsEntry("/", true, mode = 0b111101101)
    }

    val fileCount: Int get() = entries.size

    fun exists(path: String): Boolean = entries.containsKey(Text.normPath(path))

    fun isDir(path: String): Boolean = entries[Text.normPath(path)]?.isDir == true

    fun isFile(path: String): Boolean = entries[Text.normPath(path)]?.let { !it.isDir } == true

    fun get(path: String): VfsEntry? = entries[Text.normPath(path)]

    fun mkdirs(path: String): Boolean {
        val norm = Text.normPath(path)
        if (entries.containsKey(norm)) return true
        if (entries.size >= maxFiles) {
            truncated = true
            return false
        }
        val parent = Text.dirName(norm)
        if (parent != norm && parent.isNotEmpty()) mkdirs(parent)
        entries[norm] = VfsEntry(norm, true, mode = 0b111101101)
        return true
    }

    /** Add (or overwrite) a file. [content] may be null for oversized members we do not keep. */
    fun addFile(
        path: String,
        content: ByteArray?,
        size: Long = content?.size?.toLong() ?: 0L,
        mode: Int = 0b110100100,
        linkTarget: String? = null,
        source: String = "",
    ): Boolean {
        val norm = Text.normPath(path)
        if (norm == "/") return false
        if (entries.size >= maxFiles) {
            truncated = true
            skippedFiles++
            return false
        }
        mkdirs(Text.dirName(norm))
        val previouslyStored = entries[norm]?.let { if (it.contentStored) it.size else 0L } ?: 0L

        var kept: ByteArray? = null
        var stored = false
        if (linkTarget != null) {
            kept = null
        } else if (content != null && content.size.toLong() <= keepFileLimit &&
            storedBytes - previouslyStored + content.size <= maxBytes
        ) {
            kept = content
            stored = true
        } else if (content == null && size > 0) {
            stored = false
        }

        val effectiveSize = when {
            kept != null -> kept.size.toLong()
            size > 0 -> size
            else -> content?.size?.toLong() ?: 0L
        }
        entries[norm] = VfsEntry(
            path = norm,
            isDir = false,
            mode = mode,
            linkTarget = linkTarget,
            content = kept,
            size = effectiveSize,
            contentStored = stored,
            source = source,
        )
        if (stored) {
            storedBytes = storedBytes - previouslyStored + effectiveSize
        } else {
            storedBytes -= previouslyStored
        }
        if (!stored && effectiveSize > keepFileLimit) blocked.add(norm)
        return true
    }

    /** Paths whose bytes we refused to keep (big kernel/rootfs blobs). */
    val blocked = LinkedHashSet<String>()

    /** Shell-side file creation (lives only inside the sandbox). */
    fun write(path: String, content: ByteArray, mode: Int = 0b110100100): Boolean {
        val norm = Text.normPath(path)
        if (entries[norm]?.isDir == true) return false
        return addFile(norm, content, content.size.toLong(), mode, source = "emulated shell write")
    }

    fun append(path: String, text: String): Boolean {
        val norm = Text.normPath(path)
        val cur = entries[norm]?.content ?: ByteArray(0)
        return write(norm, cur + text.toByteArray(Charsets.UTF_8), entries[norm]?.mode ?: 0b110100100)
    }

    fun delete(path: String): Boolean {
        val norm = Text.normPath(path)
        if (norm == "/") return false // the sandbox root always survives (even "rm -rf /")
        val e = entries.remove(norm) ?: return false
        if (e.contentStored) storedBytes -= e.size
        // Remove children for directories.
        if (e.isDir) {
            val prefix = if (norm.endsWith("/")) norm else "$norm/"
            val kids = entries.keys.filter { it.startsWith(prefix) }
            for (k in kids) {
                val ke = entries.remove(k)
                if (ke?.contentStored == true) storedBytes -= ke.size
            }
        }
        return true
    }

    fun read(path: String): ByteArray? {
        val e = entries[Text.normPath(path)] ?: return null
        if (e.isDir) return null
        e.linkTarget?.let { target ->
            val resolved = if (target.startsWith("/")) target else Text.normPath(Text.dirName(e.path) + "/" + target)
            return read(resolved)
        }
        return e.content
    }

    fun readText(path: String, maxChars: Int = 512 * 1024): String? {
        val bytes = read(path) ?: return null
        val slice = if (bytes.size > maxChars) bytes.copyOf(maxChars) else bytes
        return String(slice, Charsets.UTF_8).replace("\u0000", "")
    }

    fun list(dir: String): List<VfsEntry> {
        val norm = Text.normPath(dir)
        val prefix = if (norm == "/") "/" else "$norm/"
        return entries.values.filter { it.path != norm && it.path.startsWith(prefix) && !it.path.removePrefix(prefix).contains('/') }
    }

    fun childNames(dir: String): List<String> = list(dir).map { it.name }

    fun allFiles(): List<VfsEntry> = entries.values.filter { !it.isDir }

    fun walk(visitor: (VfsEntry) -> Unit) {
        for (e in entries.values) visitor(e)
    }

    fun allEntries(): List<VfsEntry> = entries.values.toList()

    fun findBySuffix(suffix: String): List<VfsEntry> =
        entries.values.filter { !it.isDir && it.path.lowercase().endsWith(suffix.lowercase()) }

    fun findByName(name: String): List<VfsEntry> =
        entries.values.filter { !it.isDir && it.name.equals(name, ignoreCase = true) }

    fun findByContains(part: String): List<VfsEntry> =
        entries.values.filter { !it.isDir && it.path.contains(part, ignoreCase = true) }

    /**
     * Candidate document roots for the router's web UI, best first.
     */
    fun findWebRoots(): List<String> {
        val known = listOf(
            "/www", "/www/cgi-bin", "/web", "/usr/www", "/htdocs", "/var/www", "/var/web",
            "/usr/share/web", "/usr/local/www", "/usr/lib/lua/luci", "/www2", "/webroot",
            "/usr/share/www", "/rom/www", "/mnt/www",
        ).filter { entries.containsKey(Text.normPath(it)) }

        // Any directory with an index/login page also counts (vendor layouts vary wildly).
        val inferred = entries.values
            .filter { it.isDir && it.path.count { c -> c == '/' } <= 4 }
            .map { it.path }
            .filter { dir ->
                val kids = childNames(dir)
                kids.any { it.startsWith("index.") || it.startsWith("login.") || it == "cgi-bin" } ||
                    kids.any { it.endsWith(".asp") || it.endsWith(".cgi") || it.endsWith(".lua") || it.endsWith(".htm") || it.endsWith(".html") }
            }
        return (known + inferred).distinct()
    }

    fun humanSummary(): String =
        "$fileCount objects, ${Hex.humanBytes(storedBytes)} kept in RAM" + if (truncated) " (extraction truncated by limits)" else ""

    companion object {
        fun modeFromOctal(octal: Int): Int {
            var mode = 0
            var v = octal
            for (i in 0 until 3) {
                val digit = v % 10
                v /= 10
                mode = mode or when (digit) {
                    1 -> 0b001 shl (i * 3)
                    2 -> 0b010 shl (i * 3)
                    3 -> 0b011 shl (i * 3)
                    4 -> 0b100 shl (i * 3)
                    5 -> 0b101 shl (i * 3)
                    6 -> 0b110 shl (i * 3)
                    7 -> 0b111 shl (i * 3)
                    else -> 0
                }
            }
            return mode
        }
    }
}
