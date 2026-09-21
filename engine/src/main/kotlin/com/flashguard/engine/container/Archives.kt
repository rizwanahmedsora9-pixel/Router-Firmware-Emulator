package com.flashguard.engine.container

import com.flashguard.engine.compression.Compression
import com.flashguard.engine.fs.VirtualFs
import com.flashguard.engine.util.Bin
import com.flashguard.engine.util.Hex
import com.flashguard.engine.util.Limits
import com.flashguard.engine.util.Text

/** One member of an archive, with lazy content materialisation. */
class ArchiveEntry(
    val path: String,
    val isDir: Boolean,
    val size: Long,
    val mode: Int,
    val linkTarget: String?,
    val source: String,
    private val opener: () -> ByteArray?,
) {
    fun open(): ByteArray? = try {
        opener()
    } catch (t: Throwable) {
        null
    }
}

interface ArchiveReader {
    val name: String
    fun sniff(data: ByteArray): Boolean
    fun entries(data: ByteArray, maxEntries: Int = Limits.MAX_FILES): List<ArchiveEntry>
}

/** tar (ustar / GNU / PAX). Pure Kotlin, no dependency, bounded. */
object TarReader : ArchiveReader {
    override val name = "tar"

    override fun sniff(data: ByteArray): Boolean {
        if (data.size < 512) return false
        val magic = Bin.ascii(data, 257, 5)
        return magic == "ustar" || (Bin.ascii(data, 0, 8).isNotBlank() && isOctalish(data, 100, 8) && Bin.ascii(data, 257, 6).startsWith("ustar"))
            || looksLikeTar(data)
    }

    private fun isOctalish(d: ByteArray, off: Int, len: Int): Boolean {
        for (i in off until minOf(d.size, off + len)) {
            val c = d[i].toInt() and 0xFF
            if (c != 0 && (c < '0'.code || c > '7'.code) && c != ' '.code) return false
        }
        return true
    }

    private fun looksLikeTar(d: ByteArray): Boolean {
        // Fallback: verify the header checksum of the first block.
        return checksumOk(d, 0)
    }

    private fun checksumOk(d: ByteArray, off: Int): Boolean {
        if (off + 512 > d.size) return false
        var sum = 0
        for (i in 0 until 512) {
            val c = if (i in 148 until 156) ' '.code else (d[off + i].toInt() and 0xFF)
            sum += c
        }
        val storedVal = storedOctal(d, off + 148, 8) ?: return false
        return storedVal == sum.toLong()
    }

    /** Reads an octal field the way tar actually writes it: digits, then NUL/space padding. */
    private fun storedOctal(d: ByteArray, off: Int, maxLen: Int): Long? {
        val sb = StringBuilder()
        var i = off
        val end = minOf(d.size, off + maxLen)
        while (i < end) {
            val c = d[i].toInt() and 0xFF
            when {
                c == 0 || c == ' '.code -> if (sb.isEmpty()) {
                    i++
                    continue
                } else break
                c in '0'.code..'7'.code -> sb.append(c.toChar())
                else -> break
            }
            i++
        }
        return if (sb.isEmpty()) null else sb.toString().toLongOrNull(8)
    }

    override fun entries(data: ByteArray, maxEntries: Int): List<ArchiveEntry> {
        val out = ArrayList<ArchiveEntry>()
        var off = 0
        var longName: String? = null
        var paxPath: String? = null
        var paxSize: Long? = null
        var zeroBlocks = 0
        while (off + 512 <= data.size && out.size < maxEntries) {
            if (isZeroBlock(data, off)) {
                zeroBlocks++
                if (zeroBlocks >= 2) break
                off += 512
                continue
            }
            zeroBlocks = 0
            if (!checksumOk(data, off)) {
                // Header is damaged: stop rather than emit garbage paths.
                break
            }
            var name = Bin.cstr(data, off, 100)
            val prefix = Bin.cstr(data, off + 345, 155)
            if (prefix.isNotEmpty()) name = "$prefix/$name"
            var size = storedOctal(data, off + 124, 12) ?: 0L
            val typeFlag = (data[off + 156].toInt() and 0xFF).toChar()
            val linkName = Bin.cstr(data, off + 157, 100)
            val modeOctal = (storedOctal(data, off + 100, 8) ?: 644L).toInt()
            val mode = VirtualFs.modeFromOctal(modeOctal)
            val dataStart = off + 512

            when (typeFlag) {
                'L' -> { // GNU long name
                    val len = minOf(size, (data.size - dataStart).toLong()).toInt()
                    longName = String(data, dataStart, maxOf(0, len), Charsets.ISO_8859_1).trimEnd('\u0000', '\n')
                    off = dataStart + padded(size)
                    continue
                }
                'x', 'X' -> { // PAX extended header
                    val len = minOf(size, (data.size - dataStart).toLong()).toInt()
                    val text = String(data, dataStart, maxOf(0, len), Charsets.UTF_8)
                    for (line in text.split('\n')) {
                        val eq = line.indexOf('=')
                        if (eq <= 0) continue
                        val key = line.substringBefore(' ')
                        val value = line.substring(eq + 1).trimEnd('\u0000')
                        when {
                            key.endsWith("path") -> paxPath = value
                            key.endsWith("size") -> paxSize = value.toLongOrNull()
                            key.endsWith("linkpath") -> {}
                        }
                    }
                    off = dataStart + padded(size)
                    continue
                }
                'g' -> { // global PAX header - skip payload
                    off = dataStart + padded(size)
                    continue
                }
            }

            paxSize?.let { size = it }
            val finalName = paxPath ?: longName ?: name
            longName = null; paxPath = null; paxSize = null

            if (finalName.isNotBlank() && finalName != "." && finalName != "./") {
                val rel = finalName.removePrefix("./").trimStart('/')
                val isDir = typeFlag == '5' || rel.endsWith("/")
                val isLink = typeFlag == '1' || typeFlag == '2'
                val path = Text.normPath("/$rel")
                val entrySize = size
                val start = dataStart
                out.add(
                    ArchiveEntry(
                        path = path,
                        isDir = isDir,
                        size = if (isDir) 0 else entrySize,
                        mode = mode,
                        linkTarget = when {
                            typeFlag == '1' -> linkName
                            typeFlag == '2' -> linkName
                            else -> null
                        },
                        source = "tar",
                        opener = {
                            if (isDir || isLink) null
                            else {
                                val len = minOf(entrySize, (data.size - start).toLong()).toInt()
                                if (len <= 0) ByteArray(0)
                                else if (entrySize > Limits.MAX_SINGLE_FILE) null
                                else data.copyOfRange(start, start + len)
                            }
                        },
                    )
                )
            }
            off = dataStart + padded(size)
        }
        return out
    }

    private fun padded(size: Long): Int = (((size + 511) / 512) * 512).toInt()

    private fun isZeroBlock(d: ByteArray, off: Int): Boolean {
        for (i in 0 until 512) if (d[off + i].toInt() != 0) return false
        return true
    }
}

/** cpio (newc / crc with ASCII magic, plus oldc). */
object CpioReader : ArchiveReader {
    override val name = "cpio"

    override fun sniff(data: ByteArray): Boolean {
        val m = Bin.ascii(data, 0, 6)
        return m == "070701" || m == "070702" || m == "070707" ||
            (data.size > 2 && (Bin.u16be(data, 0) == 0x71C7 || Bin.u16le(data, 0) == 0xC771))
    }

    override fun entries(data: ByteArray, maxEntries: Int): List<ArchiveEntry> {
        val magic = Bin.ascii(data, 0, 6)
        return when (magic) {
            "070701", "070702" -> readNewc(data, maxEntries)
            "070707" -> readOldc(data, maxEntries)
            else -> emptyList()
        }
    }

    private fun readNewc(data: ByteArray, maxEntries: Int): List<ArchiveEntry> {
        val out = ArrayList<ArchiveEntry>()
        var off = 0
        while (off + 110 <= data.size && out.size < maxEntries) {
            val magic = Bin.ascii(data, off, 6)
            if (magic != "070701" && magic != "070702") break
            fun field(idx: Int): Long {
                val s = Bin.ascii(data, off + 6 + idx * 8, 8)
                return s.toLongOrNull(16) ?: 0L
            }
            val mode = field(1).toInt()
            val fileSize = field(6)
            val nameSize = field(11).toInt()
            val nameStart = off + 110
            if (nameSize <= 0 || nameStart + nameSize > data.size) break
            val name = String(data, nameStart, nameSize - 1, Charsets.ISO_8859_1)
            var dataStart = nameStart + nameSize
            dataStart = (dataStart + 3) / 4 * 4
            val end = dataStart + fileSize.toInt()
            if (end > data.size) break
            if (name != "TRAILER!!!") {
                addCpioEntry(out, name, mode, fileSize, data, dataStart)
            }
            off = ((end + 3) / 4) * 4
            if (name == "TRAILER!!!") break
        }
        return out
    }

    private fun readOldc(data: ByteArray, maxEntries: Int): List<ArchiveEntry> {
        val out = ArrayList<ArchiveEntry>()
        var off = 0
        val swaps = Bin.u16be(data, 0) != 0x71C7
        while (off + 76 <= data.size && out.size < maxEntries) {
            fun oct(rel: Int, len: Int): Long {
                val s = Bin.ascii(data, off + rel, len).trim()
                return s.toLongOrNull(8) ?: 0L
            }
            val mode = oct(18, 6).toInt()
            val nameSize = oct(59, 6).toInt()
            val fileSize = oct(65, 11)
            val nameStart = off + 76
            if (nameSize <= 0 || nameStart + nameSize > data.size) break
            val name = String(data, nameStart, nameSize - 1, Charsets.ISO_8859_1)
            val dataStart = nameStart + nameSize
            val end = dataStart + fileSize.toInt()
            if (end > data.size) break
            if (name != "TRAILER!!!") addCpioEntry(out, name, mode, fileSize, data, dataStart)
            off = if (swaps) end else ((end + 1) / 2) * 2
            if (name == "TRAILER!!!") break
        }
        return out
    }

    private fun addCpioEntry(
        out: MutableList<ArchiveEntry>,
        name: String,
        mode: Int,
        size: Long,
        data: ByteArray,
        dataStart: Int,
    ) {
        val type = mode and 0xF000
        val isDir = type == 0x4000
        val isSymlink = type == 0xA000
        val isDevice = type == 0x2000 || type == 0x6000
        val rel = name.removePrefix("./").trimStart('/')
        if (rel.isBlank()) return
        val path = Text.normPath("/$rel")
        val symTarget = if (isSymlink && size in 1..1024) String(data, dataStart, size.toInt(), Charsets.ISO_8859_1) else null
        val perms = mode and 0x1FF
        val vfsMode = VirtualFs.modeFromOctal(
            (if (perms and 0x100 != 0) 700 else 0) + (if (perms and 0x20 != 0) 70 else 0) + (if (perms and 4 != 0) 7 else 0) + 44
        )
        out.add(
            ArchiveEntry(
                path = path,
                isDir = isDir,
                size = if (isDir || isDevice) 0 else size,
                mode = vfsMode,
                linkTarget = symTarget,
                source = "cpio",
                opener = {
                    when {
                        isDir -> null
                        isSymlink -> null
                        size <= 0 -> ByteArray(0)
                        size > Limits.MAX_SINGLE_FILE -> null
                        else -> data.copyOfRange(dataStart, (dataStart + size).toInt())
                    }
                },
            )
        )
    }
}

/** ZIP (java.util.zip based). */
object ZipWalker : ArchiveReader {
    override val name = "zip"

    override fun sniff(data: ByteArray): Boolean =
        data.size > 4 && Bin.u32le(data, 0) == 0x04034B50L

    override fun entries(data: ByteArray, maxEntries: Int): List<ArchiveEntry> {
        val out = ArrayList<ArchiveEntry>()
        val zis = java.util.zip.ZipInputStream(java.io.ByteArrayInputStream(data))
        var guard = 0
        try {
            while (guard++ < maxEntries) {
                val e = zis.nextEntry ?: break
                val size = e.size
                val name = e.name
                var payload: ByteArray? = null
                if (!e.isDirectory && (size < 0 || size <= Limits.MAX_SINGLE_FILE)) {
                    payload = Compression.readBounded(zis, Limits.MAX_SINGLE_FILE)
                }
                val rel = name.removePrefix("./").trimStart('/')
                if (rel.isBlank()) continue
                val path = Text.normPath("/$rel")
                val isDir = e.isDirectory
                val bytes = payload
                val declared = if (size >= 0) size else (bytes?.size?.toLong() ?: 0L)
                out.add(
                    ArchiveEntry(
                        path = path,
                        isDir = isDir,
                        size = if (isDir) 0 else declared,
                        mode = 0b110100100,
                        linkTarget = null,
                        source = "zip",
                        opener = { bytes },
                    )
                )
                zis.closeEntry()
            }
        } catch (t: Throwable) {
            // Partially readable zips are still useful.
        } finally {
            try {
                zis.close()
            } catch (_: Throwable) {
            }
        }
        return out
    }
}

/** Import helpers shared by the engine. */
object ArchiveImport {
    val readers: List<ArchiveReader> = listOf(TarReader, CpioReader, ZipWalker)

    fun detect(data: ByteArray): ArchiveReader? = readers.firstOrNull { it.sniff(data) }

    fun importInto(vfs: VirtualFs, entries: List<ArchiveEntry>): Int {
        var added = 0
        for (e in entries) {
            if (e.isDir) {
                vfs.mkdirs(e.path)
                added++
                continue
            }
            val content = if (e.linkTarget != null) null else e.open()
            if (vfs.addFile(e.path, content, e.size, e.mode, e.linkTarget, e.source)) added++
        }
        return added
    }
}
