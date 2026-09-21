package com.flashguard.engine.container

import com.flashguard.engine.compression.Compression
import com.flashguard.engine.compression.XzSupport
import com.flashguard.engine.fs.VirtualFs
import com.flashguard.engine.util.Bin
import com.flashguard.engine.util.Hex
import com.flashguard.engine.util.Limits
import com.flashguard.engine.util.Text

/**
 * Minimal, dependency-light SquashFS 4.0 reader (little endian).
 *
 * Supports: uncompressed, gzip/zlib, xz and raw-lzma payloads - which covers OpenWrt, most vendor
 * router rootfs images and GPL source tarball rootfs drops. lzo/lz4/zstd are *detected* and
 * reported precisely instead of silently failing (no safe pure-Java decoder for those).
 *
 * This is a read-only parser: it never mounts anything, so it cannot damage the phone or the router.
 */
class SquashFsReader(private val data: ByteArray) {

    data class Super(
        val inodes: Long,
        val blockSize: Int,
        val blockLog: Int,
        val fragments: Long,
        val compressor: Int,
        val major: Int,
        val minor: Int,
        val flags: Int,
        val rootInode: Long,
        val bytesUsed: Long,
        val idTableStart: Long,
        val inodeTableStart: Long,
        val directoryTableStart: Long,
        val fragmentTableStart: Long,
        val lookupTableStart: Long,
    ) {
        val compressorName: String
            get() = when (compressor) {
                1 -> "gzip"
                2 -> "lzma"
                3 -> "lzo"
                4 -> "xz"
                5 -> "lz4"
                6 -> "zstd"
                else -> "unknown($compressor)"
            }

        val decodable: Boolean get() = compressor in setOf(1, 2, 4) || compressor == 0
    }

    data class Inode(
        val number: Long,
        val type: Int,
        val mode: Int,
        val uid: Int,
        val gid: Int,
        val mtime: Long,
        val path: String = "",
        // directory
        val dirStartBlock: Long = 0,
        val dirOffset: Int = 0,
        val dirSize: Long = 0,
        // file
        val startBlock: Long = 0,
        val fragment: Long = -1,
        val fragmentOffset: Int = 0,
        val fileSize: Long = 0,
        val blockSizes: List<Long> = emptyList(),
        val symlinkTarget: String? = null,
    ) {
        val isDir: Boolean get() = type == 1 || type == 8
        val isSymlink: Boolean get() = type == 3 || type == 10
        val isFile: Boolean get() = type == 2 || type == 9
        val typeName: String
            get() = when (type) {
                1 -> "dir"
                2 -> "file"
                3 -> "symlink"
                4 -> "chardev"
                5 -> "blockdev"
                6 -> "fifo"
                7 -> "socket"
                8 -> "dir"
                9 -> "file"
                10 -> "symlink"
                11 -> "chardev"
                12 -> "blockdev"
                13 -> "fifo"
                14 -> "socket"
                else -> "unknown"
            }
    }

    data class Entry(
        val path: String,
        val inode: Inode,
    ) {
        val isDir: Boolean get() = inode.isDir
        val size: Long get() = if (inode.isDir) 0 else inode.fileSize
    }

    private var superblock: Super? = null
    val superBlock: Super get() = superblock ?: throw IllegalStateException("not a squashfs image")
    val warnings = ArrayList<String>()

    // Diagnostics: when a real image only yields a handful of files we want to know exactly why.
    private var scannedInodes = 0
    private var metaBlocksVisited = 0
    private var lastMetaRel = 0L
    private var scanStop: String? = null
    private var directoryEntriesSeen = 0
    private var directoryEntriesResolved = 0

    val diagnostics: String
        get() = buildString {
            append("squashfs scan: inodes=$scannedInodes metaBlocks=$metaBlocksVisited lastRel=$lastMetaRel ")
            append("dirEntries=$directoryEntriesSeen/${directoryEntriesResolved} resolved")
            scanStop?.let { append(" stop=$it") }
            if (warnings.isNotEmpty()) append(" warnings=${warnings.take(3).joinToString("; ")}")
        }

    private class MetaBlock(val relOffset: Long, val nextRelOffset: Long, val bytes: ByteArray)

    /** Sequential metadata stream (inode table / directory table): a chain of <=8K blocks. */
    private inner class MetaStream(private val tableStart: Long) {
        private val cache = HashMap<Long, MetaBlock>()

        fun blockAt(rel: Long): MetaBlock? {
            cache[rel]?.let { return it }
            val abs = tableStart + rel
            if (abs < 0 || abs + 2 > data.size) return null
            val header = Bin.u16le(data, abs.toInt())
            val compressed = (header and 0x8000) == 0
            val size = header and 0x7FFF
            if (size == 0 || abs + 2 + size > data.size) return null
            val payload = data.copyOfRange((abs + 2).toInt(), (abs + 2 + size).toInt())
            val bytes = if (compressed) decompress(payload, 8192) ?: return null else payload
            val block = MetaBlock(rel, rel + 2 + size, bytes)
            cache[rel] = block
            return block
        }

        /** Read [length] bytes starting at block offset [rel] + [inBlockOffset]. */
        fun read(rel: Long, inBlockOffset: Int, length: Int): ByteArray? {
            if (length <= 0) return ByteArray(0)
            val out = java.io.ByteArrayOutputStream(length)
            var curRel = rel
            var offset = inBlockOffset
            var remaining = length
            var guard = 0
            while (remaining > 0 && guard++ < 4096) {
                val block = blockAt(curRel) ?: return null
                if (offset >= block.bytes.size) {
                    curRel = block.nextRelOffset
                    offset = 0
                    continue
                }
                val take = minOf(remaining, block.bytes.size - offset)
                out.write(block.bytes, offset, take)
                remaining -= take
                offset += take
                if (offset >= block.bytes.size) {
                    curRel = block.nextRelOffset
                    offset = 0
                }
            }
            return if (out.size() == 0) null else out.toByteArray()
        }
    }

    private fun decompress(payload: ByteArray, expected: Int): ByteArray? = when (hdr.let { superblock?.compressor ?: 1 }) {
        1 -> Compression.inflateZlib(payload, expected)
        4 -> XzSupport.decodeXz(payload)
        2 -> XzSupport.decodeLzma(payload)
        else -> null
    }

    private val hdr: Super
        get() = superblock ?: throw IllegalStateException("superblock not parsed")

    fun parse(): Boolean {
        if (!sniff(data)) return false
        val inodes = Bin.u32le(data, 4)
        val blockSize = Bin.u32le(data, 12).toInt()
        val fragments = Bin.u32le(data, 16)
        val compression = Bin.u16le(data, 20)
        val blockLog = Bin.u16le(data, 22)
        val flags = Bin.u16le(data, 24)
        val major = Bin.u16le(data, 28)
        val minor = Bin.u16le(data, 30)
        val rootInode = Bin.u64le(data, 32)
        val bytesUsed = Bin.u64le(data, 40)
        val idTableStart = Bin.u64le(data, 48)
        val inodeTableStart = Bin.u64le(data, 64)
        val directoryTableStart = Bin.u64le(data, 72)
        val fragmentTableStart = Bin.u64le(data, 80)
        val lookupTableStart = Bin.u64le(data, 88)
        superblock = Super(
            inodes = inodes,
            blockSize = if (blockSize in 4096..1_048_576) blockSize else 131_072,
            blockLog = if (blockLog in 12..20) blockLog else 17,
            fragments = fragments,
            compressor = compression,
            major = major,
            minor = minor,
            flags = flags,
            rootInode = rootInode,
            bytesUsed = bytesUsed,
            idTableStart = idTableStart,
            inodeTableStart = inodeTableStart,
            directoryTableStart = directoryTableStart,
            fragmentTableStart = fragmentTableStart,
            lookupTableStart = lookupTableStart,
        )
        if (major != 4) warnings.add("SquashFS major version $major (only 4.x is fully supported)")
        if (!hdr.decodable) warnings.add("SquashFS payload uses ${hdr.compressorName}, which has no safe pure-Java decoder")
        return true
    }

    // ---------------------------------------------------------------- inode table

    private val inodeByRef = HashMap<Long, Inode>()

    /** Full sequential scan of the inode table builds a (block,offset) -> inode map. */
    private fun scanInodes(max: Int = 200_000) {
        if (inodeByRef.isNotEmpty()) return
        val stream = MetaStream(hdr.inodeTableStart)
        var rel = 0L
        var guard = 0
        val tableEnd = hdr.directoryTableStart - hdr.inodeTableStart
        while (rel < tableEnd && inodeByRef.size < max && guard++ < 200_000) {
            val block = stream.blockAt(rel)
            if (block == null) {
                if (scanStop == null) scanStop = "metadata block unreadable at rel=$rel"
                break
            }
            metaBlocksVisited++
            lastMetaRel = rel
            var offset = 0
            while (offset < block.bytes.size && inodeByRef.size < max) {
                val parsed = parseInodeAt(block.bytes, offset)
                if (parsed == null) {
                    if (scanStop == null) {
                        scanStop = "unparsable inode at block=$rel offset=$offset type=${if (offset + 2 <= block.bytes.size) Bin.u16le(block.bytes, offset) else -1}"
                    }
                    break
                }
                val key = blockKey(rel, offset)
                inodeByRef[key] = parsed.inode
                scannedInodes++
                offset += parsed.consumed
            }
            rel = block.nextRelOffset
        }
    }

    private fun blockKey(rel: Long, offset: Int): Long = (rel shl 20) or offset.toLong()

    private class Parsed(val inode: Inode, val consumed: Int)

    private fun parseInodeAt(b: ByteArray, off: Int): Parsed? {
        if (off + 16 > b.size) return null
        val type = Bin.u16le(b, off)
        val mode = Bin.u16le(b, off + 2)
        val uid = Bin.u16le(b, off + 4)
        val gid = Bin.u16le(b, off + 6)
        val mtime = Bin.u32le(b, off + 8)
        val number = Bin.u32le(b, off + 12)
        fun u32(o: Int) = Bin.u32le(b, off + o)
        // Every access below is guarded: metadata blocks are padded, so the last inode in a
        // block may be a partial one (this crashed on a real OpenWrt image).
        fun fits(bytes: Int) = off + bytes <= b.size
        fun basicDir(): Parsed? {
            if (!fits(32)) return null
            return Parsed(
                Inode(
                    number = number, type = type, mode = mode, uid = uid, gid = gid, mtime = mtime,
                    dirStartBlock = u32(16), dirOffset = Bin.u16le(b, off + 26),
                    dirSize = Bin.u16le(b, off + 24).toLong(),
                ),
                32,
            )
        }
        fun basicFile(): Parsed? {
            if (!fits(32)) return null
            val blockCount = dataBlockCount(u32(28), u32(20))
            if (!fits(32 + blockCount * 4)) return null
            return Parsed(
                Inode(
                    number = number, type = type, mode = mode, uid = uid, gid = gid, mtime = mtime,
                    startBlock = u32(16), fragment = u32(20), fragmentOffset = u32(24).toInt(),
                    fileSize = u32(28), blockSizes = (0 until blockCount).map { u32(32 + it * 4) },
                ),
                32 + blockCount * 4,
            )
        }
        fun symlink(): Parsed? {
            if (!fits(24)) return null
            val targetSize = u32(20).toInt()
            if (targetSize < 0 || !fits(24 + targetSize)) return null
            return Parsed(
                Inode(
                    number = number, type = type, mode = mode, uid = uid, gid = gid, mtime = mtime,
                    symlinkTarget = String(b, off + 24, targetSize, Charsets.ISO_8859_1),
                    fileSize = targetSize.toLong(),
                ),
                24 + targetSize,
            )
        }
        return when (type) {
            1 -> basicDir()
            2 -> basicFile()
            3 -> symlink()
            4, 5 -> if (!fits(24)) null else Parsed(
                Inode(number = number, type = type, mode = mode, uid = uid, gid = gid, mtime = mtime, fileSize = 0),
                24,
            )
            6, 7 -> if (!fits(20)) null else Parsed(
                Inode(number = number, type = type, mode = mode, uid = uid, gid = gid, mtime = mtime, fileSize = 0),
                20,
            )
            8 -> { // extended directory
                if (!fits(40)) return null
                val indexCount = Bin.u16le(b, off + 32)
                if (!fits(40 + indexCount * 16)) return null
                Parsed(
                    Inode(
                        number = number, type = type, mode = mode, uid = uid, gid = gid, mtime = mtime,
                        dirStartBlock = u32(24), dirOffset = Bin.u16le(b, off + 34), dirSize = u32(20),
                    ),
                    40 + indexCount * 16,
                )
            }
            9 -> { // extended file
                if (!fits(56)) return null
                val fileSize = Bin.u64le(b, off + 24)
                val fragment = u32(44)
                val blockCount = dataBlockCount(fileSize, fragment)
                if (!fits(56 + blockCount * 4)) return null
                Parsed(
                    Inode(
                        number = number, type = type, mode = mode, uid = uid, gid = gid, mtime = mtime,
                        startBlock = Bin.u64le(b, off + 16), fragment = fragment,
                        fragmentOffset = u32(48).toInt(), fileSize = fileSize,
                        blockSizes = (0 until blockCount).map { u32(56 + it * 4) },
                    ),
                    56 + blockCount * 4,
                )
            }
            10 -> symlink() // extended symlink has the same on-disk layout as the basic one
            11, 12 -> if (!fits(28)) null else Parsed(
                Inode(number = number, type = type, mode = mode, uid = uid, gid = gid, mtime = mtime, fileSize = 0),
                28,
            )
            13, 14 -> if (!fits(24)) null else Parsed(
                Inode(number = number, type = type, mode = mode, uid = uid, gid = gid, mtime = mtime, fileSize = 0),
                24,
            )
            else -> null
        }
    }

    private fun dataBlockCount(fileSize: Long, fragment: Long): Int {
        if (fileSize <= 0) return 0
        val total = ((fileSize + hdr.blockSize - 1) / hdr.blockSize).toInt()
        val hasFragment = fragment != 0xFFFFFFFFL && fragment != -1L
        return if (hasFragment) maxOf(0, total - 1) else total
    }

    // ---------------------------------------------------------------- directory walk

    private fun readDirectory(inode: Inode, maxEntries: Int): List<Pair<String, Inode>> {
        val out = ArrayList<Pair<String, Inode>>()
        val stream = MetaStream(hdr.directoryTableStart)
        val declared = if (inode.type == 1) inode.dirSize + 3 else inode.dirSize
        val listing = stream.read(inode.dirStartBlock, inode.dirOffset, declared.toInt().coerceAtMost(1 shl 20))
            ?: return out
        var p = 0
        while (p + 12 <= listing.size && out.size < maxEntries) {
            var count = Bin.u32le(listing, p)
            val startBlock = Bin.u32le(listing, p + 4)
            val baseInode = Bin.u32le(listing, p + 8)
            p += 12
            if (count > 8192) break
            count += 1
            for (i in 0 until count) {
                if (p + 8 > listing.size) break
                val entryOffset = Bin.u16le(listing, p)
                val inodeDelta = Bin.u16le(listing, p + 2).toShort().toInt()
                val nameLen = Bin.u16le(listing, p + 6) + 1
                if (p + 8 + nameLen > listing.size) break
                val name = String(listing, p + 8, nameLen, Charsets.ISO_8859_1)
                p += 8 + nameLen
                directoryEntriesSeen++
                val child = inodeByRef[blockKey(startBlock, entryOffset)]
                if (child == null) continue
                directoryEntriesResolved++
                if (name == "." || name == "..") continue
                out.add(name to child)
            }
        }
        return out
    }

    /** Full recursive listing (bounded) with absolute paths. */
    fun list(maxEntries: Int = Limits.MAX_FILES): List<Entry> {
        scanInodes()
        val out = ArrayList<Entry>(minOf(maxEntries, 4096))
        val root = inodeByRef[blockKey(hdr.rootInode ushr 16, (hdr.rootInode and 0xFFFF).toInt())]
            ?: inodeByRef.values.firstOrNull { it.isDir }
            ?: return out
        val seen = HashSet<Long>()
        val queue = ArrayDeque<Pair<String, Inode>>()
        queue.add("/" to root)
        seen.add(root.number)
        while (queue.isNotEmpty() && out.size < maxEntries) {
            val (path, inode) = queue.removeFirst()
            out.add(Entry(path, inode))
            if (!inode.isDir) continue
            if (path.count { it == '/' } > 24) continue
            for ((name, child) in readDirectory(inode, maxEntries)) {
                if (!seen.add(child.number)) continue
                val childPath = if (path == "/") "/$name" else "$path/$name"
                queue.add(childPath to child)
            }
        }
        return out
    }

    // ---------------------------------------------------------------- file data

    private val fragmentCache = HashMap<Long, ByteArray>()

    private val fragmentMetaCache = HashMap<Int, ByteArray>()

    /** The fragment table is a list of metadata-block locations; each block holds 16-byte entries. */
    private fun fragmentTableMeta(indexBlockNo: Int): ByteArray? {
        fragmentMetaCache[indexBlockNo]?.let { return it }
        val pos = hdr.fragmentTableStart + indexBlockNo * 8L
        if (pos < 0 || pos + 8 > data.size) return null
        val metaStart = Bin.u64le(data, pos.toInt())
        if (metaStart <= 0 || metaStart + 2 > data.size) return null
        val block = MetaStream(metaStart).blockAt(0) ?: return null
        fragmentMetaCache[indexBlockNo] = block.bytes
        return block.bytes
    }

    private fun readFragment(index: Long): ByteArray? {
        fragmentCache[index]?.let { return it }
        if (hdr.fragments == 0L || hdr.fragmentTableStart == 0L || index < 0 || index >= hdr.fragments) return null
        val perMeta = maxOf(1, hdr.blockSize / 16)
        val indexBlockNo = (index / perMeta).toInt()
        val meta = fragmentTableMeta(indexBlockNo) ?: return null
        val within = (index - indexBlockNo.toLong() * perMeta).toInt()
        val entryPos = within * 16
        if (entryPos + 16 > meta.size) return null
        val start = Bin.u64le(meta, entryPos)
        val sizeField = Bin.u32le(meta, entryPos + 8)
        if (start < 0 || start > data.size) return null
        val uncompressed = (sizeField and 0x01000000L) != 0L
        val size = (sizeField and 0x00FFFFFF).toInt()
        if (size < 0 || start + size > data.size) return null
        if (size == 0) return ByteArray(0)
        val payload = data.copyOfRange(start.toInt(), (start + size).toInt())
        val block = if (uncompressed) payload else (decompress(payload, hdr.blockSize) ?: return null)
        fragmentCache[index] = block
        return block
    }

    fun readFile(inode: Inode, maxBytes: Long = Limits.MAX_SINGLE_FILE): ByteArray? {
        if (!inode.isFile || inode.fileSize <= 0) return ByteArray(0)
        if (inode.fileSize > maxBytes) return null
        val out = java.io.ByteArrayOutputStream(inode.fileSize.toInt().coerceAtMost(1 shl 20))
        var offset = inode.startBlock
        var remaining = inode.fileSize
        for (sizeField in inode.blockSizes) {
            val uncompressed = (sizeField and 0x01000000L) != 0L
            val size = (sizeField and 0x00FFFFFF).toInt()
            val blockExpected = minOf(remaining, hdr.blockSize.toLong()).toInt()
            if (size == 0) {
                // sparse block: zero filled
                out.write(ByteArray(blockExpected))
                remaining -= blockExpected
                continue
            }
            if (offset + size > data.size) return null
            if (uncompressed) {
                out.write(data, offset.toInt(), minOf(size, blockExpected))
            } else {
                val payload = data.copyOfRange(offset.toInt(), (offset + size).toInt())
                val decoded = decompress(payload, blockExpected) ?: return null
                out.write(decoded, 0, minOf(decoded.size, blockExpected))
            }
            offset += size
            remaining -= blockExpected
            if (remaining <= 0) break
        }
        if (remaining > 0 && inode.fragment != 0xFFFFFFFFL && inode.fragment != -1L) {
            val frag = readFragment(inode.fragment)
            if (frag != null) {
                val start = inode.fragmentOffset
                if (start in 0 until frag.size) {
                    val len = minOf(remaining, (frag.size - start).toLong()).toInt()
                    if (len > 0) out.write(frag, start, len)
                }
            }
        }
        // A non-empty file that produced no bytes means the payload could not be read
        // (unsupported block codec, truncated image). Report it as unreadable instead of
        // silently handing back an empty file.
        if (out.size() == 0 && inode.fileSize > 0) return null
        return out.toByteArray()
    }

    /** Convert to the generic archive-entry form so it can be poured into a VirtualFs. */
    fun toArchiveEntries(maxEntries: Int = Limits.MAX_FILES): List<ArchiveEntry> =
        list(maxEntries).map { e ->
            val inode = e.inode
            ArchiveEntry(
                path = Text.normPath(e.path),
                isDir = inode.isDir,
                size = inode.fileSize,
                mode = if (inode.mode != 0) inode.mode else 0b110100100,
                linkTarget = inode.symlinkTarget,
                source = "squashfs(${hdr.compressorName})",
                opener = {
                    when {
                        inode.isDir -> null
                        inode.isSymlink -> null
                        inode.fileSize > Limits.MAX_SINGLE_FILE -> null
                        else -> readFile(inode)
                    }
                },
            )
        }

    fun describe(): String = buildString {
        append("SquashFS ${hdr.major}.${hdr.minor}, ${hdr.compressorName} compression, ")
        append("block ${Hex.humanBytes(hdr.blockSize)}, ")
        append("${hdr.inodes} inodes, ${Hex.humanBytes(hdr.bytesUsed)} used")
        if (!hdr.decodable) append("  [!] payload not decodable on-device")
    }

    companion object {
        const val MAGIC = 0x73717368L // "hsqs" little-endian magic value

        fun sniff(data: ByteArray): Boolean =
            data.size >= 96 && Bin.u32le(data, 0) == MAGIC && Bin.u16le(data, 28) == 4

        fun sniffAny(data: ByteArray): Boolean =
            data.size >= 96 && Bin.u32le(data, 0) == MAGIC
    }
}
