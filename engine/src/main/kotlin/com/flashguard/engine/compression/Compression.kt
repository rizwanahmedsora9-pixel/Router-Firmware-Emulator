package com.flashguard.engine.compression

import com.flashguard.engine.util.Bin
import com.flashguard.engine.util.Limits
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.zip.GZIPInputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream

/**
 * Compression sniffing + decoding.
 *
 * Supported in-process (pure Java, works on Android):
 *  - gzip, zlib/deflate  -> java.util.zip
 *  - xz, lzma-alone      -> org.tukaani:xz (the only third-party dependency, pure Java)
 *
 * Detected but intentionally *not* decoded on the phone (no safe pure-Java decoder):
 *  - bzip2, zstd, lz4, lzo. The engine still reports them clearly instead of guessing, and the
 *    hardware matrix marks them amber so the user knows why nothing was extracted.
 */
object Compression {

    enum class Kind(val label: String, val decodable: Boolean) {
        GZIP("gzip", true),
        ZLIB("zlib/deflate", true),
        XZ("xz", true),
        LZMA("lzma (alone)", true),
        BZIP2("bzip2", false),
        ZSTD("zstd", false),
        LZ4("lz4", false),
        LZO("lzo", false),
        LZMA_SQUASHFS("lzma (raw, squashfs)", true),
        NONE("none", false),
    }

    fun sniff(data: ByteArray, offset: Int = 0): Kind? {
        if (offset + 4 > data.size) return null
        // gzip: 1F 8B
        if (Bin.u8(data, offset) == 0x1F && Bin.u8(data, offset + 1) == 0x8B) return Kind.GZIP
        // zlib: 78 01/9C/DA or 78 5E etc. (CMF=0x78, FLG checksum mod 31 == 0)
        if (Bin.u8(data, offset) == 0x78) {
            val cmf = Bin.u8(data, offset)
            val flg = Bin.u8(data, offset + 1)
            if (((cmf.toInt() shl 8) + flg) % 31 == 0) return Kind.ZLIB
        }
        // xz: FD 37 7A 58 5A 00
        if (Bin.u8(data, offset) == 0xFD && Bin.u8(data, offset + 1) == 0x37 &&
            Bin.u8(data, offset + 2) == 0x7A && Bin.u8(data, offset + 3) == 0x58
        ) return Kind.XZ
        // lzma alone: props byte < 9*5*5=225, then dict size u32le, then u64le uncompressed size
        // Heuristic: first byte 0x5D (lc=3,lp=0,pb=2) is by far the most common LZMA prop.
        if (Bin.u8(data, offset) == 0x5D && offset + 13 <= data.size) {
            val dict = Bin.u32le(data, offset + 1)
            if (dict in 0x1000..0x40000000L) return Kind.LZMA
        }
        if (Bin.u8(data, offset) == 0x42 && Bin.u8(data, offset + 1) == 0x5A &&
            Bin.u8(data, offset + 2) == 0x68
        ) return Kind.BZIP2
        if (offset + 4 <= data.size && Bin.u32le(data, offset) == 0xFD2FB528L) return Kind.ZSTD
        if (offset + 4 <= data.size && Bin.u32le(data, offset) == 0x184D2204L) return Kind.LZ4
        if (offset + 2 <= data.size && Bin.u16le(data, offset) == 0x015C) return Kind.LZO
        return null
    }

    /** Decode whatever [autoSniff] found at [offset]; returns null when impossible. */
    fun decode(data: ByteArray, offset: Int = 0, maxOut: Long = Limits.MAX_INFLATE_BYTES): Decoded? {
        val kind = sniff(data, offset) ?: return null
        return decodeAs(data, kind, offset, maxOut)
    }

    fun decodeAs(
        data: ByteArray,
        kind: Kind,
        offset: Int = 0,
        maxOut: Long = Limits.MAX_INFLATE_BYTES,
    ): Decoded? = try {
        val bytes = when (kind) {
            Kind.GZIP -> readBounded(GZIPInputStream(ByteArrayInputStream(data, offset, data.size - offset)), maxOut)
            Kind.ZLIB -> readBounded(InflaterInputStream(ByteArrayInputStream(data, offset, data.size - offset)), maxOut)
            Kind.XZ -> XzSupport.decodeXz(data, offset, maxOut)
            Kind.LZMA, Kind.LZMA_SQUASHFS -> XzSupport.decodeLzma(data, offset, maxOut)
            else -> null
        }
        bytes?.let { Decoded(kind, it) }
    } catch (t: Throwable) {
        null // Corrupt/truncated vendor blobs are normal; the caller reports "could not decode".
    }

    data class Decoded(val kind: Kind, val bytes: ByteArray)

    /** Raw deflate (used by SquashFS/CramFS blocks which store zlib streams). */
    fun inflateZlib(src: ByteArray, expectedSize: Int) : ByteArray? = try {
        Inflater().let { inf ->
            inf.setInput(src)
            val out = ByteArray(expectedSize)
            var off = 0
            while (off < expectedSize) {
                val n = inf.inflate(out, off, expectedSize - off)
                if (n == 0) {
                    if (inf.needsInput() || inf.finished()) break
                }
                off += n
            }
            inf.end()
            if (off == 0) null else if (off == expectedSize) out else out.copyOf(off)
        }
    } catch (t: Throwable) {
        null
    }

    fun readBounded(input: InputStream, maxOut: Long): ByteArray {
        val out = ByteArrayOutputStream(1 shl 16)
        val buf = ByteArray(1 shl 16)
        var total = 0L
        input.use { ins ->
            while (true) {
                val n = ins.read(buf)
                if (n < 0) break
                total += n
                if (total > maxOut) throw IllegalStateException("decompression limit reached")
                out.write(buf, 0, n)
            }
        }
        return out.toByteArray()
    }

    /** Grow-safe bounded read used by nested readers. */
    fun readBoundedLimited(input: InputStream, maxOut: Long, limit: Long): ByteArray =
        readBounded(input, minOf(maxOut, limit))
}
