package com.flashguard.engine.compression

import com.flashguard.engine.util.Limits
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import org.tukaani.xz.XZInputStream

/**
 * The ONLY file in the engine that touches a third-party library (org.tukaani:xz, pure Java).
 *
 * Keeping it isolated means:
 *  - the Android APK needs exactly one extra jar (no NDK, no native code, no ABI splits),
 *  - the rest of the engine compiles against a stub when running headless self-tests.
 *
 * The LZMA-alone reader is constructed reflectively on purpose: its constructor set has changed
 * between xz releases (1.8 had LZMAInputStream(InputStream); 1.9 prefers explicit memory limits),
 * and a firmware tool must not fail to build - or crash on a user's phone - because of that.
 */
object XzSupport {

    fun decodeXz(data: ByteArray, offset: Int = 0, maxOut: Long = Limits.MAX_INFLATE_BYTES): ByteArray =
        readBounded(XZInputStream(ByteArrayInputStream(data, offset, data.size - offset)), maxOut)

    fun decodeLzma(data: ByteArray, offset: Int = 0, maxOut: Long = Limits.MAX_INFLATE_BYTES): ByteArray {
        val payload = ByteArrayInputStream(data, offset, data.size - offset)
        lzmaStream(payload)?.let { return readBounded(it, maxOut) }
        // Fallback: some vendor images are actually xz streams with an lzma-looking header.
        return decodeXz(data, offset, maxOut)
    }

    private fun lzmaStream(input: InputStream): InputStream? {
        try {
            val cls = Class.forName("org.tukaani.xz.LZMAInputStream")
            // Preferred (xz 1.9+): (InputStream, int memoryLimit)
            cls.constructors.firstOrNull { c ->
                c.parameterTypes.size == 2 &&
                    InputStream::class.java.isAssignableFrom(c.parameterTypes[0]) &&
                    (c.parameterTypes[1] == Int::class.javaPrimitiveType || c.parameterTypes[1] == java.lang.Integer::class.java)
            }?.let { c ->
                return c.newInstance(input, 64 * 1024 * 1024) as InputStream
            }
            // Legacy (xz 1.8): (InputStream)
            cls.constructors.firstOrNull { c ->
                c.parameterTypes.size == 1 && InputStream::class.java.isAssignableFrom(c.parameterTypes[0])
            }?.let { c ->
                return c.newInstance(input) as InputStream
            }
        } catch (t: Throwable) {
            // Fall through: caller falls back to the xz path and reports honestly if that fails too.
        }
        return null
    }

    private fun readBounded(input: InputStream, maxOut: Long): ByteArray {
        val out = ByteArrayOutputStream(1 shl 16)
        val buf = ByteArray(1 shl 16)
        var total = 0L
        input.use { ins ->
            while (true) {
                val n = ins.read(buf)
                if (n < 0) break
                total += n
                if (total > maxOut) throw IllegalStateException("lzma/xz limit reached")
                out.write(buf, 0, n)
            }
        }
        return out.toByteArray()
    }
}
