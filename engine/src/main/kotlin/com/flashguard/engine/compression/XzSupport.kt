package com.flashguard.engine.compression

import com.flashguard.engine.util.Limits
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import org.tukaani.xz.LZMAInputStream
import org.tukaani.xz.XZInputStream

/**
 * The ONLY file in the engine that touches a third-party library (org.tukaani:xz, pure Java).
 *
 * Keeping it isolated means:
 *  - the Android APK needs exactly one extra jar (no NDK, no native code, no abi splits),
 *  - the rest of the engine compiles against a stub when running headless self-tests.
 */
object XzSupport {

    fun decodeXz(data: ByteArray, offset: Int = 0, maxOut: Long = Limits.MAX_INFLATE_BYTES): ByteArray =
        readBounded(XZInputStream(ByteArrayInputStream(data, offset, data.size - offset)), maxOut)

    fun decodeLzma(data: ByteArray, offset: Int = 0, maxOut: Long = Limits.MAX_INFLATE_BYTES): ByteArray =
        readBounded(LZMAInputStream(ByteArrayInputStream(data, offset, data.size - offset)), maxOut)

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
