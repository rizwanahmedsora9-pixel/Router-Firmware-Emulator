package com.flashguard.engine.compression

/**
 * LOCAL-ONLY STUB. The real XzSupport.kt uses org.tukaani:xz (available in CI and in the Android
 * APK). This stub lets `tools/localcheck.sh` compile and run the engine on a machine that has no
 * Maven access, so syntax/logic errors are caught in seconds. xz/lzma paths are exercised in CI.
 */
object XzSupport {
    fun decodeXz(data: ByteArray, offset: Int = 0, maxOut: Long = 0): ByteArray =
        throw UnsupportedOperationException("xz decoder not available in the local stub build")

    fun decodeLzma(data: ByteArray, offset: Int = 0, maxOut: Long = 0): ByteArray =
        throw UnsupportedOperationException("lzma decoder not available in the local stub build")
}
