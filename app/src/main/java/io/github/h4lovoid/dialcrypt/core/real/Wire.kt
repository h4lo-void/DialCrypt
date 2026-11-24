package io.github.h4lovoid.dialcrypt.core.real

import java.io.ByteArrayOutputStream

/** Return codes of the Int functions of [io.github.h4lovoid.dialcrypt.core.NativeBridge]. */
internal object NativeCode {
    const val OK = 0
    const val BAD_HANDLE = -1
    const val BAD_ARG = -2
    const val BAD_STATE = -3
    const val CRYPTO = -4
    const val LOCKED = -5
    const val ABORTED = -6
    const val BUSY = -7
    const val INTERNAL = -8

    /** Added to the contact id nativeImportPairing returns when the stored PSK is new or changed. */
    const val PAIRING_PSK_CHANGED = 0x4000_0000

    /** nativePinFinish results. */
    const val UNLOCK_WRONG = 0
    const val UNLOCK_NORMAL = 1
    const val UNLOCK_DURESS = 2

    /** nativePinChange results. */
    const val PIN_CHANGE_WRONG_CURRENT = 0
    const val PIN_CHANGE_STAGED = 1
    const val PIN_CHANGE_WRONG_LOCKED = 2
    const val PIN_CHANGE_DURESS = 3
}

/** Big-endian reader for the NativeBridge byte layouts; every read returns null past the end. */
internal class ByteReader(private val data: ByteArray) {
    private var pos = 0

    val remaining: Int get() = data.size - pos
    val atEnd: Boolean get() = pos == data.size

    fun u8(): Int? {
        if (remaining < 1) return null
        return data[pos++].toInt() and 0xFF
    }

    fun u16(): Int? {
        if (remaining < 2) return null
        val v = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        pos += 2
        return v
    }

    /** Unsigned 32-bit value. */
    fun u32(): Long? {
        if (remaining < 4) return null
        var v = 0L
        repeat(4) { v = (v shl 8) or (data[pos++].toLong() and 0xFF) }
        return v
    }

    fun bytes(n: Int): ByteArray? {
        if (n < 0 || remaining < n) return null
        val out = data.copyOfRange(pos, pos + n)
        pos += n
        return out
    }
}

internal fun ByteArrayOutputStream.putU8(v: Int) = write(v and 0xFF)

internal fun ByteArrayOutputStream.putU16(v: Int) {
    write((v ushr 8) and 0xFF)
    write(v and 0xFF)
}

internal fun ByteArrayOutputStream.putU32(v: Long) {
    for (shift in intArrayOf(24, 16, 8, 0)) write(((v ushr shift) and 0xFF).toInt())
}
