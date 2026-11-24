package io.github.h4lovoid.dialcrypt.core.real

import io.github.h4lovoid.dialcrypt.core.PinResult
import io.github.h4lovoid.dialcrypt.core.PinRules
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction

/** PIN handling on CharArrays, so no immutable String copy of a PIN is ever made. */
internal object PinInput {
    /** Byte limits of the native PIN check (aegiscall_trust MIN_PIN_LEN, NativeBridge 128 B). */
    const val NATIVE_MIN_BYTES = 4
    const val NATIVE_MAX_BYTES = 128

    /** UTF-8 bytes of [pin]; null for unpaired surrogates. The caller wipes the result. */
    fun utf8(pin: CharArray): ByteArray? {
        val encoder = Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val buf = ByteBuffer.allocate(pin.size * 3 + 4)
        try {
            if (!encoder.encode(CharBuffer.wrap(pin), buf, true).isUnderflow) return null
            if (!encoder.flush(buf).isUnderflow) return null
            return buf.array().copyOf(buf.position())
        } finally {
            buf.array().fill(0)
        }
    }

    /** Same rules and result mapping as [PinRules] for one PIN. */
    fun violation(pin: CharArray): PinResult? {
        val n = Character.codePointCount(pin, 0, pin.size)
        if (n < PinRules.MIN_LENGTH || n > PinRules.MAX_LENGTH) return PinResult.TOO_SHORT
        if (pin.toSet().size <= 3) return PinResult.TOO_SIMPLE
        return null
    }

    fun check(normal: CharArray, duress: CharArray): PinResult? =
        violation(normal) ?: violation(duress) ?: if (normal.contentEquals(duress)) PinResult.SAME_PINS else null
}
