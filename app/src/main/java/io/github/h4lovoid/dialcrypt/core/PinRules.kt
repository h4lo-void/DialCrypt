package io.github.h4lovoid.dialcrypt.core

import kotlin.math.ln

/** Rules for the normal and the emergency PIN. */
object PinRules {
    const val MIN_LENGTH = 10
    const val MAX_LENGTH = 64

    enum class Violation { TOO_SHORT, TOO_LONG, TOO_SIMPLE }
    enum class Strength { WEAK, FAIR, GOOD, STRONG }

    private fun length(pin: String) = pin.codePointCount(0, pin.length)

    fun violation(pin: String): Violation? {
        val n = length(pin)
        if (n < MIN_LENGTH) return Violation.TOO_SHORT
        if (n > MAX_LENGTH) return Violation.TOO_LONG
        if (pin.toSet().size <= 3) return Violation.TOO_SIMPLE
        return null
    }

    fun strength(pin: String): Strength {
        if (pin.isEmpty()) return Strength.WEAK
        var pool = 0
        if (pin.any { it in 'a'..'z' }) pool += 26
        if (pin.any { it in 'A'..'Z' }) pool += 26
        if (pin.any { it in '0'..'9' }) pool += 10
        if (pin.any { it.code < 128 && !it.isLetterOrDigit() }) pool += 33
        if (pin.any { it.code >= 128 }) pool += 64
        val distinct = pin.toSet().size
        val effective = minOf(length(pin), distinct * 2)
        val bits = effective * ln(pool.toDouble()) / ln(2.0)
        return when {
            distinct <= 3 || bits < 45 -> Strength.WEAK
            bits < 60 -> Strength.FAIR
            bits < 80 -> Strength.GOOD
            else -> Strength.STRONG
        }
    }

    /** The emergency PIN must differ from the normal one. */
    fun pairViolation(normal: String, duress: String): Boolean = normal == duress
}
