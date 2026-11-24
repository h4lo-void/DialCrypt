package io.github.h4lovoid.dialcrypt.core

object PhoneRules {
    private const val MIN_DIGITS = 5
    private const val MAX_DIGITS = 15

    /**
     * Calling code (digits only, no plus) used to expand local national numbers. Set once per process
     * from the SIM card's country; null while unknown, in which case local numbers are not expanded.
     */
    @Volatile
    var defaultCountryCode: String? = null

    /** Keeps digits and a single leading plus sign. */
    fun normalize(input: String): String {
        val trimmed = input.trim()
        val digits = trimmed.filter { it in '0'..'9' }
        return if (trimmed.startsWith("+")) "+$digits" else digits
    }

    fun isValid(input: String): Boolean {
        val n = normalize(input)
        val count = n.count { it in '0'..'9' }
        return count in MIN_DIGITS..MAX_DIGITS
    }

    /**
     * Converts a user-entered or Telecom number into canonical E.164 (`+<1..9><digits>`, 5..15 digits)
     * as expected by the native vault (`valid_e164`). Local national numbers starting with a single `0`
     * drop that `0` and prepend `+$defaultCountryCode`; when no country code is known they are invalid
     * and the user has to enter the full number starting with `+`.
     */
    fun toVaultE164(input: String, defaultCountryCode: String? = PhoneRules.defaultCountryCode): String? {
        val n = normalize(input)
        if (n.isEmpty()) return null
        val e164 = when {
            n.startsWith("+") -> n
            n.startsWith("00") -> "+${n.drop(2)}"
            n.startsWith("0") -> {
                if (defaultCountryCode == null) return null
                "+$defaultCountryCode${n.drop(1)}"
            }
            else -> "+$n"
        }
        val digits = e164.drop(1)
        if (digits.length !in MIN_DIGITS..MAX_DIGITS) return null
        if (digits.first() !in '1'..'9') return null
        return e164
    }

    /**
     * Returns canonical and local candidate representations for incoming caller-ID matching,
     * so `07700900101` and `+447700900101` both match a stored contact when the country code is 44.
     * Without a country code only the normalized input and its directly convertible E.164 form are returned.
     */
    fun matchCandidates(input: String, defaultCountryCode: String? = PhoneRules.defaultCountryCode): Set<String> {
        val n = normalize(input)
        if (n.isEmpty()) return emptySet()
        val out = LinkedHashSet<String>(4)
        toVaultE164(n, defaultCountryCode)?.let { e164 ->
            out += e164
            if (defaultCountryCode != null) {
                val ccPrefix = "+$defaultCountryCode"
                if (e164.startsWith(ccPrefix) && e164.length > ccPrefix.length) {
                    out += "0" + e164.removePrefix(ccPrefix)
                }
            }
        }
        out += n
        return out
    }

    /** Hides all but the last four digits. Null stays null. */
    fun mask(number: String?): String? {
        if (number == null) return null
        val digits = number.filter { it in '0'..'9' }
        if (digits.length <= 4) return "\u2022".repeat(digits.length.coerceAtLeast(1))
        return "\u2022\u2022\u2022\u2022 " + digits.takeLast(4)
    }
}
