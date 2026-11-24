package io.github.h4lovoid.dialcrypt.dialer.model

object DialInput {
    private const val ALLOWED = "0123456789*#+,;"

    /**
     * Keeps only dialable characters. The number itself is not judged: emergency numbers, service
     * codes and post-dial digits after `,` or `;` go through unchanged. Null when nothing is left.
     */
    fun clean(raw: String): String? = raw.filter { it in ALLOWED }.ifEmpty { null }
}

object DialPolicy {
    /**
     * Whether a dial may go out. [busy]: a secure call is under way, which a second call would put
     * on hold or end. Emergency numbers are always allowed.
     */
    fun allow(emergency: Boolean, busy: Boolean): Boolean = emergency || !busy
}
