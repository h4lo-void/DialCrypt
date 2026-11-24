package io.github.h4lovoid.dialcrypt.call

/**
 * One call the app placed or took over, described for finding its entry in the system call log.
 * The numbers stay in memory only; [toString] never prints them.
 */
internal class CallLogTarget(
    val numbers: List<String>,
    /** True only for an incoming call whose number was withheld or unknown. */
    val hidden: Boolean,
    val incoming: Boolean,
    val startMs: Long,
    val endMs: Long,
) {
    val windowStartMs: Long get() = startMs - CallLogMatcher.BEFORE_START_MS
    val windowEndMs: Long get() = endMs + CallLogMatcher.AFTER_END_MS

    override fun toString(): String = "CallLogTarget(numbers=${numbers.size}, hidden=$hidden, incoming=$incoming)"
}

/** The columns of one system call log row that the matcher reads. */
internal class CallLogRow(
    val number: String?,
    val presentation: Int,
    val type: Int,
    val dateMs: Long,
)

/**
 * Decides which system call log rows belong to a call the app handled. Free of Android classes so
 * it runs as a plain JVM test. A row matches only when its date is inside the call's window AND
 * its direction fits AND either its number is the far end's number or, for a hidden incoming
 * caller, the row is hidden as well. Time alone or number alone never matches.
 */
internal object CallLogMatcher {
    /** A row may be dated up to this long before the app saw the call. */
    const val BEFORE_START_MS = 5_000L

    /** The system writes the row after the call ends; later rows are someone else's. */
    const val AFTER_END_MS = 60_000L

    /** Numbers shorter than this (after normalization) must match in full. */
    const val MIN_SUFFIX_DIGITS = 8

    /** Longest extra prefix (international prefix plus country code) allowed on the longer number. */
    const val MAX_PREFIX_DIGITS = 3

    // Values of android.provider.CallLog.Calls constants, copied so this file needs no Android classes.
    const val PRESENTATION_ALLOWED = 1
    const val PRESENTATION_RESTRICTED = 2
    const val PRESENTATION_UNKNOWN = 3
    const val PRESENTATION_PAYPHONE = 4
    const val TYPE_OUTGOING = 2

    /**
     * Builds the target for a finished call, or null when nothing narrow enough identifies its row
     * (no usable number and not a hidden incoming caller).
     */
    fun target(
        numbers: List<String?>,
        hidden: Boolean,
        incoming: Boolean,
        startMs: Long,
        endMs: Long,
    ): CallLogTarget? {
        val usable = numbers.filterNotNull().filter { significantDigits(it).isNotEmpty() }.distinct()
        val hiddenCaller = usable.isEmpty() && hidden && incoming
        if (usable.isEmpty() && !hiddenCaller) return null
        // The entry is dated at the start of the call. Without a number to compare, the window stays
        // around the start, so a later hidden caller during a long call keeps its entry.
        val end = if (hiddenCaller) startMs else maxOf(startMs, endMs)
        return CallLogTarget(usable, hiddenCaller, incoming, startMs, end)
    }

    fun matches(target: CallLogTarget, row: CallLogRow): Boolean {
        if (row.dateMs < target.windowStartMs || row.dateMs > target.windowEndMs) return false
        val outgoingRow = row.type == TYPE_OUTGOING
        if (target.incoming == outgoingRow) return false
        return if (target.numbers.isNotEmpty()) {
            target.numbers.any { sameNumber(it, row.number) }
        } else {
            target.hidden && isHiddenRow(row)
        }
    }

    /**
     * Same number when, after keeping digits only and dropping leading zeros (trunk or
     * international prefix), both are equal, or the shorter one has at least
     * [MIN_SUFFIX_DIGITS] digits and ends the longer one, which has at most [MAX_PREFIX_DIGITS]
     * extra leading digits (a country code). "+44 7700-900-123" and "07700900123" match.
     */
    fun sameNumber(a: String?, b: String?): Boolean {
        val x = significantDigits(a)
        val y = significantDigits(b)
        if (x.isEmpty() || y.isEmpty()) return false
        if (x == y) return true
        val shorter = if (x.length <= y.length) x else y
        val longer = if (x.length <= y.length) y else x
        if (shorter.length < MIN_SUFFIX_DIGITS) return false
        return longer.length - shorter.length <= MAX_PREFIX_DIGITS && longer.endsWith(shorter)
    }

    private fun isHiddenRow(row: CallLogRow): Boolean =
        row.presentation == PRESENTATION_RESTRICTED || row.presentation == PRESENTATION_UNKNOWN

    private fun significantDigits(s: String?): String {
        if (s == null) return ""
        val sb = StringBuilder(s.length)
        for (ch in s) if (ch in '0'..'9') sb.append(ch)
        return sb.toString().trimStart('0')
    }
}
