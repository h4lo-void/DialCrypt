package io.github.h4lovoid.dialcrypt.call

import io.github.h4lovoid.dialcrypt.call.CallLogMatcher.PRESENTATION_ALLOWED
import io.github.h4lovoid.dialcrypt.call.CallLogMatcher.PRESENTATION_RESTRICTED
import io.github.h4lovoid.dialcrypt.call.CallLogMatcher.PRESENTATION_UNKNOWN
import io.github.h4lovoid.dialcrypt.call.CallLogMatcher.TYPE_OUTGOING
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CallLogMatcherTest {
    private val start = 1_700_000_000_000L
    private val end = start + 90_000L
    private val typeIncoming = 1
    private val typeMissed = 3

    private fun outgoing(vararg numbers: String?) =
        CallLogMatcher.target(numbers.toList(), hidden = false, incoming = false, startMs = start, endMs = end)!!

    private fun row(number: String?, dateMs: Long, type: Int = TYPE_OUTGOING, presentation: Int = PRESENTATION_ALLOWED) =
        CallLogRow(number, presentation, type, dateMs)

    @Test
    fun rowWithTheSameNumberInsideTheWindowMatches() {
        val t = outgoing("+447700900123")
        assertTrue(CallLogMatcher.matches(t, row("+447700900123", start)))
        assertTrue(CallLogMatcher.matches(t, row("+447700900123", start - 5_000L)))
        assertTrue(CallLogMatcher.matches(t, row("+447700900123", end + 60_000L)))
    }

    @Test
    fun sameNumberOutsideTheWindowIsKept() {
        val t = outgoing("+447700900123")
        assertFalse(CallLogMatcher.matches(t, row("+447700900123", start - 5_001L)))
        assertFalse(CallLogMatcher.matches(t, row("+447700900123", end + 60_001L)))
        assertFalse(CallLogMatcher.matches(t, row("+447700900123", start - 3_600_000L)))
    }

    @Test
    fun otherNumberAtTheSameTimeIsKept() {
        val t = outgoing("+447700900123")
        assertFalse(CallLogMatcher.matches(t, row("+447700900124", start + 1_000L)))
        assertFalse(CallLogMatcher.matches(t, row("+447711900123", start + 1_000L)))
        assertFalse(CallLogMatcher.matches(t, row(null, start + 1_000L, presentation = PRESENTATION_RESTRICTED)))
        assertFalse(CallLogMatcher.matches(t, row("", start + 1_000L)))
    }

    @Test
    fun directionMustFit() {
        assertFalse(CallLogMatcher.matches(outgoing("+447700900123"), row("+447700900123", start, type = typeIncoming)))
        val incoming = CallLogMatcher.target(listOf("+447700900123"), false, true, start, end)!!
        assertTrue(CallLogMatcher.matches(incoming, row("+447700900123", start, type = typeMissed)))
        assertFalse(CallLogMatcher.matches(incoming, row("+447700900123", start, type = TYPE_OUTGOING)))
    }

    @Test
    fun countryCodeAndSeparatorsDoNotMatter() {
        assertTrue(CallLogMatcher.sameNumber("+44 7700-900-123", "07700900123"))
        assertTrue(CallLogMatcher.sameNumber("00447700900123", "(07700) 900-123"))
        assertTrue(CallLogMatcher.sameNumber("+1 (415) 555-1234", "415.555.1234"))
        assertTrue(CallLogMatcher.sameNumber("+44 20 7946 0958", "020 7946 0958"))
        assertTrue(CallLogMatcher.matches(outgoing("07700 900 123"), row("+447700900123", start)))
    }

    @Test
    fun shortOrDifferentNumbersDoNotMatch() {
        assertFalse(CallLogMatcher.sameNumber("07700900123", "07711900123"))
        // Same last six digits only: too short for a suffix match.
        assertFalse(CallLogMatcher.sameNumber("900123", "07700900123"))
        // A long unrelated prefix is not a country code.
        assertFalse(CallLogMatcher.sameNumber("7700900123", "1234567700900123"))
        assertTrue(CallLogMatcher.sameNumber("112", "112"))
        // Seven matching digits under a long prefix are not enough to call it the same line.
        assertFalse(CallLogMatcher.sameNumber("5551234", "+14155551234"))
        assertFalse(CallLogMatcher.sameNumber("112", "911"))
        assertFalse(CallLogMatcher.sameNumber(null, "07700900123"))
        assertFalse(CallLogMatcher.sameNumber("---", "---"))
    }

    @Test
    fun hiddenCallerMatchesOnlyHiddenIncomingRowsInTheWindow() {
        val t = CallLogMatcher.target(listOf(null), hidden = true, incoming = true, startMs = start, endMs = end)!!
        assertTrue(t.hidden)
        assertTrue(CallLogMatcher.matches(t, row("", start + 1_000L, typeIncoming, PRESENTATION_RESTRICTED)))
        assertTrue(CallLogMatcher.matches(t, row(null, start + 1_000L, typeMissed, PRESENTATION_UNKNOWN)))
        assertFalse(CallLogMatcher.matches(t, row("+447700900123", start + 1_000L, typeIncoming, PRESENTATION_ALLOWED)))
        assertFalse(CallLogMatcher.matches(t, row("", start - 3_600_000L, typeIncoming, PRESENTATION_RESTRICTED)))
        assertFalse(CallLogMatcher.matches(t, row("", start + 1_000L, TYPE_OUTGOING, PRESENTATION_RESTRICTED)))
    }

    @Test
    fun nothingNarrowEnoughGivesNoTarget() {
        // Time alone never selects rows: no number and not a hidden incoming caller.
        assertNull(CallLogMatcher.target(listOf(null, ""), hidden = false, incoming = true, startMs = start, endMs = end))
        assertNull(CallLogMatcher.target(emptyList(), hidden = true, incoming = false, startMs = start, endMs = end))
    }

    @Test
    fun targetTextNeverContainsTheNumber() {
        assertFalse(outgoing("+447700900123").toString().contains("7700900123"))
    }
}
