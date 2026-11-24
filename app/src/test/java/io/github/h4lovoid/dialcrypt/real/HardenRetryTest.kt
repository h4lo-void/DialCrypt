package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.real.HardenRetry
import org.junit.Assert.assertEquals
import org.junit.Test

class HardenRetryTest {
    private var now = 0L
    private val sleeps = mutableListOf<Long>()
    private var calls = 0

    private fun run(callCostMs: Long = 0, harden: (Int) -> Int): Int =
        HardenRetry.run(
            {
                now += callCostMs
                harden(calls++)
            },
            { now },
            {
                sleeps += it
                now += it
            },
        )

    @Test
    fun successOnTheFirstCallDoesNotWait() {
        assertEquals(0, run { 0 })
        assertEquals(1, calls)
        assertEquals(emptyList<Long>(), sleeps)
    }

    @Test
    fun internalIsRetriedEvery100MsUntilItSucceeds() {
        assertEquals(0, run { n -> if (n < 3) -8 else 0 })
        assertEquals(4, calls)
        assertEquals(listOf(100L, 100L, 100L), sleeps)
    }

    @Test
    fun givesUpWithInternalAfterFiveSeconds() {
        assertEquals(-8, run { -8 })
        assertEquals(5_000L, sleeps.sum())
        assertEquals(51, calls)
        assertEquals(5_000L, now)
    }

    @Test
    fun successOnTheLastAttemptStillCounts() {
        assertEquals(0, run { n -> if (n < 50) -8 else 0 })
        assertEquals(51, calls)
    }

    @Test
    fun otherCodesAreReturnedAtOnce() {
        assertEquals(-1, run { -1 })
        assertEquals(1, calls)
        assertEquals(emptyList<Long>(), sleeps)
    }

    @Test
    fun slowCallsCountAgainstTheLimit() {
        assertEquals(-8, run(callCostMs = 1_000) { -8 })
        assertEquals(5, calls)
        assertEquals(listOf(100L, 100L, 100L, 100L), sleeps)
    }

    @Test
    fun theLastWaitIsCutToTheRemainingTime() {
        assertEquals(-8, run(callCostMs = 30) { -8 })
        assertEquals(5_000L, sleeps.sum() + 30L * (calls - 1))
        assertEquals(true, sleeps.last() < 100L)
    }
}
