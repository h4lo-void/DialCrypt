package io.github.h4lovoid.dialcrypt.incoming

import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The main thread only grants an answer request; a request the caller gave up on stays void. */
class AnswerTicketTest {
    @Test
    fun aGrantInTimeHandsTheCallToTheCaller() {
        val t = AnswerTicket<String>()
        assertTrue(t.grant("call"))
        assertEquals("call", t.await(1_000L))
    }

    @Test
    fun aRefusedRequestReturnsNothing() {
        val t = AnswerTicket<String>()
        t.refuse()
        assertNull(t.await(1_000L))
    }

    @Test
    fun refusingAfterAGrantKeepsTheGrant() {
        val t = AnswerTicket<String>()
        assertTrue(t.grant("call"))
        t.refuse()
        assertEquals("call", t.await(1_000L))
    }

    @Test
    fun aGrantAfterTheCallerGaveUpHasNoEffect() {
        val t = AnswerTicket<String>()
        assertNull(t.await(10L))
        assertFalse(t.grant("call"))
        assertNull(t.await(0L))
    }

    @Test
    fun aStalledMainThreadIsCancelledAndItsLateGrantIsVoid() {
        val t = AnswerTicket<String>()
        val unstall = CountDownLatch(1)
        val granted = AtomicReference<Boolean?>(null)
        val mainThread = Thread {
            unstall.await()
            granted.set(t.grant("call"))
        }.apply { start() }
        assertNull(t.await(50L))
        unstall.countDown()
        mainThread.join(2_000L)
        assertEquals(false, granted.get())
    }

    @Test
    fun aGrantFromAnotherThreadInTimeIsSeen() {
        val t = AnswerTicket<String>()
        val mainThread = Thread { t.grant("call") }.apply { start() }
        assertEquals("call", t.await(2_000L))
        mainThread.join(2_000L)
    }
}
