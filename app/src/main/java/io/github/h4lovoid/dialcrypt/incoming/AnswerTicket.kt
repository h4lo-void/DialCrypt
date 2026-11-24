package io.github.h4lovoid.dialcrypt.incoming

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * One answer request handed to the main thread. The main thread only checks and marks the call and
 * [grant]s it; the caller then sends the answer from its own thread. A caller that stops waiting
 * voids the request first, so a grant that arrives later has no effect.
 */
internal class AnswerTicket<T : Any> {
    private val state = AtomicInteger(PENDING)
    private val done = CountDownLatch(1)

    @Volatile
    private var value: T? = null

    /** Main thread: grants the request with [v]. False when the caller already gave up: nothing may be marked then. */
    fun grant(v: T): Boolean {
        value = v
        val ok = state.compareAndSet(PENDING, GRANTED)
        done.countDown()
        return ok
    }

    /** Main thread: the check ended without a grant. Has no effect after [grant]. */
    fun refuse() {
        state.compareAndSet(PENDING, REFUSED)
        done.countDown()
    }

    /**
     * Caller: waits at most [timeoutMs]. Returns the granted value, or null when the request was
     * refused or the wait ran out; running out voids the request.
     */
    fun await(timeoutMs: Long): T? {
        try {
            done.await(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        if (state.compareAndSet(PENDING, CANCELLED)) return null
        return if (state.get() == GRANTED) value else null
    }

    private companion object {
        const val PENDING = 0
        const val GRANTED = 1
        const val REFUSED = 2
        const val CANCELLED = 3
    }
}
