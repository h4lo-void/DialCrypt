package io.github.h4lovoid.dialcrypt.review

import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.dialer.model.CallLogAccess
import io.github.h4lovoid.dialcrypt.dialer.model.RecentCallsModel
import io.github.h4lovoid.dialcrypt.dialer.model.RecentEntry
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Second review: the recent calls model with edits overtaking a refresh and with a pending erase. */
class ReviewRecheckRecentsTest {
    private class FakeLog(rows: List<RecentEntry>) : CallLogAccess {
        private val rows = CopyOnWriteArrayList(rows)
        val loads = AtomicInteger()

        /** The next load takes its snapshot, counts [entered] down and then waits here. */
        @Volatile
        var gate: CountDownLatch? = null

        @Volatile
        var entered: CountDownLatch? = null

        override fun load(): List<RecentEntry>? {
            loads.incrementAndGet()
            val snapshot = rows.toList()
            val g = gate
            if (g != null) {
                gate = null
                entered?.countDown()
                g.await(10, TimeUnit.SECONDS)
            }
            return snapshot
        }

        override fun delete(id: Long): Boolean = rows.removeIf { it.id == id }

        override fun clear(): Boolean {
            rows.clear()
            return true
        }
    }

    private fun entry(id: Long, dateMs: Long, number: String = "+1555010" + id) =
        RecentEntry(id = id, number = number, type = 1, presentation = 1, dateMs = dateMs, durationSec = 10)

    private val stranger: () -> (String) -> ContactMembership = { { _: String -> ContactMembership.NOT_CONTACT } }

    private fun ids(m: RecentCallsModel) = m.state.value.items.map { it.id }

    @Test
    fun aDeleteDuringARefreshIsNotHeldUpAndTheRowDoesNotComeBack() {
        val log = FakeLog(listOf(entry(3, 3_000), entry(2, 2_000), entry(1, 1_000)))
        val model = RecentCallsModel(log, stranger, { false })
        model.refresh()
        assertEquals(listOf(3L, 2L, 1L), ids(model))

        val entered = CountDownLatch(1)
        val gate = CountDownLatch(1)
        log.entered = entered
        log.gate = gate
        val refresh = thread { model.refresh() }
        assertTrue(entered.await(10, TimeUnit.SECONDS))
        // The refresh holds a snapshot with all three rows and is still inside the call log.
        val deleted = AtomicInteger()
        val delete = thread { if (model.delete(2)) deleted.incrementAndGet() }
        delete.join(5_000)
        assertFalse("delete waited for the refresh", delete.isAlive)
        assertEquals(1, deleted.get())
        assertEquals(listOf(3L, 1L), ids(model))

        gate.countDown()
        refresh.join(10_000)
        assertFalse(refresh.isAlive)
        assertEquals(listOf(3L, 1L), ids(model))
        // The overtaken pass was thrown away and the call log was read once more.
        assertEquals(3, log.loads.get())
    }

    @Test
    fun aClearDuringARefreshLeavesTheListEmpty() {
        val log = FakeLog(listOf(entry(2, 2_000), entry(1, 1_000)))
        val model = RecentCallsModel(log, stranger, { false })
        val entered = CountDownLatch(1)
        val gate = CountDownLatch(1)
        log.entered = entered
        log.gate = gate
        val refresh = thread { model.refresh() }
        assertTrue(entered.await(10, TimeUnit.SECONDS))
        assertTrue(model.clearAll())
        gate.countDown()
        refresh.join(10_000)
        assertFalse(refresh.isAlive)
        assertEquals(emptyList<Long>(), ids(model))
        assertTrue(model.state.value.loaded)
    }

    @Test
    fun rowsFromThePendingEraseOnAreHeldBackUntilItEnds() {
        val log = FakeLog(listOf(entry(3, 9_000), entry(2, 5_000), entry(1, 4_999)))
        var pending: Long? = 5_000L
        val model = RecentCallsModel(log, stranger, { false }, { pending })
        model.refresh()
        assertEquals(listOf(1L), ids(model))
        assertEquals(5_000L, model.state.value.hiddenFromMs)
        assertFalse(model.refreshIfPendingEraseChanged())
        // Every later refresh keeps hiding them, whatever started it.
        model.refresh()
        assertEquals(listOf(1L), ids(model))

        pending = null
        assertTrue(model.refreshIfPendingEraseChanged())
        assertEquals(listOf(3L, 2L, 1L), ids(model))
        assertNull(model.state.value.hiddenFromMs)
    }

    @Test
    fun aMarkerSeenOnlyBeforeOrOnlyAfterTheCallLogWasReadStillHides() {
        val log = FakeLog(listOf(entry(2, 5_000), entry(1, 1_000)))
        val answers = ArrayDeque(listOf<Long?>(4_000L, null))
        val onlyBefore = RecentCallsModel(log, stranger, { false }, { answers.removeFirst() })
        onlyBefore.refresh()
        assertEquals(listOf(1L), ids(onlyBefore))

        val later = ArrayDeque(listOf<Long?>(null, 4_000L))
        val onlyAfter = RecentCallsModel(log, stranger, { false }, { later.removeFirst() })
        onlyAfter.refresh()
        assertEquals(listOf(1L), ids(onlyAfter))
    }

    @Test
    fun aRefreshOpensTheIndexOnceAndAsksOncePerNumber() {
        val log = FakeLog(listOf(entry(3, 3_000, "+15550100"), entry(2, 2_000, "+15550199"), entry(1, 1_000, "+15550100")))
        var opens = 0
        val asked = ArrayList<String>()
        val model = RecentCallsModel(
            log,
            {
                opens++
                val lookup: (String) -> ContactMembership = { n ->
                    asked.add(n)
                    ContactMembership.CONTACT
                }
                lookup
            },
            { false },
        )
        model.refresh()
        assertEquals(1, opens)
        assertEquals(listOf("+15550100", "+15550199"), asked)
        assertEquals(listOf(3L, 2L, 1L), ids(model))
    }
}
