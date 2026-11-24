package io.github.h4lovoid.dialcrypt.dialer

import android.provider.CallLog
import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.dialer.model.CallLogAccess
import io.github.h4lovoid.dialcrypt.dialer.model.NumberText
import io.github.h4lovoid.dialcrypt.dialer.model.RecentCalls
import io.github.h4lovoid.dialcrypt.dialer.model.RecentCallsModel
import io.github.h4lovoid.dialcrypt.dialer.model.RecentDirection
import io.github.h4lovoid.dialcrypt.dialer.model.RecentEntry
import java.time.ZoneOffset
import java.util.Locale
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RecentCallsTest {
    private val masked = NumberText.Digits("\u2022\u2022\u2022\u2022 0199")
    private val stranger = "+15550100199"

    private fun entry(
        id: Long = 1L,
        number: String? = stranger,
        type: Int = RecentCalls.TYPE_INCOMING,
        presentation: Int = RecentCalls.PRESENTATION_ALLOWED,
        durationSec: Long = 75L,
    ) = RecentEntry(id, number, type, presentation, dateMs = 1_000L * id, durationSec = durationSec)

    private fun item(e: RecentEntry, m: ContactMembership = ContactMembership.NOT_CONTACT, showFull: Boolean = false) =
        RecentCalls.item(e, { m }, showFull)

    @Test
    fun callLogValuesMatchThePlatform() {
        assertEquals(CallLog.Calls.INCOMING_TYPE, RecentCalls.TYPE_INCOMING)
        assertEquals(CallLog.Calls.OUTGOING_TYPE, RecentCalls.TYPE_OUTGOING)
        assertEquals(CallLog.Calls.MISSED_TYPE, RecentCalls.TYPE_MISSED)
        assertEquals(CallLog.Calls.VOICEMAIL_TYPE, RecentCalls.TYPE_VOICEMAIL)
        assertEquals(CallLog.Calls.REJECTED_TYPE, RecentCalls.TYPE_REJECTED)
        assertEquals(CallLog.Calls.BLOCKED_TYPE, RecentCalls.TYPE_BLOCKED)
        assertEquals(CallLog.Calls.ANSWERED_EXTERNALLY_TYPE, RecentCalls.TYPE_ANSWERED_EXTERNALLY)
        assertEquals(CallLog.Calls.PRESENTATION_ALLOWED, RecentCalls.PRESENTATION_ALLOWED)
        assertEquals(CallLog.Calls.PRESENTATION_RESTRICTED, RecentCalls.PRESENTATION_RESTRICTED)
        assertEquals(CallLog.Calls.PRESENTATION_UNKNOWN, RecentCalls.PRESENTATION_UNKNOWN)
        assertEquals(CallLog.Calls.PRESENTATION_PAYPHONE, RecentCalls.PRESENTATION_PAYPHONE)
    }

    @Test
    fun directionsCoverIncomingOutgoingAndMissed() {
        assertEquals(RecentDirection.INCOMING, RecentCalls.direction(RecentCalls.TYPE_INCOMING))
        assertEquals(RecentDirection.INCOMING, RecentCalls.direction(RecentCalls.TYPE_ANSWERED_EXTERNALLY))
        assertEquals(RecentDirection.OUTGOING, RecentCalls.direction(RecentCalls.TYPE_OUTGOING))
        assertEquals(RecentDirection.MISSED, RecentCalls.direction(RecentCalls.TYPE_MISSED))
        assertEquals(RecentDirection.MISSED, RecentCalls.direction(RecentCalls.TYPE_REJECTED))
        assertEquals(RecentDirection.MISSED, RecentCalls.direction(RecentCalls.TYPE_BLOCKED))
        assertNull(RecentCalls.direction(RecentCalls.TYPE_VOICEMAIL))
        assertNull(item(entry(type = RecentCalls.TYPE_VOICEMAIL)))
    }

    @Test
    fun numbersFollowTheDisplayRule() {
        assertEquals(NumberText.Digits(stranger), item(entry())!!.number)
        assertEquals(masked, item(entry(), ContactMembership.CONTACT)!!.number)
        assertEquals(NumberText.Digits(stranger), item(entry(), ContactMembership.CONTACT, showFull = true)!!.number)
        assertEquals(masked, item(entry(), ContactMembership.UNKNOWN, showFull = true)!!.number)
    }

    @Test
    fun hiddenUnknownAndPayphoneRowsShowWordsAndCannotBeCalled() {
        val hidden = item(entry(number = "", presentation = RecentCalls.PRESENTATION_RESTRICTED))!!
        assertEquals(NumberText.Hidden, hidden.number)
        assertNull(hidden.dialNumber)
        val unknown = item(entry(number = null, presentation = RecentCalls.PRESENTATION_UNKNOWN))!!
        assertEquals(NumberText.Unknown, unknown.number)
        assertNull(unknown.dialNumber)
        val payphone = item(entry(number = "", presentation = RecentCalls.PRESENTATION_PAYPHONE))!!
        assertEquals(NumberText.Payphone, payphone.number)
        assertNull(payphone.dialNumber)
        // A number marked as restricted is never shown or dialed, even when the log still holds it.
        assertNull(item(entry(presentation = RecentCalls.PRESENTATION_RESTRICTED))!!.dialNumber)
    }

    @Test
    fun aShownNumberIsCalledBackWithOnlyDialCharacters() {
        assertEquals("+15550100199", item(entry(number = "+1 (555) 010-0199"), ContactMembership.CONTACT)!!.dialNumber)
    }

    @Test
    fun missedCallsHaveNoDurationAndOthersOnlyWhenConnected() {
        assertNull(item(entry(type = RecentCalls.TYPE_MISSED, durationSec = 12L))!!.durationSec)
        assertEquals(75L, item(entry())!!.durationSec)
        assertNull(item(entry(type = RecentCalls.TYPE_OUTGOING, durationSec = 0L))!!.durationSec)
    }

    @Test
    fun durationAndTimeFormats() {
        assertEquals("0:09", RecentCalls.duration(9L))
        assertEquals("12:05", RecentCalls.duration(725L))
        assertEquals("1:02:03", RecentCalls.duration(3723L))
        val now = 1_795_478_400_000L // 2026-11-24T00:00:00Z
        val today = RecentCalls.time(now + 15 * 3_600_000L + 5 * 60_000L, now + 20 * 3_600_000L, ZoneOffset.UTC, Locale.US)
        assertTrue(today, today.contains("3:05"))
        val earlier = RecentCalls.time(now - 3_600_000L, now + 20 * 3_600_000L, ZoneOffset.UTC, Locale.US)
        assertTrue(earlier, earlier.contains("Nov 23"))
    }

    private class FakeLog(var rows: MutableList<RecentEntry>?) : CallLogAccess {
        var deleteWorks = true
        var clearWorks = true
        val deleted = ArrayList<Long>()
        var cleared = 0
        var loads = 0

        /** When set, the first load reports in on [loadEntered] and then waits here with its rows already read. */
        @Volatile
        var loadGate: CountDownLatch? = null
        val loadEntered = CountDownLatch(1)

        override fun load(): List<RecentEntry>? {
            val read = synchronized(this) {
                loads++
                rows?.toList()
            }
            loadGate?.let { gate ->
                loadGate = null
                loadEntered.countDown()
                gate.await(10, TimeUnit.SECONDS)
            }
            return read
        }

        @Synchronized
        override fun delete(id: Long): Boolean {
            if (!deleteWorks) return false
            deleted += id
            rows?.removeAll { it.id == id }
            return true
        }

        @Synchronized
        override fun clear(): Boolean {
            if (!clearWorks) return false
            cleared++
            rows?.clear()
            return true
        }
    }

    private val strangers: () -> (String) -> ContactMembership = { { ContactMembership.NOT_CONTACT } }

    @Test
    fun refreshReadsTheIndexOnceAsksOncePerNumberAndKeepsTheOrder() {
        val log = FakeLog(mutableListOf(entry(3), entry(2, number = "+447700900101"), entry(1)))
        val asked = ArrayList<String>()
        var opened = 0
        val model = RecentCallsModel(log, { opened++; { n -> asked += n; ContactMembership.CONTACT } }, { false })
        model.refresh()
        val s = model.state.value
        assertTrue(s.loaded)
        assertFalse(s.unavailable)
        assertEquals(listOf(3L, 2L, 1L), s.items.map { it.id })
        assertEquals(listOf(stranger, "+447700900101"), asked)
        assertEquals(1, opened)
        assertEquals(masked, s.items.first().number)
    }

    @Test
    fun anUnreadableCallLogIsShownAsUnavailable() {
        val model = RecentCallsModel(FakeLog(null), strangers, { false })
        model.refresh()
        assertTrue(model.state.value.unavailable)
        assertTrue(model.state.value.items.isEmpty())
    }

    @Test
    fun deleteRemovesOneRowOnlyWhenTheCallLogDid() {
        val log = FakeLog(mutableListOf(entry(2), entry(1)))
        val model = RecentCallsModel(log, strangers, { false })
        model.refresh()
        log.deleteWorks = false
        assertFalse(model.delete(2L))
        assertEquals(listOf(2L, 1L), model.state.value.items.map { it.id })
        log.deleteWorks = true
        assertTrue(model.delete(2L))
        assertEquals(listOf(2L), log.deleted)
        assertEquals(listOf(1L), model.state.value.items.map { it.id })
    }

    @Test
    fun clearAllEmptiesTheListOnlyWhenTheCallLogWasCleared() {
        val log = FakeLog(mutableListOf(entry(2), entry(1)))
        val model = RecentCallsModel(log, strangers, { false })
        model.refresh()
        log.clearWorks = false
        assertFalse(model.clearAll())
        assertEquals(2, model.state.value.items.size)
        log.clearWorks = true
        assertTrue(model.clearAll())
        assertEquals(1, log.cleared)
        assertTrue(model.state.value.items.isEmpty())
        model.refresh()
        assertTrue(model.state.value.items.isEmpty())
    }

    // ---- rows of a call whose entry the secure flow is still erasing ----------------------------

    @Test
    fun rowsFromAPendingEraseOnAreHeldBackUntilItIsOver() {
        // Rows dated 1 s, 2 s and 3 s; the secure call started at 2 s.
        val log = FakeLog(mutableListOf(entry(3), entry(2), entry(1)))
        var pending: Long? = 2_000L
        val model = RecentCallsModel(log, strangers, { false }, { pending })
        model.refresh()
        assertEquals(listOf(1L), model.state.value.items.map { it.id })
        assertEquals(2_000L, model.state.value.hiddenFromMs)

        // Nothing changed: no reload. The same holds for every refresh while the erase is pending.
        assertFalse(model.refreshIfPendingEraseChanged())
        model.refresh()
        assertEquals(listOf(1L), model.state.value.items.map { it.id })

        // The eraser deleted the entry and removed the marker: the other held-back row shows.
        log.delete(2L)
        pending = null
        assertTrue(model.refreshIfPendingEraseChanged())
        assertEquals(listOf(3L, 1L), model.state.value.items.map { it.id })
        assertNull(model.state.value.hiddenFromMs)
        assertFalse(model.refreshIfPendingEraseChanged())
    }

    @Test
    fun aMarkerThatGoesAwayWhileTheCallLogIsReadStillHidesTheRow() {
        val log = FakeLog(mutableListOf(entry(2), entry(1)))
        val answers = ArrayDeque(listOf<Long?>(2_000L, null, null, null))
        val model = RecentCallsModel(log, strangers, { false }, { answers.removeFirst() })
        model.refresh()
        assertEquals(listOf(1L), model.state.value.items.map { it.id })
        assertEquals(2_000L, model.state.value.hiddenFromMs)
    }

    @Test
    fun aMarkerWrittenWhileTheCallLogIsReadHidesTheRowToo() {
        val log = FakeLog(mutableListOf(entry(2), entry(1)))
        val answers = ArrayDeque(listOf<Long?>(null, 2_000L))
        val model = RecentCallsModel(log, strangers, { false }, { answers.removeFirst() })
        model.refresh()
        assertEquals(listOf(1L), model.state.value.items.map { it.id })
    }

    @Test
    fun deleteDoesNotWaitForARunningRefreshAndTheRowStaysGone() {
        val log = FakeLog(mutableListOf(entry(3), entry(2), entry(1)))
        val model = RecentCallsModel(log, strangers, { false })
        model.refresh()
        val gate = CountDownLatch(1)
        log.loadGate = gate
        val refresher = thread { model.refresh() }
        assertTrue(log.loadEntered.await(10, TimeUnit.SECONDS))

        // The refresh holds rows it read before the delete; the delete returns without waiting for it.
        assertTrue(model.delete(2L))
        assertEquals(listOf(3L, 1L), model.state.value.items.map { it.id })

        gate.countDown()
        refresher.join(10_000L)
        assertFalse(refresher.isAlive)
        // The overtaken refresh loaded again instead of bringing the row back.
        assertEquals(listOf(3L, 1L), model.state.value.items.map { it.id })
        assertEquals(3, log.loads)
    }
}
