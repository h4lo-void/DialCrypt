package io.github.h4lovoid.dialcrypt.call

import android.telephony.TelephonyManager.CALL_STATE_IDLE
import android.telephony.TelephonyManager.CALL_STATE_OFFHOOK
import android.telephony.TelephonyManager.CALL_STATE_RINGING
import io.github.h4lovoid.dialcrypt.call.PreciseState.ACTIVE
import io.github.h4lovoid.dialcrypt.call.PreciseState.ALERTING
import io.github.h4lovoid.dialcrypt.call.PreciseState.DIALING
import io.github.h4lovoid.dialcrypt.call.PreciseState.DISCONNECTED
import io.github.h4lovoid.dialcrypt.call.PreciseState.HOLDING
import io.github.h4lovoid.dialcrypt.call.PreciseState.IDLE
import io.github.h4lovoid.dialcrypt.call.PreciseState.INCOMING
import io.github.h4lovoid.dialcrypt.call.PreciseState.WAITING
import org.junit.Assert.assertEquals
import org.junit.Test

class CallTrackerTest {
    private val number = "+447700900001"

    @Test
    fun outgoingCallIsActiveOnlyWhenTheFarEndAnswers() {
        val t = CallTracker()
        t.beginDial(number)
        assertEquals(CallStatus(CallPhase.DIALING, false, number), t.status)
        // Stale idle report from before telephony saw the call.
        assertEquals(CallPhase.DIALING, t.onPrecise(IDLE, IDLE, IDLE).phase)
        assertEquals(CallPhase.DIALING, t.onPrecise(IDLE, DIALING, IDLE).phase)
        // OFFHOOK at dial time must not count as answered.
        assertEquals(CallPhase.DIALING, t.onLegacy(CALL_STATE_OFFHOOK, null).phase)
        assertEquals(CallPhase.DIALING, t.onPrecise(IDLE, ALERTING, IDLE).phase)
        assertEquals(CallStatus(CallPhase.ACTIVE, false, number), t.onPrecise(IDLE, ACTIVE, IDLE))
        assertEquals(CallStatus(CallPhase.ENDED, false, number), t.onPrecise(IDLE, DISCONNECTED, IDLE))
        assertEquals(CallPhase.ENDED, t.onPrecise(IDLE, IDLE, IDLE).phase)
    }

    @Test
    fun outgoingCallRejectedAfterDialingEnds() {
        val t = CallTracker()
        t.beginDial(number)
        t.onPrecise(IDLE, DIALING, IDLE)
        assertEquals(CallPhase.ENDED, t.onPrecise(IDLE, IDLE, IDLE).phase)
    }

    @Test
    fun incomingNumberBeforeOrAfterThePreciseRing() {
        val first = CallTracker()
        first.onLegacy(CALL_STATE_RINGING, number)
        assertEquals(CallStatus(CallPhase.RINGING, true, number), first.onPrecise(INCOMING, IDLE, IDLE))
        assertEquals(CallStatus(CallPhase.ACTIVE, true, number), first.onPrecise(IDLE, ACTIVE, IDLE))

        val second = CallTracker()
        assertEquals(CallStatus(CallPhase.RINGING, true, null), second.onPrecise(INCOMING, IDLE, IDLE))
        assertEquals(CallStatus(CallPhase.RINGING, true, number), second.onLegacy(CALL_STATE_RINGING, number))
    }

    @Test
    fun hiddenIncomingNumberStaysNull() {
        val t = CallTracker()
        t.onLegacy(CALL_STATE_RINGING, "")
        assertEquals(CallStatus(CallPhase.RINGING, true, null), t.onPrecise(INCOMING, IDLE, IDLE))
    }

    @Test
    fun callWaitingKeepsTheActiveCall() {
        val t = CallTracker()
        t.onLegacy(CALL_STATE_RINGING, number)
        t.onPrecise(INCOMING, IDLE, IDLE)
        t.onPrecise(IDLE, ACTIVE, IDLE)
        t.onLegacy(CALL_STATE_OFFHOOK, null)
        t.onLegacy(CALL_STATE_RINGING, "+447700900002")
        assertEquals(CallStatus(CallPhase.ACTIVE, true, number), t.onPrecise(WAITING, ACTIVE, IDLE))
        assertEquals(CallPhase.ACTIVE, t.onPrecise(IDLE, IDLE, HOLDING).phase)
    }

    @Test
    fun newCycleStartsClean() {
        val t = CallTracker()
        t.onLegacy(CALL_STATE_RINGING, number)
        t.onPrecise(INCOMING, IDLE, IDLE)
        t.onPrecise(IDLE, IDLE, IDLE)
        t.onLegacy(CALL_STATE_IDLE, null)
        assertEquals(CallPhase.ENDED, t.status.phase)
        assertEquals(CallStatus(CallPhase.RINGING, true, null), t.onPrecise(INCOMING, IDLE, IDLE))
    }

    @Test
    fun callAlreadyUpWhenListeningStarts() {
        val t = CallTracker()
        assertEquals(CallStatus(CallPhase.ACTIVE, false, null), t.onPrecise(IDLE, ACTIVE, IDLE))
    }

    @Test
    fun legacyFallbackMapsOffhook() {
        val t = CallTracker()
        t.usePrecise(false)
        t.beginDial(number)
        assertEquals(CallPhase.DIALING, t.onLegacy(CALL_STATE_IDLE, null).phase)
        assertEquals(CallStatus(CallPhase.ACTIVE, false, number), t.onLegacy(CALL_STATE_OFFHOOK, null))
        assertEquals(CallPhase.ACTIVE, t.onLegacy(CALL_STATE_RINGING, "+447700900002").phase)
        assertEquals(CallPhase.ENDED, t.onLegacy(CALL_STATE_IDLE, null).phase)

        assertEquals(CallStatus(CallPhase.RINGING, true, number), t.onLegacy(CALL_STATE_RINGING, number))
        assertEquals(CallStatus(CallPhase.ACTIVE, true, number), t.onLegacy(CALL_STATE_OFFHOOK, null))
        // Precise reports are ignored in fallback mode.
        assertEquals(CallPhase.ACTIVE, t.onPrecise(IDLE, IDLE, IDLE).phase)
    }

    @Test
    fun switchingToFallbackReplaysTheLastPlainState() {
        val t = CallTracker()
        t.onLegacy(CALL_STATE_RINGING, number)
        assertEquals(CallPhase.IDLE, t.status.phase)
        assertEquals(CallStatus(CallPhase.RINGING, true, number), t.usePrecise(false))
    }

    @Test
    fun dialThatNeverReachesTelephonyTimesOut() {
        val t = CallTracker()
        t.beginDial(number)
        val stale = t.dialSeq
        t.onDialTimeout(stale)
        assertEquals(CallPhase.ENDED, t.status.phase)

        t.beginDial(number)
        assertEquals(CallPhase.DIALING, t.onDialTimeout(stale).phase)
        t.onPrecise(IDLE, DIALING, IDLE)
        assertEquals(CallPhase.DIALING, t.onDialTimeout(t.dialSeq).phase)
    }

    @Test
    fun refusedDialRestoresThePreviousStatus() {
        val t = CallTracker()
        val previous = t.beginDial(number)
        t.cancelDial(previous)
        assertEquals(CallStatus(), t.status)
        assertEquals(CallPhase.IDLE, t.onPrecise(IDLE, IDLE, IDLE).phase)
    }

    @Test
    fun hangUpWithNoCallEndsAPendingDial() {
        val t = CallTracker()
        t.beginDial(number)
        assertEquals(CallPhase.ENDED, t.onNothingToEnd().phase)
    }
}
