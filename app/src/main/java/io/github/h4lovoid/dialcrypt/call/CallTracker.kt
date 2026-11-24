package io.github.h4lovoid.dialcrypt.call

import android.telephony.TelephonyManager

/** Values of the @SystemApi constants android.telephony.PreciseCallState.PRECISE_CALL_STATE_*. */
internal object PreciseState {
    const val NOT_VALID = -1
    const val IDLE = 0
    const val ACTIVE = 1
    const val HOLDING = 2
    const val DIALING = 3
    const val ALERTING = 4
    const val INCOMING = 5
    const val WAITING = 6
    const val DISCONNECTED = 7
    const val DISCONNECTING = 8
    const val INCOMING_SETUP = 9
}

/** What one telephony callback says about the calls on the device. */
internal enum class Observed { NONE, DIALING, RINGING, ACTIVE }

internal val LIVE_PHASES = setOf(CallPhase.DIALING, CallPhase.RINGING, CallPhase.ACTIVE)

/**
 * Precise call state: the far end has answered only when the foreground call is ACTIVE;
 * DIALING and ALERTING mean it is still ringing out. A held call still counts as connected.
 */
internal fun preciseObservation(ringing: Int, foreground: Int, background: Int): Observed = when {
    foreground == PreciseState.ACTIVE -> Observed.ACTIVE
    foreground == PreciseState.DIALING || foreground == PreciseState.ALERTING -> Observed.DIALING
    ringing == PreciseState.INCOMING || ringing == PreciseState.WAITING ||
        ringing == PreciseState.INCOMING_SETUP -> Observed.RINGING
    background == PreciseState.HOLDING -> Observed.ACTIVE
    else -> Observed.NONE
}

/**
 * Fallback when precise call state is unavailable. OFFHOOK is the only signal for a connected
 * call, so an outgoing call counts as ACTIVE from OFFHOOK on, which can be before the far end
 * answers. Nothing is sent in clear meanwhile: the secure handshake cannot complete until the
 * far end answers and the core's own handshake timeout covers an unanswered call.
 */
internal fun legacyObservation(state: Int): Observed? = when (state) {
    TelephonyManager.CALL_STATE_IDLE -> Observed.NONE
    TelephonyManager.CALL_STATE_RINGING -> Observed.RINGING
    TelephonyManager.CALL_STATE_OFFHOOK -> Observed.ACTIVE
    else -> null
}

/**
 * Turns telephony callbacks into [CallStatus]. Not thread safe; the owner serializes all calls.
 * In precise mode the legacy callback only supplies the incoming number.
 */
internal class CallTracker {
    var preciseMode: Boolean = true
        private set
    var status: CallStatus = CallStatus()
        private set
    var dialSeq: Int = 0
        private set

    /** Our placeCall has not shown up in telephony yet; idle reports are stale until it does. */
    private var awaitingDial = false
    private var ringingNumber: String? = null
    private var lastLegacyState = TelephonyManager.CALL_STATE_IDLE

    /** Starts an outgoing call; returns the status to restore if the platform refuses it. */
    fun beginDial(number: String): CallStatus {
        val previous = status
        dialSeq++
        awaitingDial = true
        ringingNumber = null
        status = CallStatus(CallPhase.DIALING, incoming = false, number = number)
        return previous
    }

    fun cancelDial(previous: CallStatus) {
        awaitingDial = false
        status = previous
    }

    /** The dialed call never reached telephony. */
    fun onDialTimeout(seq: Int): CallStatus {
        if (seq == dialSeq) endPendingDial()
        return status
    }

    /** hangUp found no call to end. */
    fun onNothingToEnd(): CallStatus {
        endPendingDial()
        return status
    }

    fun usePrecise(enabled: Boolean): CallStatus {
        if (preciseMode == enabled) return status
        preciseMode = enabled
        if (!enabled) legacyObservation(lastLegacyState)?.let(::step)
        return status
    }

    fun onPrecise(ringing: Int, foreground: Int, background: Int): CallStatus {
        if (preciseMode) {
            step(preciseObservation(ringing, foreground, background))
            fillIncomingNumber()
        }
        return status
    }

    fun onLegacy(state: Int, number: String?): CallStatus {
        lastLegacyState = state
        if (state == TelephonyManager.CALL_STATE_RINGING) {
            number?.trim()?.takeIf { it.isNotEmpty() }?.let { ringingNumber = it }
        }
        if (!preciseMode) legacyObservation(state)?.let(::step)
        fillIncomingNumber()
        if (state == TelephonyManager.CALL_STATE_IDLE) ringingNumber = null
        return status
    }

    private fun endPendingDial() {
        if (!awaitingDial) return
        awaitingDial = false
        status = status.copy(phase = CallPhase.ENDED)
    }

    private fun fillIncomingNumber() {
        val number = ringingNumber ?: return
        val s = status
        if (s.phase == CallPhase.RINGING && s.incoming && s.number == null) status = s.copy(number = number)
    }

    private fun step(observed: Observed) {
        val current = status
        val live = current.phase in LIVE_PHASES
        status = when (observed) {
            Observed.NONE -> if (live && !awaitingDial) current.copy(phase = CallPhase.ENDED) else current
            Observed.DIALING -> {
                awaitingDial = false
                if (live) current.copy(phase = CallPhase.DIALING) else CallStatus(CallPhase.DIALING)
            }
            Observed.ACTIVE -> {
                awaitingDial = false
                if (live) current.copy(phase = CallPhase.ACTIVE) else CallStatus(CallPhase.ACTIVE)
            }
            // Next to a live call this is call waiting (or the same ring): the live call stays.
            Observed.RINGING -> if (live) current else CallStatus(CallPhase.RINGING, incoming = true, number = ringingNumber)
        }
        if (status.phase == CallPhase.ENDED && current.phase != CallPhase.ENDED) ringingNumber = null
    }
}
