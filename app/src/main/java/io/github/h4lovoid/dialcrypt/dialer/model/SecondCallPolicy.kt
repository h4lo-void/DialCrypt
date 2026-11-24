package io.github.h4lovoid.dialcrypt.dialer.model

/**
 * A second, non-emergency call while the secure flow owns a live call would hold or end it. Such a
 * call is ended as soon as it is added, whichever way it goes: a call that still rings is rejected,
 * any other call (an outgoing call, or an incoming one a headset or the system already answered) is
 * disconnected. Emergency calls are never touched. A secure call Telecom held meanwhile is resumed.
 */
object SecondCallPolicy {
    enum class Drop { KEEP, REJECT, DISCONNECT }

    enum class Resume {
        /** No call was dropped recently. */
        IDLE,

        /** The window passed or the secure flow no longer owns a call: stop watching. */
        EXPIRED,

        /** Keep watching: the secure call is not held, or another call is still live. */
        WAIT,

        /** Take the secure call off hold now. */
        UNHOLD,
    }

    /** How long after a drop a held secure call is resumed. */
    const val RESUME_WINDOW_MS = 5_000L

    /**
     * What to do with a call just added. [secureLive]: another call, tracked by the secure flow,
     * is not ending. [telecomState] is the new call's android.telecom.Call state.
     */
    fun drop(secureOwned: Boolean, secureLive: Boolean, emergency: Boolean, telecomState: Int): Drop = when {
        !secureOwned || !secureLive || emergency -> Drop.KEEP
        TelecomState.isRinging(telecomState) -> Drop.REJECT
        else -> Drop.DISCONNECT
    }

    /**
     * A rejected call that stopped ringing without ending was answered anyway (for example by a
     * headset before the rejection arrived): it must be disconnected, once.
     */
    fun disconnectAfterReject(telecomState: Int, disconnectSent: Boolean): Boolean =
        !disconnectSent && !TelecomState.isRinging(telecomState) && !TelecomState.isEnding(telecomState)

    /**
     * Whether to resume the secure call. [resumeUntilMs] is 0 when nothing was dropped, else the end
     * of the window; [secureState] is null when no secure call is listed; [othersLive]: another call
     * is not ending.
     */
    fun resume(nowMs: Long, resumeUntilMs: Long, secureOwned: Boolean, secureState: Int?, othersLive: Boolean): Resume = when {
        resumeUntilMs == 0L -> Resume.IDLE
        nowMs > resumeUntilMs || !secureOwned -> Resume.EXPIRED
        secureState == TelecomState.HOLDING && !othersLive -> Resume.UNHOLD
        else -> Resume.WAIT
    }
}
