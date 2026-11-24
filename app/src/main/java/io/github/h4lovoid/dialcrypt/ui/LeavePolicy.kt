package io.github.h4lovoid.dialcrypt.ui

import io.github.h4lovoid.dialcrypt.core.SessionPhase

/**
 * What the secure screen does while it is not visible (screen off, another app in front), and
 * when it may lock on its own while visible. Pure, so every case can be tested.
 */
internal object LeavePolicy {
    enum class Action {
        /** A call is ringing, starting or up (ours or a plain one): check again later. */
        WAIT,

        /** The call ended normally: end the secure session now. */
        EXIT,

        /** The call ended with an error: clear that screen, then lock and end after the grace period. */
        DISMISS_AND_LEAVE,

        /** Nothing going on: lock now and end the secure session after the grace period. */
        LEAVE,

        /** Already locked and leaving. */
        NONE,
    }

    fun decide(phase: SessionPhase, callHeld: Boolean, incoming: Boolean, phoneBusy: Boolean, alreadyLeft: Boolean): Action = when {
        callHeld || incoming || phase in IN_CALL -> Action.WAIT
        phoneBusy -> Action.WAIT
        phase == SessionPhase.CLEARED -> Action.EXIT
        phase == SessionPhase.ABORTED -> Action.DISMISS_AND_LEAVE
        alreadyLeft -> Action.NONE
        else -> Action.LEAVE
    }

    /**
     * Whether an unlocked, visible app with no input for [IDLE_LOCK_MS] locks: never during a call
     * or a ringing one. A finished call's end screen (ABORTED, CLEARED) counts as idle; it is
     * cleared before locking.
     */
    fun mayIdleLock(phase: SessionPhase, callHeld: Boolean, incoming: Boolean, phoneBusy: Boolean): Boolean =
        phase in IDLE_PHASES && !callHeld && !incoming && !phoneBusy

    const val IDLE_LOCK_MS = 5L * 60 * 1000
    /** How often a stopped screen checks again while it waits for a call to end. */
    const val POLL_MS = 2_000L

    private val IN_CALL = setOf(SessionPhase.CONNECTING, SessionPhase.ESTABLISHED, SessionPhase.KEY_CHANGED, SessionPhase.CLEARING)
    private val IDLE_PHASES = setOf(SessionPhase.IDLE, SessionPhase.ABORTED, SessionPhase.CLEARED)
}
