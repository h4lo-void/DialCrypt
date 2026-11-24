package io.github.h4lovoid.dialcrypt

import io.github.h4lovoid.dialcrypt.core.SessionPhase
import io.github.h4lovoid.dialcrypt.ui.LeavePolicy
import io.github.h4lovoid.dialcrypt.ui.LeavePolicy.Action
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LeavePolicyTest {
    private fun decide(
        phase: SessionPhase,
        callHeld: Boolean = false,
        incoming: Boolean = false,
        phoneBusy: Boolean = false,
        alreadyLeft: Boolean = false,
    ) = LeavePolicy.decide(phase, callHeld, incoming, phoneBusy, alreadyLeft)

    @Test
    fun everyPhaseWithNothingElseGoingOn() {
        val expected = mapOf(
            SessionPhase.IDLE to Action.LEAVE,
            SessionPhase.CONNECTING to Action.WAIT,
            SessionPhase.ESTABLISHED to Action.WAIT,
            SessionPhase.KEY_CHANGED to Action.WAIT,
            SessionPhase.CLEARING to Action.WAIT,
            SessionPhase.ABORTED to Action.DISMISS_AND_LEAVE,
            SessionPhase.CLEARED to Action.EXIT,
        )
        assertEquals(SessionPhase.entries.toSet(), expected.keys)
        for ((phase, action) in expected) assertEquals(phase.name, action, decide(phase))
    }

    @Test
    fun aHeldCallARingingOfferOrAPhoneCallMakeItWaitInEveryPhase() {
        for (phase in SessionPhase.entries) {
            assertEquals(Action.WAIT, decide(phase, callHeld = true))
            assertEquals(Action.WAIT, decide(phase, incoming = true))
            assertEquals(Action.WAIT, decide(phase, phoneBusy = true))
        }
    }

    @Test
    fun leavingHappensOnceButEndStatesStillAct() {
        assertEquals(Action.NONE, decide(SessionPhase.IDLE, alreadyLeft = true))
        assertEquals(Action.EXIT, decide(SessionPhase.CLEARED, alreadyLeft = true))
        assertEquals(Action.DISMISS_AND_LEAVE, decide(SessionPhase.ABORTED, alreadyLeft = true))
    }

    @Test
    fun idleLockOnlyWithNothingGoingOn() {
        assertTrue(LeavePolicy.mayIdleLock(SessionPhase.IDLE, callHeld = false, incoming = false, phoneBusy = false))
        assertFalse(LeavePolicy.mayIdleLock(SessionPhase.IDLE, callHeld = true, incoming = false, phoneBusy = false))
        assertFalse(LeavePolicy.mayIdleLock(SessionPhase.IDLE, callHeld = false, incoming = true, phoneBusy = false))
        assertFalse(LeavePolicy.mayIdleLock(SessionPhase.IDLE, callHeld = false, incoming = false, phoneBusy = true))
        // The end screens of a finished call count as idle; a call being set up, up or hung up does not.
        for (phase in listOf(SessionPhase.ABORTED, SessionPhase.CLEARED)) assertTrue(LeavePolicy.mayIdleLock(phase, false, false, false))
        for (phase in listOf(SessionPhase.CONNECTING, SessionPhase.ESTABLISHED, SessionPhase.KEY_CHANGED, SessionPhase.CLEARING)) {
            assertFalse(phase.name, LeavePolicy.mayIdleLock(phase, false, false, false))
        }
        assertFalse(LeavePolicy.mayIdleLock(SessionPhase.CLEARED, callHeld = false, incoming = true, phoneBusy = false))
        assertEquals(5L * 60 * 1000, LeavePolicy.IDLE_LOCK_MS)
        assertEquals(2_000L, LeavePolicy.POLL_MS)
    }
}
