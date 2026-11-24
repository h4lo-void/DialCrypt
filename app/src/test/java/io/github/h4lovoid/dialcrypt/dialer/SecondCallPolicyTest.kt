package io.github.h4lovoid.dialcrypt.dialer

import io.github.h4lovoid.dialcrypt.dialer.model.SecondCallPolicy
import io.github.h4lovoid.dialcrypt.dialer.model.SecondCallPolicy.Drop
import io.github.h4lovoid.dialcrypt.dialer.model.SecondCallPolicy.Resume
import io.github.h4lovoid.dialcrypt.dialer.model.TelecomState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** A second, non-emergency call during a secure call is ended at once, and a held secure call resumes. */
class SecondCallPolicyTest {
    private val allStates = listOf(
        TelecomState.RINGING,
        TelecomState.SIMULATED_RINGING,
        TelecomState.DIALING,
        TelecomState.CONNECTING,
        TelecomState.SELECT_PHONE_ACCOUNT,
        TelecomState.ACTIVE,
        TelecomState.HOLDING,
    )

    private fun drop(state: Int, secureOwned: Boolean = true, secureLive: Boolean = true, emergency: Boolean = false) =
        SecondCallPolicy.drop(secureOwned, secureLive, emergency, state)

    @Test
    fun aRingingSecondCallIsRejected() {
        assertEquals(Drop.REJECT, drop(TelecomState.RINGING))
        assertEquals(Drop.REJECT, drop(TelecomState.SIMULATED_RINGING))
    }

    @Test
    fun anOutgoingOrAlreadyAnsweredSecondCallIsDisconnected() {
        for (state in listOf(TelecomState.DIALING, TelecomState.CONNECTING, TelecomState.SELECT_PHONE_ACCOUNT, TelecomState.ACTIVE, TelecomState.HOLDING)) {
            assertEquals("state $state", Drop.DISCONNECT, drop(state))
        }
    }

    @Test
    fun emergencyCallsAreNeverDropped() {
        for (state in allStates) assertEquals("state $state", Drop.KEEP, drop(state, emergency = true))
    }

    @Test
    fun withoutALiveSecureCallNothingIsDropped() {
        for (state in allStates) {
            assertEquals(Drop.KEEP, drop(state, secureOwned = false))
            assertEquals(Drop.KEEP, drop(state, secureLive = false))
        }
    }

    @Test
    fun aRejectedCallAnsweredAnywayIsDisconnectedOnce() {
        assertTrue(SecondCallPolicy.disconnectAfterReject(TelecomState.ACTIVE, disconnectSent = false))
        assertTrue(SecondCallPolicy.disconnectAfterReject(TelecomState.HOLDING, disconnectSent = false))
        assertFalse(SecondCallPolicy.disconnectAfterReject(TelecomState.ACTIVE, disconnectSent = true))
        assertFalse(SecondCallPolicy.disconnectAfterReject(TelecomState.RINGING, disconnectSent = false))
        assertFalse(SecondCallPolicy.disconnectAfterReject(TelecomState.DISCONNECTING, disconnectSent = false))
        assertFalse(SecondCallPolicy.disconnectAfterReject(TelecomState.DISCONNECTED, disconnectSent = false))
    }

    @Test
    fun aHeldSecureCallResumesWithinTheWindowOnceTheOtherCallEnded() {
        assertEquals(5_000L, SecondCallPolicy.RESUME_WINDOW_MS)
        val until = 10_000L
        fun resume(now: Long, owned: Boolean = true, state: Int? = TelecomState.HOLDING, others: Boolean = false) =
            SecondCallPolicy.resume(now, until, owned, state, others)
        assertEquals(Resume.IDLE, SecondCallPolicy.resume(9_000L, 0L, true, TelecomState.HOLDING, false))
        assertEquals(Resume.UNHOLD, resume(9_000L))
        assertEquals(Resume.UNHOLD, resume(10_000L))
        assertEquals(Resume.WAIT, resume(9_000L, others = true))
        assertEquals(Resume.WAIT, resume(9_000L, state = TelecomState.ACTIVE))
        assertEquals(Resume.WAIT, resume(9_000L, state = null))
        assertEquals(Resume.EXPIRED, resume(10_001L))
        assertEquals(Resume.EXPIRED, resume(9_000L, owned = false))
    }
}
