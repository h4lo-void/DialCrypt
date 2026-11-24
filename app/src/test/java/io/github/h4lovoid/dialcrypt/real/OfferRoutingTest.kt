package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.SessionPhase
import io.github.h4lovoid.dialcrypt.core.real.OfferRouting
import io.github.h4lovoid.dialcrypt.core.real.OfferRouting.Action
import org.junit.Assert.assertEquals
import org.junit.Test

class OfferRoutingTest {
    @Test
    fun aSecureCallInProgressIgnoresTheOffer() {
        for (phase in SessionPhase.entries) {
            assertEquals(Action.IGNORE, OfferRouting.route(callActive = true, phase = phase, handoff = false, canPresent = true))
        }
    }

    @Test
    fun anErrorScreenIsClearedSoTheCallShows() {
        assertEquals(Action.RESET_AND_PRESENT, OfferRouting.route(false, SessionPhase.ABORTED, handoff = false, canPresent = true))
        assertEquals(Action.RESET_AND_PRESENT, OfferRouting.route(false, SessionPhase.ABORTED, handoff = true, canPresent = false))
        // The end screen of a finished call is cleared too, so the unlock screen after it can show the call.
        assertEquals(Action.RESET_AND_PRESENT, OfferRouting.route(false, SessionPhase.CLEARED, handoff = false, canPresent = true))
        assertEquals(Action.RESET_AND_PRESENT, OfferRouting.route(false, SessionPhase.CLEARED, handoff = true, canPresent = true))
        assertEquals(Action.PRESENT, OfferRouting.route(false, SessionPhase.IDLE, handoff = false, canPresent = true))
    }

    @Test
    fun whatCannotBeShownGoesBackToThePrompt() {
        assertEquals(Action.RETURN, OfferRouting.route(false, SessionPhase.IDLE, handoff = false, canPresent = false))
        assertEquals(Action.RETURN, OfferRouting.route(false, SessionPhase.ABORTED, handoff = false, canPresent = false))
        // The app is ending after a finished call (the screen no longer counts as in front).
        assertEquals(Action.RETURN, OfferRouting.route(false, SessionPhase.CLEARED, handoff = false, canPresent = false))
        // A call is still being set up or hung up with no session object: not this screen's to show.
        assertEquals(Action.RETURN, OfferRouting.route(false, SessionPhase.CLEARING, handoff = false, canPresent = true))
    }

    @Test
    fun aHandoffIsShownBeforeTheScreenIsInFront() {
        assertEquals(Action.PRESENT, OfferRouting.route(false, SessionPhase.IDLE, handoff = true, canPresent = false))
    }
}
