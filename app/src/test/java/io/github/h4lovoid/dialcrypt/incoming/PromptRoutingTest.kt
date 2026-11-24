package io.github.h4lovoid.dialcrypt.incoming

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PromptRoutingTest {
    @Test
    fun withoutTheDialerScreenTheOldPromptRuleHolds() {
        assertTrue(PromptRouting.showPrompt(dialerUiBound = false, deliveredToSecure = false, promptShown = false))
        assertFalse(PromptRouting.showPrompt(dialerUiBound = false, deliveredToSecure = true, promptShown = false))
        assertFalse(PromptRouting.showPrompt(dialerUiBound = false, deliveredToSecure = false, promptShown = true))
    }

    @Test
    fun theDialerScreenReplacesThePrompt() {
        assertFalse(PromptRouting.showPrompt(dialerUiBound = true, deliveredToSecure = false, promptShown = false))
    }

    @Test
    fun onlyTheRingingUnclaimedOfferOfThatTokenCanBeReturnedOrDeclined() {
        assertTrue(PromptRouting.offerOpen(tokenMatches = true, ringing = true, claimedBySecure = false, plainAnswered = false))
        assertFalse("another token", PromptRouting.offerOpen(false, true, false, false))
        assertFalse("no longer ringing", PromptRouting.offerOpen(true, false, false, false))
        assertFalse("claimed for a secure answer", PromptRouting.offerOpen(true, true, true, false))
        assertFalse("answered as a plain call", PromptRouting.offerOpen(true, true, false, true))
    }

    @Test
    fun aReturnedOfferOpensThePromptOnlyOnce() {
        // After a return the offer no longer counts as delivered to the secure process.
        assertTrue(PromptRouting.showPrompt(dialerUiBound = false, deliveredToSecure = false, promptShown = false))
        assertFalse(PromptRouting.showPrompt(dialerUiBound = false, deliveredToSecure = false, promptShown = true))
        assertFalse(PromptRouting.showPrompt(dialerUiBound = true, deliveredToSecure = false, promptShown = false))
    }
}
