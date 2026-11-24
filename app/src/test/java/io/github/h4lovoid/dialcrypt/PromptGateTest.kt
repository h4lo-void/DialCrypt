package io.github.h4lovoid.dialcrypt

import io.github.h4lovoid.dialcrypt.incoming.PromptGate
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The incoming prompt's answer buttons come back after a cancelled or failed unlock. */
class PromptGateTest {
    @Test
    fun onlyOneAnswerAtATime() {
        val gate = PromptGate()
        assertFalse(gate.busy)
        assertTrue(gate.tryBegin())
        assertTrue(gate.busy)
        assertTrue(gate.handoffStarted)
        assertFalse("a second tap is ignored", gate.tryBegin())
    }

    @Test
    fun abandonedUnlockOffersBothAnswersAgain() {
        val gate = PromptGate()
        assertTrue(gate.tryBegin())
        gate.release()
        assertFalse(gate.busy)
        assertFalse(gate.handoffStarted)
        assertTrue("the user can answer again", gate.tryBegin())
    }
}
