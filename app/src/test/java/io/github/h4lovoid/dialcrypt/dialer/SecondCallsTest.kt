package io.github.h4lovoid.dialcrypt.dialer

import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.dialer.model.CallSnapshot
import io.github.h4lovoid.dialcrypt.dialer.model.MergePolicy
import io.github.h4lovoid.dialcrypt.dialer.model.TelecomState
import io.github.h4lovoid.dialcrypt.dialer.model.UiCallState
import io.github.h4lovoid.dialcrypt.dialer.model.WaitingCallPlan
import io.github.h4lovoid.dialcrypt.dialer.model.WaitingCallPlan.Choice
import io.github.h4lovoid.dialcrypt.dialer.model.WaitingCallPlan.Step
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SecondCallsTest {
    private fun snap(id: Int, state: Int, child: Boolean = false, canMerge: Boolean = false) = CallSnapshot(
        id = id,
        telecomState = state,
        incoming = false,
        number = "+15550100199",
        presentation = NumberPresentation.SHOWN,
        connectMs = 0L,
        canHold = true,
        conferenceChild = child,
        emergency = false,
        postDial = null,
        accounts = emptyList(),
        canMerge = canMerge,
    )

    @Test
    fun endAndAnswerIsOfferedOnlyNextToACurrentCall() {
        assertEquals(listOf(Choice.HOLD_AND_ANSWER, Choice.END_AND_ANSWER, Choice.DECLINE), WaitingCallPlan.choices(UiCallState.ACTIVE, false))
        assertEquals(listOf(Choice.HOLD_AND_ANSWER, Choice.END_AND_ANSWER, Choice.DECLINE), WaitingCallPlan.choices(UiCallState.DIALING, false))
        assertEquals(listOf(Choice.HOLD_AND_ANSWER, Choice.DECLINE), WaitingCallPlan.choices(UiCallState.HOLDING, false))
        assertEquals(listOf(Choice.HOLD_AND_ANSWER, Choice.DECLINE), WaitingCallPlan.choices(null, false))
    }

    @Test
    fun whileTheSecureFlowOwnsACallOnlyDeclineIsOffered() {
        for (other in listOf(UiCallState.ACTIVE, UiCallState.HOLDING, null)) {
            assertEquals(listOf(Choice.DECLINE), WaitingCallPlan.choices(other, true))
        }
    }

    @Test
    fun holdAndAnswerAnswersAndDeclineRejects() {
        val calls = listOf(snap(1, TelecomState.ACTIVE), snap(2, TelecomState.RINGING))
        assertEquals(listOf(Step.Answer(2)), WaitingCallPlan.steps(Choice.HOLD_AND_ANSWER, 2, calls))
        assertEquals(listOf(Step.Reject(2)), WaitingCallPlan.steps(Choice.DECLINE, 2, calls))
    }

    @Test
    fun endAndAnswerEndsTheCurrentCallFirstAndKeepsAHeldOne() {
        val calls = listOf(
            snap(1, TelecomState.ACTIVE),
            snap(3, TelecomState.HOLDING),
            snap(4, TelecomState.ACTIVE, child = true),
            snap(5, TelecomState.DISCONNECTING),
            snap(2, TelecomState.RINGING),
        )
        assertEquals(listOf(Step.Disconnect(1), Step.Answer(2)), WaitingCallPlan.steps(Choice.END_AND_ANSWER, 2, calls))
    }

    @Test
    fun endAndAnswerWithNothingCurrentOnlyAnswers() {
        val calls = listOf(snap(3, TelecomState.HOLDING), snap(2, TelecomState.RINGING))
        assertEquals(listOf(Step.Answer(2)), WaitingCallPlan.steps(Choice.END_AND_ANSWER, 2, calls))
    }

    @Test
    fun mergeNeedsAnActiveAndAHeldCallThatTelecomCanMerge() {
        val active = snap(1, TelecomState.ACTIVE, canMerge = true)
        val held = snap(2, TelecomState.HOLDING)
        assertTrue(MergePolicy.canMerge(active, held, secureOwned = false))
        assertTrue(MergePolicy.canMerge(snap(1, TelecomState.ACTIVE), snap(2, TelecomState.HOLDING, canMerge = true), false))
        assertFalse(MergePolicy.canMerge(snap(1, TelecomState.ACTIVE), held, false))
        assertFalse(MergePolicy.canMerge(active, held, secureOwned = true))
        assertFalse(MergePolicy.canMerge(active, null, false))
        assertFalse(MergePolicy.canMerge(active, snap(2, TelecomState.ACTIVE), false))
        assertFalse(MergePolicy.canMerge(active, snap(2, TelecomState.HOLDING, child = true), false))
    }
}
