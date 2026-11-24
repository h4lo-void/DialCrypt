package io.github.h4lovoid.dialcrypt.dialer.model

/**
 * What the user may do with a call that rings while another call is up, and which Telecom commands
 * each choice sends. While the secure flow owns a call the second call is ended at once
 * ([SecondCallPolicy]); the screen then offers only to decline.
 */
object WaitingCallPlan {
    enum class Choice { HOLD_AND_ANSWER, END_AND_ANSWER, DECLINE }

    sealed interface Step {
        data class Answer(val id: Int) : Step

        data class Disconnect(val id: Int) : Step

        data class Reject(val id: Int) : Step
    }

    /** The choices for a waiting call; [other] is the state of the call already up, if any. */
    fun choices(other: UiCallState?, secureOwned: Boolean): List<Choice> = when {
        secureOwned -> listOf(Choice.DECLINE)
        other == UiCallState.ACTIVE || other == UiCallState.DIALING ->
            listOf(Choice.HOLD_AND_ANSWER, Choice.END_AND_ANSWER, Choice.DECLINE)
        else -> listOf(Choice.HOLD_AND_ANSWER, Choice.DECLINE)
    }

    /**
     * The commands for [choice] on the waiting call [waitingId]. Holding and answering is one answer:
     * Telecom holds the current call itself. Ending and answering first disconnects every current call
     * (up, not ringing, not held, not ending, not part of a conference) and then answers. A held call
     * stays on hold.
     */
    fun steps(choice: Choice, waitingId: Int, calls: List<CallSnapshot>): List<Step> = when (choice) {
        Choice.HOLD_AND_ANSWER -> listOf(Step.Answer(waitingId))
        Choice.DECLINE -> listOf(Step.Reject(waitingId))
        Choice.END_AND_ANSWER -> calls
            .filter { it.id != waitingId && !it.conferenceChild && isCurrent(it.telecomState) }
            .map<CallSnapshot, Step> { Step.Disconnect(it.id) } + Step.Answer(waitingId)
    }

    private fun isCurrent(state: Int): Boolean =
        !TelecomState.isRinging(state) && !TelecomState.isEnding(state) && state != TelecomState.HOLDING
}

/** When the in-call screen offers to merge the two calls into a conference. */
object MergePolicy {
    /**
     * One call is active and one is held, neither is part of a conference already, Telecom reports
     * that they can be merged, and the secure flow does not own a call.
     */
    fun canMerge(active: CallSnapshot?, held: CallSnapshot?, secureOwned: Boolean): Boolean =
        !secureOwned && active != null && held != null &&
            active.telecomState == TelecomState.ACTIVE && held.telecomState == TelecomState.HOLDING &&
            !active.conferenceChild && !held.conferenceChild &&
            (active.canMerge || held.canMerge)
}
