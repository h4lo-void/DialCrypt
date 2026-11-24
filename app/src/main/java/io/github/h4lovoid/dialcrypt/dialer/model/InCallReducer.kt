package io.github.h4lovoid.dialcrypt.dialer.model

import io.github.h4lovoid.dialcrypt.core.ContactMembership

object InCallReducer {
    /**
     * Turns the Telecom calls into what the in-call screen shows: the call that needs attention
     * first, at most one other call, never conference children. [nowMs] is elapsed realtime, on
     * the same clock as [CallSnapshot.addedMs]. [membership] tells whether a number is a contact.
     */
    fun reduce(
        calls: List<CallSnapshot>,
        audio: AudioUi,
        reg: RegistryView,
        showFull: Boolean,
        locked: Boolean,
        membership: (String) -> ContactMembership,
        nowMs: Long = 0L,
    ): InCallUiState {
        val visible = calls.filter { !it.conferenceChild }
        val ordered = visible
            .map { it to stateOf(it, visible) }
            .sortedWith(compareBy<Pair<CallSnapshot, UiCallState>>({ rank(it.second) }, { it.first.id }))
        val primary = ordered.firstOrNull()
        val secondary = ordered.drop(1).firstOrNull { it.second != UiCallState.ENDED }
        val trackedRinging = visible.any { it.tracked && TelecomState.isRinging(it.telecomState) }
        val active = ordered.firstOrNull { it.first.telecomState == TelecomState.ACTIVE }?.first
        val held = ordered.firstOrNull { it.first.telecomState == TelecomState.HOLDING }?.first
        return InCallUiState(
            primary = primary?.let { toUi(it.first, it.second, reg, showFull, locked, membership, nowMs) },
            secondary = secondary?.let { toUi(it.first, it.second, reg, showFull, locked, membership, nowMs) },
            audio = audio,
            secureOffer = reg.screening == Screening.OFFER && trackedRinging && !reg.secureOwned,
            secureOwned = reg.secureOwned,
            screening = reg.screening,
            canMerge = visible.size == 2 && MergePolicy.canMerge(active, held, reg.secureOwned),
        )
    }

    private fun stateOf(s: CallSnapshot, all: List<CallSnapshot>): UiCallState = when (s.telecomState) {
        TelecomState.RINGING, TelecomState.SIMULATED_RINGING ->
            if (all.any { it !== s && isLiveNotRinging(it.telecomState) }) UiCallState.WAITING else UiCallState.RINGING
        TelecomState.SELECT_PHONE_ACCOUNT -> UiCallState.SELECT_ACCOUNT
        TelecomState.ACTIVE, TelecomState.AUDIO_PROCESSING -> UiCallState.ACTIVE
        TelecomState.HOLDING -> UiCallState.HOLDING
        TelecomState.DISCONNECTING -> UiCallState.DISCONNECTING
        TelecomState.DISCONNECTED -> UiCallState.ENDED
        else -> UiCallState.DIALING
    }

    private fun isLiveNotRinging(state: Int): Boolean = !TelecomState.isRinging(state) && !TelecomState.isEnding(state)

    private fun rank(state: UiCallState): Int = when (state) {
        UiCallState.RINGING -> 0
        UiCallState.WAITING -> 1
        UiCallState.SELECT_ACCOUNT -> 2
        UiCallState.DIALING -> 3
        UiCallState.ACTIVE -> 4
        UiCallState.DISCONNECTING -> 5
        UiCallState.HOLDING -> 6
        UiCallState.ENDED -> 7
    }

    private fun toUi(
        s: CallSnapshot,
        state: UiCallState,
        reg: RegistryView,
        showFull: Boolean,
        locked: Boolean,
        membership: (String) -> ContactMembership,
        nowMs: Long,
    ): UiCall {
        val ringing = state == UiCallState.RINGING || state == UiCallState.WAITING
        // An untracked lone ringing call is about to be tracked and screened; a waiting call never is.
        val screening = when {
            s.tracked -> reg.screening
            state == UiCallState.WAITING -> Screening.PLAIN
            else -> Screening.PENDING
        }
        val answer = ringing && !reg.secureOwned && IncomingUiPolicy.answerEnabled(screening, nowMs - s.addedMs)
        val connected = state == UiCallState.ACTIVE || state == UiCallState.HOLDING
        val member = s.number?.trim()?.takeIf { it.isNotEmpty() }?.let(membership) ?: ContactMembership.UNKNOWN
        return UiCall(
            id = s.id,
            state = state,
            number = if (s.conference) {
                NumberText.Conference(s.participants)
            } else {
                NumberTexts.of(s.number, s.presentation, member, showFull, locked, s.payphone)
            },
            connectMs = s.connectMs.takeIf { connected && it > 0L },
            canHold = s.canHold,
            emergency = s.emergency,
            postDial = s.postDial,
            accounts = s.accounts,
            answerEnabled = answer,
        )
    }
}
