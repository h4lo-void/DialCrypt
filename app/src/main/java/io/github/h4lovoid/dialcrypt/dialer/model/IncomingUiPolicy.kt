package io.github.h4lovoid.dialcrypt.dialer.model

/**
 * What the notification of a ringing call carries. [openUi]: a content intent to the in-call
 * screen; [fullScreen]: the full-screen intent; [answer]: the answer button.
 */
data class IncomingNotice(val openUi: Boolean, val fullScreen: Boolean, val answer: Boolean)

object IncomingUiPolicy {
    /** Longest wait for the screening result before the ringing call is shown anyway. */
    const val SCREENING_WAIT_MS = 500L

    /** Answering waits for the screening result, at most this long. */
    const val ANSWER_WAIT_MS = 2_000L

    /**
     * How to present a ringing call. [offerToSecure]: the offer went to an open `:secure`, which
     * shows its own answer choice. [secureOwnedOther]: a secure call is under way and this is
     * another call. [fsiAllowed]: a full-screen notification can be posted.
     */
    fun decide(
        s: Screening,
        offerToSecure: Boolean,
        secureOwnedOther: Boolean,
        waitedMs: Long,
        fsiAllowed: Boolean,
    ): IncomingUi = when {
        secureOwnedOther -> IncomingUi.NOTICE_ONLY
        s == Screening.PENDING && waitedMs < SCREENING_WAIT_MS -> IncomingUi.WAIT
        s == Screening.OFFER && offerToSecure -> IncomingUi.NOTICE_ONLY
        fsiAllowed -> IncomingUi.FULL_SCREEN
        else -> IncomingUi.FULL_SCREEN_AND_START
    }

    /**
     * Whether the in-call screen may open at all. It never opens over a secure call, including a
     * call the secure flow dialed ([appDial]).
     */
    fun mayShowInCall(reg: RegistryView, appDial: Boolean): Boolean = !reg.secureOwned && !appDial

    /**
     * The notification for a ringing call presented as [ui]. A notice (the offer went to an open
     * `:secure`, which shows its own answer choice, or a secure call is under way) carries nothing
     * that answers or opens the in-call screen: only decline remains.
     */
    fun notice(ui: IncomingUi, reg: RegistryView, screening: Screening, waitedMs: Long): IncomingNotice {
        val openUi = ui != IncomingUi.NOTICE_ONLY && mayShowInCall(reg, appDial = false)
        return IncomingNotice(openUi = openUi, fullScreen = openUi, answer = openUi && answerEnabled(screening, waitedMs))
    }

    /**
     * Whether Telecom's request to bring the call UI forward may open the in-call screen. [ringing]
     * is how the ringing call is presented, null without one; a notice keeps the screen closed.
     */
    fun mayBringToForeground(ringing: IncomingUi?, reg: RegistryView, appDial: Boolean): Boolean =
        ringing != IncomingUi.NOTICE_ONLY && mayShowInCall(reg, appDial)

    /** Answering is offered once screening is over, or after [ANSWER_WAIT_MS] without a result. */
    fun answerEnabled(screening: Screening, waitedMs: Long): Boolean =
        screening != Screening.PENDING || waitedMs >= ANSWER_WAIT_MS
}
