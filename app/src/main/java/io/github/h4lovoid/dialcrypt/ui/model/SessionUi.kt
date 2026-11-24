package io.github.h4lovoid.dialcrypt.ui.model

import androidx.annotation.StringRes
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.core.ConnectStep
import io.github.h4lovoid.dialcrypt.core.IdentityStatus
import io.github.h4lovoid.dialcrypt.core.MessageStatus
import io.github.h4lovoid.dialcrypt.core.QuickConnect
import io.github.h4lovoid.dialcrypt.core.SessionPhase
import io.github.h4lovoid.dialcrypt.core.SessionState
import io.github.h4lovoid.dialcrypt.ui.theme.Tone

data class StatusBanner(@StringRes val textRes: Int, val tone: Tone)

data class PqLabel(@StringRes val res: Int, val percent: Int?)

enum class SessionScreen { CONNECTING, CHAT, SAS, KEY_CHANGED, ABORTED, ENDING }

/** Pure mapping from core state to what the screens may say. No Android types beyond resource ids. */
object SessionUi {

    fun screenFor(s: SessionState): SessionScreen? = when (s.phase) {
        SessionPhase.IDLE -> null
        SessionPhase.CONNECTING -> SessionScreen.CONNECTING
        SessionPhase.ESTABLISHED -> if (s.sas != null) SessionScreen.SAS else SessionScreen.CHAT
        SessionPhase.KEY_CHANGED -> if (s.sas != null) SessionScreen.SAS else SessionScreen.KEY_CHANGED
        SessionPhase.ABORTED -> SessionScreen.ABORTED
        SessionPhase.CLEARING, SessionPhase.CLEARED -> SessionScreen.ENDING
    }

    /**
     * The one-line identity status. Null until the link is established, so neither
     * "verified" nor "encrypted" can appear while connecting, aborted or ending.
     */
    fun identityBanner(s: SessionState): StatusBanner? {
        if (s.phase != SessionPhase.ESTABLISHED && s.phase != SessionPhase.KEY_CHANGED) return null
        val effective = if (s.phase == SessionPhase.KEY_CHANGED) IdentityStatus.KEY_CHANGED else s.identity
        return when (effective) {
            IdentityStatus.UNKNOWN -> StatusBanner(R.string.status_unverified, Tone.WARN)
            IdentityStatus.VERIFIED_THIS_CALL -> StatusBanner(R.string.status_verified_call, Tone.OK)
            IdentityStatus.KEY_CHANGED -> StatusBanner(R.string.status_key_changed, Tone.DANGER)
            IdentityStatus.VERIFIED_CONTACT -> {
                val quick = s.quickConnect == QuickConnect.READY
                val res = when {
                    s.paired && quick -> R.string.status_contact_paired_quick
                    s.paired -> R.string.status_contact_paired
                    quick -> R.string.status_contact_quick
                    else -> R.string.status_contact
                }
                StatusBanner(res, Tone.OK)
            }
        }
    }

    /** "Included" only after the post-quantum secret is mixed in; progress before that. */
    fun pqLabel(s: SessionState): PqLabel? {
        if (s.phase != SessionPhase.ESTABLISHED) return null
        return if (s.pq.mixed) PqLabel(R.string.pq_mixed, null)
        else PqLabel(R.string.pq_progress, s.pq.percent.coerceIn(0, 100))
    }

    fun canSend(s: SessionState): Boolean =
        s.phase == SessionPhase.ESTABLISHED && s.identity != IdentityStatus.KEY_CHANGED && s.sas == null

    fun canVerify(s: SessionState): Boolean =
        s.phase == SessionPhase.ESTABLISHED && s.identity == IdentityStatus.UNKNOWN && s.sas == null

    fun showSaveOffer(s: SessionState): Boolean =
        s.saveOffer != null && s.phase == SessionPhase.ESTABLISHED && s.sas == null

    @StringRes
    fun statusRes(status: MessageStatus): Int? = when (status) {
        MessageStatus.SENDING -> R.string.msg_sending
        MessageStatus.SENT -> R.string.msg_sent
        MessageStatus.DELIVERED -> R.string.msg_delivered
        MessageStatus.READ -> R.string.msg_read
        MessageStatus.FAILED -> R.string.msg_failed
        MessageStatus.RECEIVED -> null
    }
}

/** Everything the connecting screen can say. Kept in one list so a test can check every word. */
object ConnectingUi {
    @StringRes val title = R.string.connect_title
    @StringRes val incomingTitle = R.string.connect_incoming_title
    @StringRes val note = R.string.connect_note
    @StringRes val eta = R.string.connect_eta
    @StringRes val percent = R.string.connect_percent
    @StringRes val calling = R.string.connect_calling
    @StringRes val answering = R.string.connect_answering
    @StringRes val cancel = R.string.connect_cancel
    @StringRes val stepAnswering = R.string.connect_step_answering

    @StringRes
    fun stepRes(step: ConnectStep): Int = when (step) {
        ConnectStep.DIALING -> R.string.connect_step_dialing
        ConnectStep.WAIT_PEER -> R.string.connect_step_wait_peer
        ConnectStep.KEY_EXCHANGE -> R.string.connect_step_exchange
        ConnectStep.IDENTITY -> R.string.connect_step_identity
        ConnectStep.FINALIZING -> R.string.connect_step_finalizing
    }

    val allRes: List<Int> =
        listOf(title, incomingTitle, note, eta, percent, calling, answering, cancel, stepAnswering) +
            ConnectStep.values().map { stepRes(it) }
}
