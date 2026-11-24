package io.github.h4lovoid.dialcrypt.core.real

import io.github.h4lovoid.dialcrypt.core.ChatMessage
import io.github.h4lovoid.dialcrypt.core.ConnectProgress
import io.github.h4lovoid.dialcrypt.core.ConnectStep
import io.github.h4lovoid.dialcrypt.core.Contact
import io.github.h4lovoid.dialcrypt.core.HardwareLevel
import io.github.h4lovoid.dialcrypt.core.IdentityStatus
import io.github.h4lovoid.dialcrypt.core.MessageBody
import io.github.h4lovoid.dialcrypt.core.MessageStatus
import io.github.h4lovoid.dialcrypt.core.PeerInfo
import io.github.h4lovoid.dialcrypt.core.PqState
import io.github.h4lovoid.dialcrypt.core.QuickCommand
import io.github.h4lovoid.dialcrypt.core.QuickConnect
import io.github.h4lovoid.dialcrypt.core.SasState
import io.github.h4lovoid.dialcrypt.core.SaveOffer
import io.github.h4lovoid.dialcrypt.core.SendResult
import io.github.h4lovoid.dialcrypt.core.SessionFailure
import io.github.h4lovoid.dialcrypt.core.SessionLimits
import io.github.h4lovoid.dialcrypt.core.SessionPhase
import io.github.h4lovoid.dialcrypt.core.SessionState

/** Why a call session ended. */
internal sealed interface EndCause {
    /** Our hang-up, our "words differ", or a wipe. */
    data object Local : EndCause

    /** ENDED, REMOTE_WIPE or WIPE_SENT. */
    data object Ended : EndCause

    /** The cellular call or its audio went away. */
    data object Dropped : EndCause

    /** ABORTED(reason) from the native session. */
    data class Aborted(val reason: Int) : EndCause

    /** The app side failed (dial refused, no audio, no session, malformed events). */
    data class Failed(val failure: SessionFailure) : EndCause

    /** Number for the AegisSession log. */
    val logCode: Int
        get() = when (this) {
            Local -> 1
            Ended -> 2
            Dropped -> 3
            is Aborted -> 100 + reason
            is Failed -> 200 + failure.ordinal
        }
}

/** Pure mapping from native session events to [SessionState]; the screens expect what FakeSecureCore shows. */
internal object SessionReducer {
    /** Rough handshake durations for the time estimate (full path about 205 slots, resume about 25). */
    const val FULL_PATH_SECONDS = 35
    const val RESUME_PATH_SECONDS = 6
    const val DIAL_SECONDS = 15
    /** VOICE_WINDOW_MAX_MS of the native session. */
    const val VOICE_WINDOW_SECONDS = 60

    fun dialing(peer: PeerInfo) = SessionState(
        phase = SessionPhase.CONNECTING,
        peer = peer,
        connect = ConnectProgress(ConnectStep.DIALING, 0, DIAL_SECONDS + FULL_PATH_SECONDS),
    )

    fun incoming(peer: PeerInfo) = SessionState(
        phase = SessionPhase.CONNECTING,
        direction = io.github.h4lovoid.dialcrypt.core.CallDirection.INCOMING,
        peer = peer,
        connect = ConnectProgress(ConnectStep.WAIT_PEER, 0, FULL_PATH_SECONDS),
    )

    fun waitingPeer(s: SessionState): SessionState =
        if (s.phase != SessionPhase.CONNECTING) s else s.copy(connect = ConnectProgress(ConnectStep.WAIT_PEER, 5, FULL_PATH_SECONDS))

    fun progress(s: SessionState, percent: Int, resume: Boolean): SessionState {
        if (s.phase != SessionPhase.CONNECTING) return s
        val p = percent.coerceIn(0, 100)
        val step = when {
            p < 50 -> ConnectStep.KEY_EXCHANGE
            p < 90 -> ConnectStep.IDENTITY
            else -> ConnectStep.FINALIZING
        }
        val total = if (resume) RESUME_PATH_SECONDS else FULL_PATH_SECONDS
        return s.copy(connect = ConnectProgress(step, (10 + p * 89 / 100).coerceAtMost(99), total * (100 - p) / 100))
    }

    /** [contact] is the saved contact holding the peer's key (ESTABLISHED storedContact), if any. */
    fun established(s: SessionState, e: NativeEvent.Established, contact: Contact?): SessionState {
        val stored = e.storedContactId != 0L
        val identity = when (e.identity) {
            NativeIdentity.UNVERIFIED -> IdentityStatus.UNKNOWN
            NativeIdentity.SAS_VERIFIED, NativeIdentity.KNOWN_CONTACT ->
                if (stored) IdentityStatus.VERIFIED_CONTACT else IdentityStatus.VERIFIED_THIS_CALL
            NativeIdentity.KEY_CHANGED -> IdentityStatus.KEY_CHANGED
        }
        val changed = identity == IdentityStatus.KEY_CHANGED || s.phase == SessionPhase.KEY_CHANGED
        return s.copy(
            phase = if (changed) SessionPhase.KEY_CHANGED else SessionPhase.ESTABLISHED,
            connect = null,
            identity = if (changed) IdentityStatus.KEY_CHANGED else identity,
            peer = PeerInfo(
                contactId = if (stored) e.storedContactId else null,
                name = contact?.name,
                number = s.peer?.number,
            ),
            paired = e.pskContactId != 0L,
            quickConnect = if (e.path.resume) QuickConnect.READY else contact?.quickConnect ?: QuickConnect.UNAVAILABLE,
            hardware = contact?.hardware ?: s.hardware,
            fingerprint = Fingerprint.of(e.peerPub33),
            // The full path mixes ML-KEM into the handshake; resume gets it in the background.
            pq = PqState(mixed = !e.path.resume, percent = if (e.path.resume) 0 else 100),
        )
    }

    fun keyChanged(s: SessionState): SessionState =
        s.copy(phase = SessionPhase.KEY_CHANGED, identity = IdentityStatus.KEY_CHANGED, connect = null)

    /** SAS bytes arrived; shown only after [sasShown]. */
    fun sasWords(s: SessionState, words: List<Int>): SessionState = s.sas?.let { s.copy(sas = it.copy(wordIndices = words)) } ?: s

    fun sasShown(s: SessionState, words: List<Int>): SessionState =
        s.copy(sas = s.sas?.copy(wordIndices = words) ?: SasState(words, voiceWindowOpen = false, voiceSecondsLeft = 0))

    fun voiceWindow(s: SessionState, open: Boolean, secondsLeft: Int): SessionState =
        s.sas?.let { s.copy(sas = it.copy(voiceWindowOpen = open, voiceSecondsLeft = if (open) secondsLeft.coerceAtLeast(0) else 0)) } ?: s

    fun voiceSecondsLeft(openedAtMs: Long, nowMs: Long): Int {
        val left = VOICE_WINDOW_SECONDS * 1000L - (nowMs - openedAtMs)
        return if (left <= 0) 0 else ((left + 999) / 1000).toInt()
    }

    fun localMatch(s: SessionState): SessionState = s.sas?.let { s.copy(sas = it.copy(localMatched = true)) } ?: s

    /** Both sides confirmed. [offerSave]: the peer is no saved contact and no changed key is being updated. */
    fun sasConfirmed(s: SessionState, offerSave: Boolean): SessionState = s.copy(
        phase = SessionPhase.ESTABLISHED,
        sas = null,
        identity = if (s.identity == IdentityStatus.VERIFIED_CONTACT) s.identity else IdentityStatus.VERIFIED_THIS_CALL,
        saveOffer = if (offerSave && s.peer?.contactId == null) SaveOffer(s.peer?.number) else s.saveOffer,
    )

    fun contactSaved(s: SessionState, id: Long, name: String, number: String?): SessionState =
        s.copy(peer = PeerInfo(id, name, number), identity = IdentityStatus.VERIFIED_CONTACT, saveOffer = null)

    fun pqProgress(s: SessionState, percent: Int): SessionState =
        if (s.pq.mixed) s else s.copy(pq = PqState(mixed = false, percent = percent.coerceIn(0, 100)))

    fun pqMixed(s: SessionState): SessionState = s.copy(pq = PqState(mixed = true, percent = 100))

    /** A failed verification shows no hardware proof; identity trust is judged separately. */
    fun attestation(s: SessionState, a: NativeEvent.Attestation): SessionState = s.copy(
        hardware = if (a.result != 0) {
            HardwareLevel.UNATTESTED
        } else {
            when (a.boot) {
                0 -> HardwareLevel.STRONGBOX_LOCKED
                1 -> HardwareLevel.STRONGBOX_SELF_SIGNED
                else -> HardwareLevel.STRONGBOX_UNLOCKED
            }
        },
    )

    fun messageAdded(s: SessionState, m: ChatMessage): SessionState = s.copy(messages = s.messages + m)

    fun messageStatus(s: SessionState, id: Long, status: MessageStatus): SessionState = s.copy(
        messages = s.messages.map { if (it.id == id && it.outgoing) it.copy(status = status, sendPercent = 100) else it },
    )

    /** Delivery progress of a message still SENDING: 1..99 percent of the confirmed shards; total 0 is ignored. */
    fun messageProgress(s: SessionState, id: Long, acked: Int, total: Int): SessionState {
        if (total <= 0) return s
        val percent = (acked.toLong() * 100 / total).toInt().coerceIn(1, 99)
        return s.copy(
            messages = s.messages.map {
                if (it.id == id && it.outgoing && it.status == MessageStatus.SENDING) it.copy(sendPercent = percent) else it
            },
        )
    }

    /** Checks before anything goes to the native session, in FakeSecureCore's order. */
    fun sendCheck(s: SessionState, body: MessageBody, empty: Boolean): SendResult? = when {
        s.identity == IdentityStatus.KEY_CHANGED || s.phase == SessionPhase.KEY_CHANGED -> SendResult.BLOCKED_KEY_CHANGED
        s.phase != SessionPhase.ESTABLISHED -> SendResult.BLOCKED_NOT_ESTABLISHED
        empty -> SendResult.EMPTY
        body is MessageBody.Text && body.text.length > SessionLimits.MAX_TEXT_CHARS -> SendResult.TOO_LONG
        else -> null
    }

    fun sendFailure(rc: Int): SendResult = when (rc) {
        NativeCode.BAD_ARG -> SendResult.TOO_LONG
        else -> SendResult.BLOCKED_NOT_ESTABLISHED
    }

    /** Abort reason (aegiscall_chat AbortReason) to the screen's failure; null = our own decision, nothing to report. */
    fun failure(reason: Int): SessionFailure? = when (reason) {
        1, 19 -> null
        2 -> SessionFailure.NO_PREAMBLE
        9, 20 -> SessionFailure.PEER_ABORTED
        15, 16 -> SessionFailure.PSK_REQUIRED
        24 -> SessionFailure.BEARER_VIOLATION
        in 3..8, in 10..14, 17, 18, in 21..23, 26 -> SessionFailure.HANDSHAKE_FAILED
        else -> SessionFailure.UNKNOWN
    }

    /**
     * State after the session is gone. [localEnd]: the user hung up or rejected the words.
     * A drop counts as "established" only from the ESTABLISHED phase (the handshake finished and the chat
     * accepts messages). CONNECTING, KEY_CHANGED (sending is blocked) and every other phase do not count.
     */
    fun finalState(prev: SessionState, cause: EndCause, localEnd: Boolean): SessionState {
        if (localEnd) return SessionState(phase = SessionPhase.CLEARED)
        val failure = when (cause) {
            EndCause.Local, EndCause.Ended -> null
            EndCause.Dropped -> if (prev.phase == SessionPhase.CLEARING) null else SessionFailure.CALL_DROPPED
            is EndCause.Aborted -> failure(cause.reason)
            is EndCause.Failed -> cause.failure
        }
        return if (failure == null) {
            SessionState(phase = SessionPhase.CLEARED)
        } else {
            SessionState(
                phase = SessionPhase.ABORTED,
                peer = prev.peer,
                abort = failure,
                wasEstablished = cause == EndCause.Dropped && prev.phase == SessionPhase.ESTABLISHED,
            )
        }
    }

    /**
     * When the call must be finished, from the pump results and a pending terminal event.
     * Null: keep going. A terminal event normally ends the transmit pump (the native session
     * sends its last frames, then nothing); [graceMs] bounds the wait for that.
     */
    fun endCause(tx: PumpEnd?, rx: PumpEnd?, pending: EndCause?, pendingSinceMs: Long, nowMs: Long, graceMs: Long): EndCause? = when {
        tx == PumpEnd.AUDIO_FAILED || rx == PumpEnd.AUDIO_FAILED -> pending ?: EndCause.Dropped
        tx == PumpEnd.SESSION_OVER || tx == PumpEnd.NATIVE_ERROR -> pending ?: EndCause.Failed(SessionFailure.UNKNOWN)
        rx == PumpEnd.SESSION_OVER || rx == PumpEnd.NATIVE_ERROR -> pending ?: EndCause.Failed(SessionFailure.UNKNOWN)
        pending != null && nowMs - pendingSinceMs >= graceMs -> pending
        else -> null
    }
}

/**
 * Quick replies travel as text with a control-character prefix both ends of this app understand;
 * the native quick codes are a different, tactical set.
 */
internal object QuickText {
    private const val MARK = "\u0001Q:"

    fun encode(command: QuickCommand): String = MARK + command.name

    fun decode(text: String): MessageBody {
        if (!text.startsWith(MARK)) return MessageBody.Text(text)
        val name = text.substring(MARK.length)
        return QuickCommand.entries.firstOrNull { it.name == name }?.let { MessageBody.Quick(it) } ?: MessageBody.Text(text)
    }
}

internal enum class PumpEnd {
    /** The stop flag was set (local teardown). */
    STOPPED,

    /** The native session reported its end (no more PCM, or the handle is gone). */
    SESSION_OVER,

    /** CallAudio returned -1: the call or its streams are gone. */
    AUDIO_FAILED,

    /** The native receive call failed. */
    NATIVE_ERROR,
}

/** The two audio loops, with the I/O passed in so their end conditions are testable. */
internal object PumpLoops {
    /** Largest chunk nativeSessionRxPcm accepts. */
    const val MAX_RX_CHUNK = 32_000

    /**
     * [next]: PCM for the next slot; empty = voice window (nothing to write, [idle] once), null = session over.
     * [write]: CallAudio.write result.
     */
    fun runTx(stopped: () -> Boolean, next: () -> ShortArray?, write: (ShortArray) -> Int, idle: () -> Unit): PumpEnd {
        while (true) {
            if (stopped()) return PumpEnd.STOPPED
            val pcm = next() ?: return if (stopped()) PumpEnd.STOPPED else PumpEnd.SESSION_OVER
            if (pcm.isEmpty()) {
                idle()
                continue
            }
            if (write(pcm) < 0) return if (stopped()) PumpEnd.STOPPED else PumpEnd.AUDIO_FAILED
        }
    }

    /** [read] fills the buffer (CallAudio.read result); [feed] passes the samples on (nativeSessionRxPcm result). */
    fun runRx(stopped: () -> Boolean, buf: ShortArray, read: (ShortArray) -> Int, feed: (ShortArray) -> Int): PumpEnd {
        require(buf.size in 1..MAX_RX_CHUNK)
        while (true) {
            if (stopped()) return PumpEnd.STOPPED
            val n = read(buf)
            if (n < 0) return if (stopped()) PumpEnd.STOPPED else PumpEnd.AUDIO_FAILED
            if (n == 0) continue
            val rc = feed(if (n >= buf.size) buf else buf.copyOf(n))
            if (rc == NativeCode.BAD_HANDLE || rc == NativeCode.ABORTED) {
                return if (stopped()) PumpEnd.STOPPED else PumpEnd.SESSION_OVER
            }
            if (rc < 0) return if (stopped()) PumpEnd.STOPPED else PumpEnd.NATIVE_ERROR
        }
    }
}
