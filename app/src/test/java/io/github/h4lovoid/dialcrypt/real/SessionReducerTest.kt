package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.ChatMessage
import io.github.h4lovoid.dialcrypt.core.ConnectStep
import io.github.h4lovoid.dialcrypt.core.Contact
import io.github.h4lovoid.dialcrypt.core.HardwareLevel
import io.github.h4lovoid.dialcrypt.core.IdentityStatus
import io.github.h4lovoid.dialcrypt.core.MessageBody
import io.github.h4lovoid.dialcrypt.core.MessageStatus
import io.github.h4lovoid.dialcrypt.core.PeerInfo
import io.github.h4lovoid.dialcrypt.core.QuickCommand
import io.github.h4lovoid.dialcrypt.core.QuickConnect
import io.github.h4lovoid.dialcrypt.core.SaveOffer
import io.github.h4lovoid.dialcrypt.core.SendResult
import io.github.h4lovoid.dialcrypt.core.SessionFailure
import io.github.h4lovoid.dialcrypt.core.SessionPhase
import io.github.h4lovoid.dialcrypt.core.SessionState
import io.github.h4lovoid.dialcrypt.core.real.EndCause
import io.github.h4lovoid.dialcrypt.core.real.Fingerprint
import io.github.h4lovoid.dialcrypt.core.real.NativeEvent
import io.github.h4lovoid.dialcrypt.core.real.NativeIdentity
import io.github.h4lovoid.dialcrypt.core.real.PumpEnd
import io.github.h4lovoid.dialcrypt.core.real.QuickText
import io.github.h4lovoid.dialcrypt.core.real.SessionPath
import io.github.h4lovoid.dialcrypt.core.real.SessionReducer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SessionReducerTest {
    private val peerKey = ByteArray(33) { (it + 3).toByte() }
    private val full = SessionPath(resume = false, usedNew = false, contactId = 0)
    private val dialing = SessionReducer.dialing(PeerInfo(null, null, "+15550100"))

    private fun est(identity: NativeIdentity, stored: Long = 0, psk: Long = 0, path: SessionPath = full) =
        NativeEvent.Established(responder = false, path = path, identity = identity, pskContactId = psk, storedContactId = stored, peerPub33 = peerKey)

    private fun established(): SessionState = SessionReducer.established(SessionReducer.waitingPeer(dialing), est(NativeIdentity.UNVERIFIED), null)

    @Test
    fun connectingSteps() {
        assertEquals(SessionPhase.CONNECTING, dialing.phase)
        assertEquals(ConnectStep.DIALING, dialing.connect!!.step)
        val waiting = SessionReducer.waitingPeer(dialing)
        assertEquals(ConnectStep.WAIT_PEER, waiting.connect!!.step)
        assertEquals(ConnectStep.KEY_EXCHANGE, SessionReducer.progress(waiting, 10, false).connect!!.step)
        assertEquals(ConnectStep.IDENTITY, SessionReducer.progress(waiting, 60, false).connect!!.step)
        val late = SessionReducer.progress(waiting, 95, false).connect!!
        assertEquals(ConnectStep.FINALIZING, late.step)
        assertTrue(late.percent in 90..99)
        val percents = (0..100 step 5).map { SessionReducer.progress(waiting, it, false).connect!!.percent }
        assertEquals(percents.sorted(), percents)
        assertTrue(SessionReducer.progress(waiting, 50, true).connect!!.etaSeconds < SessionReducer.progress(waiting, 50, false).connect!!.etaSeconds)
        val est = established()
        assertEquals(est, SessionReducer.progress(est, 40, false))
        assertEquals(est, SessionReducer.waitingPeer(est))
    }

    @Test
    fun unknownPeerOnTheFullPath() {
        val s = established()
        assertEquals(SessionPhase.ESTABLISHED, s.phase)
        assertNull(s.connect)
        assertEquals(IdentityStatus.UNKNOWN, s.identity)
        assertEquals(PeerInfo(null, null, "+15550100"), s.peer)
        assertTrue(s.pq.mixed)
        assertFalse(s.paired)
        assertEquals(QuickConnect.UNAVAILABLE, s.quickConnect)
        assertEquals(Fingerprint.of(peerKey), s.fingerprint)
    }

    @Test
    fun savedContactOnTheResumePath() {
        val contact = Contact(7, "Ann", null, "F", verified = true, paired = true, quickConnect = QuickConnect.READY, hardware = HardwareLevel.STRONGBOX_LOCKED)
        val resume = SessionPath(resume = true, usedNew = false, contactId = 7)
        val s = SessionReducer.established(dialing, est(NativeIdentity.KNOWN_CONTACT, stored = 7, psk = 7, path = resume), contact)
        assertEquals(IdentityStatus.VERIFIED_CONTACT, s.identity)
        assertEquals(PeerInfo(7, "Ann", "+15550100"), s.peer)
        assertTrue(s.paired)
        assertEquals(QuickConnect.READY, s.quickConnect)
        assertEquals(HardwareLevel.STRONGBOX_LOCKED, s.hardware)
        assertFalse(s.pq.mixed)
        val p = SessionReducer.pqProgress(s, 40)
        assertEquals(40, p.pq.percent)
        assertTrue(SessionReducer.pqMixed(p).pq.mixed)
        assertEquals(SessionReducer.pqMixed(p), SessionReducer.pqProgress(SessionReducer.pqMixed(p), 10))
    }

    @Test
    fun changedKeyBlocksSendingUntilTheWordsMatch() {
        val viaEstablished = SessionReducer.established(dialing, est(NativeIdentity.KEY_CHANGED), null)
        assertEquals(SessionPhase.KEY_CHANGED, viaEstablished.phase)
        val viaEvent = SessionReducer.established(SessionReducer.keyChanged(dialing), est(NativeIdentity.UNVERIFIED), null)
        assertEquals(SessionPhase.KEY_CHANGED, viaEvent.phase)
        assertEquals(IdentityStatus.KEY_CHANGED, viaEvent.identity)
        assertEquals(SendResult.BLOCKED_KEY_CHANGED, SessionReducer.sendCheck(viaEvent, MessageBody.Text("hi"), false))
        val words = listOf(1, 2, 3, 4, 5)
        val confirmed = SessionReducer.sasConfirmed(SessionReducer.sasShown(viaEvent, words), offerSave = false)
        assertEquals(SessionPhase.ESTABLISHED, confirmed.phase)
        assertEquals(IdentityStatus.VERIFIED_THIS_CALL, confirmed.identity)
        assertNull(confirmed.saveOffer)
        val saved = SessionReducer.contactSaved(confirmed, 9, "Bo", "+15550100")
        assertEquals(IdentityStatus.VERIFIED_CONTACT, saved.identity)
        assertEquals(PeerInfo(9, "Bo", "+15550100"), saved.peer)
    }

    @Test
    fun sasFlow() {
        val s = established()
        val words = listOf(12, 87, 143, 201, 250)
        assertEquals(s, SessionReducer.sasWords(s, words))
        val shown = SessionReducer.sasShown(s, words)
        assertEquals(words, shown.sas!!.wordIndices)
        assertFalse(shown.sas!!.voiceWindowOpen)
        val open = SessionReducer.voiceWindow(shown, true, 60)
        assertTrue(open.sas!!.voiceWindowOpen)
        assertEquals(60, open.sas!!.voiceSecondsLeft)
        assertEquals(0, SessionReducer.voiceWindow(open, false, 60).sas!!.voiceSecondsLeft)
        assertEquals(60, SessionReducer.voiceSecondsLeft(1_000, 1_000))
        assertEquals(30, SessionReducer.voiceSecondsLeft(1_000, 31_000))
        assertEquals(1, SessionReducer.voiceSecondsLeft(0, 59_500))
        assertEquals(0, SessionReducer.voiceSecondsLeft(0, 61_000))
        val matched = SessionReducer.localMatch(open)
        assertTrue(matched.sas!!.localMatched)
        val done = SessionReducer.sasConfirmed(matched, offerSave = true)
        assertNull(done.sas)
        assertEquals(IdentityStatus.VERIFIED_THIS_CALL, done.identity)
        assertEquals(SaveOffer("+15550100"), done.saveOffer)
        assertNull(SessionReducer.sendCheck(done, MessageBody.Text("hi"), false))
    }

    @Test
    fun messages() {
        val s = established()
        val out = ChatMessage(1, true, MessageBody.Text("a"), MessageStatus.SENDING)
        val inc = ChatMessage(2, false, MessageBody.Text("b"), MessageStatus.RECEIVED)
        val both = SessionReducer.messageAdded(SessionReducer.messageAdded(s, out), inc)
        assertEquals(listOf(out, inc), both.messages)
        val delivered = SessionReducer.messageStatus(both, 1, MessageStatus.DELIVERED)
        assertEquals(MessageStatus.DELIVERED, delivered.messages[0].status)
        assertEquals(MessageStatus.RECEIVED, SessionReducer.messageStatus(both, 2, MessageStatus.FAILED).messages[1].status)
    }

    @Test
    fun messageProgressMapsConfirmedShardsToPercentWhileSending() {
        val out = ChatMessage(1, true, MessageBody.Text("a"), MessageStatus.SENDING)
        val inc = ChatMessage(2, false, MessageBody.Text("b"), MessageStatus.RECEIVED)
        val s = SessionReducer.messageAdded(SessionReducer.messageAdded(established(), out), inc)
        assertEquals(25, SessionReducer.messageProgress(s, 1, 5, 20).messages[0].sendPercent)
        assertEquals(1, SessionReducer.messageProgress(s, 1, 1, 250).messages[0].sendPercent)
        assertEquals(96, SessionReducer.messageProgress(s, 1, 29, 30).messages[0].sendPercent)
        assertEquals(99, SessionReducer.messageProgress(s, 1, 30, 30).messages[0].sendPercent)
        assertEquals(MessageStatus.SENDING, SessionReducer.messageProgress(s, 1, 5, 20).messages[0].status)
        // total 0, unknown ids and incoming messages change nothing.
        assertEquals(s, SessionReducer.messageProgress(s, 1, 3, 0))
        assertEquals(s, SessionReducer.messageProgress(s, 9, 3, 10))
        assertEquals(s, SessionReducer.messageProgress(s, 2, 3, 10))
        // A message that already left SENDING keeps its final state and percent.
        val delivered = SessionReducer.messageStatus(s, 1, MessageStatus.DELIVERED)
        assertEquals(delivered, SessionReducer.messageProgress(delivered, 1, 3, 10))
        val failed = SessionReducer.messageStatus(s, 1, MessageStatus.FAILED)
        assertEquals(failed, SessionReducer.messageProgress(failed, 1, 3, 10))
    }

    @Test
    fun sendChecksFollowTheFakeCore() {
        assertEquals(SendResult.BLOCKED_NOT_ESTABLISHED, SessionReducer.sendCheck(dialing, MessageBody.Text("hi"), false))
        val s = established()
        assertEquals(SendResult.EMPTY, SessionReducer.sendCheck(s, MessageBody.Text(""), true))
        assertEquals(SendResult.TOO_LONG, SessionReducer.sendCheck(s, MessageBody.Text("x".repeat(201)), false))
        assertNull(SessionReducer.sendCheck(s, MessageBody.Text("x".repeat(200)), false))
        assertNull(SessionReducer.sendCheck(s, MessageBody.Quick(QuickCommand.YES), false))
        assertEquals(SendResult.TOO_LONG, SessionReducer.sendFailure(-2))
        assertEquals(SendResult.BLOCKED_NOT_ESTABLISHED, SessionReducer.sendFailure(-3))
    }

    @Test
    fun attestationLevels() {
        val s = established()
        assertEquals(HardwareLevel.STRONGBOX_LOCKED, SessionReducer.attestation(s, NativeEvent.Attestation(0, 0, 1, true)).hardware)
        assertEquals(HardwareLevel.STRONGBOX_SELF_SIGNED, SessionReducer.attestation(s, NativeEvent.Attestation(0, 1, 1, true)).hardware)
        assertEquals(HardwareLevel.STRONGBOX_UNLOCKED, SessionReducer.attestation(s, NativeEvent.Attestation(0, 2, 1, false)).hardware)
        assertEquals(HardwareLevel.UNATTESTED, SessionReducer.attestation(s, NativeEvent.Attestation(-4, 0, 0, false)).hardware)
    }

    @Test
    fun abortReasonsAndEndStates() {
        assertNull(SessionReducer.failure(1))
        assertNull(SessionReducer.failure(19))
        assertEquals(SessionFailure.NO_PREAMBLE, SessionReducer.failure(2))
        assertEquals(SessionFailure.PEER_ABORTED, SessionReducer.failure(20))
        assertEquals(SessionFailure.PSK_REQUIRED, SessionReducer.failure(16))
        assertEquals(SessionFailure.BEARER_VIOLATION, SessionReducer.failure(24))
        assertEquals(SessionFailure.HANDSHAKE_FAILED, SessionReducer.failure(14))
        assertEquals(SessionFailure.HANDSHAKE_FAILED, SessionReducer.failure(26))
        assertEquals(SessionFailure.UNKNOWN, SessionReducer.failure(25))
        assertEquals(SessionFailure.UNKNOWN, SessionReducer.failure(99))

        val s = established()
        val cleared = SessionState(phase = SessionPhase.CLEARED)
        assertEquals(cleared, SessionReducer.finalState(s, EndCause.Aborted(2), localEnd = true))
        assertEquals(cleared, SessionReducer.finalState(s, EndCause.Ended, localEnd = false))
        assertEquals(cleared, SessionReducer.finalState(s, EndCause.Aborted(1), localEnd = false))
        assertEquals(cleared, SessionReducer.finalState(s.copy(phase = SessionPhase.CLEARING), EndCause.Dropped, localEnd = false))
        val dropped = SessionReducer.finalState(s, EndCause.Dropped, localEnd = false)
        assertEquals(SessionPhase.ABORTED, dropped.phase)
        assertEquals(SessionFailure.CALL_DROPPED, dropped.abort)
        assertEquals(s.peer, dropped.peer)
        assertTrue(dropped.messages.isEmpty())
        assertTrue(dropped.wasEstablished)
        assertEquals(SessionFailure.NO_PREAMBLE, SessionReducer.finalState(dialing, EndCause.Aborted(2), false).abort)
        assertEquals(SessionFailure.UNKNOWN, SessionReducer.finalState(dialing, EndCause.Failed(SessionFailure.UNKNOWN), false).abort)
    }

    @Test
    fun droppedOnlyCountsAsEstablishedFromTheChatPhase() {
        val early = SessionReducer.finalState(dialing, EndCause.Dropped, localEnd = false)
        assertEquals(SessionPhase.ABORTED, early.phase)
        assertEquals(SessionFailure.CALL_DROPPED, early.abort)
        assertFalse(early.wasEstablished)
        assertFalse(SessionReducer.finalState(established(), EndCause.Aborted(20), localEnd = false).wasEstablished)
        assertEquals(
            SessionPhase.CLEARED,
            SessionReducer.finalState(established().copy(phase = SessionPhase.CLEARING), EndCause.Dropped, localEnd = false).phase,
        )
    }

    @Test
    fun loopEndConditions() {
        val g = 3_000L
        assertNull(SessionReducer.endCause(null, null, null, 0, 10_000, g))
        assertNull(SessionReducer.endCause(null, null, EndCause.Ended, 9_000, 10_000, g))
        assertEquals(EndCause.Ended, SessionReducer.endCause(null, null, EndCause.Ended, 7_000, 10_000, g))
        assertEquals(EndCause.Ended, SessionReducer.endCause(PumpEnd.SESSION_OVER, null, EndCause.Ended, 9_900, 10_000, g))
        assertEquals(EndCause.Failed(SessionFailure.UNKNOWN), SessionReducer.endCause(PumpEnd.SESSION_OVER, null, null, 0, 10_000, g))
        assertEquals(EndCause.Dropped, SessionReducer.endCause(null, PumpEnd.AUDIO_FAILED, null, 0, 10_000, g))
        assertEquals(EndCause.Aborted(9), SessionReducer.endCause(PumpEnd.AUDIO_FAILED, null, EndCause.Aborted(9), 9_999, 10_000, g))
        assertEquals(EndCause.Failed(SessionFailure.UNKNOWN), SessionReducer.endCause(null, PumpEnd.NATIVE_ERROR, null, 0, 10_000, g))
        assertNull(SessionReducer.endCause(PumpEnd.STOPPED, PumpEnd.STOPPED, null, 0, 10_000, g))
    }

    @Test
    fun quickRepliesRoundTrip() {
        for (c in QuickCommand.entries) assertEquals(MessageBody.Quick(c), QuickText.decode(QuickText.encode(c)))
        assertEquals(MessageBody.Text("Q:YES"), QuickText.decode("Q:YES"))
        val unknown = QuickText.encode(QuickCommand.YES).replace("YES", "MAYBE")
        assertEquals(MessageBody.Text(unknown), QuickText.decode(unknown))
    }
}
