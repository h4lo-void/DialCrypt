package io.github.h4lovoid.dialcrypt.dialer

import android.telecom.Call
import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.dialer.model.AudioUi
import io.github.h4lovoid.dialcrypt.dialer.model.CallSnapshot
import io.github.h4lovoid.dialcrypt.dialer.model.InCallReducer
import io.github.h4lovoid.dialcrypt.dialer.model.InCallUiState
import io.github.h4lovoid.dialcrypt.dialer.model.NumberText
import io.github.h4lovoid.dialcrypt.dialer.model.RegistryView
import io.github.h4lovoid.dialcrypt.dialer.model.Screening
import io.github.h4lovoid.dialcrypt.dialer.model.TelecomState
import io.github.h4lovoid.dialcrypt.dialer.model.UiCallState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class InCallReducerTest {
    private fun snap(
        id: Int,
        state: Int,
        incoming: Boolean = false,
        child: Boolean = false,
        tracked: Boolean = false,
        connectMs: Long = 0L,
    ) = CallSnapshot(
        id = id,
        telecomState = state,
        incoming = incoming,
        number = "+15550100199",
        presentation = NumberPresentation.SHOWN,
        connectMs = connectMs,
        canHold = true,
        conferenceChild = child,
        emergency = false,
        postDial = null,
        accounts = emptyList(),
        tracked = tracked,
        addedMs = 0L,
    )

    private fun reduce(
        calls: List<CallSnapshot>,
        reg: RegistryView = RegistryView(),
        showFull: Boolean = true,
        locked: Boolean = false,
        membership: ContactMembership = ContactMembership.CONTACT,
        now: Long = 10_000L,
    ): InCallUiState = InCallReducer.reduce(calls, AudioUi(), reg, showFull, locked, { membership }, now)

    @Test
    fun ringingNextToAnActiveCallIsWaitingAndComesFirst() {
        val s = reduce(listOf(snap(1, TelecomState.ACTIVE, connectMs = 1_000L), snap(2, TelecomState.RINGING, incoming = true)))
        assertEquals(UiCallState.WAITING, s.primary!!.state)
        assertEquals(2, s.primary!!.id)
        assertEquals(UiCallState.ACTIVE, s.secondary!!.state)
    }

    @Test
    fun aLoneRingingCallIsRinging() {
        val s = reduce(listOf(snap(1, TelecomState.RINGING, incoming = true)))
        assertEquals(UiCallState.RINGING, s.primary!!.state)
        assertNull(s.secondary)
    }

    @Test
    fun conferenceChildrenAreNotListed() {
        val s = reduce(listOf(snap(1, TelecomState.ACTIVE), snap(2, TelecomState.ACTIVE, child = true), snap(3, TelecomState.ACTIVE, child = true)))
        assertEquals(1, s.primary!!.id)
        assertNull(s.secondary)
    }

    @Test
    fun theActiveCallComesBeforeTheHeldOne() {
        val s = reduce(listOf(snap(1, TelecomState.HOLDING), snap(2, TelecomState.ACTIVE)))
        assertEquals(UiCallState.ACTIVE, s.primary!!.state)
        assertEquals(UiCallState.HOLDING, s.secondary!!.state)
    }

    @Test
    fun dialingStatesMap() {
        assertEquals(UiCallState.SELECT_ACCOUNT, reduce(listOf(snap(1, TelecomState.SELECT_PHONE_ACCOUNT))).primary!!.state)
        assertEquals(UiCallState.DIALING, reduce(listOf(snap(1, TelecomState.CONNECTING))).primary!!.state)
        assertEquals(UiCallState.DIALING, reduce(listOf(snap(1, TelecomState.DIALING))).primary!!.state)
        assertEquals(UiCallState.ENDED, reduce(listOf(snap(1, TelecomState.DISCONNECTED))).primary!!.state)
    }

    @Test
    fun theLockScreenAlwaysMasksAContact() {
        val s = reduce(listOf(snap(1, TelecomState.ACTIVE)), showFull = true, locked = true)
        assertEquals(NumberText.Digits("\u2022\u2022\u2022\u2022 0199"), s.primary!!.number)
        val open = reduce(listOf(snap(1, TelecomState.ACTIVE)), showFull = true, locked = false)
        assertEquals(NumberText.Digits("+15550100199"), open.primary!!.number)
    }

    @Test
    fun aStrangerIsWholeOverTheLockScreenAndAnUnplacedNumberIsMasked() {
        val stranger = reduce(listOf(snap(1, TelecomState.RINGING, incoming = true)), showFull = false, locked = true, membership = ContactMembership.NOT_CONTACT)
        assertEquals(NumberText.Digits("+15550100199"), stranger.primary!!.number)
        val unknown = reduce(listOf(snap(1, TelecomState.ACTIVE)), showFull = true, locked = false, membership = ContactMembership.UNKNOWN)
        assertEquals(NumberText.Digits("\u2022\u2022\u2022\u2022 0199"), unknown.primary!!.number)
    }

    @Test
    fun connectTimeOnlyOnceConnected() {
        assertNull(reduce(listOf(snap(1, TelecomState.DIALING, connectMs = 5L))).primary!!.connectMs)
        assertEquals(5L, reduce(listOf(snap(1, TelecomState.ACTIVE, connectMs = 5L))).primary!!.connectMs)
    }

    @Test
    fun secureOfferOnlyForTheTrackedRingingCall() {
        val ringing = listOf(snap(1, TelecomState.RINGING, incoming = true, tracked = true))
        assertTrue(reduce(ringing, RegistryView(screening = Screening.OFFER)).secureOffer)
        assertFalse(reduce(ringing, RegistryView(screening = Screening.OFFER, secureOwned = true)).secureOffer)
        assertFalse(reduce(listOf(snap(1, TelecomState.RINGING, incoming = true)), RegistryView(screening = Screening.OFFER)).secureOffer)
    }

    @Test
    fun answeringWaitsForScreening() {
        val ringing = listOf(snap(1, TelecomState.RINGING, incoming = true, tracked = true))
        val pending = RegistryView(screening = Screening.PENDING)
        assertFalse(reduce(ringing, pending, now = 1_999L).primary!!.answerEnabled)
        assertTrue(reduce(ringing, pending, now = 2_000L).primary!!.answerEnabled)
        assertTrue(reduce(ringing, RegistryView(screening = Screening.PLAIN), now = 1L).primary!!.answerEnabled)
    }

    @Test
    fun noAnswerWhileTheSecureFlowOwnsACall() {
        val calls = listOf(snap(1, TelecomState.ACTIVE, tracked = true), snap(2, TelecomState.RINGING, incoming = true))
        val s = reduce(calls, RegistryView(secureOwned = true))
        assertEquals(UiCallState.WAITING, s.primary!!.state)
        assertFalse(s.primary!!.answerEnabled)
        assertTrue(s.secureOwned)
    }

    @Test
    fun telecomStateValuesMatchThePlatform() {
        assertEquals(Call.STATE_NEW, TelecomState.NEW)
        assertEquals(Call.STATE_DIALING, TelecomState.DIALING)
        assertEquals(Call.STATE_RINGING, TelecomState.RINGING)
        assertEquals(Call.STATE_HOLDING, TelecomState.HOLDING)
        assertEquals(Call.STATE_ACTIVE, TelecomState.ACTIVE)
        assertEquals(Call.STATE_DISCONNECTED, TelecomState.DISCONNECTED)
        assertEquals(Call.STATE_SELECT_PHONE_ACCOUNT, TelecomState.SELECT_PHONE_ACCOUNT)
        assertEquals(Call.STATE_CONNECTING, TelecomState.CONNECTING)
        assertEquals(Call.STATE_DISCONNECTING, TelecomState.DISCONNECTING)
        assertEquals(Call.STATE_PULLING_CALL, TelecomState.PULLING_CALL)
        assertEquals(Call.STATE_AUDIO_PROCESSING, TelecomState.AUDIO_PROCESSING)
        assertEquals(Call.STATE_SIMULATED_RINGING, TelecomState.SIMULATED_RINGING)
    }

    // ---- merging --------------------------------------------------------------------------------

    @Test
    fun mergeIsOfferedForAnActiveAndAHeldCallTelecomCanMerge() {
        val active = snap(1, TelecomState.ACTIVE).copy(canMerge = true)
        val held = snap(2, TelecomState.HOLDING)
        assertTrue(reduce(listOf(active, held)).canMerge)
        assertFalse(reduce(listOf(snap(1, TelecomState.ACTIVE), held)).canMerge)
        assertFalse(reduce(listOf(active, held), RegistryView(secureOwned = true)).canMerge)
        assertFalse(reduce(listOf(active)).canMerge)
    }

    @Test
    fun aMergedCallShowsAsOneConferenceWithItsParticipants() {
        val parent = snap(3, TelecomState.ACTIVE).copy(number = null, presentation = NumberPresentation.UNKNOWN, conference = true, participants = 2)
        val children = listOf(snap(1, TelecomState.ACTIVE, child = true), snap(2, TelecomState.ACTIVE, child = true))
        val s = reduce(children + parent)
        assertEquals(3, s.primary!!.id)
        assertEquals(UiCallState.ACTIVE, s.primary!!.state)
        assertEquals(NumberText.Conference(2), s.primary!!.number)
        assertNull(s.secondary)
        assertFalse(s.canMerge)
    }
}
