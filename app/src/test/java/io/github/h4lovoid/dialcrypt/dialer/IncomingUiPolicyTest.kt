package io.github.h4lovoid.dialcrypt.dialer

import io.github.h4lovoid.dialcrypt.dialer.model.IncomingNotice
import io.github.h4lovoid.dialcrypt.dialer.model.IncomingUi
import io.github.h4lovoid.dialcrypt.dialer.model.IncomingUiPolicy
import io.github.h4lovoid.dialcrypt.dialer.model.RegistryView
import io.github.h4lovoid.dialcrypt.dialer.model.Screening
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IncomingUiPolicyTest {
    private fun decide(s: Screening, toSecure: Boolean = false, other: Boolean = false, waited: Long = 0L, fsi: Boolean = true) =
        IncomingUiPolicy.decide(s, toSecure, other, waited, fsi)

    @Test
    fun pendingWaitsHalfASecond() {
        assertEquals(IncomingUi.WAIT, decide(Screening.PENDING, waited = 0L))
        assertEquals(IncomingUi.WAIT, decide(Screening.PENDING, waited = 499L))
        assertEquals(IncomingUi.FULL_SCREEN, decide(Screening.PENDING, waited = 500L))
    }

    @Test
    fun withoutFullScreenIntentTheScreenIsStarted() {
        assertEquals(IncomingUi.FULL_SCREEN_AND_START, decide(Screening.PLAIN, fsi = false))
    }

    @Test
    fun offerAtAnOpenSecureAppIsOnlyANotice() {
        assertEquals(IncomingUi.NOTICE_ONLY, decide(Screening.OFFER, toSecure = true))
        assertEquals(IncomingUi.FULL_SCREEN, decide(Screening.OFFER, toSecure = false))
    }

    @Test
    fun aSecondCallDuringASecureCallIsOnlyANotice() {
        assertEquals(IncomingUi.NOTICE_ONLY, decide(Screening.PENDING, other = true))
        assertEquals(IncomingUi.NOTICE_ONLY, decide(Screening.PLAIN, other = true))
    }

    @Test
    fun theInCallScreenNeverOpensOverASecureCall() {
        assertTrue(IncomingUiPolicy.mayShowInCall(RegistryView(), appDial = false))
        assertFalse(IncomingUiPolicy.mayShowInCall(RegistryView(secureOwned = true), appDial = false))
        assertFalse(IncomingUiPolicy.mayShowInCall(RegistryView(), appDial = true))
    }

    @Test
    fun answeringWaitsForScreeningAtMostTwoSeconds() {
        assertFalse(IncomingUiPolicy.answerEnabled(Screening.PENDING, 1_999L))
        assertTrue(IncomingUiPolicy.answerEnabled(Screening.PENDING, 2_000L))
        assertTrue(IncomingUiPolicy.answerEnabled(Screening.PLAIN, 0L))
        assertTrue(IncomingUiPolicy.answerEnabled(Screening.OFFER, 0L))
        assertTrue(IncomingUiPolicy.answerEnabled(Screening.NONE, 0L))
    }

    @Test
    fun aNoticeCarriesNothingThatAnswersOrOpensTheScreen() {
        val none = IncomingNotice(openUi = false, fullScreen = false, answer = false)
        // The offer went to an open :secure app, which shows its own answer choice.
        val offered = decide(Screening.OFFER, toSecure = true, waited = 5_000L)
        assertEquals(IncomingUi.NOTICE_ONLY, offered)
        val reg = RegistryView(screening = Screening.OFFER, offerToSecure = true)
        assertEquals(none, IncomingUiPolicy.notice(offered, reg, Screening.OFFER, 5_000L))
        // A second call while a secure call is under way.
        assertEquals(none, IncomingUiPolicy.notice(IncomingUi.NOTICE_ONLY, RegistryView(secureOwned = true), Screening.PLAIN, 5_000L))
    }

    @Test
    fun aFullScreenCallOpensTheScreenAndOffersAnsweringOnceScreeningIsOver() {
        assertEquals(IncomingNotice(true, true, true), IncomingUiPolicy.notice(IncomingUi.FULL_SCREEN, RegistryView(), Screening.PLAIN, 0L))
        assertEquals(IncomingNotice(true, true, false), IncomingUiPolicy.notice(IncomingUi.FULL_SCREEN, RegistryView(), Screening.PENDING, 600L))
        assertEquals(IncomingNotice(true, true, true), IncomingUiPolicy.notice(IncomingUi.FULL_SCREEN_AND_START, RegistryView(), Screening.OFFER, 0L))
        assertEquals(
            IncomingNotice(false, false, false),
            IncomingUiPolicy.notice(IncomingUi.FULL_SCREEN, RegistryView(secureOwned = true), Screening.PLAIN, 0L),
        )
    }

    @Test
    fun bringingTheCallForwardNeverOpensTheScreenOverANotice() {
        assertFalse(IncomingUiPolicy.mayBringToForeground(IncomingUi.NOTICE_ONLY, RegistryView(offerToSecure = true), appDial = false))
        assertTrue(IncomingUiPolicy.mayBringToForeground(IncomingUi.FULL_SCREEN, RegistryView(), appDial = false))
        assertTrue(IncomingUiPolicy.mayBringToForeground(null, RegistryView(), appDial = false))
        assertFalse(IncomingUiPolicy.mayBringToForeground(null, RegistryView(secureOwned = true), appDial = false))
        assertFalse(IncomingUiPolicy.mayBringToForeground(null, RegistryView(), appDial = true))
    }
}
