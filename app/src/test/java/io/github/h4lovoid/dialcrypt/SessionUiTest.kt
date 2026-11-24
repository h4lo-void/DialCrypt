package io.github.h4lovoid.dialcrypt

import android.content.Context
import android.content.res.Configuration
import androidx.test.core.app.ApplicationProvider
import io.github.h4lovoid.dialcrypt.core.ConnectStep
import io.github.h4lovoid.dialcrypt.core.FakeScenarios
import io.github.h4lovoid.dialcrypt.core.HardwareLevel
import io.github.h4lovoid.dialcrypt.core.IdentityStatus
import io.github.h4lovoid.dialcrypt.core.PqState
import io.github.h4lovoid.dialcrypt.core.SessionFailure
import io.github.h4lovoid.dialcrypt.core.SessionPhase
import io.github.h4lovoid.dialcrypt.core.SessionState
import io.github.h4lovoid.dialcrypt.ui.model.ConnectingUi
import io.github.h4lovoid.dialcrypt.ui.model.SessionScreen
import io.github.h4lovoid.dialcrypt.ui.model.SessionUi
import io.github.h4lovoid.dialcrypt.ui.model.TextMaps
import io.github.h4lovoid.dialcrypt.ui.theme.Tone
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SessionUiTest {

    private fun context(tag: String): Context {
        val base = ApplicationProvider.getApplicationContext<Context>()
        val config = Configuration(base.resources.configuration)
        config.setLocale(Locale.forLanguageTag(tag))
        return base.createConfigurationContext(config)
    }

    private val languages = listOf("en", "es", "fr")

    @Test
    fun unknownPeerIsNeverShownAsVerified() {
        val banner = SessionUi.identityBanner(FakeScenarios.chatUnknown)!!
        assertEquals(R.string.status_unverified, banner.textRes)
        assertEquals(Tone.WARN, banner.tone)
        val verifiedRes = listOf(
            R.string.status_verified_call, R.string.status_contact, R.string.status_contact_paired,
            R.string.status_contact_quick, R.string.status_contact_paired_quick,
        )
        languages.forEach { lang ->
            val ctx = context(lang)
            verifiedRes.forEach { assertNotEquals(ctx.getString(R.string.status_unverified), ctx.getString(it)) }
        }
    }

    @Test
    fun verifiedWordingNeedsTheMatchingState() {
        assertEquals(R.string.status_verified_call, SessionUi.identityBanner(FakeScenarios.chatVerifiedCall)!!.textRes)
        assertEquals(Tone.OK, SessionUi.identityBanner(FakeScenarios.chatVerifiedCall)!!.tone)
        // Ana is paired and has quick connect ready; Marc has neither ready nor paired.
        assertEquals(R.string.status_contact_paired_quick, SessionUi.identityBanner(FakeScenarios.chatContactPairedQuick)!!.textRes)
        assertEquals(R.string.status_contact, SessionUi.identityBanner(FakeScenarios.chatContactPq)!!.textRes)
    }

    @Test
    fun nothingIsClaimedBeforeTheLinkExists() {
        val early = FakeScenarios.connecting(ConnectStep.KEY_EXCHANGE, 40, 20)
        // Even if the core already guessed an identity, the banner stays hidden while connecting.
        val optimistic = early.copy(identity = IdentityStatus.VERIFIED_CONTACT, pq = PqState(mixed = true))
        assertNull(SessionUi.identityBanner(optimistic))
        assertNull(SessionUi.pqLabel(optimistic))
        assertNull(SessionUi.identityBanner(FakeScenarios.aborted(SessionFailure.NO_PREAMBLE)))
        assertNull(SessionUi.identityBanner(FakeScenarios.clearing))
    }

    @Test
    fun connectingScreenNeverUsesEncryptionOrSecurityWords() {
        val forbidden = Regex("encrypt|secur|cifr|segur|chiffr|s\u00E9cur|verified|verific|v\u00E9rifi|protect|prote[gc]", RegexOption.IGNORE_CASE)
        languages.forEach { lang ->
            val ctx = context(lang)
            val texts = ConnectingUi.allRes.map { ctx.getString(it, 5) } +
                listOf(R.string.abort_nothing_sent, R.string.abort_no_preamble, R.string.abort_handshake, R.string.abort_peer)
                    .map { ctx.getString(it) }
            texts.forEach { assertFalse(lang + ": " + it, forbidden.containsMatchIn(it)) }
        }
    }

    @Test
    fun postQuantumIsOnlyClaimedOnceMixedIn() {
        val inProgress = SessionUi.pqLabel(FakeScenarios.chatContactPairedQuick)!!
        assertEquals(R.string.pq_progress, inProgress.res)
        assertEquals(42, inProgress.percent)
        val done = SessionUi.pqLabel(FakeScenarios.chatContactPq)!!
        assertEquals(R.string.pq_mixed, done.res)
        assertNull(done.percent)
    }

    @Test
    fun sendingIsOffWheneverTheKeyChanged() {
        assertTrue(SessionUi.canSend(FakeScenarios.chatUnknown))
        assertTrue(SessionUi.canSend(FakeScenarios.chatVerifiedCall))
        assertFalse(SessionUi.canSend(FakeScenarios.keyChanged))
        assertFalse(SessionUi.canSend(FakeScenarios.chatContactPq.copy(identity = IdentityStatus.KEY_CHANGED)))
        // While the words are on screen the chat is hidden and sending is off too.
        assertFalse(SessionUi.canSend(FakeScenarios.withSas(FakeScenarios.chatUnknown)))
        assertFalse(SessionUi.canSend(FakeScenarios.connecting(ConnectStep.DIALING, 0, 40)))
        assertFalse(SessionUi.canSend(SessionState(phase = SessionPhase.IDLE)))
    }

    @Test
    fun keyChangeShowsTheRedScreenAndComparisonKeepsItRed() {
        assertEquals(SessionScreen.KEY_CHANGED, SessionUi.screenFor(FakeScenarios.keyChanged))
        val comparing = FakeScenarios.withSas(FakeScenarios.keyChanged)
        assertEquals(SessionScreen.SAS, SessionUi.screenFor(comparing))
        assertEquals(Tone.DANGER, SessionUi.identityBanner(comparing)!!.tone)
        assertFalse(SessionUi.canSend(comparing))
    }

    @Test
    fun saveOfferOnlyAppearsAfterTheWordsMatchedAndNeverOverTheWordCard() {
        assertTrue(SessionUi.showSaveOffer(FakeScenarios.saveOffer))
        assertFalse(SessionUi.showSaveOffer(FakeScenarios.withSas(FakeScenarios.saveOffer)))
        assertFalse(SessionUi.showSaveOffer(FakeScenarios.chatUnknown))
    }

    @Test
    fun verifyActionIsOfferedOnlyForUnverifiedPeers() {
        assertTrue(SessionUi.canVerify(FakeScenarios.chatUnknown))
        assertFalse(SessionUi.canVerify(FakeScenarios.chatVerifiedCall))
        assertFalse(SessionUi.canVerify(FakeScenarios.chatContactPq))
    }

    @Test
    fun everyFailureCodeHasASentenceInEveryLanguage() {
        languages.forEach { lang ->
            val ctx = context(lang)
            SessionFailure.values().forEach { assertTrue(ctx.getString(TextMaps.sessionFailure(it)).isNotBlank()) }
        }
    }

    @Test
    fun hardwareProofHasAPlainTitleAndKeepsTheTermInItsNote() {
        languages.forEach { lang ->
            val ctx = context(lang)
            HardwareLevel.values().forEach { level ->
                val title = ctx.getString(TextMaps.hardwareTitle(level))
                val note = ctx.getString(TextMaps.hardwareExplain(level))
                val term = ctx.getString(TextMaps.hardwareDetail(level))
                assertFalse(lang + ": " + title, title.contains("StrongBox"))
                assertTrue(lang + ": " + note, note.startsWith(term))
            }
        }
    }
}
