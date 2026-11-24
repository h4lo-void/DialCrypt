package io.github.h4lovoid.dialcrypt

import androidx.compose.runtime.getValue
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.longClick
import com.github.takahirom.roborazzi.captureRoboImage
import io.github.h4lovoid.dialcrypt.core.AppLanguage
import io.github.h4lovoid.dialcrypt.core.BiometricState
import io.github.h4lovoid.dialcrypt.core.ConnectStep
import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.CoreAvailability
import io.github.h4lovoid.dialcrypt.core.CoreState
import io.github.h4lovoid.dialcrypt.core.FakeLockdownController
import io.github.h4lovoid.dialcrypt.core.FakeScenarios
import io.github.h4lovoid.dialcrypt.core.FakeSecureCore
import io.github.h4lovoid.dialcrypt.core.HardeningLevel
import io.github.h4lovoid.dialcrypt.core.InMemoryUiPreferences
import io.github.h4lovoid.dialcrypt.core.LockdownFailure
import io.github.h4lovoid.dialcrypt.core.LockdownState
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.core.PrepItem
import io.github.h4lovoid.dialcrypt.core.SessionFailure
import io.github.h4lovoid.dialcrypt.core.SessionState
import io.github.h4lovoid.dialcrypt.dialer.model.AudioUi
import io.github.h4lovoid.dialcrypt.dialer.model.Endpoint
import io.github.h4lovoid.dialcrypt.dialer.model.InCallUiState
import io.github.h4lovoid.dialcrypt.dialer.model.NumberText
import io.github.h4lovoid.dialcrypt.dialer.model.NumberTexts
import io.github.h4lovoid.dialcrypt.dialer.model.RecentDirection
import io.github.h4lovoid.dialcrypt.dialer.model.RecentItem
import io.github.h4lovoid.dialcrypt.dialer.model.RecentState
import io.github.h4lovoid.dialcrypt.dialer.model.Screening
import io.github.h4lovoid.dialcrypt.dialer.model.UiCall
import io.github.h4lovoid.dialcrypt.dialer.model.UiCallState
import io.github.h4lovoid.dialcrypt.dialer.ui.DialTab
import io.github.h4lovoid.dialcrypt.dialer.ui.DialerTabs
import io.github.h4lovoid.dialcrypt.dialer.ui.DialpadScreen
import io.github.h4lovoid.dialcrypt.dialer.ui.InCallActions
import io.github.h4lovoid.dialcrypt.dialer.ui.InCallScreen
import io.github.h4lovoid.dialcrypt.dialer.ui.RecentsScreen
import io.github.h4lovoid.dialcrypt.ui.AppRoot
import io.github.h4lovoid.dialcrypt.ui.keyboard.InputHost
import io.github.h4lovoid.dialcrypt.ui.screens.AboutScreen
import io.github.h4lovoid.dialcrypt.ui.screens.BiometricSettings
import io.github.h4lovoid.dialcrypt.ui.screens.PreparationScreen
import io.github.h4lovoid.dialcrypt.ui.screens.SettingsScreen
import io.github.h4lovoid.dialcrypt.ui.screens.StartScreen
import java.io.File
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/**
 * Renders each main screen and state to a PNG. Output folder comes from -Daegis.previewDir, which
 * app/build.gradle.kts sets to app/build/ui-preview. Run it with
 * ./gradlew :app:testPixelTitanDebugUnitTest --tests "io.github.h4lovoid.dialcrypt.ScreenshotTest"
 * and copy the PNGs to docs/ui-preview. Every capture waits for the screen transition to end first.
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "w411dp-h891dp-xxhdpi")
class ScreenshotTest {
    @get:Rule
    val rule = createComposeRule()

    private val pin = "abcdefghij"
    private val emergency = "klmnopqrst"

    private fun capture(name: String, lang: AppLanguage = AppLanguage.EN) {
        rule.waitForIdle()
        val dir = File(System.getProperty("aegis.previewDir") ?: "build/ui-preview").also { it.mkdirs() }
        val suffix = if (lang == AppLanguage.ZH_HANS) "zh" else (lang.tag ?: "system")
        rule.onRoot().captureRoboImage(File(dir, name + "_" + suffix + ".png").path)
    }

    private fun app(
        core: FakeSecureCore,
        lang: AppLanguage = AppLanguage.EN,
        lockdown: FakeLockdownController = FakeLockdownController(FakeScenarios.lockdownReady()),
    ) {
        rule.setContent { AppRoot(core, lockdown, InMemoryUiPreferences(lang), onExit = {}) }
    }

    private fun unlockedCore(session: SessionState = SessionState(), contacts: List<io.github.h4lovoid.dialcrypt.core.Contact> = FakeScenarios.contacts) =
        FakeSecureCore(FakeScenarios.unlocked, contacts, session)

    private fun typeText(s: String) {
        s.forEach { c -> rule.onNodeWithTag(if (c == ' ') "key_space" else "key_$c").performClick() }
    }

    private fun screen(lang: AppLanguage = AppLanguage.EN, content: @androidx.compose.runtime.Composable () -> Unit) {
        val host = InputHost()
        rule.setContent { Harness(lang, host, content) }
    }

    // ---- start-up ---------------------------------------------------------------------

    @Test fun startScreen() {
        screen { StartScreen(onStart = {}) }
        capture("00-start")
    }

    @Test fun prepRunning() {
        screen { PreparationScreen(FakeScenarios.lockdown(done = 4), {}, {}) }
        capture("01-prep-running")
    }

    @Test fun prepFailedVolte() {
        screen { PreparationScreen(FakeScenarios.lockdownFailed(PrepItem.VOLTE, LockdownFailure.VOLTE_NOT_REGISTERED), {}, {}) }
        capture("02-prep-failed")
    }

    @Test fun prepReady() {
        screen { PreparationScreen(FakeScenarios.lockdownReady(), {}, {}) }
        capture("03-prep-ready")
    }

    @Test fun notConnected() {
        app(FakeSecureCore(CoreState(CoreAvailability.NOT_CONNECTED)))
        capture("04-not-connected")
    }

    // ---- PIN -----------------------------------------------------------------------------

    @Test fun pinSetupFirst() {
        app(FakeSecureCore(CoreState(CoreAvailability.READY)))
        typeText("correct horse")
        capture("05-pin-setup")
    }

    @Test fun pinSetupEmergency() {
        app(FakeSecureCore(CoreState(CoreAvailability.READY)))
        typeText(pin); rule.onNodeWithText("Continue").performClick()
        typeText(pin); rule.onNodeWithText("Continue").performClick()
        typeText("klmno")
        capture("06-pin-setup-emergency")
    }

    @Test fun unlock() {
        val core = FakeSecureCore(CoreState(CoreAvailability.READY, pinConfigured = true, locked = true))
        core.presetPins(pin, emergency)
        app(core)
        typeText("abcd")
        capture("07-unlock")
    }

    @Test fun unlockWrong() {
        val core = FakeSecureCore(CoreState(CoreAvailability.READY, pinConfigured = true, locked = true))
        core.presetPins(pin, emergency)
        app(core)
        typeText("zzzzzzzzzz")
        rule.onNodeWithText("Unlock").performClick()
        capture("08-unlock-wrong")
    }

    @Test fun vaultDestroyed() {
        app(FakeSecureCore(CoreState(CoreAvailability.READY, pinConfigured = true, locked = true, attemptsLeft = 0, vaultDestroyed = true)))
        capture("09-vault-destroyed")
    }

    // ---- home, dial, contacts ------------------------------------------------------------

    @Test fun homeContacts() { app(unlockedCore()); capture("10-home-contacts") }

    @Test fun homeEmpty() { app(unlockedCore(contacts = emptyList())); capture("11-home-empty") }

    @Test fun homeSearch() {
        app(unlockedCore())
        rule.onNodeWithTag("search_input").performClick()
        typeText("ma")
        capture("12-home-search")
    }

    @Test fun keyboardAccents() {
        app(unlockedCore())
        rule.onNodeWithTag("search_input").performClick()
        typeText("m")
        rule.onNodeWithTag("key_e").performTouchInput { longClick() }
        capture("13-keyboard-accents")
    }

    @Test fun keyboardSymbols() {
        app(unlockedCore())
        rule.onNodeWithTag("search_input").performClick()
        rule.onNodeWithTag("key_page").performClick()
        capture("14-keyboard-symbols")
    }

    @Test fun dial() {
        app(unlockedCore())
        rule.onNodeWithText("Call").performClick()
        capture("15-dial")
    }

    @Test fun dialKeypad() {
        app(unlockedCore())
        rule.onNodeWithText("Call").performClick()
        rule.onNodeWithTag("dial_number").performClick()
        rule.onNodeWithTag("key_4").performClick()
        rule.onNodeWithTag("key_1").performClick()
        rule.onNodeWithTag("key_5").performClick()
        capture("16-dial-keypad")
    }

    @Test fun contactDetail() {
        app(unlockedCore())
        rule.onNodeWithText("Ana Torres").performClick()
        capture("17-contact-detail")
    }

    @Test fun contactDetailBottom() {
        app(unlockedCore())
        rule.onNodeWithText("Ana Torres").performClick()
        rule.onNodeWithText("Delete contact").performScrollTo()
        capture("18-contact-detail-bottom")
    }

    @Test fun contactEdit() {
        app(unlockedCore())
        rule.onNodeWithText("Ana Torres").performClick()
        rule.onNodeWithText("Edit name and number").performClick()
        capture("19-contact-edit")
    }

    // ---- settings -------------------------------------------------------------------------

    @Test fun settings() {
        app(unlockedCore(), lockdown = FakeLockdownController(FakeScenarios.lockdownReady(HardeningLevel.LEVEL_1)))
        rule.onNodeWithContentDescription("Settings").performClick()
        capture("20-settings")
    }

    @Test fun changePin() {
        val core = unlockedCore()
        core.presetPins(pin, emergency)
        app(core)
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithText("Change PINs").performScrollTo().performClick()
        capture("21-change-pin")
    }

    // The dialog is a window of its own, so the whole screen is captured instead of one root.
    @OptIn(com.github.takahirom.roborazzi.ExperimentalRoborazziApi::class)
    @Test fun settingsBioWarning() {
        // The dialog hides other apps' overlay windows, which needs this permission.
        org.robolectric.Shadows.shadowOf(androidx.test.core.app.ApplicationProvider.getApplicationContext<android.app.Application>())
            .grantPermissions("android.permission.HIDE_OVERLAY_WINDOWS")
        screen {
            SettingsScreen(
                language = AppLanguage.EN,
                onLanguage = {},
                lockdown = FakeScenarios.lockdownReady(HardeningLevel.LEVEL_1),
                pinChanged = false,
                onBack = {},
                onChangePin = {},
                onAbout = {},
                onWipeConfirmed = {},
                biometric = BiometricSettings(BiometricState.OFF, hasFingerprint = true, failed = false, onTurnOn = {}, onTurnOff = {}),
            )
        }
        rule.onNodeWithTag(BiometricSettings.TOGGLE_TAG).performScrollTo().performClick()
        rule.waitForIdle()
        val dir = File(System.getProperty("aegis.previewDir") ?: "build/ui-preview").also { it.mkdirs() }
        com.github.takahirom.roborazzi.captureScreenRoboImage(File(dir, "20-settings-bio-warning_en.png").path)
    }

    @Test fun about() {
        screen { AboutScreen(onBack = {}) }
        capture("22-about")
    }

    // ---- call session ------------------------------------------------------------------------

    @Test fun connectingEarly() {
        app(unlockedCore(FakeScenarios.connecting(ConnectStep.WAIT_PEER, 12, 36)))
        capture("23-connecting-early")
    }

    @Test fun connectingLate() {
        app(unlockedCore(FakeScenarios.connecting(ConnectStep.IDENTITY, 82, 8, FakeScenarios.ana)))
        capture("24-connecting-late")
    }

    @Test fun sasVoiceOpen() {
        app(unlockedCore(FakeScenarios.withSas(FakeScenarios.chatUnknown)))
        capture("25-sas-voice-open")
    }

    @Test fun sasVoiceClosedWaiting() {
        app(unlockedCore(FakeScenarios.withSas(FakeScenarios.chatUnknown, open = false, seconds = 0, local = true)))
        capture("26-sas-waiting")
    }

    @Test fun chatUnknown() {
        app(unlockedCore(FakeScenarios.chatUnknown))
        capture("27-chat-unverified")
    }

    @Test fun chatUnknownTyping() {
        app(unlockedCore(FakeScenarios.chatUnknown))
        rule.onNodeWithTag("chat_input").performClick()
        typeText("on my way")
        capture("28-chat-typing")
    }

    @Test fun chatVerifiedCall() {
        app(unlockedCore(FakeScenarios.chatVerifiedCall))
        capture("29-chat-verified-call")
    }

    @Test fun chatContactPqProgress() {
        app(unlockedCore(FakeScenarios.chatContactPairedQuick))
        capture("30-chat-contact-pq-progress")
    }

    @Test fun chatContactPqDone() {
        app(unlockedCore(FakeScenarios.chatContactPq))
        capture("31-chat-contact-pq-done")
    }

    @Test fun saveContact() {
        app(unlockedCore(FakeScenarios.saveOffer))
        typeText("jo")
        capture("32-save-contact")
    }

    @Test fun keyChanged() {
        app(unlockedCore(FakeScenarios.keyChanged))
        capture("33-key-changed")
    }

    @Test fun keyChangedCompare() {
        val core = unlockedCore(FakeScenarios.keyChanged)
        app(core)
        rule.onNodeWithText("Compare again").performClick()
        capture("34-key-changed-compare")
    }

    @Test fun aborted() {
        app(unlockedCore(FakeScenarios.aborted(SessionFailure.NO_PREAMBLE)))
        capture("35-aborted")
    }

    @Test fun endedByPeer() {
        app(unlockedCore(FakeScenarios.endedByPeer))
        capture("35b-ended-by-peer")
    }

    @Test fun clearing() { app(unlockedCore(FakeScenarios.clearing)); capture("36-clearing") }

    @Test fun cleared() { app(unlockedCore(FakeScenarios.cleared)); capture("37-cleared") }

    // ---- Spanish and French -----------------------------------------------------------------

    // ---- more states of the redesigned screens ------------------------------------------------

    @Test fun homeProtectionPreparing() {
        app(unlockedCore(), lockdown = FakeLockdownController(FakeScenarios.lockdown(done = 4)))
        capture("38-home-protection-preparing")
    }

    @Test fun homeProtectionFailed() {
        app(unlockedCore(), lockdown = FakeLockdownController(FakeScenarios.lockdownFailed(PrepItem.VOLTE, LockdownFailure.VOLTE_NOT_REGISTERED)))
        capture("39-home-protection-failed")
    }

    @Test fun contactDetailKeyChanged() {
        app(unlockedCore())
        rule.onNodeWithText("Luc\u00EDa Pe\u00F1a").performClick()
        capture("40-contact-detail-key-changed")
    }

    @Test fun esContactDetail() {
        app(unlockedCore(), AppLanguage.ES)
        rule.onNodeWithText("Ana Torres").performClick()
        capture("17-contact-detail", AppLanguage.ES)
    }

    @Test fun frContactDetail() {
        app(unlockedCore(), AppLanguage.FR)
        rule.onNodeWithText("Ana Torres").performClick()
        capture("17-contact-detail", AppLanguage.FR)
    }

    @Test fun esHome() { app(unlockedCore(), AppLanguage.ES); capture("10-home-contacts", AppLanguage.ES) }
    @Test fun esConnecting() { app(unlockedCore(FakeScenarios.connecting(ConnectStep.KEY_EXCHANGE, 48, 21)), AppLanguage.ES); capture("23-connecting", AppLanguage.ES) }
    @Test fun esSas() { app(unlockedCore(FakeScenarios.withSas(FakeScenarios.chatUnknown)), AppLanguage.ES); capture("25-sas-voice-open", AppLanguage.ES) }
    @Test fun esChat() { app(unlockedCore(FakeScenarios.chatUnknown), AppLanguage.ES); capture("27-chat-unverified", AppLanguage.ES) }
    @Test fun esKeyChanged() { app(unlockedCore(FakeScenarios.keyChanged), AppLanguage.ES); capture("33-key-changed", AppLanguage.ES) }
    @Test fun esPrepFailed() {
        screen(AppLanguage.ES) { PreparationScreen(FakeScenarios.lockdownFailed(PrepItem.VOLTE, LockdownFailure.VOLTE_NOT_REGISTERED), {}, {}) }
        capture("02-prep-failed", AppLanguage.ES)
    }

    @Test fun frHome() { app(unlockedCore(), AppLanguage.FR); capture("10-home-contacts", AppLanguage.FR) }
    @Test fun frConnecting() { app(unlockedCore(FakeScenarios.connecting(ConnectStep.KEY_EXCHANGE, 48, 21)), AppLanguage.FR); capture("23-connecting", AppLanguage.FR) }
    @Test fun frSas() { app(unlockedCore(FakeScenarios.withSas(FakeScenarios.chatUnknown)), AppLanguage.FR); capture("25-sas-voice-open", AppLanguage.FR) }
    @Test fun frChat() { app(unlockedCore(FakeScenarios.chatUnknown), AppLanguage.FR); capture("27-chat-unverified", AppLanguage.FR) }
    @Test fun frKeyChanged() { app(unlockedCore(FakeScenarios.keyChanged), AppLanguage.FR); capture("33-key-changed", AppLanguage.FR) }
    @Test fun frPrepFailed() {
        screen(AppLanguage.FR) { PreparationScreen(FakeScenarios.lockdownFailed(PrepItem.VOLTE, LockdownFailure.VOLTE_NOT_REGISTERED), {}, {}) }
        capture("02-prep-failed", AppLanguage.FR)
    }

    // ---- Simplified Chinese ------------------------------------------------------------------

    @Test fun zhHome() { app(unlockedCore(), AppLanguage.ZH_HANS); capture("10-home-contacts", AppLanguage.ZH_HANS) }

    @Test fun zhUnlock() {
        val core = FakeSecureCore(CoreState(CoreAvailability.READY, pinConfigured = true, locked = true))
        core.presetPins(pin, emergency)
        app(core, AppLanguage.ZH_HANS)
        typeText("abcd")
        capture("07-unlock", AppLanguage.ZH_HANS)
    }

    @Test fun zhChat() { app(unlockedCore(FakeScenarios.chatUnknown), AppLanguage.ZH_HANS); capture("27-chat-unverified", AppLanguage.ZH_HANS) }

    @Test fun zhSas() { app(unlockedCore(FakeScenarios.withSas(FakeScenarios.chatUnknown)), AppLanguage.ZH_HANS); capture("25-sas-voice-open", AppLanguage.ZH_HANS) }

    @Test fun zhKeyChanged() { app(unlockedCore(FakeScenarios.keyChanged), AppLanguage.ZH_HANS); capture("33-key-changed", AppLanguage.ZH_HANS) }

    @Test fun zhSettings() {
        app(unlockedCore(), AppLanguage.ZH_HANS, FakeLockdownController(FakeScenarios.lockdownReady(HardeningLevel.LEVEL_1)))
        rule.onNodeWithContentDescription("设置").performClick()
        capture("20-settings", AppLanguage.ZH_HANS)
    }

    // ---- default dialer ------------------------------------------------------------------------

    // The caller line is masked the way it is over the lock screen.
    private fun dialerCall(state: UiCallState, answerEnabled: Boolean = false, connectMs: Long? = null) = UiCall(
        id = 1,
        state = state,
        number = NumberTexts.of("+1 555 123 4567", NumberPresentation.SHOWN, ContactMembership.CONTACT, showFull = false, locked = true),
        connectMs = connectMs,
        canHold = true,
        emergency = false,
        postDial = null,
        accounts = emptyList(),
        answerEnabled = answerEnabled,
    )

    @Test fun inCallRinging() {
        val state = InCallUiState(
            primary = dialerCall(UiCallState.RINGING, answerEnabled = true),
            secureOffer = true,
            screening = Screening.OFFER,
        )
        screen { InCallScreen(state, InCallActions(), nowMs = 0L) }
        capture("50-incall-ringing")
    }

    @Test fun inCallActive() {
        val state = InCallUiState(
            primary = dialerCall(UiCallState.ACTIVE, connectMs = 1_000L),
            audio = AudioUi(endpoint = Endpoint.EARPIECE, available = listOf(Endpoint.EARPIECE, Endpoint.SPEAKER, Endpoint.BLUETOOTH)),
        )
        // 754 s of wall clock minus a connect time of 1 s: the timer reads 12:33.
        screen { InCallScreen(state, InCallActions(), nowMs = 754_000L) }
        capture("51-incall-active")
    }

    @Test fun dialpad() {
        screen {
            androidx.compose.foundation.layout.Column {
                DialerTabs(DialTab.KEYPAD, {})
                DialpadScreen(digits = "5551234", notice = null, onKey = {}, onDelete = {}, onClear = {}, onCall = {}, modifier = androidx.compose.ui.Modifier.weight(1f))
            }
        }
        capture("52-dialpad")
    }

    @Test fun recents() {
        // 2026-11-24 12:00 UTC; the rows are earlier the same day and the day before.
        val now = 1_795_521_600_000L
        val state = RecentState(
            items = listOf(
                RecentItem(4L, RecentDirection.MISSED, NumberText.Digits("+1 555 010 0199"), now - 25 * 60_000L, null, "+15550100199"),
                RecentItem(3L, RecentDirection.INCOMING, NumberText.Digits("\u2022\u2022\u2022\u2022 0101"), now - 2 * 3_600_000L, 312L, "+447700900101"),
                RecentItem(2L, RecentDirection.OUTGOING, NumberText.Digits("+34 600 555 010"), now - 5 * 3_600_000L, 64L, "+34600555010"),
                RecentItem(1L, RecentDirection.INCOMING, NumberText.Hidden, now - 26 * 3_600_000L, 41L, null),
            ),
            loaded = true,
        )
        val zone = java.util.TimeZone.getDefault()
        java.util.TimeZone.setDefault(java.util.TimeZone.getTimeZone("UTC"))
        try {
            screen {
                androidx.compose.foundation.layout.Column {
                    DialerTabs(DialTab.RECENTS, {})
                    RecentsScreen(state, nowMs = now, notice = null, onCall = {}, onDelete = {}, onClearAll = {}, modifier = androidx.compose.ui.Modifier.weight(1f))
                }
            }
            capture("53-recents")
        } finally {
            java.util.TimeZone.setDefault(zone)
        }
    }

    @Test fun inCallConference() {
        val state = InCallUiState(
            primary = dialerCall(UiCallState.ACTIVE, connectMs = 1_000L).copy(id = 3, number = NumberText.Conference(3)),
            audio = AudioUi(endpoint = Endpoint.SPEAKER, available = listOf(Endpoint.EARPIECE, Endpoint.SPEAKER)),
        )
        screen { InCallScreen(state, InCallActions(), nowMs = 425_000L) }
        capture("54-incall-conference")
    }
}
