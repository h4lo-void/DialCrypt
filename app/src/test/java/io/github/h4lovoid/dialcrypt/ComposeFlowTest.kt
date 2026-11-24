package io.github.h4lovoid.dialcrypt

import androidx.activity.ComponentActivity
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertHeightIsAtLeast
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.isEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.longClick
import androidx.compose.ui.test.printToString
import androidx.compose.ui.unit.dp
import androidx.compose.ui.test.hasText
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import io.github.h4lovoid.dialcrypt.core.AppLanguage
import io.github.h4lovoid.dialcrypt.core.CoreAvailability
import io.github.h4lovoid.dialcrypt.core.CoreState
import io.github.h4lovoid.dialcrypt.core.FakeLockdownController
import io.github.h4lovoid.dialcrypt.core.FakeScenarios
import io.github.h4lovoid.dialcrypt.core.FakeSecureCore
import io.github.h4lovoid.dialcrypt.core.InMemoryUiPreferences
import io.github.h4lovoid.dialcrypt.core.SendResult
import io.github.h4lovoid.dialcrypt.core.SharedPrefsUiPreferences
import io.github.h4lovoid.dialcrypt.ui.AppRoot
import io.github.h4lovoid.dialcrypt.ui.LauncherRoot
import io.github.h4lovoid.dialcrypt.ui.keyboard.InputHost
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureInputState
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureTextField
import io.github.h4lovoid.dialcrypt.ui.screens.ChatScreen
import io.github.h4lovoid.dialcrypt.ui.screens.ConnectingScreen
import io.github.h4lovoid.dialcrypt.ui.screens.ContactDetailScreen
import io.github.h4lovoid.dialcrypt.ui.screens.DialScreen
import io.github.h4lovoid.dialcrypt.ui.screens.HomeScreen
import io.github.h4lovoid.dialcrypt.ui.screens.KeyChangedScreen
import io.github.h4lovoid.dialcrypt.ui.screens.PinMode
import io.github.h4lovoid.dialcrypt.ui.screens.PinWizardScreen
import io.github.h4lovoid.dialcrypt.ui.screens.UnlockScreen
import io.github.h4lovoid.dialcrypt.core.ConnectStep
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "w411dp-h891dp-xxhdpi")
class ComposeFlowTest {
    @get:Rule
    val rule = createAndroidComposeRule<ComponentActivity>()

    @org.junit.Before
    fun grantDialogPermission() {
        // SecureDialog hides overlay windows, which needs this permission.
        org.robolectric.Shadows.shadowOf(rule.activity.application).grantPermissions("android.permission.HIDE_OVERLAY_WINDOWS")
    }

    private fun typeText(s: String) {
        s.forEach { c -> rule.onNodeWithTag(if (c == ' ') "key_space" else "key_$c").performClick() }
    }

    private fun longPress(tag: String) = rule.onNodeWithTag(tag).performTouchInput { longClick() }

    // ---- keyboard ---------------------------------------------------------------------

    @Test
    fun longPressTypesAccentedLettersThroughTheInAppKeyboard() {
        val input = SecureInputState()
        val host = InputHost()
        rule.setContent {
            Harness(AppLanguage.ES, host) {
                LaunchedEffect(Unit) { host.focus(input) }
                SecureTextField(input, Modifier)
            }
        }
        longPress("key_e")
        rule.onNodeWithTag("accent_\u00E9").performClick()
        longPress("key_n")
        rule.onNodeWithTag("accent_\u00F1").performClick()
        longPress("key_c")
        rule.onNodeWithTag("accent_\u00E7").performClick()
        rule.onNodeWithTag("key_shift").performClick()
        longPress("key_a")
        rule.onNodeWithTag("accent_\u00C0").performClick()
        rule.runOnIdle { assertEquals("\u00E9\u00F1\u00E7\u00C0", input.text()) }
    }

    @Test
    fun deleteKeyRemovesOneCharacterAndLongPressClearsAll() {
        val input = SecureInputState()
        val host = InputHost()
        rule.setContent { Harness(AppLanguage.EN, host) { LaunchedEffect(Unit) { host.focus(input) }; SecureTextField(input) } }
        typeText("abc")
        rule.onNodeWithTag("key_backspace").performClick()
        rule.runOnIdle { assertEquals("ab", input.text()) }
        longPress("key_backspace")
        rule.runOnIdle { assertTrue(input.isEmpty) }
    }

    @Test
    fun noKeyboardUntilAFieldIsTouched() {
        val input = SecureInputState()
        val host = InputHost()
        rule.setContent { Harness(AppLanguage.EN, host) { SecureTextField(input, tag = "plain") } }
        assertEquals(0, rule.onAllNodesWithTag("key_a").fetchSemanticsNodes().size)
        rule.onNodeWithTag("plain").performClick()
        assertEquals(1, rule.onAllNodesWithTag("key_a").fetchSemanticsNodes().size)
    }

    // ---- PIN ----------------------------------------------------------------------------

    @Test
    fun pinSetupEnforcesLengthAndKeepsTheEmergencyPinDifferent() {
        val core = FakeSecureCore(CoreState(CoreAvailability.READY))
        val host = InputHost()
        var finished = false
        rule.setContent {
            Harness(AppLanguage.EN, host) { PinWizardScreen(PinMode.SETUP, core, onFinished = { finished = true }, onBack = null) }
        }
        typeText("abcdefghi")
        rule.onNodeWithText("Continue").assertIsNotEnabled()
        typeText("j")
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()

        // Confirmation must match.
        typeText("abcdefghi")
        rule.onNodeWithText("Continue").assertIsNotEnabled()
        typeText("j")
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()

        // Emergency PIN: same as the normal PIN is refused.
        typeText("abcdefghij")
        rule.onNodeWithText("Continue").assertIsNotEnabled()
        rule.onNodeWithText("The emergency PIN must be different from your PIN.").assertExists()
        longPress("key_backspace")
        typeText("klmnopqrst")
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()
        typeText("klmnopqrsx")
        rule.onNodeWithText("The two entries do not match.").assertExists()
        rule.onNodeWithText("Save PINs").assertIsNotEnabled()
        rule.onNodeWithTag("key_backspace").performClick()
        typeText("t")
        rule.onNodeWithText("Save PINs").assertIsEnabled().performClick()
        rule.waitForIdle()
        assertTrue(finished)
        assertEquals("abcdefghij", core.normalPin)
        assertEquals("klmnopqrst", core.duressPin)
        assertTrue(core.state.value.pinConfigured)
    }

    @Test
    fun aSimplePinIsRefusedWithAnExplanation() {
        val core = FakeSecureCore(CoreState(CoreAvailability.READY))
        val host = InputHost()
        rule.setContent { Harness(AppLanguage.EN, host) { PinWizardScreen(PinMode.SETUP, core, {}, null) } }
        typeText("aaaaaaaaaa")
        rule.onNodeWithText("Continue").assertIsNotEnabled()
        rule.onNodeWithText("Too simple: use at least 4 different characters.").assertExists()
    }

    @Test
    fun wrongPinShowsAttemptsLeftAndLeavesTheKeysAlone() {
        val core = FakeSecureCore(CoreState(CoreAvailability.READY, pinConfigured = true, locked = true))
        core.presetPins("abcdefghij", "klmnopqrst")
        val host = InputHost()
        rule.setContent { Harness(AppLanguage.EN, host) { UnlockScreen(core, core.state.value, onDuress = {}) } }
        typeText("zzzzzzzzzz")
        rule.onNodeWithText("Unlock").performClick()
        rule.waitForIdle()
        assertFalse(core.keysDestroyed)
        assertEquals(4, core.state.value.attemptsLeft)
        assertTrue(core.state.value.locked)
    }

    @Test
    fun emergencyPinDestroysKeysAndShowsNothing() {
        val core = FakeSecureCore(CoreState(CoreAvailability.READY, pinConfigured = true, locked = true))
        core.presetPins("abcdefghij", "klmnopqrst")
        val host = InputHost()
        var closed = false
        rule.setContent { Harness(AppLanguage.EN, host) { UnlockScreen(core, core.state.value, onDuress = { closed = true }) } }
        typeText("klmnopqrst")
        rule.onNodeWithText("Unlock").performClick()
        rule.waitForIdle()
        assertTrue(closed)
        assertTrue(core.keysDestroyed)
        assertEquals(0, textNodes("Wrong PIN").size)
    }

    @Test
    fun pinChangeWizardRejectsWrongCurrentAndSavesNewPins() {
        val core = FakeSecureCore(CoreState(CoreAvailability.READY, pinConfigured = true, locked = false))
        core.presetPins("abcdefghij", "klmnopqrst")
        val host = InputHost()
        var finished = false
        rule.setContent {
            Harness(AppLanguage.EN, host) { PinWizardScreen(PinMode.CHANGE, core, onFinished = { finished = true }, onBack = {}) }
        }
        // Wrong current PIN: caught on save, returns to step 1.
        typeText("wrongcurre")
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()
        typeText("mnopqrstuv")
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()
        typeText("mnopqrstuv")
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()
        typeText("pqrstuvwxy")
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()
        typeText("pqrstuvwxy")
        rule.onNodeWithText("Save PINs").assertIsEnabled().performClick()
        rule.waitForIdle()
        assertFalse(finished)
        rule.onNodeWithText("The current PIN is wrong.").assertExists()

        // Correct current PIN: updates both PINs and finishes.
        typeText("abcdefghij")
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()
        typeText("mnopqrstuv")
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()
        typeText("mnopqrstuv")
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()
        typeText("pqrstuvwxy")
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()
        typeText("pqrstuvwxy")
        rule.onNodeWithText("Save PINs").assertIsEnabled().performClick()
        rule.waitForIdle()
        assertTrue(finished)
        assertEquals("mnopqrstuv", core.normalPin)
        assertEquals("pqrstuvwxy", core.duressPin)
    }

    /** One pass through the change wizard: current PIN, new PIN twice, emergency PIN twice, save. */
    private fun submitPinChange(current: String, normal: String, duress: String) {
        typeText(current)
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()
        typeText(normal)
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()
        typeText(normal)
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()
        typeText(duress)
        rule.onNodeWithText("Continue").assertIsEnabled().performClick()
        typeText(duress)
        rule.onNodeWithText("Save PINs").assertIsEnabled().performClick()
        rule.waitForIdle()
    }

    @Test
    fun pinChangeWizardLocksAfterTheThirdWrongCurrentPin() {
        val core = FakeSecureCore(CoreState(CoreAvailability.READY, pinConfigured = true, locked = false))
        core.presetPins("abcdefghij", "klmnopqrst")
        val host = InputHost()
        var finished = false
        rule.setContent {
            Harness(AppLanguage.EN, host) { PinWizardScreen(PinMode.CHANGE, core, onFinished = { finished = true }, onBack = {}) }
        }
        repeat(2) {
            submitPinChange("wrongcurre", "mnopqrstuv", "pqrstuvwxy")
            rule.onNodeWithText("The current PIN is wrong.").assertExists()
            assertFalse(core.state.value.locked)
        }
        submitPinChange("wrongcurre", "mnopqrstuv", "pqrstuvwxy")
        assertTrue(core.state.value.locked)
        assertFalse(finished)
        assertFalse(core.keysDestroyed)
        assertEquals("abcdefghij", core.normalPin)
    }

    @Test
    fun emergencyPinAsTheCurrentPinDestroysKeysAndClosesLikeTheUnlockScreen() {
        val core = FakeSecureCore(CoreState(CoreAvailability.READY, pinConfigured = true, locked = false))
        core.presetPins("abcdefghij", "klmnopqrst")
        val host = InputHost()
        var finished = false
        var closed = false
        rule.setContent {
            Harness(AppLanguage.EN, host) {
                PinWizardScreen(PinMode.CHANGE, core, onFinished = { finished = true }, onBack = {}, onDuress = { closed = true })
            }
        }
        submitPinChange("klmnopqrst", "mnopqrstuv", "pqrstuvwxy")
        assertTrue(closed)
        assertFalse(finished)
        assertTrue(core.keysDestroyed)
        assertTrue(core.state.value.locked)
        assertEquals(0, textNodes("The current PIN is wrong.").size)
    }

    private fun textNodes(text: String) = rule.onAllNodes(hasText(text, substring = true)).fetchSemanticsNodes()

    // ---- session screens ----------------------------------------------------------------

    @Test
    fun unverifiedPeerIsLabelledUnverifiedAndNotAsVerified() {
        val core = FakeSecureCore(FakeScenarios.unlocked, FakeScenarios.contacts, FakeScenarios.chatUnknown)
        val host = InputHost()
        rule.setContent { Harness(AppLanguage.EN, host) { ChatScreen(FakeScenarios.chatUnknown, core) } }
        rule.onNodeWithText("Encrypted \u00B7 identity not verified").assertExists()
        rule.onNodeWithText("Compare words").assertExists()
        assertEquals(0, textNodes("Verified").size)
    }

    private fun connectingDump(language: AppLanguage): String {
        val host = InputHost()
        val state = FakeScenarios.connecting(ConnectStep.KEY_EXCHANGE, 55, 18, FakeScenarios.ana)
        rule.setContent { Harness(language, host) { ConnectingScreen(state, onCancel = {}) } }
        return rule.onRoot().printToString(Int.MAX_VALUE).lowercase()
    }

    private val forbiddenBeforeLink = Regex("encrypt|secur|cifr|segur|chiffr|s\u00E9cur|verified|verific|v\u00E9rifi")

    @Test
    fun noEncryptionWordsAppearWhileConnectingEnglish() {
        val dump = connectingDump(AppLanguage.EN)
        assertTrue(dump.contains("about 18 s left"))
        assertFalse(forbiddenBeforeLink.find(dump)?.value, forbiddenBeforeLink.containsMatchIn(dump))
    }

    @Test
    fun noEncryptionWordsAppearWhileConnectingSpanish() {
        val dump = connectingDump(AppLanguage.ES)
        assertTrue(dump.contains("quedan unos 18 s"))
        assertFalse(forbiddenBeforeLink.find(dump)?.value, forbiddenBeforeLink.containsMatchIn(dump))
    }

    @Test
    fun noEncryptionWordsAppearWhileConnectingFrench() {
        val dump = connectingDump(AppLanguage.FR)
        assertTrue(dump.contains("environ 18 s restantes"))
        assertFalse(forbiddenBeforeLink.find(dump)?.value, forbiddenBeforeLink.containsMatchIn(dump))
    }

    @Test
    fun droppedAfterEstablishedShowsCallEndedNotNothingSent() {
        val host = InputHost()
        rule.setContent {
            Harness(AppLanguage.EN, host) {
                io.github.h4lovoid.dialcrypt.ui.screens.AbortedScreen(
                    io.github.h4lovoid.dialcrypt.core.SessionFailure.CALL_DROPPED, onDone = {}, wasEstablished = true,
                )
            }
        }
        rule.onNodeWithText("The call has ended.").assertExists()
        assertEquals(0, textNodes("Nothing was sent").size)
        assertEquals(0, textNodes("The call was dropped.").size)
    }

    @Test
    fun keyChangeScreenOffersOnlyCompareAgainAndHangUp() {
        val core = FakeSecureCore(FakeScenarios.unlocked, FakeScenarios.contacts, FakeScenarios.keyChanged)
        val host = InputHost()
        var rematch = 0
        var hangUp = 0
        rule.setContent { Harness(AppLanguage.EN, host) { KeyChangedScreen({ rematch++ }, { hangUp++ }) } }
        rule.onNodeWithText("The other side\u2019s key has changed").assertExists()
        assertEquals(2, rule.onAllNodes(hasClickAction().and(isEnabled())).fetchSemanticsNodes().size)
        assertEquals(0, rule.onAllNodesWithTag("chat_input").fetchSemanticsNodes().size)
        rule.onNodeWithText("Compare again").performClick()
        rule.onNodeWithText("Hang up").performClick()
        assertEquals(1, rematch)
        assertEquals(1, hangUp)
        // The core itself also refuses to send.
        assertEquals(SendResult.BLOCKED_KEY_CHANGED, core.sendText("hello"))
    }

    @Test
    fun sendingControlsAreDisabledWhileTheKeyIsChanged() {
        val state = FakeScenarios.chatContactPq.copy(identity = io.github.h4lovoid.dialcrypt.core.IdentityStatus.KEY_CHANGED, messages = emptyList())
        val core = FakeSecureCore(FakeScenarios.unlocked, FakeScenarios.contacts, state)
        val host = InputHost()
        rule.setContent { Harness(AppLanguage.EN, host) { ChatScreen(state, core) } }
        rule.onNodeWithContentDescription("Send").assertIsNotEnabled()
        rule.onNodeWithText("Yes").assertIsNotEnabled()
        rule.onNodeWithText("Understood").assertIsNotEnabled()
    }

    @Test
    fun sendingWorksWhenTheLinkIsEstablished() {
        val core = FakeSecureCore(FakeScenarios.unlocked, FakeScenarios.contacts, FakeScenarios.chatUnknown.copy(messages = emptyList()))
        val host = InputHost()
        rule.setContent {
            val state by core.session.collectAsState()
            Harness(AppLanguage.EN, host) { ChatScreen(state, core) }
        }
        rule.onNodeWithTag("chat_input").performClick()
        typeText("hi")
        rule.onNodeWithContentDescription("Send").assertIsEnabled().performClick()
        rule.waitForIdle()
        assertEquals(1, core.session.value.messages.size)
        rule.onNodeWithText("hi").assertExists()
    }

    // ---- contacts -----------------------------------------------------------------------

    @Test
    fun contactListShowsOneStatusPerCardAndKeepsPairingAndHardwareOut() {
        val host = InputHost()
        var opened = -1L
        rule.setContent {
            Harness(AppLanguage.EN, host) { HomeScreen(FakeScenarios.contacts, onOpenContact = { opened = it }, onStartCall = {}, onSettings = {}) }
        }
        // Ana, Marc and the courier are verified; Sam is not; Lucia's key changed.
        assertEquals(3, textNodes("Verified").size)
        assertEquals(1, textNodes("Not verified").size)
        assertEquals(1, textNodes("Key changed").size)
        assertEquals(1, textNodes("Quick connect").size)
        listOf("Paired", "Hardware", "StrongBox", "locked", "rebuilt").forEach { assertEquals(it, 0, textNodes(it).size) }
        // The card itself is the touch target.
        rule.onNodeWithTag("contact_1").assertHeightIsAtLeast(64.dp).performClick()
        assertEquals(1L, opened)
    }

    private val maskedAna = "\u2022\u2022\u2022\u2022 3456"

    @Test
    fun contactListShowsOnlyTheLastFourDigitsOfEachNumber() {
        val host = InputHost()
        rule.setContent {
            Harness(AppLanguage.EN, host) { HomeScreen(FakeScenarios.contacts, onOpenContact = {}, onStartCall = {}, onSettings = {}) }
        }
        rule.onNodeWithText(maskedAna).assertExists()
        rule.onNodeWithText("\u2022\u2022\u2022\u2022 5678").assertExists()
        assertEquals(0, textNodes("+34600123456").size)
        assertEquals(0, textNodes("600123456").size)
        // A contact without a number keeps the plain label.
        rule.onNodeWithText("Hidden number").assertExists()
    }

    @Test
    fun dialScreenContactListShowsOnlyTheLastFourDigitsOfEachNumber() {
        val host = InputHost()
        rule.setContent {
            Harness(AppLanguage.EN, host) { DialScreen(FakeScenarios.contacts, onCallContact = {}, onCallNumber = {}, onBack = {}) }
        }
        rule.onNodeWithText(maskedAna).assertExists()
        assertEquals(0, textNodes("+34600123456").size)
    }

    @Test
    fun contactDetailStillShowsTheFullNumber() {
        val core = FakeSecureCore(FakeScenarios.unlocked, FakeScenarios.contacts)
        val host = InputHost()
        rule.setContent { Harness(AppLanguage.EN, host) { ContactDetailScreen(FakeScenarios.ana, core, {}, {}, {}, {}) } }
        assertEquals(1, textNodes("+34600123456").size)
    }

    @Test
    fun connectingScreenMasksThePeerNumberUntilTheIndexPlacesIt() {
        val host = InputHost()
        val state = FakeScenarios.connecting(ConnectStep.KEY_EXCHANGE, 55, 18)
        rule.setContent { Harness(AppLanguage.EN, host) { ConnectingScreen(state, onCancel = {}) } }
        rule.onNodeWithText("Calling \u2022\u2022\u2022\u2022 0199").assertExists()
        assertEquals(0, textNodes("+14155550199").size)
    }

    @Test
    fun connectingScreenShowsTheWholeNumberOfAPeerWhoIsNotAContact() {
        val host = InputHost()
        val state = FakeScenarios.connecting(ConnectStep.KEY_EXCHANGE, 55, 18)
        rule.setContent {
            Harness(AppLanguage.EN, host) {
                androidx.compose.runtime.CompositionLocalProvider(
                    io.github.h4lovoid.dialcrypt.ui.model.LocalContactLookup provides { io.github.h4lovoid.dialcrypt.core.ContactMembership.NOT_CONTACT },
                    // The lookup runs inline, so the answer needs no other thread and no waiting on the clock.
                    io.github.h4lovoid.dialcrypt.ui.model.LocalContactLookupDispatcher provides kotlinx.coroutines.Dispatchers.Unconfined,
                ) { ConnectingScreen(state, onCancel = {}) }
            }
        }
        rule.waitForIdle()
        rule.onNodeWithText("Calling +14155550199").assertExists()
        assertEquals(0, textNodes("Calling \u2022\u2022\u2022\u2022 0199").size)
    }

    @Test
    fun connectingScreenMasksAContactPeerNumber() {
        val host = InputHost()
        val state = FakeScenarios.connecting(ConnectStep.KEY_EXCHANGE, 55, 18)
        rule.setContent {
            Harness(AppLanguage.EN, host) {
                androidx.compose.runtime.CompositionLocalProvider(
                    io.github.h4lovoid.dialcrypt.ui.model.LocalContactLookup provides { io.github.h4lovoid.dialcrypt.core.ContactMembership.CONTACT },
                    io.github.h4lovoid.dialcrypt.ui.model.LocalContactLookupDispatcher provides kotlinx.coroutines.Dispatchers.Unconfined,
                ) { ConnectingScreen(state, onCancel = {}) }
            }
        }
        rule.waitForIdle()
        rule.onNodeWithText("Calling \u2022\u2022\u2022\u2022 0199").assertExists()
        assertEquals(0, textNodes("+14155550199").size)
    }

    @Test
    fun appListsShowOnlyTheLastFourDigitsByDefault() {
        appRoot(unlockedCore())
        rule.onNodeWithText(maskedAna).assertExists()
        assertEquals(0, textNodes("+34600123456").size)
    }

    @Test
    fun turningOnFullNumbersInSettingsShowsWholeNumbersInTheList() {
        appRoot(unlockedCore())
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithText(
            "Off: contact numbers show only the last four digits. Other numbers always show in full, and the lock screen always masks contact numbers.",
        ).performScrollTo()
        rule.onNodeWithText("Show full numbers of contacts").performClick()
        rule.waitForIdle()

        pressBack()
        rule.onNodeWithText("Search contacts").assertExists()
        rule.onNodeWithText("+34600123456").assertExists()
        assertEquals(0, textNodes(maskedAna).size)
    }

    @Test
    fun fullNumbersPreferenceIsStillOnWhenReadAgain() {
        val store = rule.activity.getSharedPreferences("full_numbers_test", android.content.Context.MODE_PRIVATE)
        store.edit().clear().commit()
        val first = SharedPrefsUiPreferences(store)
        assertFalse(first.showFullNumbers.value)
        first.setShowFullNumbers(true)
        assertTrue(SharedPrefsUiPreferences(store).showFullNumbers.value)
        store.edit().clear().commit()
    }

    @Test
    fun contactDetailNamesHardwareInPlainWordsWithTheTermInTheNote() {
        val core = FakeSecureCore(FakeScenarios.unlocked, FakeScenarios.contacts)
        val host = InputHost()
        val ana = FakeScenarios.ana.copy(mutual = true)
        rule.setContent { Harness(AppLanguage.EN, host) { ContactDetailScreen(ana, core, {}, {}, {}, {}) } }
        rule.onNodeWithText("Phone is locked and verified").assertExists()
        assertEquals(1, textNodes("StrongBox \u00B7 locked:").size)
        rule.onNodeWithText("Paired").assertExists()
        rule.onNodeWithText("Waiting for them to add you").assertDoesNotExist()
    }

    @Test
    fun contactDetailSaysItWaitsForThemWhenOnlyWeSavedThem() {
        val core = FakeSecureCore(FakeScenarios.unlocked, FakeScenarios.contacts)
        val host = InputHost()
        val ana = FakeScenarios.ana.copy(mutual = false)
        rule.setContent { Harness(AppLanguage.EN, host) { ContactDetailScreen(ana, core, {}, {}, {}, {}) } }
        rule.onNodeWithText("Waiting for them to add you").assertExists()
        rule.onNodeWithText("You both need to add each other", substring = true).assertExists()
        rule.onNodeWithText("Paired").assertDoesNotExist()
    }

    // ---- launcher start screen ----------------------------------------------------------

    private fun launcherRoot(lockdown: FakeLockdownController, fastHandoff: Boolean = false, onReady: () -> Unit = {}) {
        rule.setContent {
            LauncherRoot(lockdown, InMemoryUiPreferences(AppLanguage.EN), onReady = onReady, fastHandoff = fastHandoff)
        }
    }

    @Test
    fun launcherShowsOnlyAStartButtonAndDoesNotPrepareByItself() {
        val lockdown = FakeLockdownController()
        launcherRoot(lockdown)
        rule.waitForIdle()
        rule.onNodeWithText("Start").assertExists()
        rule.onNodeWithText("Tap Start to continue.").assertExists()
        rule.onNodeWithText("Getting ready").assertDoesNotExist()
        assertEquals(0, lockdown.prepareCalls)
    }

    @Test
    fun tappingStartPreparesOnceAndShowsTheChecklist() {
        val lockdown = FakeLockdownController()
        launcherRoot(lockdown)
        rule.onNodeWithText("Start").performClick()
        rule.waitForIdle()
        assertEquals(1, lockdown.prepareCalls)
        rule.onNodeWithText("Getting ready").assertExists()
        rule.onNodeWithText("Start").assertDoesNotExist()
    }

    @Test
    fun launcherWithoutATrustedHandoffNeverReachesReadyOnItsOwn() {
        var ready = 0
        launcherRoot(FakeLockdownController(), onReady = { ready++ })
        rule.waitForIdle()
        assertEquals(0, ready)
    }

    @Test
    fun aTrustedCallHandoffSkipsTheStartScreen() {
        val lockdown = FakeLockdownController(FakeScenarios.lockdown(done = 2))
        launcherRoot(lockdown, fastHandoff = true)
        rule.waitForIdle()
        rule.onNodeWithText("Start").assertDoesNotExist()
        rule.onNodeWithText("Getting ready").assertExists()
        assertEquals(0, lockdown.prepareCalls)
    }

    @Test
    fun backOnTheStartScreenLeaves() {
        launcherRoot(FakeLockdownController())
        pressBack()
        assertTrue(rule.activity.isFinishing)
    }

    @Test
    fun backWhilePreparingIsSwallowed() {
        launcherRoot(FakeLockdownController(FakeScenarios.lockdown(done = 2)))
        pressBack()
        assertFalse(rule.activity.isFinishing)
    }

    // ---- system back --------------------------------------------------------------------

    /** The system back key, delivered the way the activity would. Waits until screen transitions are over. */
    private fun pressBack() {
        rule.runOnUiThread { rule.activity.onBackPressedDispatcher.onBackPressed() }
        rule.waitForIdle()
    }

    private fun appRoot(core: FakeSecureCore, onExit: () -> Unit = {}) {
        rule.setContent {
            AppRoot(core, FakeLockdownController(FakeScenarios.lockdownReady()), InMemoryUiPreferences(AppLanguage.EN), onExit = onExit)
        }
    }

    private fun unlockedCore(session: io.github.h4lovoid.dialcrypt.core.SessionState = io.github.h4lovoid.dialcrypt.core.SessionState()) =
        FakeSecureCore(FakeScenarios.unlocked, FakeScenarios.contacts, session)

    private fun keyboardOpen() = rule.onAllNodesWithTag("key_a").fetchSemanticsNodes().isNotEmpty() ||
        rule.onAllNodesWithTag("key_4").fetchSemanticsNodes().isNotEmpty()

    @Test
    fun backFromASubScreenGoesUpOneLevelAtATime() {
        var exits = 0
        appRoot(unlockedCore()) { exits++ }
        rule.onNodeWithContentDescription("Settings").performClick()
        rule.onNodeWithText("About and licenses").performScrollTo().performClick()
        rule.waitForIdle()
        rule.onNodeWithText("Licenses").assertExists()

        pressBack()
        rule.onNodeWithText("Licenses").assertDoesNotExist()
        rule.onNodeWithText("Language").assertExists()

        pressBack()
        rule.onNodeWithText("Language").assertDoesNotExist()
        rule.onNodeWithText("Search contacts").assertExists()
        assertEquals(0, exits)
        assertFalse(rule.activity.isFinishing)
    }

    @Test
    fun backOnTheHomeScreenLeavesOnlyThroughTheSafeExit() {
        var exits = 0
        appRoot(unlockedCore()) { exits++ }
        pressBack()
        assertEquals(1, exits)
        // The app asked to exit; the system did not end the activity by itself.
        assertFalse(rule.activity.isFinishing)
    }

    @Test
    fun backClosesTheKeyboardBeforeItLeavesTheScreen() {
        var exits = 0
        appRoot(unlockedCore()) { exits++ }
        rule.onNodeWithText("Call").performClick()
        rule.onNodeWithTag("dial_number").performClick()
        assertTrue(keyboardOpen())

        pressBack()
        assertFalse(keyboardOpen())
        rule.onNodeWithText("Secure call").assertExists()

        pressBack()
        rule.onNodeWithText("Secure call").assertDoesNotExist()
        assertEquals(0, exits)
    }

    @Test
    fun unlockScreenClosesTheKeyboardFirstAndThenExitsSafely() {
        val core = FakeSecureCore(CoreState(CoreAvailability.READY, pinConfigured = true, locked = true))
        var exits = 0
        appRoot(core) { exits++ }
        rule.waitForIdle()
        assertTrue(keyboardOpen())
        pressBack()
        assertFalse(keyboardOpen())
        assertEquals(0, exits)
        pressBack()
        assertEquals(1, exits)
        assertFalse(rule.activity.isFinishing)
    }

    @Test
    fun backIsIgnoredOnTheDestroyedScreen() {
        val core = FakeSecureCore(
            CoreState(CoreAvailability.READY, pinConfigured = true, locked = true, attemptsLeft = 0, vaultDestroyed = true),
        )
        var exits = 0
        appRoot(core) { exits++ }
        pressBack()
        assertEquals(0, exits)
        assertFalse(rule.activity.isFinishing)
        rule.onNodeWithText("Locked for good").assertExists()
    }

    @Test
    fun backWhileConnectingAsksBeforeHangingUp() {
        val core = unlockedCore(FakeScenarios.connecting(ConnectStep.WAIT_PEER, 12, 36))
        var exits = 0
        appRoot(core) { exits++ }
        val before = core.session.value
        pressBack()
        rule.onNodeWithText("Hang up?").assertExists()
        assertEquals(before, core.session.value)
        assertEquals(0, exits)
        assertFalse(rule.activity.isFinishing)
        rule.onNodeWithText("Cancel").performClick()
        rule.onNodeWithText("Hang up?").assertDoesNotExist()
        assertEquals(before, core.session.value)
    }

    @Test
    fun backWhileComparingWordsAsksBeforeHangingUp() {
        val core = unlockedCore(FakeScenarios.withSas(FakeScenarios.chatUnknown))
        var exits = 0
        appRoot(core) { exits++ }
        val before = core.session.value
        pressBack()
        rule.onNodeWithText("Hang up?").assertExists()
        assertEquals(before, core.session.value)
        assertEquals(0, exits)
        assertFalse(rule.activity.isFinishing)
    }

    @Test
    fun backInTheChatClosesTheKeyboardThenAsksBeforeEnding() {
        val core = unlockedCore(FakeScenarios.chatUnknown)
        var exits = 0
        appRoot(core) { exits++ }
        val before = core.session.value
        rule.onNodeWithTag("chat_input").performClick()
        assertTrue(keyboardOpen())

        pressBack()
        assertFalse(keyboardOpen())
        rule.onNodeWithText("End and clear?").assertDoesNotExist()

        pressBack()
        rule.onNodeWithText("End and clear?").assertExists()
        assertEquals(before, core.session.value)
        assertEquals(0, exits)
        assertFalse(rule.activity.isFinishing)
    }

    @Test
    fun pinWizardBackGoesToThePreviousStepLikeTheArrow() {
        val core = FakeSecureCore(CoreState(CoreAvailability.READY))
        val host = InputHost()
        rule.setContent { Harness(AppLanguage.EN, host) { PinWizardScreen(PinMode.SETUP, core, {}, null) } }
        typeText("abcdefghij")
        rule.onNodeWithText("Continue").performClick()
        rule.onNodeWithText("Enter it again").assertExists()

        pressBack()
        rule.onNodeWithText("Enter it again").assertExists()
        assertFalse(keyboardOpen())
        pressBack()
        rule.onNodeWithText("Choose your PIN").assertExists()
        assertFalse(rule.activity.isFinishing)
    }
}
