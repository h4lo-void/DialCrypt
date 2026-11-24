package io.github.h4lovoid.dialcrypt

import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.ContextWrapper
import android.graphics.Bitmap
import android.graphics.Canvas
import android.view.View
import android.view.WindowManager
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.core.app.ApplicationProvider
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import io.github.h4lovoid.dialcrypt.core.AppLanguage
import io.github.h4lovoid.dialcrypt.core.CoreAvailability
import io.github.h4lovoid.dialcrypt.core.CoreState
import io.github.h4lovoid.dialcrypt.core.FakeScenarios
import io.github.h4lovoid.dialcrypt.core.FakeSecureCore
import io.github.h4lovoid.dialcrypt.core.InviteCard
import io.github.h4lovoid.dialcrypt.core.PairingCodeCodec
import io.github.h4lovoid.dialcrypt.core.PairingPreview
import io.github.h4lovoid.dialcrypt.core.PairingResult
import io.github.h4lovoid.dialcrypt.core.SecureCore
import io.github.h4lovoid.dialcrypt.ui.model.TextMaps
import io.github.h4lovoid.dialcrypt.ui.keyboard.InputHost
import io.github.h4lovoid.dialcrypt.ui.screens.AddContactScreen
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/**
 * Compose flow tests for the add-contact page: cards are exchanged by showing and scanning QR codes
 * (the scanner reads the QR code actually drawn on the other screen), names are cleaned, a tagged
 * reply finishes the exchange, remote cards still need the code check, and the clipboard is cleaned up.
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "w411dp-h891dp-xxhdpi")
class AddContactFlowTest {
    @get:Rule
    val rule = createComposeRule()

    private val context: Context = ApplicationProvider.getApplicationContext()
    // The clipboard service of the very context the screen runs in (Robolectric keeps one clip per service object).
    private lateinit var clipboard: ClipboardManager
    private lateinit var screenView: View
    private var visible by mutableStateOf(true)

    private fun str(id: Int): String = context.getString(id)

    @Before
    fun grantDialogPermission() {
        // SecureDialog hides overlay windows, which needs this permission.
        shadowOf(context as android.app.Application).grantPermissions("android.permission.HIDE_OVERLAY_WINDOWS")
    }

    /** Stands in for the camera: the test hands it the text of a QR code it "sees". */
    private class FakeCamera {
        var onText: ((String) -> Boolean)? = null
        val scanner: @Composable ((String) -> Boolean) -> Unit = { callback ->
            SideEffect { onText = callback }
            DisposableEffect(Unit) { onDispose { onText = null } }
            Box(Modifier.testTag("fake_camera"))
        }
    }

    /** Fake core with a valid own pairing code that records saved contacts and the cards it makes. */
    private class SpyCore(
        val inner: FakeSecureCore = FakeSecureCore(CoreState(CoreAvailability.READY, pinConfigured = true, locked = false)),
    ) : SecureCore by inner {
        var ownCode = OWN_CODE
        val added = mutableListOf<Triple<String, String?, String>>()
        /** The mutual flag of each save, in order. */
        val mutualFlags = mutableListOf<Boolean>()
        val made = mutableListOf<InviteCard>()
        var rotations = 0
        /** What the core says saving a card would do. */
        var preview: PairingPreview = PairingPreview.New
        var rotateFails = false

        override suspend fun previewPairing(code: String): PairingPreview = preview

        override suspend fun addPairedContact(name: String, number: String?, code: String, mutual: Boolean): PairingResult {
            added += Triple(name, number, code)
            mutualFlags += mutual
            return inner.addPairedContact(name, number, code, mutual)
        }

        override suspend fun ownPairingCode(): String? = ownCode

        override suspend fun rotatePairingCode(): String? {
            rotations++
            if (rotateFails) return null
            ownCode = ROTATED_CODE
            return ownCode
        }

        override suspend fun ownInviteCard(name: String, number: String?): InviteCard? =
            InviteCard(name.trim(), number, ownCode, InviteCard.newNonce()).also { made += it }
    }

    private fun show(core: SecureCore, camera: FakeCamera = FakeCamera(), onAdded: () -> Unit = {}) {
        val host = InputHost()
        rule.setContent {
            Harness(AppLanguage.EN, host) {
                clipboard = LocalContext.current.getSystemService(ClipboardManager::class.java)
                screenView = LocalView.current
                if (visible) AddContactScreen(core, onBack = {}, onAdded = onAdded, scanner = camera.scanner)
            }
        }
        rule.waitForIdle()
    }

    private fun tap(text: String) {
        rule.onNodeWithText(text).performScrollTo().performClick()
        rule.waitForIdle()
    }

    /** For dialog buttons, which are not inside the scrolling page. */
    private fun tapDialog(text: String) {
        rule.onNodeWithText(text).performClick()
        rule.waitForIdle()
    }

    private fun typeKeys(text: String) {
        text.forEach { c -> rule.onNodeWithTag(if (c == ' ') "key_space" else "key_$c").performClick() }
        rule.onNodeWithTag("key_done").performClick()
        rule.waitForIdle()
    }

    private fun typeInto(tag: String, text: String) {
        rule.onNodeWithTag(tag).performScrollTo().performClick()
        typeKeys(text)
    }

    /** Points the fake camera at a QR code holding [text]; returns whether the page took it. */
    private fun point(camera: FakeCamera, text: String): Boolean {
        var used = false
        rule.runOnIdle { used = checkNotNull(camera.onText) { "the camera is not open" }(text) }
        rule.waitForIdle()
        return used
    }

    private fun scanCard(camera: FakeCamera, card: InviteCard) {
        tap(str(R.string.add_scan_qr))
        assertTrue(point(camera, card.toTextCard()!!))
    }

    /** Reads the QR code drawn on screen, pixel by pixel, with the decoder the camera uses. */
    private fun readQr(node: SemanticsNodeInteraction): String {
        node.performScrollTo()
        rule.waitForIdle()
        val bounds = node.fetchSemanticsNode().boundsInRoot
        lateinit var bmp: Bitmap
        // Draws the page into a bitmap (window capture never finishes under Robolectric) and cuts out the code.
        rule.runOnIdle {
            val full = Bitmap.createBitmap(screenView.width, screenView.height, Bitmap.Config.ARGB_8888)
            screenView.draw(Canvas(full))
            val left = bounds.left.toInt().coerceIn(0, full.width - 1)
            val top = bounds.top.toInt().coerceIn(0, full.height - 1)
            val width = bounds.width.toInt().coerceAtMost(full.width - left)
            val height = bounds.height.toInt().coerceAtMost(full.height - top)
            bmp = Bitmap.createBitmap(full, left, top, width, height)
        }
        val pixels = IntArray(bmp.width * bmp.height)
        bmp.getPixels(pixels, 0, bmp.width, 0, 0, bmp.width, bmp.height)
        val source = RGBLuminanceSource(bmp.width, bmp.height, pixels)
        val hints = mapOf(DecodeHintType.TRY_HARDER to true)
        // Same two passes as the scanner: local thresholds first, one global threshold for large close-up codes.
        return runCatching { QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), hints).text }
            .getOrElse { QRCodeReader().decode(BinaryBitmap(GlobalHistogramBinarizer(source)), hints).text }
    }

    private fun shownCard(): InviteCard = InviteCard.parse(readQr(rule.onNodeWithTag("add_my_qr")))!!

    private fun textOf(node: SemanticsNodeInteraction): String =
        node.fetchSemanticsNode().config[SemanticsProperties.Text].joinToString("") { it.text }

    private fun brightness(): Float {
        var ctx: Context? = screenView.context
        while (ctx is ContextWrapper && ctx !is Activity) ctx = ctx.baseContext
        return (ctx as Activity).window.attributes.screenBrightness
    }

    // ---- 1. a scanned card is saved by name, without a confirmation code -----------------------------

    @Test
    fun aScannedCardShowsTheNameAndIsSavedWithoutAConfirmationCode() {
        val card = InviteCard("Alice", "5551234567", code(1), 5L)
        val core = SpyCore()
        val camera = FakeCamera()
        var added = 0
        show(core, camera, onAdded = { added++ })

        scanCard(camera, card)

        assertEquals("nothing may be saved before the user saves", 0, core.added.size)
        rule.onNodeWithText(str(R.string.add_scanned_title)).assertExists()
        rule.onNodeWithTag("add_peer_name").assertTextContains("Alice")
        rule.onNodeWithTag("add_peer_number").assertTextContains("5551234567")
        // Their confirmation code is there to compare if they like; saving does not ask for it.
        rule.onNodeWithTag("add_peer_code").assertTextEquals(card.fingerprint()!!)
        rule.onNodeWithText(str(R.string.add_scanned_code_hint)).assertExists()
        rule.onNodeWithTag("fake_camera").assertDoesNotExist()

        tap(str(R.string.action_save))

        val (name, number, savedCode) = core.added.single()
        assertEquals("Alice", name)
        assertEquals("5551234567", number)
        assertEquals(card.code, savedCode)
        assertEquals(listOf("Alice"), core.inner.contacts.value.map { it.name })
        // Nothing proves Alice saved us yet: the contact waits for her instead of showing as paired.
        assertEquals(listOf(false), core.mutualFlags)
        assertFalse(core.inner.contacts.value.single().mutual)

        // Alice never showed a card tagged for ours, so our tagged card goes up for her to scan.
        rule.onNodeWithText(str(R.string.add_qr_your_turn)).assertExists()
        rule.onNodeWithText(str(R.string.add_reply_paired_later)).assertExists()
        rule.onNodeWithText(str(R.string.add_both_done)).assertDoesNotExist()
        val ours = shownCard()
        assertEquals(OWN_CODE, ours.code)
        assertTrue("our card tells her phone that we saved hers", InviteCard.answers(ours, card))

        assertEquals(0, added)
        tap(str(R.string.add_done))
        assertEquals(1, added)
    }

    @Test
    fun aQrCodeThatIsNotACardIsReportedAndScanningGoesOn() {
        val core = SpyCore()
        val camera = FakeCamera()
        show(core, camera)
        tap(str(R.string.add_scan_qr))

        assertFalse(point(camera, "https://example.com/menu"))
        rule.onNodeWithText(str(R.string.add_scan_not_card)).assertExists()
        rule.onNodeWithTag("fake_camera").assertExists()
        // A bare pairing code or a broken card is not a card from this app either.
        assertFalse(point(camera, code(1)))
        assertFalse(point(camera, "AEGISCARD1:not-a-card"))
        rule.onNodeWithText(str(R.string.add_scanned_title)).assertDoesNotExist()

        assertTrue(point(camera, InviteCard("Alice", null, code(1), 1L).toTextCard()!!))
        rule.onNodeWithText(str(R.string.add_scanned_title)).assertExists()
        rule.onNodeWithText(str(R.string.add_scan_not_card)).assertDoesNotExist()
        assertEquals(0, core.added.size)
    }

    // ---- 2. discard ---------------------------------------------------------------------------------

    @Test
    fun discardSavesNothingReturnsToStartAndClearsTheNameField() {
        val core = SpyCore()
        val camera = FakeCamera()
        show(core, camera)

        scanCard(camera, InviteCard("Alice", null, code(1), 1L))
        rule.onNodeWithTag("add_peer_name").assertTextContains("Alice")
        tap(str(R.string.add_discard))

        assertEquals(0, core.added.size)
        assertTrue(core.inner.contacts.value.isEmpty())
        rule.onNodeWithText(str(R.string.add_scanned_title)).assertDoesNotExist()
        rule.onNodeWithText(str(R.string.add_discarded)).assertExists()
        rule.onNodeWithText(str(R.string.add_show_qr)).assertExists()

        // The next card has no name: the old one must not be left in the field, so saving stays off.
        scanCard(camera, InviteCard("", null, code(2), 2L))
        rule.onNodeWithText("Alice").assertDoesNotExist()
        rule.onNodeWithText(str(R.string.action_save)).assertIsNotEnabled()
        assertEquals(0, core.added.size)
    }

    // ---- 3. names are cleaned -----------------------------------------------------------------------

    @Test
    fun directionOverridesAndControlCharactersAreRemovedFromTheSavedName() {
        val core = SpyCore()
        val camera = FakeCamera()
        show(core, camera)

        scanCard(camera, InviteCard("\u202Eevil\u200B.exe\u0007", null, code(3), 3L))
        tap(str(R.string.action_save))

        assertEquals("evil.exe", core.added.single().first)
        assertEquals(listOf("evil.exe"), core.inner.contacts.value.map { it.name })
    }

    @Test
    fun privateUseAndUnassignedCharactersAreRemovedFromTheSavedName() {
        val core = SpyCore()
        val camera = FakeCamera()
        show(core, camera)

        scanCard(camera, InviteCard("A\u202E\uE000\u0378B", null, code(3), 3L))
        tap(str(R.string.action_save))
        assertEquals("AB", core.added.single().first)
    }

    @Test
    fun aNameThatCleansToNothingCannotBeSaved() {
        val core = SpyCore()
        val camera = FakeCamera()
        show(core, camera)

        scanCard(camera, InviteCard("\u202E\u200B\u0007", null, code(4), 4L))
        rule.onNodeWithText(str(R.string.action_save)).assertIsNotEnabled()
        assertEquals(0, core.added.size)
    }

    @Test
    fun aClearedNumberFieldIsSavedWithoutANumber() {
        val core = SpyCore()
        val camera = FakeCamera()
        show(core, camera)

        scanCard(camera, InviteCard("Alice", "5551234567", code(1), 1L))
        rule.onNodeWithTag("add_peer_number").assertTextContains("5551234567")
        rule.onNodeWithTag("add_peer_number").performScrollTo().performClick()
        repeat(10) { rule.onNodeWithTag("key_backspace").performClick() }
        rule.onNodeWithTag("key_done").performClick()
        rule.waitForIdle()
        tap(str(R.string.action_save))

        assertNull("an empty field saves no number, not the one on the card", core.added.single().second)
    }

    // ---- 4. our QR code -------------------------------------------------------------------------------

    @Test
    fun theNameAndNumberWeTypeAreInTheQrCodeWeShow() {
        val core = SpyCore()
        show(core)

        typeInto("add_my_number", "5551234567")
        typeInto("add_my_name", "bob")
        tap(str(R.string.add_show_qr))

        val shown = shownCard()
        assertEquals("bob", shown.name)
        assertEquals("5551234567", shown.number)
        assertEquals(OWN_CODE, shown.code)
        assertEquals(core.made.single().nonce, shown.nonce)
        assertNull("nothing saved yet, so no tag", shown.replyTo)
        rule.onNodeWithText(str(R.string.add_qr_show_body)).assertExists()
    }

    @Test
    fun anEmptyNumberFieldShowsTheCardWithoutANumberAndEveryShowIsANewCard() {
        val core = SpyCore()
        show(core)

        tap(str(R.string.add_show_qr))
        val first = shownCard()
        assertNull(first.number)
        tap(str(R.string.action_cancel))
        rule.onNodeWithTag("add_my_qr").assertDoesNotExist()
        tap(str(R.string.add_show_qr))

        assertNotEquals("a new nonce every time", first.nonce, shownCard().nonce)
    }

    @Test
    fun showingOurQrCodeTurnsTheScreenToFullBrightnessAndBackAfter() {
        val core = SpyCore()
        show(core)
        val before = brightness()

        tap(str(R.string.add_show_qr))
        assertEquals(WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_FULL, brightness())

        tap(str(R.string.action_cancel))
        assertEquals(before, brightness())
    }

    @Test
    fun theScreenStaysOnWhileThePageIsShownAndNotAfter() {
        val core = SpyCore()
        show(core)

        // Leaving the foreground locks the app, and a screen that times out counts as leaving.
        assertTrue(screenView.keepScreenOn)

        visible = false
        rule.waitForIdle()
        assertFalse(screenView.keepScreenOn)
    }

    @Test
    fun theConfirmationCodeUnderOurQrCodeIsTheOneTheirPhoneWorksOut() {
        val core = SpyCore()
        show(core)

        typeInto("add_my_name", "bob")
        tap(str(R.string.add_show_qr))

        assertEquals(shownCard().fingerprint(), textOf(rule.onNodeWithTag("add_my_qr_code")))
    }

    @Test
    fun ourQrCodeIsTakenDownAfterAMinuteAndANewOneCanBeShown() {
        val core = SpyCore()
        rule.mainClock.autoAdvance = true
        show(core)
        val before = brightness()

        tap(str(R.string.add_show_qr))
        val first = shownCard()
        rule.mainClock.advanceTimeBy(59_000)
        rule.waitForIdle()
        rule.onNodeWithTag("add_my_qr").assertExists()
        assertEquals(WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_FULL, brightness())

        rule.mainClock.advanceTimeBy(2_000)
        rule.waitForIdle()
        rule.onNodeWithTag("add_my_qr").assertDoesNotExist()
        rule.onNodeWithTag("add_my_qr_code").assertDoesNotExist()
        rule.onNodeWithText(first.fingerprint()!!).assertDoesNotExist()
        rule.onNodeWithText(str(R.string.add_qr_hidden)).assertExists()
        assertEquals("full brightness only while a QR code is up", before, brightness())
        assertTrue("the page still keeps the screen on", screenView.keepScreenOn)

        tap(str(R.string.add_qr_show_again))
        val second = shownCard()
        assertNotEquals("a new card, not the old one again", first.nonce, second.nonce)
        assertEquals(second.fingerprint(), textOf(rule.onNodeWithTag("add_my_qr_code")))
        rule.onNodeWithText(str(R.string.add_qr_hidden)).assertDoesNotExist()
        assertEquals(WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_FULL, brightness())
    }

    @Test
    fun ourTaggedQrCodeShownAgainAfterTheMinuteIsStillTagged() {
        val core = SpyCore()
        val camera = FakeCamera()
        rule.mainClock.autoAdvance = true
        show(core, camera)
        val card = InviteCard("Alice", null, code(1), 1L)

        scanCard(camera, card)
        tap(str(R.string.action_save))
        val first = shownCard()
        rule.mainClock.advanceTimeBy(61_000)
        rule.waitForIdle()
        rule.onNodeWithTag("add_my_qr").assertDoesNotExist()
        rule.onNodeWithText(str(R.string.add_qr_your_turn)).assertExists()

        tap(str(R.string.add_qr_show_again))
        val again = shownCard()
        assertNotEquals(first.nonce, again.nonce)
        assertTrue("still tells her phone that we saved hers", InviteCard.answers(again, card))
    }

    // ---- 5. a tagged reply finishes both sides ----------------------------------------------------------

    @Test
    fun aReplyTaggedForTheCardWeShowedMeansBothAreDone() {
        val core = SpyCore()
        val camera = FakeCamera()
        var added = 0
        show(core, camera, onAdded = { added++ })

        tap(str(R.string.add_show_qr))
        val ours = shownCard()
        tap(str(R.string.add_scan_qr))
        val reply = InviteCard("Bob", null, code(2), 7L, InviteCard.replyTag(ours, code(2)))
        assertTrue(point(camera, reply.toTextCard()!!))
        tap(str(R.string.action_save))

        assertEquals(listOf("Bob"), core.added.map { it.first })
        assertEquals("their tagged reply proves they saved us", listOf(true), core.mutualFlags)
        assertTrue(core.inner.contacts.value.single().mutual)
        rule.onNodeWithText(str(R.string.add_both_done)).assertExists()
        rule.onNodeWithTag("add_my_qr").assertDoesNotExist()
        assertEquals("no second card is made", 1, core.made.size)
        tap(str(R.string.add_done))
        assertEquals(1, added)
    }

    @Test
    fun aReplyWithAWrongTagIsNotTakenAsProofThatTheySavedUs() {
        val core = SpyCore()
        val camera = FakeCamera()
        show(core, camera)

        tap(str(R.string.add_show_qr))
        val ours = shownCard()
        tap(str(R.string.add_scan_qr))
        val otherCard = ours.copy(nonce = ours.nonce!! + 1)
        assertTrue(point(camera, InviteCard("Bob", null, code(2), 7L, InviteCard.replyTag(otherCard, code(2))).toTextCard()!!))
        tap(str(R.string.action_save))

        rule.onNodeWithText(str(R.string.add_both_done)).assertDoesNotExist()
        rule.onNodeWithText(str(R.string.add_qr_your_turn)).assertExists()
        assertEquals(listOf(false), core.mutualFlags)
    }

    // ---- 6. a new pairing code needs a confirmation -------------------------------------------------------

    @Test
    fun aNewPairingCodeIsOnlyMadeAfterTheDialogIsConfirmed() {
        val core = SpyCore()
        show(core)

        tap(str(R.string.add_code_rotate))
        rule.onNodeWithText(str(R.string.add_rotate_title)).assertExists()
        rule.onNodeWithText(str(R.string.add_rotate_body)).assertExists()
        assertEquals(0, core.rotations)

        tapDialog(str(R.string.action_cancel))
        assertEquals(0, core.rotations)
        rule.onNodeWithText(str(R.string.add_rotate_title)).assertDoesNotExist()

        tap(str(R.string.add_code_rotate))
        tapDialog(str(R.string.add_rotate_confirm))
        assertEquals(1, core.rotations)
        tap(str(R.string.add_show_qr))
        assertEquals(ROTATED_CODE, shownCard().code)
    }

    @Test
    fun aTagForACardShownBeforeANewPairingCodeNoLongerCounts() {
        val core = SpyCore()
        val camera = FakeCamera()
        show(core, camera)

        tap(str(R.string.add_show_qr))
        val old = shownCard()
        tap(str(R.string.action_cancel))
        tap(str(R.string.add_code_rotate))
        tapDialog(str(R.string.add_rotate_confirm))
        scanCard(camera, InviteCard("Alice", null, code(1), 1L, InviteCard.replyTag(old, code(1))))
        tap(str(R.string.action_save))

        rule.onNodeWithText(str(R.string.add_both_done)).assertDoesNotExist()
        rule.onNodeWithText(str(R.string.add_qr_your_turn)).assertExists()
        assertEquals("our card goes up again with the new code", ROTATED_CODE, shownCard().code)
    }

    @Test
    fun aFailedNewPairingCodeStillTakesTheCardsMadeBeforeOffTheScreen() {
        val core = SpyCore()
        core.rotateFails = true
        show(core)
        openRemote()
        tap(str(R.string.add_card_copy))
        rule.onNodeWithTag("add_my_code").assertExists()

        tap(str(R.string.add_code_rotate))
        tapDialog(str(R.string.add_rotate_confirm))
        assertEquals(1, core.rotations)
        rule.onNodeWithTag("add_my_code").assertDoesNotExist()
        rule.onNodeWithText(str(TextMaps.pairing(PairingResult.FAILED))).assertExists()
        // A card shown now is made again from the code still in use.
        val before = core.made.size
        tap(str(R.string.add_show_qr))
        assertEquals(before + 1, core.made.size)
        assertEquals(OWN_CODE, shownCard().code)
    }

    // ---- 6b. a card for a saved contact with another pairing --------------------------------------------

    @Test
    fun aCardForASavedContactWithAnotherPairingAsksBeforeReplacingIt() {
        val existing = FakeScenarios.contacts.first()
        val core = SpyCore(FakeSecureCore(CoreState(CoreAvailability.READY, pinConfigured = true, locked = false), FakeScenarios.contacts))
        core.preview = PairingPreview.Replaces(existing.id)
        val camera = FakeCamera()
        show(core, camera)
        val card = InviteCard("Mallory", null, code(1), 1L)

        scanCard(camera, card)
        rule.onNodeWithText(context.getString(R.string.add_replace_title, existing.name)).assertExists()
        rule.onNodeWithText(context.getString(R.string.add_replace_body, existing.name)).assertExists()
        rule.onNodeWithTag("add_peer_name").assertTextContains(existing.name)
        rule.onNodeWithText(str(R.string.action_save)).assertDoesNotExist()

        // Keeping the pairing is the main button and saves nothing.
        tap(str(R.string.add_replace_keep))
        assertEquals(0, core.added.size)

        scanCard(camera, card)
        tap(str(R.string.add_replace_confirm))
        val (name, _, savedCode) = core.added.single()
        assertEquals("the saved name stays unless changed on screen", existing.name, name)
        assertEquals(card.code, savedCode)
    }

    @Test
    fun aCardForANewContactOrTheSamePairingIsAnOrdinarySave() {
        val existing = FakeScenarios.contacts.first()
        val core = SpyCore(FakeSecureCore(CoreState(CoreAvailability.READY, pinConfigured = true, locked = false), FakeScenarios.contacts))
        core.preview = PairingPreview.Unchanged(existing.id)
        val camera = FakeCamera()
        show(core, camera)
        scanCard(camera, InviteCard("Someone", null, code(2), 2L))
        rule.onNodeWithText(context.getString(R.string.add_replace_title, existing.name)).assertDoesNotExist()
        rule.onNodeWithTag("add_peer_name").assertTextContains(existing.name)
        tap(str(R.string.action_save))
        assertEquals(existing.name, core.added.single().first)
    }

    @Test
    fun aCardTheCoreCannotCheckCannotBeSaved() {
        val core = SpyCore()
        core.preview = PairingPreview.Invalid
        val camera = FakeCamera()
        show(core, camera)
        scanCard(camera, InviteCard("Alice", null, code(3), 3L))
        rule.onNodeWithText(str(R.string.action_save)).performScrollTo().assertIsNotEnabled()
        rule.onNodeWithText(str(TextMaps.pairing(PairingResult.FAILED))).assertExists()
        assertEquals(0, core.added.size)
    }

    // ---- 7. remote cards still need the code check ---------------------------------------------------------

    private fun openRemote() = tap(str(R.string.add_remote_title))

    @Test
    fun aRemoteCardGetsTheCodeCheckAndOurCardIsOfferedAsText() {
        val core = SpyCore()
        var added = 0
        show(core, onAdded = { added++ })
        val card = InviteCard("Remote", null, code(6), 6L)
        clipboard.setPrimaryClip(ClipData.newPlainText("x", card.toTextCard()))

        openRemote()
        tap(str(R.string.add_card_paste))
        rule.onNodeWithText(str(R.string.add_confirm_body_remote)).assertExists()
        rule.onNodeWithText(card.fingerprint()!!).assertExists()
        tap(str(R.string.add_confirm_save))

        assertEquals(1, core.added.size)
        assertEquals(0, added)
        rule.onNodeWithText(str(R.string.add_remote_saved)).assertExists()
        rule.onNodeWithTag("add_my_qr").assertDoesNotExist()
        tap(str(R.string.add_card_copy))
        rule.onNodeWithText(str(R.string.add_card_copied)).assertExists()
        rule.onNodeWithText(str(R.string.add_card_copy)).assertDoesNotExist()
        rule.onNodeWithTag("add_my_code").assertExists()
        tap(str(R.string.add_done))
        assertEquals(1, added)
    }

    @Test
    fun aTypedCardThatIsNotValidShowsAFormatErrorInsteadOfTheConfirmationScreen() {
        val core = SpyCore()
        show(core)
        openRemote()
        rule.onNodeWithText(str(R.string.add_card_check)).assertIsNotEnabled()

        typeInto("add_peer_card", "abc")
        rule.onNodeWithText(str(R.string.add_card_check)).assertIsEnabled()
        tap(str(R.string.add_card_check))

        rule.onNodeWithText(str(R.string.pair_bad_format)).assertExists()
        rule.onNodeWithText(str(R.string.add_confirm_title)).assertDoesNotExist()
        assertEquals(0, core.added.size)
    }

    @Test
    fun aPastedCardThatIsNotValidShowsAFormatErrorInsteadOfTheConfirmationScreen() {
        val core = SpyCore()
        show(core)
        clipboard.setPrimaryClip(ClipData.newPlainText("x", "AEGISCARD1:not-a-card"))
        openRemote()

        tap(str(R.string.add_card_paste))

        rule.onNodeWithText(str(R.string.pair_bad_format)).assertExists()
        rule.onNodeWithText(str(R.string.add_confirm_title)).assertDoesNotExist()
        assertEquals(0, core.added.size)
    }

    @Test
    fun aPastedValidCardGoesToTheConfirmationScreenAndTheClipboardIsCleared() {
        val card = InviteCard("Remote", null, code(6), 6L)
        val core = SpyCore()
        show(core)
        clipboard.setPrimaryClip(ClipData.newPlainText("x", card.toTextCard()))
        openRemote()

        tap(str(R.string.add_card_paste))

        rule.onNodeWithTag("add_peer_code").assertTextContains(card.fingerprint()!!)
        assertEquals(0, core.added.size)
        assertNull("the pasted card holds a secret and must not stay on the clipboard", clipboard.primaryClip)
    }

    @Test
    fun copiedCardIsMarkedSensitiveShowsOurCodeAndIsClearedAfterSixtySeconds() {
        val core = SpyCore()
        rule.mainClock.autoAdvance = true
        show(core)
        openRemote()
        rule.onNodeWithTag("add_my_code").assertDoesNotExist()

        tap(str(R.string.add_card_copy))

        val clip = clipboard.primaryClip
        assertNotNull(clip)
        val copied = clip!!.getItemAt(0).text.toString()
        assertTrue(copied.startsWith("AEGISCARD1:"))
        assertTrue(clip.description.extras?.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE) == true)
        rule.onNodeWithText(str(R.string.add_card_copied)).assertExists()
        rule.onNodeWithTag("add_my_code").assertTextContains(InviteCard.parse(copied)!!.fingerprint()!!)

        rule.mainClock.advanceTimeBy(59_000)
        rule.waitForIdle()
        assertNotNull("still there at 59 s", clipboard.primaryClip)
        rule.mainClock.advanceTimeBy(2_000)
        rule.waitForIdle()
        assertNull("cleared after 60 s", clipboard.primaryClip)
    }

    @Test
    fun leavingThePageClearsTheCopiedCard() {
        val core = SpyCore()
        show(core)
        openRemote()
        tap(str(R.string.add_card_copy))
        assertNotNull(clipboard.primaryClip)

        visible = false
        rule.waitForIdle()

        assertNull(clipboard.primaryClip)
    }

    @Test
    fun leavingThePageKeepsAnUnrelatedClipboardEntry() {
        val core = SpyCore()
        show(core)
        openRemote()
        tap(str(R.string.add_card_copy))
        clipboard.setPrimaryClip(ClipData.newPlainText("other", "something else"))

        visible = false
        rule.waitForIdle()

        assertEquals("something else", clipboard.primaryClip?.getItemAt(0)?.text?.toString())
    }

    // ---- 8. two phones, face to face -----------------------------------------------------------------------

    /** A phone with its own pairing code; everything else is the fake core. */
    private class Phone(private val code: String) :
        SecureCore by FakeSecureCore(CoreState(CoreAvailability.READY, pinConfigured = true, locked = false)) {
        val added = mutableListOf<Pair<String, String>>()
        val mutualFlags = mutableListOf<Boolean>()

        override suspend fun ownPairingCode(): String = code

        override suspend fun ownInviteCard(name: String, number: String?): InviteCard =
            InviteCard(name, number, code, InviteCard.newNonce())

        override suspend fun addPairedContact(name: String, number: String?, code: String, mutual: Boolean): PairingResult {
            added += name to code
            mutualFlags += mutual
            return PairingResult.OK
        }
    }

    private fun on(phone: String, text: String): SemanticsNodeInteraction =
        rule.onNode(hasText(text) and hasAnyAncestor(hasTestTag(phone)))

    private fun tagOn(phone: String, tag: String): SemanticsNodeInteraction =
        rule.onNode(hasTestTag(tag) and hasAnyAncestor(hasTestTag(phone)))

    private fun tapOn(phone: String, text: String) {
        on(phone, text).performScrollTo().performClick()
        rule.waitForIdle()
    }

    /** The QR code on [phone]'s screen, as the other phone's camera reads it. */
    private fun qrOn(phone: String): String = readQr(tagOn(phone, "add_my_qr"))

    private fun twoPhones(a: Phone, b: Phone, camA: FakeCamera, camB: FakeCamera, onA: () -> Unit = {}, onB: () -> Unit = {}) {
        val host = InputHost()
        rule.setContent {
            Harness(AppLanguage.EN, host) {
                screenView = LocalView.current
                Row(Modifier.fillMaxSize()) {
                    Box(Modifier.weight(1f).testTag("phoneA")) { AddContactScreen(a, onBack = {}, onAdded = onA, scanner = camA.scanner) }
                    Box(Modifier.weight(1f).testTag("phoneB")) { AddContactScreen(b, onBack = {}, onAdded = onB, scanner = camB.scanner) }
                }
            }
        }
        rule.waitForIdle()
        tagOn("phoneA", "add_my_name").performScrollTo().performClick()
        typeKeys("ann")
        tagOn("phoneB", "add_my_name").performScrollTo().performClick()
        typeKeys("bob")
    }

    @Test
    fun twoPhonesAddEachOtherWhenTheFirstShowsAndThenScansBack() {
        val a = Phone(code(31))
        val b = Phone(code(32))
        val camA = FakeCamera()
        val camB = FakeCamera()
        var aDone = 0
        var bDone = 0
        twoPhones(a, b, camA, camB, onA = { aDone++ }, onB = { bDone++ })

        // A shows its QR code; B scans it and saves A.
        tapOn("phoneA", str(R.string.add_show_qr))
        tapOn("phoneB", str(R.string.add_scan_qr))
        assertTrue(point(camB, qrOn("phoneA")))
        tagOn("phoneB", "add_peer_name").assertTextContains("ann")
        assertEquals(
            "both screens show the same confirmation code",
            textOf(tagOn("phoneA", "add_my_qr_code")),
            textOf(tagOn("phoneB", "add_peer_code")),
        )
        tapOn("phoneB", str(R.string.action_save))
        assertEquals(listOf("ann" to code(31)), b.added)

        // B now shows its own QR code, tagged; A scans it from where it is and saves B.
        on("phoneB", str(R.string.add_qr_your_turn)).assertExists()
        tapOn("phoneA", str(R.string.add_scan_qr))
        assertTrue(point(camA, qrOn("phoneB")))
        tagOn("phoneA", "add_peer_name").assertTextContains("bob")
        tapOn("phoneA", str(R.string.action_save))
        assertEquals(listOf("bob" to code(32)), a.added)

        on("phoneA", str(R.string.add_both_done)).assertExists()
        tagOn("phoneA", "add_my_qr").assertDoesNotExist()
        // A scanned B's tagged reply, so A knows both sides are saved; B cannot know until a call connects.
        assertEquals(listOf(true), a.mutualFlags)
        assertEquals(listOf(false), b.mutualFlags)
        assertEquals(0, aDone + bDone)
        tapOn("phoneA", str(R.string.add_done))
        tapOn("phoneB", str(R.string.add_done))
        assertEquals(1, aDone)
        assertEquals(1, bDone)
    }

    @Test
    fun twoPhonesAddEachOtherWhenTheFirstScansAndThenShows() {
        val a = Phone(code(41))
        val b = Phone(code(42))
        val camA = FakeCamera()
        val camB = FakeCamera()
        twoPhones(a, b, camA, camB)

        // A opens its camera before B has anything on screen; then B shows its QR code.
        tapOn("phoneA", str(R.string.add_scan_qr))
        tapOn("phoneB", str(R.string.add_show_qr))
        assertTrue(point(camA, qrOn("phoneB")))
        tapOn("phoneA", str(R.string.action_save))
        assertEquals(listOf("bob" to code(42)), a.added)

        // A shows its tagged card by itself; B switches from showing to scanning and saves A.
        on("phoneA", str(R.string.add_qr_your_turn)).assertExists()
        tapOn("phoneB", str(R.string.add_scan_qr))
        assertTrue(point(camB, qrOn("phoneA")))
        tapOn("phoneB", str(R.string.action_save))
        assertEquals(listOf("ann" to code(41)), b.added)

        on("phoneB", str(R.string.add_both_done)).assertExists()
        on("phoneA", str(R.string.add_both_done)).assertDoesNotExist()
    }

    @Test
    fun crossedScansBeforeEitherSavesStillSaveBothButClaimNothingMore() {
        val a = Phone(code(51))
        val b = Phone(code(52))
        val camA = FakeCamera()
        val camB = FakeCamera()
        twoPhones(a, b, camA, camB)

        tapOn("phoneA", str(R.string.add_show_qr))
        tapOn("phoneB", str(R.string.add_show_qr))
        val cardA = qrOn("phoneA")
        val cardB = qrOn("phoneB")
        tapOn("phoneA", str(R.string.add_scan_qr))
        tapOn("phoneB", str(R.string.add_scan_qr))
        assertTrue(point(camA, cardB))
        assertTrue(point(camB, cardA))
        tapOn("phoneA", str(R.string.action_save))
        tapOn("phoneB", str(R.string.action_save))

        assertEquals(listOf("bob" to code(52)), a.added)
        assertEquals(listOf("ann" to code(51)), b.added)
        // Neither card carried a tag, so neither phone can know the other saved it.
        on("phoneA", str(R.string.add_both_done)).assertDoesNotExist()
        on("phoneB", str(R.string.add_both_done)).assertDoesNotExist()
        on("phoneA", str(R.string.add_qr_your_turn)).assertExists()
        on("phoneB", str(R.string.add_qr_your_turn)).assertExists()
        assertEquals(listOf(false), a.mutualFlags)
        assertEquals(listOf(false), b.mutualFlags)
    }

    private fun code(seed: Int): String = codeOf(seed)

    private companion object {
        val OWN_CODE: String = codeOf(90)
        val ROTATED_CODE: String = codeOf(91)

        fun codeOf(seed: Int): String {
            val raw = ByteArray(PairingCodeCodec.RAW_LEN)
            raw[0] = 3
            for (i in 1 until 66) raw[i] = ((i * 37 + seed * 101 + 5) and 0xFF).toByte()
            var crc = 0xFFFF
            for (i in 0 until 66) {
                crc = crc xor ((raw[i].toInt() and 0xFF) shl 8)
                repeat(8) {
                    crc = if ((crc and 0x8000) != 0) ((crc shl 1) xor 0x1021) and 0xFFFF else (crc shl 1) and 0xFFFF
                }
            }
            raw[66] = ((crc ushr 8) and 0xFF).toByte()
            raw[67] = (crc and 0xFF).toByte()
            return PairingCodeCodec.encode(raw)!!
        }
    }
}
