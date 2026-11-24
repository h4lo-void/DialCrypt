package io.github.h4lovoid.dialcrypt

import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.longClick
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import io.github.h4lovoid.dialcrypt.core.AppLanguage
import io.github.h4lovoid.dialcrypt.ui.keyboard.InputHost
import io.github.h4lovoid.dialcrypt.ui.keyboard.InputKind
import io.github.h4lovoid.dialcrypt.ui.keyboard.KeyboardController
import io.github.h4lovoid.dialcrypt.ui.keyboard.KeyboardLayouts
import io.github.h4lovoid.dialcrypt.ui.keyboard.KeyboardPage
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureInputState
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureTextField
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.Random

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "w411dp-h891dp-xxhdpi")
class KeyboardShuffleTest {
    @get:Rule
    val rule = createComposeRule()

    private fun secretInput() = SecureInputState().also { it.markSecret() }

    /** Rows of the letter page and of the symbol page as the keyboard would draw them now. */
    private fun layouts(kb: KeyboardController): Pair<List<String>, List<String>> {
        assertEquals(KeyboardPage.LETTERS, kb.page)
        val letters = kb.rows
        kb.togglePage()
        val symbols = kb.rows
        kb.togglePage()
        return letters to symbols
    }

    private fun assertSameKeysSameShape(original: List<String>, shuffled: List<String>) {
        assertEquals(original.map { it.length }, shuffled.map { it.length })
        assertEquals(original.joinToString("").toList().sorted(), shuffled.joinToString("").toList().sorted())
        assertNotEquals(original, shuffled)
    }

    @Test
    fun secretInputShufflesLettersAndSymbolsKeepingKeysAndRowLengths() {
        val host = InputHost(Random(42))
        host.focus(secretInput())
        assertTrue(host.keyboard.scrambled)
        val (letters, symbols) = layouts(host.keyboard)
        assertSameKeysSameShape(KeyboardLayouts.letters, letters)
        assertSameKeysSameShape(KeyboardLayouts.symbols, symbols)
        assertEquals(listOf(10, 9, 7), letters.map { it.length })
    }

    @Test
    fun refocusAndClearShuffleAgainButTypingDoesNot() {
        val host = InputHost(Random(7))
        val kb = host.keyboard
        val input = secretInput()
        host.focus(input)
        val first = layouts(kb)

        kb.type(input, first.first[0][0].toString())
        kb.togglePage()
        kb.type(input, first.second[0][0].toString())
        kb.togglePage()
        kb.backspace(input)
        kb.tapShift()
        kb.type(input, "q")
        assertEquals(first, layouts(kb))

        host.blur()
        host.focus(input)
        val refocused = layouts(kb)
        assertNotEquals(first.first, refocused.first)
        assertNotEquals(first.second, refocused.second)

        // Tapping the field again while it already owns the keyboard keeps the order and the page.
        kb.togglePage()
        val pageBefore = kb.page
        host.focus(input)
        assertEquals(pageBefore, kb.page)
        kb.togglePage()
        assertEquals(refocused, layouts(kb))

        kb.type(input, "abc")
        input.clear()
        val cleared = layouts(kb)
        assertNotEquals(refocused.first, cleared.first)
        assertNotEquals(refocused.second, cleared.second)
        assertSameKeysSameShape(KeyboardLayouts.letters, cleared.first)
        assertSameKeysSameShape(KeyboardLayouts.symbols, cleared.second)

        // Clearing an input that does not own the keyboard leaves the keys alone.
        val other = secretInput()
        other.clear()
        assertEquals(cleared, layouts(kb))
    }

    @Test
    fun plainTextAndPhoneInputsKeepTheNormalOrder() {
        val host = InputHost(Random(1))
        val kb = host.keyboard
        host.focus(secretInput())
        assertTrue(kb.scrambled)

        host.focus(SecureInputState())
        assertFalse(kb.scrambled)
        assertEquals(KeyboardLayouts.letters to KeyboardLayouts.symbols, layouts(kb))

        host.focus(SecureInputState(kind = InputKind.PHONE))
        assertFalse(kb.scrambled)
        assertEquals(KeyboardLayouts.phone, kb.rows)
    }

    @Test
    fun maskedFieldDrawsTheShuffledOrderAndEachTagTypesItsOwnCharacter() {
        val input = SecureInputState()
        val host = InputHost(Random(3))
        rule.setContent {
            Harness(AppLanguage.EN, host) {
                LaunchedEffect(Unit) { host.focus(input) }
                SecureTextField(input, masked = true)
            }
        }
        rule.runOnIdle { assertTrue(input.secret); assertTrue(host.keyboard.scrambled) }
        assertDrawnInOrder(host.keyboard.rows)

        rule.onNodeWithTag("key_a").assertTextEquals("a")
        "qaz".forEach { rule.onNodeWithTag("key_$it").performClick() }
        rule.onNodeWithTag("key_page").performClick()
        "7#".forEach { rule.onNodeWithTag("key_$it").performClick() }
        rule.runOnIdle { assertEquals("qaz7#", input.text()) }
        assertDrawnInOrder(host.keyboard.rows)

        val before = host.keyboard.rows
        rule.runOnIdle { input.clear() }
        rule.runOnIdle { assertNotEquals(before, host.keyboard.rows) }
        assertDrawnInOrder(host.keyboard.rows)
    }

    @Test
    fun longPressOnMaskedFieldTypesTheKeyWithoutAnAccentRow() {
        val input = SecureInputState()
        val host = InputHost(Random(5))
        rule.setContent {
            Harness(AppLanguage.ES, host) {
                LaunchedEffect(Unit) { host.focus(input) }
                SecureTextField(input, masked = true)
            }
        }
        rule.onNodeWithTag("key_e").assert(SemanticsMatcher.keyNotDefined(SemanticsActions.OnLongClick))
        rule.onNodeWithTag("key_e").performTouchInput { longClick() }
        assertEquals(0, rule.onAllNodesWithTag("accent_\u00E9").fetchSemanticsNodes().size)
        rule.onNodeWithTag("key_shift").performClick()
        rule.onNodeWithTag("key_a").performTouchInput { longClick() }
        assertEquals(0, rule.onAllNodesWithTag("accent_\u00C0").fetchSemanticsNodes().size)
        rule.runOnIdle {
            assertEquals("eA", input.text())
            assertTrue(host.keyboard.accents.isEmpty())
        }
    }

    /** Each row's keys sit left to right in the controller's order. */
    private fun assertDrawnInOrder(rows: List<String>) {
        rows.forEach { row ->
            val lefts = row.map { c -> rule.onNodeWithTag("key_$c").fetchSemanticsNode().boundsInRoot.left }
            assertEquals(lefts.sorted(), lefts)
        }
    }
}
