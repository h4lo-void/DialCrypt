package io.github.h4lovoid.dialcrypt

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.printToString
import io.github.h4lovoid.dialcrypt.core.AppLanguage
import io.github.h4lovoid.dialcrypt.ui.keyboard.InputHost
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureInputState
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureTextField
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
class SecureTextFieldRevealTest {
    @get:Rule
    val rule = createComposeRule()

    private val pin = "48206"

    private val context: Context = ApplicationProvider.getApplicationContext()

    private fun setMaskedField(state: SecureInputState) {
        val host = InputHost()
        rule.setContent {
            Harness(AppLanguage.EN, host) {
                LaunchedEffect(Unit) { host.focus(state) }
                SecureTextField(state, masked = true)
            }
        }
        rule.waitForIdle()
    }

    private fun semanticsDump() = rule.onRoot(useUnmergedTree = true).printToString(Int.MAX_VALUE)

    @Test
    fun maskedFieldNeverReadsTextWhetherRevealedOrNot() {
        val state = SecureInputState()
        state.append(pin)
        setMaskedField(state)
        rule.runOnIdle { assertEquals(0, state.textReadCount) }

        rule.onNodeWithContentDescription(context.getString(R.string.field_show)).performClick()
        rule.waitForIdle()
        rule.onNodeWithContentDescription(context.getString(R.string.field_hide)).assertExists()
        state.append("7")
        rule.waitForIdle()
        rule.runOnIdle { assertEquals(0, state.textReadCount) }

        rule.onNodeWithContentDescription(context.getString(R.string.field_hide)).performClick()
        rule.waitForIdle()
        rule.runOnIdle { assertEquals(0, state.textReadCount) }
    }

    @Test
    fun revealedPinIsAbsentFromSemanticsTree() {
        val state = SecureInputState()
        state.append(pin)
        setMaskedField(state)
        rule.onNodeWithContentDescription(context.getString(R.string.field_show)).performClick()
        rule.waitForIdle()
        val dump = semanticsDump()
        assertFalse(dump, dump.contains(pin))
    }

    @Test
    fun plainFieldStillReadsText() {
        val state = SecureInputState()
        state.append("Alice")
        rule.setContent { Harness(AppLanguage.EN, InputHost()) { SecureTextField(state) } }
        rule.waitForIdle()
        rule.runOnIdle { assertTrue(state.textReadCount > 0) }
    }
}
