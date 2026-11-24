package io.github.h4lovoid.dialcrypt.dialer

import android.app.Application
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import io.github.h4lovoid.dialcrypt.core.AppLanguage
import io.github.h4lovoid.dialcrypt.dialer.model.NumberText
import io.github.h4lovoid.dialcrypt.dialer.model.RecentDirection
import io.github.h4lovoid.dialcrypt.dialer.model.RecentItem
import io.github.h4lovoid.dialcrypt.dialer.model.RecentState
import io.github.h4lovoid.dialcrypt.dialer.ui.DialNotice
import io.github.h4lovoid.dialcrypt.dialer.ui.DialTab
import io.github.h4lovoid.dialcrypt.dialer.ui.DialerTabs
import io.github.h4lovoid.dialcrypt.dialer.ui.RecentsScreen
import io.github.h4lovoid.dialcrypt.dialer.ui.RecentsTags
import io.github.h4lovoid.dialcrypt.ui.ProvideAppLanguage
import io.github.h4lovoid.dialcrypt.ui.theme.DialCryptTheme
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "w411dp-h891dp-xxhdpi")
class RecentsScreenTest {
    @get:Rule
    val rule = createComposeRule()

    private val now = 1_795_478_400_000L

    private val items = listOf(
        RecentItem(3L, RecentDirection.MISSED, NumberText.Digits("+15550100199"), now - 60_000L, null, "+15550100199"),
        RecentItem(2L, RecentDirection.OUTGOING, NumberText.Digits("\u2022\u2022\u2022\u2022 0101"), now - 120_000L, 75L, "+447700900101"),
        RecentItem(1L, RecentDirection.INCOMING, NumberText.Hidden, now - 180_000L, 30L, null),
    )

    private val calls = ArrayList<String>()
    private val deletes = ArrayList<Long>()
    private var clears = 0

    @Before
    fun allowHidingOverlays() {
        // SecureDialog hides overlay windows, which needs this permission.
        shadowOf(ApplicationProvider.getApplicationContext<Application>()).grantPermissions("android.permission.HIDE_OVERLAY_WINDOWS")
    }

    private fun show(state: RecentState, notice: DialNotice? = null) {
        rule.setContent {
            ProvideAppLanguage(AppLanguage.EN) {
                DialCryptTheme {
                    RecentsScreen(
                        state = state,
                        nowMs = now,
                        notice = notice,
                        onCall = { calls += it },
                        onDelete = { deletes += it },
                        onClearAll = { clears++ },
                    )
                }
            }
        }
    }

    @Test
    fun rowsShowDirectionNumberAndDurationButNeverAMaskedDigit() {
        show(RecentState(items, loaded = true))
        rule.onNodeWithText("+15550100199").assertExists()
        rule.onNodeWithText("\u2022\u2022\u2022\u2022 0101").assertExists()
        rule.onNodeWithText("Hidden number").assertExists()
        rule.onNodeWithText("Missed", substring = true).assertExists()
        rule.onNodeWithText("Outgoing", substring = true).assertExists()
        rule.onNodeWithText("1:15", substring = true).assertExists()
        rule.onNodeWithText("+447700900101", substring = true).assertDoesNotExist()
    }

    @Test
    fun tappingARowCallsItsNumberBackAndAHiddenRowCannotBeTapped() {
        show(RecentState(items, loaded = true))
        rule.onNodeWithTag(RecentsTags.row(2L)).performClick()
        rule.onNodeWithTag(RecentsTags.row(1L)).assertIsNotEnabled()
        rule.onNodeWithTag(RecentsTags.row(3L)).assertHasClickAction()
        rule.runOnIdle { assertEquals(listOf("+447700900101"), calls) }
    }

    @Test
    fun aRowIsDeletedByItsOwnButton() {
        show(RecentState(items, loaded = true))
        rule.onNodeWithTag(RecentsTags.delete(3L)).performClick()
        rule.runOnIdle {
            assertEquals(listOf(3L), deletes)
            assertEquals(emptyList<String>(), calls)
        }
    }

    @Test
    fun clearAllAsksFirst() {
        show(RecentState(items, loaded = true))
        rule.onNodeWithTag(RecentsTags.CLEAR_ALL).performClick()
        rule.runOnIdle { assertEquals(0, clears) }
        rule.onNodeWithText("Clear all recent calls?").assertExists()
        rule.onNodeWithTag(RecentsTags.CLEAR_CONFIRM).performClick()
        rule.runOnIdle { assertEquals(1, clears) }
    }

    @Test
    fun emptyAndUnavailableListsSaySo() {
        show(RecentState(loaded = true))
        rule.onNodeWithTag(RecentsTags.EMPTY).assertExists()
        rule.onNodeWithTag(RecentsTags.CLEAR_ALL).assertDoesNotExist()
    }

    @Test
    fun anUnreadableCallLogIsExplained() {
        show(RecentState(loaded = true, unavailable = true))
        rule.onNodeWithTag(RecentsTags.UNAVAILABLE).assertExists()
    }

    @Test
    fun aBlockedCallBackShowsTheKeypadNotice() {
        show(RecentState(items, loaded = true), notice = DialNotice.BLOCKED)
        rule.onNodeWithTag(RecentsTags.NOTICE).assertExists()
    }

    @Test
    fun theTabsSwitchBetweenKeypadAndRecents() {
        val picked = ArrayList<DialTab>()
        rule.setContent {
            ProvideAppLanguage(AppLanguage.EN) {
                DialCryptTheme { DialerTabs(DialTab.KEYPAD, { picked += it }) }
            }
        }
        rule.onNodeWithTag(RecentsTags.TAB_RECENTS).performClick()
        rule.onNodeWithTag(RecentsTags.TAB_KEYPAD).performClick()
        rule.runOnIdle { assertEquals(listOf(DialTab.RECENTS, DialTab.KEYPAD), picked) }
    }
}
