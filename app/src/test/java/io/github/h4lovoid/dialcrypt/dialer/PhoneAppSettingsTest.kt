package io.github.h4lovoid.dialcrypt.dialer

import android.app.Application
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.core.app.ApplicationProvider
import io.github.h4lovoid.dialcrypt.BuildConfig
import io.github.h4lovoid.dialcrypt.Harness
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.core.AppLanguage
import io.github.h4lovoid.dialcrypt.core.FakeScenarios
import io.github.h4lovoid.dialcrypt.ui.keyboard.InputHost
import io.github.h4lovoid.dialcrypt.ui.screens.PhoneAppSettings
import io.github.h4lovoid.dialcrypt.ui.screens.PhoneAppTags
import io.github.h4lovoid.dialcrypt.ui.screens.SettingsScreen
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** The "Phone app" block of the settings page: when it shows and which buttons it offers. */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [34], qualifiers = "w411dp-h891dp-xxhdpi")
class PhoneAppSettingsTest {
    @get:Rule
    val rule = createComposeRule()

    private val app: Application = ApplicationProvider.getApplicationContext()

    private var uses = 0
    private var restores = 0
    private var screenings = 0

    private fun state(held: Boolean, screeningHeld: Boolean = false) = PhoneAppSettings(
        held = held,
        screeningHeld = screeningHeld,
        onUse = { uses++ },
        onRestore = { restores++ },
        onTakeScreening = { screenings++ },
    )

    private fun settings(phoneApp: PhoneAppSettings?) {
        val host = InputHost()
        rule.setContent {
            Harness(AppLanguage.EN, host) {
                SettingsScreen(
                    language = AppLanguage.EN,
                    onLanguage = {},
                    lockdown = FakeScenarios.lockdownReady(),
                    pinChanged = false,
                    onBack = {},
                    onChangePin = {},
                    onAbout = {},
                    onWipeConfirmed = {},
                    phoneApp = phoneApp,
                )
            }
        }
    }

    private fun assertPresent(vararg tags: String) = tags.forEach { rule.onNodeWithTag(it).assertExists() }

    private fun assertAbsent(vararg tags: String) = tags.forEach { rule.onNodeWithTag(it).assertDoesNotExist() }

    // ---- the block shows only when it is handed in ------------------------------------------------------

    @Test
    fun theBlockIsAbsentWithoutAState() {
        settings(null)
        assertAbsent(
            PhoneAppTags.SECTION,
            PhoneAppTags.ENABLE,
            PhoneAppTags.RESTORE,
            PhoneAppTags.SCREENING_ENABLE,
            PhoneAppTags.SCREENING_ON,
        )
    }

    @Test
    fun theBlockShowsWhenAStateIsHandedIn() {
        settings(state(held = false))
        assertPresent(PhoneAppTags.SECTION)
        rule.onNodeWithText(app.getString(R.string.settings_dialer_title)).assertExists()
    }

    // ---- role not held ----------------------------------------------------------------------------------------

    @Test
    fun withoutTheRoleOnlyTheGetButtonShows() {
        settings(state(held = false))
        assertPresent(PhoneAppTags.ENABLE)
        assertAbsent(PhoneAppTags.RESTORE, PhoneAppTags.SCREENING_ENABLE, PhoneAppTags.SCREENING_ON)
        rule.onNodeWithText(app.getString(R.string.settings_dialer_off)).assertExists()
        rule.onNodeWithTag(PhoneAppTags.ENABLE).performScrollTo().performClick()
        rule.runOnIdle {
            assertEquals(1, uses)
            assertEquals(0, restores)
            assertEquals(0, screenings)
        }
    }

    // ---- role held ----------------------------------------------------------------------------------------------

    @Test
    fun withTheRoleTheGiveBackButtonAndTheScreeningRowShow() {
        settings(state(held = true, screeningHeld = false))
        assertPresent(PhoneAppTags.RESTORE, PhoneAppTags.SCREENING_ENABLE)
        assertAbsent(PhoneAppTags.ENABLE, PhoneAppTags.SCREENING_ON)
        rule.onNodeWithText(app.getString(R.string.settings_dialer_on)).assertExists()
        rule.onNodeWithTag(PhoneAppTags.RESTORE).performScrollTo().performClick()
        rule.onNodeWithTag(PhoneAppTags.SCREENING_ENABLE).performScrollTo().performClick()
        rule.runOnIdle {
            assertEquals(0, uses)
            assertEquals(1, restores)
            assertEquals(1, screenings)
        }
    }

    @Test
    fun withBothRolesTheScreeningRowIsAStatusLine() {
        settings(state(held = true, screeningHeld = true))
        assertPresent(PhoneAppTags.RESTORE, PhoneAppTags.SCREENING_ON)
        assertAbsent(PhoneAppTags.ENABLE, PhoneAppTags.SCREENING_ENABLE)
        rule.onNodeWithText(app.getString(R.string.settings_screening_on)).assertExists()
    }

    // ---- build switch -------------------------------------------------------------------------------------------

    private val appDir = File(System.getProperty("aegis.resDir") ?: "src/main/res").parentFile.parentFile.parentFile

    @Test
    fun theDebugBuildHasTheSwitchOn() {
        assertTrue(BuildConfig.DIALER_ROLE_UI)
    }

    @Test
    fun theReleaseBuildTypeHasTheSwitchOff() {
        val text = File(appDir, "build.gradle.kts").readText()
        val start = text.indexOf("getByName(\"release\")")
        val end = text.indexOf("create(\"fieldTest\")")
        assertTrue("release block not found", start >= 0 && end > start)
        val block = text.substring(start, end)
        assertTrue(block, Regex("\"DIALER_ROLE_UI\",\\s*\"false\"").containsMatchIn(block))
        assertTrue(block, !Regex("\"DIALER_ROLE_UI\",\\s*\"true\"").containsMatchIn(block))
    }

    @Test
    fun theSettingsPageHandsInTheStateOnlyWhenTheSwitchIsOn() {
        val root = File(appDir, "src/main/java/io/github/h4lovoid/dialcrypt/ui/AppRoot.kt").readText()
        assertTrue(root.contains("if (BuildConfig.DIALER_ROLE_UI) rememberPhoneAppSettings() else null"))
    }
}
