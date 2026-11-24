package io.github.h4lovoid.dialcrypt

import android.app.Application
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import io.github.h4lovoid.dialcrypt.core.SharedPrefsUiPreferences
import io.github.h4lovoid.dialcrypt.incoming.screen.DisplaySettings
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** The "show whole numbers" choice is mirrored to one byte that `:call` and `:dialer` can read. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DisplaySettingsTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val app: Application = ApplicationProvider.getApplicationContext()

    @Before
    fun clean() {
        DisplaySettings.file(app).delete()
    }

    @Test
    fun aMissingFileReadsAsMasked() {
        assertFalse(DisplaySettings.read(File(tmp.root, "absent")))
    }

    @Test
    fun theMirrorIsOneByte() {
        val f = File(tmp.root, "show_full_numbers")
        assertTrue(DisplaySettings.write(f, true))
        assertEquals(1L, f.length())
        assertTrue(DisplaySettings.read(f))
        assertTrue(DisplaySettings.write(f, false))
        assertFalse(DisplaySettings.read(f))
    }

    @Test
    fun aDamagedFileReadsAsMasked() {
        val f = File(tmp.root, "show_full_numbers")
        f.writeBytes(byteArrayOf(1, 1))
        assertFalse(DisplaySettings.read(f))
        f.writeBytes(byteArrayOf(7))
        assertFalse(DisplaySettings.read(f))
        f.writeBytes(ByteArray(0))
        assertFalse(DisplaySettings.read(f))
    }

    @Test
    fun changingThePreferenceUpdatesTheMirror() {
        val prefs = app.getSharedPreferences("display_settings_test", Context.MODE_PRIVATE)
        val ui = SharedPrefsUiPreferences(prefs, app)
        assertFalse(DisplaySettings.read(app))
        ui.setShowFullNumbers(true)
        assertTrue(DisplaySettings.read(app))
        ui.setShowFullNumbers(false)
        assertFalse(DisplaySettings.read(app))
    }

    @Test
    fun anEarlierChoiceIsCopiedOnStart() {
        val prefs = app.getSharedPreferences("display_settings_copy", Context.MODE_PRIVATE)
        prefs.edit().putBoolean("show_full_numbers", true).commit()
        SharedPrefsUiPreferences(prefs, app)
        assertTrue(DisplaySettings.read(app))
    }
}
