package io.github.h4lovoid.dialcrypt.dialer

import android.app.Application
import android.content.Intent
import android.os.Looper
import android.os.UserManager
import androidx.test.core.app.ApplicationProvider
import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.DirectBoot
import io.github.h4lovoid.dialcrypt.incoming.screen.ContactNumberIndex
import io.github.h4lovoid.dialcrypt.incoming.screen.DisplaySettings
import io.github.h4lovoid.dialcrypt.incoming.screen.NumberIndexKey
import java.io.File
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/** Before the first unlock after boot `:call` reads no file and falls back to defaults that mask. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DirectBootTest {
    private val app: Application = ApplicationProvider.getApplicationContext()

    private fun setUnlocked(unlocked: Boolean) {
        shadowOf(app.getSystemService(UserManager::class.java)).setUserUnlocked(unlocked)
    }

    @After
    fun unlockAgain() = setUnlocked(true)

    @Test
    fun theUnlockStateComesFromUserManager() {
        setUnlocked(true)
        assertTrue(DirectBoot.isUserUnlocked(app))
        setUnlocked(false)
        assertFalse(DirectBoot.isUserUnlocked(app))
    }

    @Test
    fun theFullNumberSettingReadsAsOffBeforeTheFirstUnlock() {
        assertTrue(DisplaySettings.write(app, true))
        setUnlocked(true)
        assertTrue(DisplaySettings.read(app))
        setUnlocked(false)
        assertFalse(DisplaySettings.read(app))
    }

    @Test
    fun theSecureBusyMarkerIsNeitherReadNorWrittenBeforeTheFirstUnlock() {
        setUnlocked(false)
        SecureBusyMarker.set(app, true)
        assertFalse(SecureBusyMarker.file(app).exists())
        setUnlocked(true)
        SecureBusyMarker.set(app, true)
        assertTrue(SecureBusyMarker.isSet(app))
        setUnlocked(false)
        assertFalse(SecureBusyMarker.isSet(app))
        setUnlocked(true)
        SecureBusyMarker.set(app, false)
    }

    @Test
    fun everyNumberIsUnknownBeforeTheFirstUnlock() {
        val key = object : NumberIndexKey {
            override fun hmac(input: ByteArray): ByteArray? = throw AssertionError("the key must not be used before the first unlock")

            override fun ensure(): Boolean = false

            override fun delete(): Boolean = true
        }
        // Before the first unlock the index and the vault both look absent, which would read as "no vault".
        val index = ContactNumberIndex(File(app.cacheDir, "missing.bin"), key, vaultExists = { false }, userUnlocked = { false })
        assertEquals(ContactMembership.UNKNOWN, index.lookup("+15550100199"))
    }

    // ---- what was skipped before the first unlock is done right after it ------------------------

    @Test
    fun workRunsAtOnceWhenTheUserIsUnlocked() {
        setUnlocked(true)
        var runs = 0
        AfterFirstUnlock.run(app) { runs++ }
        assertEquals(1, runs)
    }

    @Test
    fun workSkippedBeforeTheFirstUnlockRunsOnceAfterIt() {
        setUnlocked(true)
        SecureBusyMarker.set(app, true)
        setUnlocked(false)
        var runs = 0
        val reset: (android.content.Context) -> Unit = { ctx ->
            runs++
            SecureBusyMarker.set(ctx, false)
        }
        AfterFirstUnlock.run(app, reset)
        // A second component asking while the first still waits adds nothing.
        AfterFirstUnlock.run(app, reset)
        assertEquals(0, runs)
        // The marker left by an interrupted secure call is still there: it could not be removed.
        assertTrue(SecureBusyMarker.file(app).exists())

        setUnlocked(true)
        app.sendBroadcast(Intent(Intent.ACTION_USER_UNLOCKED))
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(1, runs)
        assertFalse(SecureBusyMarker.isSet(app))

        // The receiver is gone: another broadcast does nothing.
        app.sendBroadcast(Intent(Intent.ACTION_USER_UNLOCKED))
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(1, runs)
    }
}
