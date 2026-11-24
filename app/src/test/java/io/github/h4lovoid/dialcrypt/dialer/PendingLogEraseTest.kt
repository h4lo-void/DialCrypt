package io.github.h4lovoid.dialcrypt.dialer

import android.app.Application
import android.os.UserManager
import androidx.test.core.app.ApplicationProvider
import io.github.h4lovoid.dialcrypt.call.CallLogMatcher
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/** The marker that keeps a secure call's row out of the recent calls until the eraser is done with it. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PendingLogEraseTest {
    private val app: Application = ApplicationProvider.getApplicationContext()
    private val file get() = PendingLogErase.file(app)
    private val now = 1_795_478_400_000L

    private fun setUnlocked(unlocked: Boolean) {
        shadowOf(app.getSystemService(UserManager::class.java)).setUserUnlocked(unlocked)
    }

    private fun hiddenFrom(nowMs: Long = System.currentTimeMillis(), alive: Boolean = true) =
        PendingLogErase.hiddenFrom(app, nowMs) { alive }

    @Before
    fun start() {
        setUnlocked(true)
        PendingLogErase.forgetForTest()
        file.delete()
    }

    @After
    fun cleanUp() {
        setUnlocked(true)
        PendingLogErase.forgetForTest()
        file.delete()
    }

    @Test
    fun theMarginMatchesTheEraser() {
        assertEquals(CallLogMatcher.BEFORE_START_MS, PendingLogErase.MARGIN_MS)
    }

    @Test
    fun aPendingEraseHidesRowsFromTheStartOfTheCallOn() {
        assertNull(hiddenFrom())
        PendingLogErase.begin(app, now)
        assertEquals(now - PendingLogErase.MARGIN_MS, hiddenFrom())
        // The file holds the start time and nothing else.
        assertEquals(now.toString(), file.readText())
        PendingLogErase.end(app, now)
        assertNull(hiddenFrom())
        assertFalse(file.exists())
    }

    @Test
    fun withTwoPendingErasesTheEarlierStartCountsUntilItIsDone() {
        PendingLogErase.begin(app, now)
        PendingLogErase.begin(app, now + 60_000L)
        assertEquals(now - PendingLogErase.MARGIN_MS, hiddenFrom())
        PendingLogErase.end(app, now)
        assertEquals(now + 60_000L - PendingLogErase.MARGIN_MS, hiddenFrom())
        PendingLogErase.end(app, now + 60_000L)
        assertFalse(file.exists())
    }

    @Test
    fun aMarkerNobodyLooksAfterIsDropped() {
        PendingLogErase.begin(app, now)
        assertNull(hiddenFrom(alive = false))
        assertFalse(file.exists())

        PendingLogErase.forgetForTest()
        PendingLogErase.begin(app, now)
        val written = file.lastModified()
        assertEquals(now - PendingLogErase.MARGIN_MS, hiddenFrom(nowMs = written + PendingLogErase.MAX_AGE_MS))
        assertNull(hiddenFrom(nowMs = written + PendingLogErase.MAX_AGE_MS + 1L))
        assertFalse(file.exists())
    }

    @Test
    fun aDamagedMarkerIsDropped() {
        file.parentFile?.mkdirs()
        file.writeText("not a time")
        assertNull(hiddenFrom())
        assertFalse(file.exists())
    }

    @Test
    fun aNewProcessDropsWhatAnEarlierOneLeftButNotItsOwn() {
        PendingLogErase.begin(app, now)
        // The same process still waits on its call: a second service starting changes nothing.
        PendingLogErase.reset(app)
        assertTrue(file.exists())
        // A new process has nothing pending in memory.
        PendingLogErase.forgetForTest()
        PendingLogErase.reset(app)
        assertFalse(file.exists())
    }

    @Test
    fun beforeTheFirstUnlockNothingIsReadOrWritten() {
        setUnlocked(false)
        PendingLogErase.begin(app, now)
        assertFalse(file.exists())
        setUnlocked(true)
        PendingLogErase.forgetForTest()
        PendingLogErase.begin(app, now)
        setUnlocked(false)
        assertNull(hiddenFrom())
        assertTrue(file.exists())
    }
}
