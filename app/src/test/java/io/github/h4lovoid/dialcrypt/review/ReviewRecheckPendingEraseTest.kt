package io.github.h4lovoid.dialcrypt.review

import android.app.Application
import android.os.UserManager
import androidx.test.core.app.ApplicationProvider
import io.github.h4lovoid.dialcrypt.dialer.PendingLogErase
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

/** Second review: the marker that holds back call log rows while an erase is pending. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ReviewRecheckPendingEraseTest {
    private val app: Application = ApplicationProvider.getApplicationContext()
    private val file get() = PendingLogErase.file(app)
    private val alive: (android.content.Context) -> Boolean = { true }

    private fun setUnlocked(unlocked: Boolean) {
        shadowOf(app.getSystemService(UserManager::class.java)).setUserUnlocked(unlocked)
    }

    @Before
    @After
    fun clean() {
        setUnlocked(true)
        PendingLogErase.forgetForTest()
        file.delete()
    }

    @Test
    fun theMarkerHoldsOnlyStartTimesAndGoesWhenTheLastEraseEnds() {
        val first = 1_700_000_000_000L
        val second = 1_700_000_050_000L
        PendingLogErase.begin(app, second)
        PendingLogErase.begin(app, first)
        val text = file.readText()
        assertTrue(text, Regex("[0-9]+(\n[0-9]+)*").matches(text))
        assertEquals(first - PendingLogErase.MARGIN_MS, PendingLogErase.hiddenFrom(app, ownerAlive = alive))
        PendingLogErase.end(app, first)
        assertEquals(second - PendingLogErase.MARGIN_MS, PendingLogErase.hiddenFrom(app, ownerAlive = alive))
        PendingLogErase.end(app, second)
        assertFalse(file.exists())
        assertNull(PendingLogErase.hiddenFrom(app, ownerAlive = alive))
    }

    @Test
    fun aMarkerNobodyLooksAfterIsDropped() {
        PendingLogErase.begin(app, 1_000L)
        assertNull(PendingLogErase.hiddenFrom(app, ownerAlive = { false }))
        assertFalse(file.exists())

        PendingLogErase.forgetForTest()
        PendingLogErase.begin(app, 2_000L)
        val now = System.currentTimeMillis()
        assertTrue(file.setLastModified(now - PendingLogErase.MAX_AGE_MS - 60_000L))
        assertNull(PendingLogErase.hiddenFrom(app, nowMs = now, ownerAlive = alive))
        assertFalse(file.exists())
    }

    @Test
    fun aNewCallProcessDropsTheMarkerOfAnEarlierOneButNotItsOwn() {
        PendingLogErase.begin(app, 5_000L)
        PendingLogErase.reset(app)
        assertTrue(file.exists())
        // A new process knows of no pending erase.
        PendingLogErase.forgetForTest()
        PendingLogErase.reset(app)
        assertFalse(file.exists())
    }

    @Test
    fun beforeTheFirstUnlockNothingIsReadWrittenOrThrown() {
        PendingLogErase.begin(app, 3_000L)
        setUnlocked(false)
        assertNull(PendingLogErase.hiddenFrom(app, ownerAlive = alive))
        PendingLogErase.begin(app, 4_000L)
        PendingLogErase.end(app, 4_000L)
        PendingLogErase.reset(app)
        assertTrue(file.exists())
        setUnlocked(true)
        assertEquals(3_000L - PendingLogErase.MARGIN_MS, PendingLogErase.hiddenFrom(app, ownerAlive = alive))
    }
}
