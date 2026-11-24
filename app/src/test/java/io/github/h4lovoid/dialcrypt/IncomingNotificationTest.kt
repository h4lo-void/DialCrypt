package io.github.h4lovoid.dialcrypt

import android.Manifest
import android.app.Application
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import io.github.h4lovoid.dialcrypt.call.IncomingOffer
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.incoming.IncomingCallService
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/** The incoming call notification names nobody and stays off the lock screen. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class IncomingNotificationTest {
    private val app: Application = ApplicationProvider.getApplicationContext()

    private fun texts(n: Notification): List<String> {
        val keys = listOf(
            Notification.EXTRA_TITLE, Notification.EXTRA_TEXT, Notification.EXTRA_SUB_TEXT,
            Notification.EXTRA_INFO_TEXT, Notification.EXTRA_BIG_TEXT, Notification.EXTRA_SUMMARY_TEXT,
        )
        return keys.mapNotNull { n.extras.getCharSequence(it)?.toString() } + listOfNotNull(n.tickerText?.toString())
    }

    @Test
    fun promptNotificationUsesFixedNeutralTextAndIsSecret() {
        val pi = PendingIntent.getActivity(app, 0, Intent(), PendingIntent.FLAG_IMMUTABLE)
        val n = IncomingCallService.buildPromptNotification(app, pi)
        assertEquals(Notification.VISIBILITY_SECRET, n.visibility)
        assertNull(n.publicVersion)
        assertEquals(app.getString(R.string.incoming_prompt_title), n.extras.getCharSequence(Notification.EXTRA_TITLE).toString())
        assertEquals(app.getString(R.string.incoming_prompt_subtitle), n.extras.getCharSequence(Notification.EXTRA_TEXT).toString())
    }

    @Test
    fun shownNumberNeverReachesTheNotification() {
        shadowOf(app).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)
        val number = "+447700900123"
        IncomingCallService.showIncomingPrompt(app, IncomingOffer(byteArrayOf(1, 2, 3), number, NumberPresentation.SHOWN))
        val nm = app.getSystemService(NotificationManager::class.java)
        val posted = shadowOf(nm).allNotifications
        assertEquals(1, posted.size)
        val n = posted[0]
        assertFalse(texts(n).any { it.contains("7700900123") })
        assertEquals(Notification.VISIBILITY_SECRET, n.visibility)
        assertEquals(Notification.VISIBILITY_SECRET, nm.getNotificationChannel(IncomingCallService.CHANNEL_ID).lockscreenVisibility)
    }
}
