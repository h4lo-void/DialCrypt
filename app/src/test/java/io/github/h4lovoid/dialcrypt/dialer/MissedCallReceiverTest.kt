package io.github.h4lovoid.dialcrypt.dialer

import android.Manifest
import android.app.Application
import android.app.Notification
import android.app.NotificationManager
import android.app.Person
import android.content.Intent
import android.telecom.TelecomManager
import androidx.test.core.app.ApplicationProvider
import io.github.h4lovoid.dialcrypt.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/** The missed call broadcast of Telecom becomes a notification that holds only the count. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class MissedCallReceiverTest {
    private val app: Application = ApplicationProvider.getApplicationContext()
    private val nm: NotificationManager = app.getSystemService(NotificationManager::class.java)
    private val number = "+15551234567"

    @Before
    fun allowNotifications() {
        shadowOf(app).grantPermissions(Manifest.permission.POST_NOTIFICATIONS)
    }

    private fun broadcast(count: Int, withNumber: Boolean = false, action: String = TelecomManager.ACTION_SHOW_MISSED_CALLS_NOTIFICATION): Intent =
        Intent(action).putExtra(TelecomManager.EXTRA_NOTIFICATION_COUNT, count).apply {
            if (withNumber) {
                putExtra(TelecomManager.EXTRA_NOTIFICATION_PHONE_NUMBER, number)
                putExtra(Intent.EXTRA_PHONE_NUMBER, number)
                putExtra(Intent.EXTRA_TEXT, number)
            }
        }

    private fun receive(intent: Intent) = MissedCallReceiver().onReceive(app, intent)

    private fun posted(): Notification? = shadowOf(nm).getNotification(DialerNotifications.ID_MISSED)

    @Suppress("DEPRECATION")
    private fun strings(n: Notification): List<String> {
        val out = ArrayList<String>()
        for (key in n.extras.keySet()) {
            when (val v = n.extras.get(key)) {
                is CharSequence -> out += v.toString()
                is Array<*> -> v.filterIsInstance<CharSequence>().forEach { out += it.toString() }
                is Person -> out += v.name?.toString().orEmpty()
            }
        }
        n.tickerText?.let { out += it.toString() }
        n.actions?.forEach { out += it.title.toString() }
        n.publicVersion?.let { out += strings(it) }
        return out
    }

    @Test
    fun aBroadcastPostsOneNotificationWithOnlyTheCount() {
        receive(broadcast(3))
        val n = posted()
        assertNotNull(n)
        assertEquals(1, shadowOf(nm).allNotifications.size)
        assertEquals(app.getString(R.string.dialer_notif_missed, 3), n!!.extras.getCharSequence(Notification.EXTRA_TITLE).toString())
        assertEquals(Notification.CATEGORY_MISSED_CALL, n.category)
        assertEquals(Notification.VISIBILITY_PUBLIC, n.visibility)
        assertNotNull(n.contentIntent)
    }

    @Test
    fun theNotificationHoldsNoDigitsOtherThanTheCountEvenWhenTheBroadcastCarriesANumber() {
        receive(broadcast(2, withNumber = true))
        val n = posted()
        assertNotNull(n)
        val texts = strings(n!!)
        assertFalse(texts.toString(), texts.any { it.contains("555") || it.contains("1234567") || it.contains(number) })
        assertFalse(texts.toString(), texts.any { Regex("\\d{3,}").containsMatchIn(it) })
        assertNull(n.extras.get(Notification.EXTRA_PEOPLE_LIST))
        assertNull(n.tickerText)
        assertNull(n.extras.getCharSequence(Notification.EXTRA_SUB_TEXT))
        assertNull(n.extras.getCharSequence(Notification.EXTRA_INFO_TEXT))
    }

    @Test
    fun theNumberExtraDoesNotChangeTheNotification() {
        receive(broadcast(4))
        val without = strings(posted()!!)
        receive(broadcast(4, withNumber = true))
        val with = strings(posted()!!)
        assertEquals(without, with)
    }

    @Test
    fun aCountOfZeroCancelsTheNotification() {
        receive(broadcast(2))
        assertNotNull(posted())
        receive(broadcast(0))
        assertNull(posted())
    }

    @Test
    fun aMissingCountCountsAsZero() {
        receive(broadcast(2))
        receive(Intent(TelecomManager.ACTION_SHOW_MISSED_CALLS_NOTIFICATION))
        assertNull(posted())
    }

    @Test
    fun anotherActionIsIgnored() {
        receive(broadcast(2, action = "io.github.h4lovoid.dialcrypt.test.OTHER"))
        assertNull(posted())
        receive(broadcast(2))
        receive(broadcast(0, action = "io.github.h4lovoid.dialcrypt.test.OTHER"))
        assertNotNull(posted())
    }
}
