package io.github.h4lovoid.dialcrypt.dialer

import android.app.Application
import android.app.Notification
import android.app.NotificationManager
import android.app.Person
import androidx.test.core.app.ApplicationProvider
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.dialer.model.IncomingUiPolicy
import io.github.h4lovoid.dialcrypt.dialer.model.RegistryView
import io.github.h4lovoid.dialcrypt.dialer.model.Screening
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Dialer notifications carry only fixed neutral text and never anything that names the caller. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DialerNotificationsTest {
    private val app: Application = ApplicationProvider.getApplicationContext()
    private val nonce = ByteArray(16) { it.toByte() }
    private val digitRun = Regex("\\d{3,}")

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

    private fun assertNeutral(n: Notification) {
        val texts = strings(n)
        assertFalse(texts.toString(), texts.any { digitRun.containsMatchIn(it) })
        assertEquals(Notification.VISIBILITY_PUBLIC, n.visibility)
    }

    @Test
    fun channelsArePublicAndRingingIsLeftToTelecom() {
        DialerNotifications.ensureChannels(app)
        val nm = app.getSystemService(NotificationManager::class.java)
        val incoming = nm.getNotificationChannel(DialerNotifications.CHANNEL_INCOMING)
        assertEquals(NotificationManager.IMPORTANCE_HIGH, incoming.importance)
        assertNull(incoming.sound)
        assertEquals(Notification.VISIBILITY_PUBLIC, incoming.lockscreenVisibility)
        assertEquals(NotificationManager.IMPORTANCE_LOW, nm.getNotificationChannel(DialerNotifications.CHANNEL_ONGOING).importance)
        assertEquals(NotificationManager.IMPORTANCE_DEFAULT, nm.getNotificationChannel(DialerNotifications.CHANNEL_MISSED).importance)
    }

    @Test
    fun incomingCarriesAFullScreenIntentAndNeutralText() {
        val n = DialerNotifications.incoming(app, 7, nonce, fullScreen = true, answerEnabled = true, openUi = true)
        assertNotNull(n.fullScreenIntent)
        assertNotNull(n.contentIntent)
        assertEquals(Notification.CATEGORY_CALL, n.category)
        assertEquals(app.getString(R.string.dialer_notif_incoming), n.extras.getCharSequence(Notification.EXTRA_TITLE).toString())
        assertEquals(2, n.actions.size)
        assertNeutral(n)
    }

    @Test
    fun aNoticeHasNoFullScreenIntent() {
        val n = DialerNotifications.incoming(app, 7, nonce, fullScreen = false, answerEnabled = true, openUi = true)
        assertNull(n.fullScreenIntent)
        assertNotNull(n.contentIntent)
        assertNeutral(n)
    }

    @Test
    fun whileScreeningOnlyDeclineIsOffered() {
        val n = DialerNotifications.incoming(app, 7, nonce, fullScreen = true, answerEnabled = false, openUi = true)
        assertEquals(1, n.actions.size)
        assertEquals(app.getString(R.string.dialer_notif_decline), n.actions[0].title.toString())
        assertEquals(app.getString(R.string.dialer_notif_checking), n.extras.getCharSequence(Notification.EXTRA_TEXT).toString())
        assertNeutral(n)
    }

    @Test
    fun aSecureCallLeavesNothingThatOpensTheInCallScreen() {
        val ringing = DialerNotifications.incoming(app, 7, nonce, fullScreen = true, answerEnabled = true, openUi = false)
        assertNull(ringing.fullScreenIntent)
        assertNull(ringing.contentIntent)
        assertEquals(1, ringing.actions.size)
        val ongoing = DialerNotifications.ongoing(app, 7, nonce, secureOwned = true, connectMs = 1_000L)
        assertNull(ongoing.contentIntent)
        assertEquals(1, ongoing.actions.size)
        assertEquals(app.getString(R.string.dialer_notif_hang_up), ongoing.actions[0].title.toString())
        assertNeutral(ringing)
        assertNeutral(ongoing)
    }

    @Test
    fun aPlainOngoingCallOpensTheInCallScreen() {
        val n = DialerNotifications.ongoing(app, 7, nonce, secureOwned = false, connectMs = 0L)
        assertNotNull(n.contentIntent)
        assertEquals(app.getString(R.string.dialer_notif_ongoing), n.extras.getCharSequence(Notification.EXTRA_TITLE).toString())
        assertNeutral(n)
    }

    @Test
    fun anOfferAtAnOpenSecureAppCanOnlyBeDeclinedFromTheNotification() {
        val reg = RegistryView(screening = Screening.OFFER, offerToSecure = true)
        val ui = IncomingUiPolicy.decide(Screening.OFFER, offerToSecure = true, secureOwnedOther = false, waitedMs = 1_000L, fsiAllowed = true)
        val notice = IncomingUiPolicy.notice(ui, reg, Screening.OFFER, 1_000L)
        val n = DialerNotifications.incoming(app, 7, nonce, notice.fullScreen, notice.answer, notice.openUi)
        assertNull(n.fullScreenIntent)
        assertNull(n.contentIntent)
        assertEquals(1, n.actions.size)
        assertEquals(app.getString(R.string.dialer_notif_decline), n.actions[0].title.toString())
        assertNeutral(n)
    }

    @Test
    fun missedShowsOnlyTheCount() {
        assertNull(DialerNotifications.missed(app, 0))
        val n = DialerNotifications.missed(app, 3)!!
        assertEquals(app.getString(R.string.dialer_notif_missed, 3), n.extras.getCharSequence(Notification.EXTRA_TITLE).toString())
        assertNeutral(n)
    }
}
