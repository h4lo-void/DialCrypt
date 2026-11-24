package io.github.h4lovoid.dialcrypt.dialer

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import io.github.h4lovoid.dialcrypt.R

/**
 * Notifications of the default dialer. Every field holds fixed neutral text: no number, no name,
 * no person, so they may show on the lock screen. Ringing and vibration come from Telecom.
 */
internal object DialerNotifications {
    const val CHANNEL_INCOMING = "dialer_incoming_v1"
    const val CHANNEL_ONGOING = "dialer_ongoing_v1"
    const val CHANNEL_MISSED = "dialer_missed_v1"
    const val ID_INCOMING = 4201
    const val ID_ONGOING = 4202
    const val ID_MISSED = 4203

    /** The in-call screen, started by name so this package does not depend on it. */
    const val IN_CALL_ACTIVITY = "io.github.h4lovoid.dialcrypt.dialer.InCallActivity"

    /** The dial pad, opened on its recent calls tab from the missed call notification. */
    const val DIALPAD_ACTIVITY = "io.github.h4lovoid.dialcrypt.dialer.DialpadActivity"

    /** Boolean extra of the dial pad intent: open the recent calls tab. */
    const val EXTRA_SHOW_RECENTS = "io.github.h4lovoid.dialcrypt.dialer.extra.SHOW_RECENTS"

    private const val KIND_SCREEN = 0
    private const val KIND_ANSWER = 1
    private const val KIND_DECLINE = 2
    private const val KIND_HANG_UP = 3

    fun ensureChannels(c: Context) {
        val nm = c.getSystemService(NotificationManager::class.java) ?: return
        if (nm.getNotificationChannel(CHANNEL_INCOMING) == null) {
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_INCOMING,
                    c.getString(R.string.dialer_channel_incoming),
                    NotificationManager.IMPORTANCE_HIGH,
                ).apply {
                    setSound(null, null)
                    enableVibration(false)
                    setShowBadge(false)
                    lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                },
            )
        }
        if (nm.getNotificationChannel(CHANNEL_ONGOING) == null) {
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ONGOING,
                    c.getString(R.string.dialer_channel_ongoing),
                    NotificationManager.IMPORTANCE_LOW,
                ).apply {
                    setShowBadge(false)
                    lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                },
            )
        }
        if (nm.getNotificationChannel(CHANNEL_MISSED) == null) {
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_MISSED,
                    c.getString(R.string.dialer_channel_missed),
                    NotificationManager.IMPORTANCE_DEFAULT,
                ).apply {
                    lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                },
            )
        }
    }

    /**
     * A ringing call. [fullScreen] adds the full-screen intent and [answerEnabled] the answer
     * button. With [openUi] false (a secure call is under way) nothing in it opens the in-call
     * screen: no content intent, no full-screen intent, no answer button; only decline remains.
     */
    fun incoming(
        c: Context,
        id: Int,
        nonce: ByteArray,
        fullScreen: Boolean,
        answerEnabled: Boolean,
        openUi: Boolean,
    ): Notification {
        val b = base(c, CHANNEL_INCOMING)
            .setContentTitle(c.getString(R.string.dialer_notif_incoming))
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setOngoing(true)
            .setShowWhen(false)
        if (openUi) {
            val screen = screenIntent(c, id, nonce, null, KIND_SCREEN)
            b.setContentIntent(screen)
            if (fullScreen) b.setFullScreenIntent(screen, true)
            if (!answerEnabled) b.setContentText(c.getString(R.string.dialer_notif_checking))
        }
        b.addAction(0, c.getString(R.string.dialer_notif_decline), actionIntent(c, CallActionReceiver.ACTION_DECLINE, id, nonce, KIND_DECLINE))
        if (openUi && answerEnabled) {
            b.addAction(0, c.getString(R.string.dialer_notif_answer), screenIntent(c, id, nonce, CallActionReceiver.ACTION_ANSWER, KIND_ANSWER))
        }
        return b.build()
    }

    /**
     * The call in progress. A secure call gets no content intent, so the in-call screen cannot be
     * opened over it; hang up is always there.
     */
    fun ongoing(c: Context, id: Int, nonce: ByteArray, secureOwned: Boolean, connectMs: Long): Notification {
        val b = base(c, CHANNEL_ONGOING)
            .setContentTitle(c.getString(R.string.dialer_notif_ongoing))
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
        if (connectMs > 0L) {
            b.setWhen(connectMs).setShowWhen(true).setUsesChronometer(true)
        } else {
            b.setShowWhen(false)
        }
        if (!secureOwned) b.setContentIntent(screenIntent(c, id, nonce, null, KIND_SCREEN))
        b.addAction(0, c.getString(R.string.dialer_notif_hang_up), actionIntent(c, CallActionReceiver.ACTION_HANG_UP, id, nonce, KIND_HANG_UP))
        return b.build()
    }

    /** Missed calls; null when [count] is zero, meaning the notification is cancelled. */
    fun missed(c: Context, count: Int): Notification? {
        if (count <= 0) return null
        val open = PendingIntent.getActivity(
            c,
            ID_MISSED,
            Intent().setClassName(c, DIALPAD_ACTIVITY)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                .putExtra(EXTRA_SHOW_RECENTS, true),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return base(c, CHANNEL_MISSED)
            .setContentTitle(c.getString(R.string.dialer_notif_missed, count))
            .setCategory(Notification.CATEGORY_MISSED_CALL)
            .setContentIntent(open)
            .setAutoCancel(true)
            .setNumber(count)
            .build()
    }

    private fun base(c: Context, channel: String): NotificationCompat.Builder =
        NotificationCompat.Builder(c, channel)
            .setSmallIcon(R.drawable.ic_launcher_monochrome)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setOnlyAlertOnce(true)
            .setLocalOnly(true)

    private fun screenIntent(c: Context, id: Int, nonce: ByteArray, action: String?, kind: Int): PendingIntent {
        val intent = Intent()
            .setClassName(c, IN_CALL_ACTIVITY)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            .putExtra(CallActionReceiver.EXTRA_CALL_ID, id)
            .putExtra(CallActionReceiver.EXTRA_NONCE, nonce)
        if (action != null) intent.action = action
        return PendingIntent.getActivity(
            c,
            requestCode(id, kind),
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    private fun actionIntent(c: Context, action: String, id: Int, nonce: ByteArray, kind: Int): PendingIntent {
        val intent = Intent(c, CallActionReceiver::class.java)
            .setAction(action)
            .putExtra(CallActionReceiver.EXTRA_CALL_ID, id)
            .putExtra(CallActionReceiver.EXTRA_NONCE, nonce)
        return PendingIntent.getBroadcast(
            c,
            requestCode(id, kind),
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    private fun requestCode(id: Int, kind: Int): Int = id * 4 + kind
}
