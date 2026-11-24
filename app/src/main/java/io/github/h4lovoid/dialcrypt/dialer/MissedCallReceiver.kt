package io.github.h4lovoid.dialcrypt.dialer

import android.Manifest
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.telecom.TelecomManager
import androidx.core.content.ContextCompat

/**
 * Telecom's missed call broadcast to the default dialer, in `:dialer`. Only the count is read: the
 * number and the two PendingIntent extras of the broadcast are left untouched, and nothing is
 * logged. A count of zero removes the notification.
 */
class MissedCallReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != TelecomManager.ACTION_SHOW_MISSED_CALLS_NOTIFICATION) return
        show(context.applicationContext, intent.getIntExtra(TelecomManager.EXTRA_NOTIFICATION_COUNT, 0))
    }

    companion object {
        internal fun show(c: Context, count: Int) {
            val nm = c.getSystemService(NotificationManager::class.java) ?: return
            val notification = DialerNotifications.missed(c, count)
            if (notification == null) {
                runCatching { nm.cancel(DialerNotifications.ID_MISSED) }
                return
            }
            if (ContextCompat.checkSelfPermission(c, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
            DialerNotifications.ensureChannels(c)
            runCatching { nm.notify(DialerNotifications.ID_MISSED, notification) }
        }
    }
}

