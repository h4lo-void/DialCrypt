package io.github.h4lovoid.dialcrypt.call

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.ui.SecureActivity

/**
 * Foreground service in `:secure` (`phoneCall|microphone`) keeping audio capture/playback and
 * the cipher session alive during an active encrypted call if another window briefly covers `:secure`.
 */
class SecureCallService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        ensureChannel(applicationContext)
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val combinedType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL or
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            } else {
                0
            }
            if (combinedType != 0) {
                try {
                    startForeground(NOTIFY_ID, notification, combinedType)
                } catch (_: SecurityException) {
                    startForeground(NOTIFY_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE)
                }
            } else {
                startForeground(NOTIFY_ID, notification)
            }
        } else {
            startForeground(NOTIFY_ID, notification)
        }
        return START_NOT_STICKY
    }

    private fun buildNotification(): Notification {
        val openApp = PendingIntent.getActivity(
            this,
            NOTIFY_ID,
            Intent(this, SecureActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_monochrome)
            .setContentTitle(getString(R.string.call_service_title))
            .setContentText(getString(R.string.call_service_body))
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setOngoing(true)
            .setContentIntent(openApp)
            .build()
    }

    companion object {
        private const val CHANNEL_ID = "aegis_secure_call"
        private const val NOTIFY_ID = 4102
        private const val ACTION_STOP = "io.github.h4lovoid.dialcrypt.call.STOP_FGS"

        fun start(context: Context) {
            val app = context.applicationContext
            ensureChannel(app)
            val intent = Intent(app, SecureCallService::class.java)
            runCatching { ContextCompat.startForegroundService(app, intent) }
        }

        fun stop(context: Context) {
            val app = context.applicationContext
            val intent = Intent(app, SecureCallService::class.java)
            runCatching { app.stopService(intent) }
        }

        private fun ensureChannel(context: Context) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
            val nm = context.getSystemService(NotificationManager::class.java) ?: return
            if (nm.getNotificationChannel(CHANNEL_ID) != null) return
            val ch = NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.call_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                setSound(null, null)
                enableVibration(false)
                setShowBadge(false)
            }
            nm.createNotificationChannel(ch)
        }
    }
}
