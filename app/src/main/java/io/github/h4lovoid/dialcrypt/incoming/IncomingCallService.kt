package io.github.h4lovoid.dialcrypt.incoming

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.IBinder
import android.telecom.Call
import android.telecom.CallAudioState
import android.telecom.InCallService
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.call.IncomingOffer

/**
 * Isolated `InCallService` bound by Telecom in the `:call` process so incoming calls can be
 * screened even while `:secure` is completely stopped and the vault is locked.
 */
class IncomingCallService : InCallService() {
    override fun onCreate() {
        super.onCreate()
        io.github.h4lovoid.dialcrypt.call.CallAudioMuter.recoverLeftover(applicationContext)
        io.github.h4lovoid.dialcrypt.call.CallAudioMuter.recoverOrphan(applicationContext, "secure")
        io.github.h4lovoid.dialcrypt.dialer.PendingLogErase.reset(applicationContext)
        CallRegistry.attachService(CallSource.NON_UI, this)
        ensureChannel(applicationContext)
    }

    override fun onBind(intent: Intent?): IBinder? {
        CallRegistry.refreshRoleHeld(this)
        return super.onBind(intent)
    }

    override fun onUnbind(intent: Intent?): Boolean {
        // A call still tracked from this service is ended in CallRegistry first, then the role is read again.
        CallRegistry.onServiceUnbound(CallSource.NON_UI, this)
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        CallRegistry.detachService(CallSource.NON_UI, this)
        super.onDestroy()
    }

    override fun onCallAdded(call: Call) {
        super.onCallAdded(call)
        CallRegistry.onCallAdded(CallSource.NON_UI, this, call)
    }

    override fun onCallRemoved(call: Call) {
        super.onCallRemoved(call)
        CallRegistry.onCallRemoved(CallSource.NON_UI, this, call)
    }

    override fun onCallAudioStateChanged(audioState: CallAudioState?) {
        super.onCallAudioStateChanged(audioState)
        CallRegistry.onCallAudioStateChanged(CallSource.NON_UI, audioState)
    }

    companion object {
        // A channel's lock screen visibility cannot change once created: the old channel (public on
        // the lock screen) is replaced by a new one created with VISIBILITY_SECRET.
        internal const val CHANNEL_ID = "aegis_incoming_call_secret"
        private const val LEGACY_CHANNEL_ID = "aegis_incoming_call"
        private const val NOTIFY_ID = 4101

        fun ensureChannel(context: Context) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
            val nm = context.getSystemService(NotificationManager::class.java) ?: return
            if (nm.getNotificationChannel(LEGACY_CHANNEL_ID) != null) {
                runCatching { nm.deleteNotificationChannel(LEGACY_CHANNEL_ID) }
            }
            if (nm.getNotificationChannel(CHANNEL_ID) != null) return
            val ch = NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.incoming_channel_name),
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                setSound(null, null)
                enableVibration(false)
                setShowBadge(false)
                lockscreenVisibility = Notification.VISIBILITY_SECRET
            }
            nm.createNotificationChannel(ch)
        }

        /**
         * The prompt notification never names the caller: no number and no contact name, only fixed
         * neutral text, and it is hidden on the lock screen. The caller is shown inside the
         * full-screen prompt, which uses FLAG_SECURE.
         */
        internal fun buildPromptNotification(context: Context, contentIntent: PendingIntent): Notification =
            NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_launcher_monochrome)
                .setContentTitle(context.getString(R.string.incoming_prompt_title))
                .setContentText(context.getString(R.string.incoming_prompt_subtitle))
                .setCategory(NotificationCompat.CATEGORY_CALL)
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setVisibility(NotificationCompat.VISIBILITY_SECRET)
                .setOngoing(true)
                .setAutoCancel(false)
                .setFullScreenIntent(contentIntent, true)
                .setContentIntent(contentIntent)
                .build()

        fun showIncomingPrompt(context: Context, offer: IncomingOffer) {
            val promptIntent = postPromptNotification(context, offer)
            runCatching { context.startActivity(promptIntent) }
        }

        /** Posts (or re-posts) the prompt notification for [offer] and returns the prompt's intent. */
        internal fun postPromptNotification(context: Context, offer: IncomingOffer): Intent {
            ensureChannel(context)
            val promptIntent = Intent(context, IncomingPromptActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or
                    Intent.FLAG_ACTIVITY_SINGLE_TOP or
                    Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
                putExtra(RelayProtocol.EXTRA_HANDOFF_TOKEN, offer.token)
            }
            val fullScreenPi = PendingIntent.getActivity(
                context,
                NOTIFY_ID,
                promptIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )

            if (canNotify(context)) {
                val nm = context.getSystemService(NotificationManager::class.java)
                val notification = buildPromptNotification(context, fullScreenPi)
                runCatching { nm?.notify(NOTIFY_ID, notification) }
            }
            return promptIntent
        }

        fun cancelPromptNotification(context: Context) {
            val nm = context.getSystemService(NotificationManager::class.java)
            runCatching { nm?.cancel(NOTIFY_ID) }
        }

        private fun canNotify(context: Context): Boolean {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
            return ContextCompat.checkSelfPermission(
                context,
                android.Manifest.permission.POST_NOTIFICATIONS,
            ) == PackageManager.PERMISSION_GRANTED
        }
    }
}
