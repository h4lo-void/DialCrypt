package io.github.h4lovoid.dialcrypt.dialer

import android.Manifest
import android.app.Notification
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.IBinder
import android.os.Process
import android.os.SystemClock
import android.telecom.Call
import android.telecom.CallAudioState
import android.telecom.CallEndpoint
import android.telecom.InCallService
import android.util.Log
import androidx.core.content.ContextCompat
import io.github.h4lovoid.dialcrypt.call.CallAudioMuter
import io.github.h4lovoid.dialcrypt.dialer.model.IncomingUi
import io.github.h4lovoid.dialcrypt.dialer.model.IncomingUiPolicy
import io.github.h4lovoid.dialcrypt.dialer.model.RegistryView
import io.github.h4lovoid.dialcrypt.dialer.model.Screening
import io.github.h4lovoid.dialcrypt.dialer.model.TelecomState
import io.github.h4lovoid.dialcrypt.incoming.CallRegistry
import io.github.h4lovoid.dialcrypt.incoming.CallSource

/**
 * The default dialer's in-call service (UI = true) in `:call`. Telecom binds it only while the app
 * holds the dialer role. It feeds [CallRegistry], which then tracks these Call objects, and
 * [InCallStore], and presents ringing and ongoing calls through notifications and the in-call
 * screen. Nothing that would open the in-call screen is used while the secure flow owns a call.
 */
class DialerInCallService : InCallService() {
    private val watchdog = CallWatchdog(
        isCallLive = { InCallStore.hasLiveCall() },
        kill = {
            Log.w(TAG, "main thread stalled during a call; restarting the call process")
            Process.killProcess(Process.myPid())
        },
    )
    private val presenter: () -> Unit = { present() }

    // Dialer-call thread only.
    private var incomingShown: List<Any>? = null
    private var ongoingShown: List<Any>? = null
    private val screenStarted = HashSet<Int>()
    private val incomingReset: () -> Unit = { incomingShown = null }

    override fun onCreate() {
        super.onCreate()
        // Before the first unlock these files cannot be read; the resets then run right after the unlock.
        AfterFirstUnlock.run(applicationContext, ::resetLeftovers)
        DialerRole.syncLauncherAlias(applicationContext)
        DialerNotifications.ensureChannels(applicationContext)
        CallRegistry.attachService(CallSource.DIALER_UI, this)
        InCallStore.onChanged = presenter
        InCallStore.onIncomingReset = incomingReset
        InCallStore.attach(this)
        watchdog.start()
    }

    override fun onBind(intent: Intent?): IBinder? {
        CallRegistry.refreshRoleHeld(this)
        CallRegistry.setDialerUiBound(true)
        return super.onBind(intent)
    }

    override fun onUnbind(intent: Intent?): Boolean {
        // Also when Telecom hands an emergency call to the system phone app: step aside quietly.
        // A call still tracked from this service is ended in CallRegistry first, then the role is read again.
        CallRegistry.onServiceUnbound(CallSource.DIALER_UI, this)
        CallRegistry.setDialerUiBound(false)
        InCallStore.detach(this)
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        watchdog.stop()
        CallRegistry.detachService(CallSource.DIALER_UI, this)
        InCallStore.detach(this)
        InCallStore.handler.post {
            cancelAll()
            if (InCallStore.onChanged === presenter) InCallStore.onChanged = null
            if (InCallStore.onIncomingReset === incomingReset) InCallStore.onIncomingReset = null
        }
        super.onDestroy()
    }

    override fun onCallAdded(call: Call) {
        super.onCallAdded(call)
        CallRegistry.onCallAdded(CallSource.DIALER_UI, this, call)
        InCallStore.add(call)
    }

    override fun onCallRemoved(call: Call) {
        super.onCallRemoved(call)
        CallRegistry.onCallRemoved(CallSource.DIALER_UI, this, call)
        InCallStore.remove(call)
    }

    // Deprecated on API 34 but still delivered; CallRegistry steers the data route through it.
    @Suppress("OVERRIDE_DEPRECATION")
    override fun onCallAudioStateChanged(audioState: CallAudioState?) {
        super.onCallAudioStateChanged(audioState)
        CallRegistry.onCallAudioStateChanged(CallSource.DIALER_UI, audioState)
    }

    override fun onMuteStateChanged(isMuted: Boolean) {
        super.onMuteStateChanged(isMuted)
        InCallStore.setMuted(isMuted)
    }

    override fun onCallEndpointChanged(callEndpoint: CallEndpoint) {
        super.onCallEndpointChanged(callEndpoint)
        InCallStore.setEndpoint(callEndpoint)
    }

    override fun onAvailableCallEndpointsChanged(availableEndpoints: List<CallEndpoint>) {
        super.onAvailableCallEndpointsChanged(availableEndpoints)
        InCallStore.setAvailable(availableEndpoints)
    }

    override fun onBringToForeground(showDialpad: Boolean) {
        super.onBringToForeground(showDialpad)
        InCallStore.handler.post {
            val entries = InCallStore.entries()
            if (entries.isEmpty()) return@post
            val reg = CallRegistry.view.value
            val appDial = entries.any { !CallSnapshots.isIncoming(it.call.details) && isAppDial(it) }
            val ringing = entries.firstOrNull { !it.dropped && TelecomState.isRinging(it.call.details.state) }
            val ringingUi = ringing?.let { incomingUi(applicationContext, it, reg, SystemClock.elapsedRealtime()) }
            if (IncomingUiPolicy.mayBringToForeground(ringingUi, reg, appDial)) startScreen()
        }
    }

    /** Brings notifications and the in-call screen in line with the calls. Dialer-call thread. */
    private fun present() {
        val ctx = applicationContext
        val reg = CallRegistry.view.value
        val entries = InCallStore.entries()
        val now = SystemClock.elapsedRealtime()
        screenStarted.retainAll(entries.map { it.id }.toSet())

        val ringing = entries.firstOrNull { !it.dropped && TelecomState.isRinging(it.call.details.state) }
        if (ringing == null) {
            cancel(DialerNotifications.ID_INCOMING)
            incomingShown = null
        } else {
            val screening = InCallStore.screeningFor(ringing)
            val waited = now - ringing.addedMs
            val decision = incomingUi(ctx, ringing, reg, now)
            if (screening == Screening.PENDING) {
                val deadline = if (waited < IncomingUiPolicy.SCREENING_WAIT_MS) {
                    IncomingUiPolicy.SCREENING_WAIT_MS
                } else {
                    IncomingUiPolicy.ANSWER_WAIT_MS
                }
                if (waited < deadline) InCallStore.scheduleTick(ringing.addedMs + deadline)
            }
            if (decision != IncomingUi.WAIT) {
                val notice = IncomingUiPolicy.notice(decision, reg, screening, waited)
                val key = listOf(ringing.id, notice.fullScreen, notice.answer, notice.openUi)
                if (key != incomingShown) {
                    incomingShown = key
                    show(
                        ctx,
                        DialerNotifications.ID_INCOMING,
                        DialerNotifications.incoming(ctx, ringing.id, ringing.nonce, notice.fullScreen, notice.answer, notice.openUi),
                    )
                }
                if (decision == IncomingUi.FULL_SCREEN_AND_START && notice.openUi) startScreenOnce(ringing.id)
            }
        }

        val live = entries.filter { val s = it.call.details.state; !it.dropped && !TelecomState.isRinging(s) && !TelecomState.isEnding(s) }
        val ongoing = live.firstOrNull { it.call.details.state == Call.STATE_ACTIVE } ?: live.firstOrNull()
        if (ongoing == null) {
            cancel(DialerNotifications.ID_ONGOING)
            ongoingShown = null
        } else {
            val outgoing = !CallSnapshots.isIncoming(ongoing.call.details)
            val appDial = outgoing && isAppDial(ongoing)
            val secure = reg.secureOwned || appDial
            val connectMs = ongoing.call.details.connectTimeMillis
            val key = listOf(ongoing.id, secure, connectMs)
            if (key != ongoingShown) {
                ongoingShown = key
                show(
                    ctx,
                    DialerNotifications.ID_ONGOING,
                    DialerNotifications.ongoing(ctx, ongoing.id, ongoing.nonce, secure, connectMs),
                )
            }
            if (outgoing && IncomingUiPolicy.mayShowInCall(reg, appDial)) startScreenOnce(ongoing.id)
        }
    }

    private fun isAppDial(e: InCallStore.Entry): Boolean = CallRegistry.isAppDial(CallSnapshots.number(e.call.details))

    /** How the ringing call [e] is presented. Dialer-call thread. */
    private fun incomingUi(ctx: Context, e: InCallStore.Entry, reg: RegistryView, now: Long): IncomingUi {
        val tracked = CallRegistry.isTracked(e.call)
        return IncomingUiPolicy.decide(
            s = InCallStore.screeningFor(e),
            offerToSecure = tracked && reg.offerToSecure,
            secureOwnedOther = reg.secureOwned && !tracked,
            waitedMs = now - e.addedMs,
            fsiAllowed = fsiAllowed(ctx),
        )
    }

    private fun startScreenOnce(id: Int) {
        if (screenStarted.add(id)) startScreen()
    }

    private fun startScreen() {
        val intent = Intent().setClassName(this, DialerNotifications.IN_CALL_ACTIVITY).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { startActivity(intent) }
    }

    private fun cancelAll() {
        cancel(DialerNotifications.ID_INCOMING)
        cancel(DialerNotifications.ID_ONGOING)
        incomingShown = null
        ongoingShown = null
        screenStarted.clear()
    }

    private fun canNotify(ctx: Context): Boolean =
        ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    /** A full-screen notification can actually be shown; otherwise the screen is started directly. */
    private fun fsiAllowed(ctx: Context): Boolean {
        val nm = ctx.getSystemService(NotificationManager::class.java) ?: return false
        return canNotify(ctx) && nm.areNotificationsEnabled() && runCatching { nm.canUseFullScreenIntent() }.getOrDefault(false)
    }

    private fun show(ctx: Context, id: Int, n: Notification) {
        if (!canNotify(ctx)) return
        runCatching { ctx.getSystemService(NotificationManager::class.java)?.notify(id, n) }
    }

    private fun cancel(id: Int) {
        runCatching { applicationContext.getSystemService(NotificationManager::class.java)?.cancel(id) }
    }

    private companion object {
        const val TAG = "DialerInCall"

        /** Undoes what an interrupted call or an earlier process left behind. Needs the user to be unlocked. */
        fun resetLeftovers(ctx: Context) {
            CallAudioMuter.recoverLeftover(ctx)
            CallAudioMuter.recoverOrphan(ctx, "secure")
            SecureBusyMarker.set(ctx, CallRegistry.view.value.secureOwned)
            PendingLogErase.reset(ctx)
            InCallStore.onUserUnlocked()
        }
    }
}
