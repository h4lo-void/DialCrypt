package io.github.h4lovoid.dialcrypt.dialer

import android.app.KeyguardManager
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.os.SystemClock
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.dialer.model.InCallReducer
import io.github.h4lovoid.dialcrypt.dialer.model.IncomingUiPolicy
import io.github.h4lovoid.dialcrypt.dialer.model.UiCallState
import io.github.h4lovoid.dialcrypt.dialer.ui.InCallActions
import io.github.h4lovoid.dialcrypt.dialer.ui.InCallScreen
import io.github.h4lovoid.dialcrypt.incoming.CallRegistry
import io.github.h4lovoid.dialcrypt.incoming.PromptGate
import io.github.h4lovoid.dialcrypt.incoming.SecureHandoff
import io.github.h4lovoid.dialcrypt.ui.SecureWindow
import io.github.h4lovoid.dialcrypt.ui.theme.DialCryptTheme
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

/**
 * The default dialer's call screen in `:call`, shown over the lock screen. It reads the calls of
 * [InCallStore] as plain data and never opens over a call the secure flow owns: it closes as soon as
 * [InCallStore.finishRequests] fires or the registry reports a secure call. Over the lock screen
 * a contact's number shows only its last four digits; a number that is not a contact shows whole.
 */
class InCallActivity : ComponentActivity() {
    private val gate = PromptGate()
    private lateinit var handoff: SecureHandoff
    private val now = MutableStateFlow(System.currentTimeMillis())
    private val locked = MutableStateFlow(true)
    private var receiverRegistered = false

    private val screenReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) = refreshLocked()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecureWindow.apply(this)
        setShowWhenLocked(true)
        setTurnScreenOn(true)
        // A stale notification after `:call` restarted, or a secure call under way: nothing to show.
        if (InCallStore.service == null || !IncomingUiPolicy.mayShowInCall(CallRegistry.view.value, appDial = false)) {
            finishAndRemoveTask()
            return
        }
        handoff = SecureHandoff(
            activity = this,
            gate = gate,
            cancelNotices = ::cancelIncomingNotice,
            // The unlock was cancelled: the ringing call's notification, cancelled by the handoff, comes back.
            onAbandoned = InCallStore::representIncoming,
        )
        refreshLocked()
        if (savedInstanceState == null) answerFromNotification(intent)

        lifecycleScope.launch { InCallStore.finishRequests.collect { finishAndRemoveTask() } }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                while (true) {
                    now.value = System.currentTimeMillis()
                    delay(TIMER_STEP_MS)
                }
            }
        }

        val commands = InCallStore.commands
        val actions = InCallActions(
            answer = commands::answer,
            answerSecure = ::answerSecure,
            endAndAnswer = commands::endAndAnswer,
            decline = commands::reject,
            end = commands::end,
            hold = commands::hold,
            swap = commands::swap,
            merge = commands::merge,
            setMuted = commands::setMuted,
            route = commands::route,
            dtmf = commands::dtmf,
            selectAccount = commands::selectAccount,
            postDial = commands::postDial,
        )

        setContent {
            DialCryptTheme {
                val snapshots by InCallStore.snapshots.collectAsState()
                val audio by InCallStore.audio.collectAsState()
                val reg by CallRegistry.view.collectAsState()
                val showFull by InCallStore.showFull.collectAsState()
                val members by InCallStore.memberships.collectAsState()
                val ticks by InCallStore.ticks.collectAsState()
                val isLocked by locked.collectAsState()
                val nowMs by now.collectAsState()
                val ui = remember(snapshots, audio, reg, showFull, members, ticks, isLocked) {
                    InCallReducer.reduce(
                        snapshots, audio, reg, showFull, isLocked,
                        { n -> members[n] ?: ContactMembership.UNKNOWN },
                        SystemClock.elapsedRealtime(),
                    )
                }

                LaunchedEffect(ui.secureOwned) {
                    if (ui.secureOwned) finishAndRemoveTask()
                }
                val primary = ui.primary
                val gone = primary == null
                val ended = gone || (primary?.state == UiCallState.ENDED && ui.secondary == null)
                LaunchedEffect(ended, gone) {
                    if (ended && !gate.handoffStarted) {
                        if (!gone) delay(ENDED_LINGER_MS)
                        finishAndRemoveTask()
                    }
                }

                Box(Modifier.fillMaxSize().background(Palette.Background).safeDrawingPadding()) {
                    InCallScreen(state = ui, actions = actions, nowMs = nowMs, handoffBusy = gate.busy)
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        answerFromNotification(intent)
    }

    override fun onStart() {
        super.onStart()
        if (!receiverRegistered) {
            val filter = IntentFilter().apply {
                addAction(Intent.ACTION_USER_PRESENT)
                addAction(Intent.ACTION_SCREEN_OFF)
                addAction(Intent.ACTION_SCREEN_ON)
            }
            ContextCompat.registerReceiver(this, screenReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
            receiverRegistered = true
        }
        refreshLocked()
    }

    override fun onResume() {
        super.onResume()
        refreshLocked()
    }

    override fun onStop() {
        if (receiverRegistered) {
            runCatching { unregisterReceiver(screenReceiver) }
            receiverRegistered = false
        }
        super.onStop()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        refreshLocked()
    }

    /**
     * The notification's answer button opens this screen with [CallActionReceiver.ACTION_ANSWER].
     * The call id and nonce must name a call of this process; an old notification does nothing.
     */
    private fun answerFromNotification(intent: Intent?) {
        if (intent?.action != CallActionReceiver.ACTION_ANSWER) return
        val id = intent.getIntExtra(CallActionReceiver.EXTRA_CALL_ID, -1)
        val nonce = intent.getByteArrayExtra(CallActionReceiver.EXTRA_NONCE)
        if (InCallStore.accepts(id, nonce)) InCallStore.commands.answer(id)
    }

    private fun answerSecure() {
        val offer = CallRegistry.offers.value ?: return
        if (!gate.tryBegin()) return
        handoff.start(offer.token)
    }

    private fun refreshLocked() {
        locked.value = getSystemService(KeyguardManager::class.java)?.isKeyguardLocked ?: true
    }

    private fun cancelIncomingNotice() {
        runCatching { getSystemService(NotificationManager::class.java)?.cancel(DialerNotifications.ID_INCOMING) }
    }

    private companion object {
        const val TIMER_STEP_MS = 1_000L

        /** How long "Call ended" stays before the screen closes. */
        const val ENDED_LINGER_MS = 1_500L
    }
}

