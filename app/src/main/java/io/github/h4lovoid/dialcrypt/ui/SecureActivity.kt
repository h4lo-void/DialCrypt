package io.github.h4lovoid.dialcrypt.ui

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.telephony.TelephonyManager
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import io.github.h4lovoid.dialcrypt.core.CoreProvider
import io.github.h4lovoid.dialcrypt.core.SecureForeground
import io.github.h4lovoid.dialcrypt.core.SessionPhase
import io.github.h4lovoid.dialcrypt.core.daemon.DaemonLockdownController
import io.github.h4lovoid.dialcrypt.core.daemon.DaemonProtocol
import io.github.h4lovoid.dialcrypt.core.daemon.SessionLease
import io.github.h4lovoid.dialcrypt.incoming.FrontKeeper
import io.github.h4lovoid.dialcrypt.incoming.RelayProtocol
import io.github.h4lovoid.dialcrypt.incoming.screen.ContactNumberIndex
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/** Runs in the ":secure" process. Wipe and duress end the whole process. */
class SecureActivity : ComponentActivity() {
    private var lease: SessionLease? = null
    private lateinit var frontKeeper: FrontKeeper
    private var attachReady by mutableStateOf(true)
    private var exitingUi by mutableStateOf(false)
    private val sessionOver = AtomicBoolean(false)
    private val exiting = AtomicBoolean(false)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private val mainHandler = Handler(Looper.getMainLooper())
    /** Between onStart and onStop. */
    private var started = false
    /** Stopped after having been started (false before the first onStart). */
    private var stopped = false
    /** The app was left while idle: locked, and the session ends after the grace period. */
    private var leftWhileIdle = false
    // Ends the secure session a little after the app was left; coming back in time cancels it.
    private val endAfterLeaving = Runnable {
        if (isChangingConfigurations) return@Runnable
        Log.w(TAG, "left the app: ending the secure session")
        exitApp()
    }
    // While stopped and not yet left, the call that kept the app open is checked again.
    private val leavePoll = object : Runnable {
        override fun run() {
            if (!stopped || sessionOver.get()) return
            evaluateLeave()
            if (!leftWhileIdle && !sessionOver.get()) mainHandler.postDelayed(this, LeavePolicy.POLL_MS)
        }
    }
    // No input for a while with nothing going on: lock while the app is in front.
    private val idleLock = Runnable { onIdle() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The process died and the system is rebuilding this screen from saved state, with the old
        // launch intent and its spent lease: start over from the launcher instead. A configuration
        // change also brings saved state, but within a process that already showed this screen.
        if (savedInstanceState != null && !shownInThisProcess) {
            Log.w(TAG, "rebuilt after the process died: restarting from the launcher")
            startActivity(Intent(this, LauncherActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            // This process started before the new READY, so the daemon would refuse its ATTACH: end it too.
            exiting.set(true)
            finishAndRemoveTask()
            return
        }
        shownInThisProcess = true
        // A secure call cut off by a crash or kill may have left the phone's microphone muted.
        io.github.h4lovoid.dialcrypt.call.CallAudioMuter.recoverLeftover(applicationContext)
        io.github.h4lovoid.dialcrypt.call.CallAudioMuter.recoverOrphan(applicationContext, "call")
        SecureWindow.apply(this)
        val core = CoreProvider.secureCore(this)
        val lockdown = CoreProvider.lockdown(this)
        val prefs = CoreProvider.preferences(this)
        frontKeeper = FrontKeeper(
            activity = this,
            shouldHold = { !exiting.get() && (core.callHeld.value || core.incoming.value != null) },
        )
        // Debug builds run on fakes without a daemon, so only the daemon-backed controller needs a lease.
        if (lockdown is DaemonLockdownController) {
            attachReady = false
            if (!attachToDaemon(lockdown)) {
                finish()
                return
            }
        }
        handleHandoffIntent(intent, core)
        // Not tied to Compose, which pauses while the screen is stopped: a call that ends then must still lock.
        scope.launch {
            combine(core.session, core.callHeld, core.incoming) { _, _, _ -> Unit }.collect { evaluateLeave() }
        }
        val numberIndex = ContactNumberIndex(applicationContext)
        setContent {
            AppRoot(
                core = core,
                lockdown = lockdown,
                prefs = prefs,
                onExit = ::secureExit,
                attachReady = attachReady,
                exiting = exitingUi,
                contactLookup = numberIndex::lookup,
            )
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleHandoffIntent(intent, CoreProvider.secureCore(this))
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) {
            if (::frontKeeper.isInitialized) frontKeeper.resetUserLeft()
        } else if (::frontKeeper.isInitialized) {
            frontKeeper.onCovered()
        }
    }

    override fun onStart() {
        super.onStart()
        started = true
        stopped = false
        SecureForeground.started = true
        leftWhileIdle = false
        mainHandler.removeCallbacks(leavePoll)
        // Back within the grace period (e.g. a stray tap on the system clipboard preview, which opens
        // its own editor on top): the vault stays locked, but the hardened session is kept.
        if (mainHandler.hasCallbacks(endAfterLeaving)) Log.w(TAG, "back within the grace period")
        mainHandler.removeCallbacks(endAfterLeaving)
        armIdleLock()
    }

    override fun onStop() {
        super.onStop()
        started = false
        stopped = true
        SecureForeground.started = false
        mainHandler.removeCallbacks(idleLock)
        if (isChangingConfigurations) return
        // Leaving the app locks it, unless a call or incoming handoff is in progress; then it is
        // checked again when that ends, and every few seconds while a plain call may still hold it.
        evaluateLeave()
        mainHandler.removeCallbacks(leavePoll)
        if (!leftWhileIdle && !sessionOver.get()) mainHandler.postDelayed(leavePoll, LeavePolicy.POLL_MS)
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        armIdleLock()
    }

    /** Main thread. What a stopped screen does now (see [LeavePolicy]). */
    private fun evaluateLeave() {
        if (!stopped || isChangingConfigurations || sessionOver.get()) return
        val core = CoreProvider.secureCore(this)
        val action = LeavePolicy.decide(
            phase = core.session.value.phase,
            callHeld = core.callHeld.value,
            incoming = core.incoming.value != null,
            phoneBusy = phoneBusy(),
            alreadyLeft = leftWhileIdle,
        )
        when (action) {
            LeavePolicy.Action.WAIT, LeavePolicy.Action.NONE -> Unit
            LeavePolicy.Action.EXIT -> {
                Log.w(TAG, "call ended while away: ending the secure session")
                exitApp()
            }
            LeavePolicy.Action.DISMISS_AND_LEAVE -> {
                core.dismissAbort()
                leaveIdle()
            }
            LeavePolicy.Action.LEAVE -> leaveIdle()
        }
    }

    /** Locks, and with a daemon lease ends the secure session after a short grace period. */
    private fun leaveIdle() {
        leftWhileIdle = true
        mainHandler.removeCallbacks(leavePoll)
        if (::frontKeeper.isInitialized) frontKeeper.markUserLeft()
        CoreProvider.secureCore(this).lock()
        // The vault is already locked, and the phone stays hardened until the session ends.
        if (lease != null) {
            Log.w(TAG, "left the app: locked, session ends in " + LEAVE_GRACE_MS / 1000 + " s")
            mainHandler.removeCallbacks(endAfterLeaving)
            mainHandler.postDelayed(endAfterLeaving, LEAVE_GRACE_MS)
        }
    }

    private fun armIdleLock() {
        mainHandler.removeCallbacks(idleLock)
        if (started) mainHandler.postDelayed(idleLock, LeavePolicy.IDLE_LOCK_MS)
    }

    private fun onIdle() {
        if (!started || sessionOver.get()) return
        val core = CoreProvider.secureCore(this)
        if (core.state.value.locked) return
        val phase = core.session.value.phase
        val idle = LeavePolicy.mayIdleLock(phase, core.callHeld.value, core.incoming.value != null, phoneBusy())
        if (idle) {
            Log.w(TAG, "no input for " + LeavePolicy.IDLE_LOCK_MS / 60_000 + " min: locked")
            // A finished call's end screen goes with the lock.
            if (phase != SessionPhase.IDLE) core.dismissAbort()
            core.lock()
        } else {
            armIdleLock()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // A later screen in this same process must not be ended by this one's pending exit.
        mainHandler.removeCallbacks(endAfterLeaving)
        mainHandler.removeCallbacks(leavePoll)
        mainHandler.removeCallbacks(idleLock)
        if (started) SecureForeground.started = false
        if (isFinishing) {
            sessionOver.set(true)
            lease?.end(0)
            // The daemon only accepts an ATTACH from a secure process started after its READY
            // (AttachTooEarly), so a finished secure screen takes its process with it; otherwise
            // the next start (e.g. after Back) would land in this process and be refused.
            if (exiting.get() || lease != null) Process.killProcess(Process.myPid())
        }
        scope.cancel()
    }

    private fun handleHandoffIntent(intent: Intent?, core: io.github.h4lovoid.dialcrypt.core.SecureCore) {
        val tok = intent?.getByteArrayExtra(RelayProtocol.EXTRA_HANDOFF_TOKEN) ?: return
        intent.removeExtra(RelayProtocol.EXTRA_HANDOFF_TOKEN)
        if (tok.isNotEmpty()) core.beginHandoff(tok)
    }

    /** A call is ringing or up: the session engine may be about to take it. */
    @Suppress("DEPRECATION")
    private fun phoneBusy(): Boolean = try {
        (getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager)?.callState != TelephonyManager.CALL_STATE_IDLE
    } catch (e: SecurityException) {
        false
    }

    private fun attachToDaemon(lockdown: DaemonLockdownController): Boolean {
        val bytes = intent.getByteArrayExtra(SessionLease.EXTRA_LEASE)
        intent.removeExtra(SessionLease.EXTRA_LEASE)
        if (bytes == null || bytes.size != DaemonProtocol.LEASE_SIZE) return false
        val sLease = SessionLease(bytes, onViolation = { sessionLost() }, onLost = { sessionLost() }).also { it.start() }
        lease = sLease
        bytes.fill(0)
        scope.launch {
            sLease.info.collect { info ->
                if (info != null) {
                    lockdown.applyAttach(info)
                    attachReady = true
                }
            }
        }
        return true
    }

    /** The daemon reported a violation or the connection is gone: wipe, then end the process. */
    private fun sessionLost() {
        if (!sessionOver.compareAndSet(false, true)) return
        scope.launch {
            runCatching { CoreProvider.secureCore(this@SecureActivity).endAndWipe() }
            exitApp()
        }
    }

    private fun secureExit() {
        if (!sessionOver.compareAndSet(false, true)) return
        // From now on an incoming offer goes to the :call prompt, not to this ending screen.
        SecureForeground.started = false
        exitingUi = true
        if (::frontKeeper.isInitialized) frontKeeper.markUserLeft()
        val core = CoreProvider.secureCore(this)
        scope.launch {
            withContext(Dispatchers.IO) {
                withTimeoutOrNull(2_500L) { core.prepareExit() }
                lease?.end(2_500L)
            }
            finishAndRemoveTask()
            if (exiting.compareAndSet(false, true)) {
                Handler(Looper.getMainLooper()).postDelayed({ Process.killProcess(Process.myPid()) }, EXIT_FALLBACK_MS)
            }
        }
    }

    private fun exitApp() {
        sessionOver.set(true)
        SecureForeground.started = false
        if (::frontKeeper.isInitialized) frontKeeper.markUserLeft()
        scope.launch {
            withContext(Dispatchers.IO) { lease?.end(0) }
            finishAndRemoveTask()
            if (exiting.compareAndSet(false, true)) {
                Handler(Looper.getMainLooper()).postDelayed({ Process.killProcess(Process.myPid()) }, EXIT_FALLBACK_MS)
            }
        }
    }

    private companion object {
        const val TAG = "AegisSecure"
        const val EXIT_FALLBACK_MS = 450L
        const val LEAVE_GRACE_MS = 15_000L

        // Set once this process has shown the secure screen; saved state without it means the process was rebuilt.
        @Volatile
        var shownInThisProcess = false
    }
}
