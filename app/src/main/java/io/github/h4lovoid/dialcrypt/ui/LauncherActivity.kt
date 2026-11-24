package io.github.h4lovoid.dialcrypt.ui

import android.app.ActivityManager
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import io.github.h4lovoid.dialcrypt.core.CoreProvider
import io.github.h4lovoid.dialcrypt.core.LockdownPhase
import io.github.h4lovoid.dialcrypt.core.daemon.DaemonLockdownController
import io.github.h4lovoid.dialcrypt.core.daemon.SessionLease
import io.github.h4lovoid.dialcrypt.incoming.RelayProtocol

/**
 * Default process. Loads no native code and touches no secrets: it shows a neutral start screen,
 * asks the privileged helper to prepare once the user taps Start, then starts the secure process
 * and ends itself. The activity is exported, so no other app may start the preparation or hand it
 * a call token: only a launch by this app's own uid counts as a call handoff.
 */
class LauncherActivity : ComponentActivity() {
    private var handoffToken: ByteArray? = null
    private var launchedByThisApp = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        SecureWindow.apply(this)
        // A window drawn over this screen must not be able to pass a tap through to Start.
        window.decorView.filterTouchesWhenObscured = true
        launchedByThisApp = isOwnLaunch(
            Build.VERSION.SDK_INT,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) launchedFromUid else Process.INVALID_UID,
            Process.myUid(),
        )
        captureHandoff(intent)
        // The secure screen is still up (left a moment ago, within its grace period): go back to it.
        // A new preparation would ask the daemon for a second session, which it refuses.
        if (returnToLiveSecureTask()) {
            finishAndRemoveTask()
            return
        }
        val lockdown = CoreProvider.lockdown(this)
        // Only a call handoff from this app prepares without a tap; every other start waits for Start.
        if (handoffToken != null && lockdown.state.value.phase == LockdownPhase.IDLE) lockdown.prepare()
        setContent {
            LauncherRoot(
                lockdown = lockdown,
                prefs = CoreProvider.preferences(this),
                onReady = ::startSecureProcess,
                fastHandoff = handoffToken != null,
            )
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // Who sent a new intent cannot be checked, so a call token never arrives this way. This app's
        // own handoff clears the task and comes in through onCreate.
        intent.removeExtra(RelayProtocol.EXTRA_HANDOFF_TOKEN)
        setIntent(intent)
    }

    private fun captureHandoff(intent: Intent?) {
        val tok = intent?.getByteArrayExtra(RelayProtocol.EXTRA_HANDOFF_TOKEN) ?: return
        intent.removeExtra(RelayProtocol.EXTRA_HANDOFF_TOKEN)
        acceptHandoffToken(launchedByThisApp, tok)?.let { handoffToken = it }
    }

    /** True when a live secure task was brought back to the front, handing over a pending call token. */
    private fun returnToLiveSecureTask(): Boolean {
        val am = getSystemService(ActivityManager::class.java) ?: return false
        // Only a task whose secure process is still alive; otherwise the system would rebuild it with a spent lease.
        val secureAlive = runCatching {
            am.runningAppProcesses?.any { it.processName == "$packageName:secure" } == true
        }.getOrDefault(false)
        if (!secureAlive) return false
        val task = runCatching {
            am.appTasks.firstOrNull { it.taskInfo.baseActivity?.className == SecureActivity::class.java.name }
        }.getOrNull() ?: return false
        val tok = handoffToken
        return runCatching {
            if (tok != null) {
                // singleTask: delivered to the running SecureActivity through onNewIntent.
                startActivity(Intent(this, SecureActivity::class.java).putExtra(RelayProtocol.EXTRA_HANDOFF_TOKEN, tok))
                handoffToken = null
            } else {
                task.moveToFront()
            }
            true
        }.getOrDefault(false)
    }

    private fun startSecureProcess() {
        val lockdown = CoreProvider.lockdown(this)
        val intent = Intent(this, SecureActivity::class.java)
        val daemon = lockdown is DaemonLockdownController
        if (lockdown is DaemonLockdownController) {
            intent.putExtra(SessionLease.EXTRA_LEASE, lockdown.lease() ?: return)
        }
        handoffToken?.let { tok ->
            intent.putExtra(RelayProtocol.EXTRA_HANDOFF_TOKEN, tok)
            handoffToken = null
        }
        startActivity(intent)
        finishAndRemoveTask()
        // The daemon accepts the secure process's ATTACH only once this process is gone, so end the whole process.
        if (daemon) Handler(Looper.getMainLooper()).postDelayed({ Process.killProcess(Process.myPid()) }, EXIT_DELAY_MS)
    }

    private companion object {
        const val EXIT_DELAY_MS = 300L
    }
}

/** True only when the platform reports the caller's uid (API 34+) and it is this app's own uid. */
internal fun isOwnLaunch(sdkInt: Int, launchedFromUid: Int, myUid: Int): Boolean =
    sdkInt >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE && launchedFromUid == myUid

/** The call token to keep, or null when it is empty or came from a launch that is not this app's own. */
internal fun acceptHandoffToken(launchedByThisApp: Boolean, token: ByteArray): ByteArray? =
    token.takeIf { launchedByThisApp && it.isNotEmpty() }
