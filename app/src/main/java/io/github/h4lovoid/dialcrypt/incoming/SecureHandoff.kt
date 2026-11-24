package io.github.h4lovoid.dialcrypt.incoming

import android.app.ActivityOptions
import android.app.KeyguardManager
import android.content.Intent
import android.os.Build
import androidx.activity.ComponentActivity
import io.github.h4lovoid.dialcrypt.ui.LauncherActivity

/**
 * Hands a ringing call over to the secure flow: unlocks the keyguard if needed, then starts a fresh
 * [LauncherActivity] carrying the offer token and closes [activity]. A cancelled or failed unlock
 * releases [gate] and calls [onAbandoned].
 */
internal class SecureHandoff(
    private val activity: ComponentActivity,
    private val gate: PromptGate,
    private val cancelNotices: () -> Unit,
    private val onAbandoned: () -> Unit,
) {
    fun start(token: ByteArray) {
        cancelNotices()
        val launchIntent = Intent(activity, LauncherActivity::class.java).apply {
            // A fresh launcher every time: it accepts the token only in onCreate, where it can check who started it.
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            putExtra(RelayProtocol.EXTRA_HANDOFF_TOKEN, token)
        }
        val km = activity.getSystemService(KeyguardManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && km?.isKeyguardLocked == true) {
            km.requestDismissKeyguard(
                activity,
                object : KeyguardManager.KeyguardDismissCallback() {
                    override fun onDismissSucceeded() {
                        startHandoff(launchIntent)
                        activity.finishAndRemoveTask()
                    }

                    override fun onDismissCancelled() {
                        abandon()
                    }

                    override fun onDismissError() {
                        abandon()
                    }
                },
            )
        } else {
            startHandoff(launchIntent)
            activity.finishAndRemoveTask()
        }
    }

    private fun abandon() {
        gate.release()
        onAbandoned()
    }

    /**
     * On API 34+ the launch shares this app's identity, so LauncherActivity's
     * getLaunchedFromUid() check reliably sees our own uid before it accepts the token.
     */
    private fun startHandoff(launchIntent: Intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val options = ActivityOptions.makeBasic().apply { setShareIdentityEnabled(true) }.toBundle()
            activity.startActivity(launchIntent, options)
        } else {
            activity.startActivity(launchIntent)
        }
    }
}
