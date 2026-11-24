package io.github.h4lovoid.dialcrypt.incoming

import android.app.Activity
import android.app.ActivityManager
import android.app.KeyguardManager
import java.util.ArrayDeque

/**
 * Re-asserts an Aegis task on top when another dialer window tries to cover it during an active
 * call or incoming prompt, rate-limited to avoid OS task-switching storms.
 */
internal class FrontKeeper(
    private val activity: Activity,
    private val shouldHold: () -> Boolean,
) {
    private val recentMoves = ArrayDeque<Long>(MAX_MOVES_IN_WINDOW)

    @Volatile
    var userLeft: Boolean = false
        private set

    fun markUserLeft() {
        userLeft = true
    }

    fun resetUserLeft() {
        userLeft = false
    }

    fun onCovered() {
        if (userLeft || activity.isFinishing || activity.isDestroyed || !shouldHold()) return
        val km = activity.getSystemService(KeyguardManager::class.java)
        if (km?.isKeyguardLocked == true && !showsWhenLocked()) return

        val now = System.currentTimeMillis()
        while (recentMoves.isNotEmpty() && now - recentMoves.first() > WINDOW_MS) {
            recentMoves.removeFirst()
        }
        if (recentMoves.size >= MAX_MOVES_IN_WINDOW) return
        recentMoves.addLast(now)

        val am = activity.getSystemService(ActivityManager::class.java) ?: return
        runCatching { am.moveTaskToFront(activity.taskId, 0) }
    }

    private fun showsWhenLocked(): Boolean = activity is IncomingPromptActivity

    private companion object {
        const val WINDOW_MS = 10_000L
        const val MAX_MOVES_IN_WINDOW = 6
    }
}
