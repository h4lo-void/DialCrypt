package io.github.h4lovoid.dialcrypt.dialer

import android.content.Context
import android.os.PowerManager
import io.github.h4lovoid.dialcrypt.dialer.model.AudioUi
import io.github.h4lovoid.dialcrypt.dialer.model.CallSnapshot
import io.github.h4lovoid.dialcrypt.dialer.model.Endpoint
import io.github.h4lovoid.dialcrypt.dialer.model.TelecomState

/**
 * Proximity screen-off lock of `:call`, driven by [InCallStore] after every change of the calls,
 * the audio route or the secure flow. It follows the calls, not the in-call screen's lifecycle: the
 * screen turning off near the ear stops the activity, and the lock must stay held through that.
 */
internal class ProximityLock(private val acquire: () -> Unit, private val release: () -> Unit) {
    var held: Boolean = false
        private set

    fun update(wanted: Boolean) {
        if (wanted == held) return
        held = wanted
        if (wanted) acquire() else release()
    }

    companion object {
        /** Upper bound of one hold, so a missed release cannot keep the lock forever. */
        private const val MAX_HOLD_MS = 6L * 60L * 60L * 1000L

        private val LIVE = setOf(TelecomState.DIALING, TelecomState.CONNECTING, TelecomState.ACTIVE, TelecomState.PULLING_CALL)

        /**
         * Held while a call is dialing or connected, the audio goes to the earpiece, and the secure
         * flow does not own the call (its own screen manages the display).
         */
        fun wanted(calls: List<CallSnapshot>, audio: AudioUi, secureOwned: Boolean): Boolean =
            !secureOwned && audio.endpoint == Endpoint.EARPIECE && calls.any { !it.conferenceChild && it.telecomState in LIVE }

        /** Null when the device has no proximity screen-off lock. */
        fun create(context: Context): ProximityLock? {
            val pm = context.getSystemService(PowerManager::class.java) ?: return null
            if (!pm.isWakeLockLevelSupported(PowerManager.PROXIMITY_SCREEN_OFF_WAKE_LOCK)) return null
            val lock = pm.newWakeLock(PowerManager.PROXIMITY_SCREEN_OFF_WAKE_LOCK, "phone:proximity")
            lock.setReferenceCounted(false)
            return ProximityLock(
                acquire = { runCatching { lock.acquire(MAX_HOLD_MS) } },
                release = {
                    runCatching { if (lock.isHeld) lock.release(PowerManager.RELEASE_FLAG_WAIT_FOR_NO_PROXIMITY) }
                },
            )
        }
    }
}
