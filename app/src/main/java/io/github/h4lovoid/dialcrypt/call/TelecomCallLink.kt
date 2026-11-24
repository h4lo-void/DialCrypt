package io.github.h4lovoid.dialcrypt.call

import android.content.Context
import android.net.Uri
import android.os.Bundle
import android.telecom.TelecomManager
import android.telecom.VideoProfile
import android.telephony.PhoneStateListener
import android.telephony.PreciseCallState
import android.telephony.TelephonyManager
import android.util.Log
import java.lang.reflect.Method
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * [CallLink] over Telecom and Telephony. Phases come from the precise call state (privileged
 * READ_PRECISE_PHONE_STATE), so an outgoing call becomes ACTIVE only once the far end answers.
 * When precise state is refused or never delivered, the link falls back to the plain call state
 * (see [legacyObservation]) and logs it once.
 */
class TelecomCallLink(context: Context) : CallLink {
    private val appContext: Context = context.applicationContext ?: context
    private val telecom: TelecomManager? = appContext.getSystemService(TelecomManager::class.java)
    private val telephony: TelephonyManager? = appContext.getSystemService(TelephonyManager::class.java)
    private val executor = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "aegis-call-state").apply { isDaemon = true }
    }
    private val lock = Any()
    private val tracker = CallTracker()
    private val state = MutableStateFlow(CallStatus())
    private var preciseSeen = false
    private var audio: PcmCallAudio? = null

    override val status: StateFlow<CallStatus> = state.asStateFlow()

    private val listener = Listener()

    init {
        register()
    }

    override fun dial(number: String): Boolean {
        val tc = telecom ?: return false
        val target = number.trim()
        if (target.isEmpty()) return false
        synchronized(lock) {
            if (tracker.status.phase in LIVE_PHASES || platformInCall(tc)) return false
            val previous = tracker.beginDial(target)
            val extras = Bundle().apply {
                putInt(TelecomManager.EXTRA_START_CALL_WITH_VIDEO_STATE, VideoProfile.STATE_AUDIO_ONLY)
                putBoolean(TelecomManager.EXTRA_START_CALL_WITH_SPEAKERPHONE, false)
            }
            try {
                tc.placeCall(Uri.fromParts("tel", target, null), extras)
            } catch (e: Exception) {
                tracker.cancelDial(previous)
                Log.w(TAG, "dial refused: ${e.javaClass.simpleName}")
                return false
            }
            publish()
            val seq = tracker.dialSeq
            executor.schedule({ update { tracker.onDialTimeout(seq) } }, DIAL_TIMEOUT_S, TimeUnit.SECONDS)
        }
        return true
    }

    @Suppress("DEPRECATION")
    override fun answer(): Boolean {
        val tc = telecom ?: return false
        synchronized(lock) {
            if (tracker.status.phase != CallPhase.RINGING) return false
        }
        return try {
            tc.acceptRingingCall(VideoProfile.STATE_AUDIO_ONLY)
            scheduleAnswerRetry(tc, ANSWER_RETRIES)
            true
        } catch (e: Exception) {
            Log.w(TAG, "answer refused: ${e.javaClass.simpleName}")
            false
        }
    }

    /**
     * Telecom ignores acceptRingingCall while it is still screening the call. Verified on a
     * Pixel 7a (Android 16): one request made the moment RINGING was reported had no effect
     * and the call rang out. Repeat until the call leaves RINGING or the attempts run out.
     */
    @Suppress("DEPRECATION")
    private fun scheduleAnswerRetry(tc: TelecomManager, left: Int) {
        if (left <= 0) return
        executor.schedule({
            val ringing = synchronized(lock) { tracker.status.phase == CallPhase.RINGING }
            if (ringing) {
                try {
                    tc.acceptRingingCall(VideoProfile.STATE_AUDIO_ONLY)
                    Log.i(TAG, "answer repeated, left=${left - 1}")
                    scheduleAnswerRetry(tc, left - 1)
                } catch (e: Exception) {
                    Log.w(TAG, "answer retry refused: ${e.javaClass.simpleName}")
                }
            }
        }, ANSWER_RETRY_MS, TimeUnit.MILLISECONDS)
    }

    @Suppress("DEPRECATION")
    override fun hangUp() {
        val tc = telecom ?: return
        val ended = try {
            tc.endCall()
        } catch (e: Exception) {
            Log.w(TAG, "hang up refused: ${e.javaClass.simpleName}")
            return
        }
        if (!ended) update { tracker.onNothingToEnd() }
    }

    override fun openAudio(): CallAudio? {
        synchronized(lock) {
            if (tracker.status.phase != CallPhase.ACTIVE) {
                Log.w(AUDIO_TAG, "openAudio refused: call not active")
                return null
            }
            if (audio?.isClosed == false) {
                Log.w(AUDIO_TAG, "openAudio refused: streams already open")
                return null
            }
            val opened = CallAudioRoutes.open(appContext)
            audio = opened
            return opened
        }
    }

    @Suppress("DEPRECATION")
    private fun register() {
        val tm = telephony
        if (tm == null) {
            Log.w(TAG, "no telephony service")
            return
        }
        if (PreciseReader.available) {
            try {
                update { tracker.usePrecise(true) }
                tm.listen(listener, PhoneStateListener.LISTEN_CALL_STATE or LISTEN_PRECISE_CALL_STATE)
                // Registration delivers the current precise state at once; silence means it never comes.
                executor.schedule({
                    update { if (preciseSeen) tracker.status else fallBack("precise call state not delivered") }
                }, PRECISE_PROBE_S, TimeUnit.SECONDS)
                return
            } catch (e: SecurityException) {
                update { fallBack("precise call state refused") }
            }
        } else {
            update { fallBack("precise call state type missing") }
        }
        try {
            tm.listen(listener, PhoneStateListener.LISTEN_CALL_STATE)
        } catch (e: SecurityException) {
            Log.w(TAG, "call state refused; status follows dial only")
        }
    }

    private fun fallBack(reason: String): CallStatus {
        Log.w(TAG, "$reason; outgoing calls count as answered at OFFHOOK")
        return tracker.usePrecise(false)
    }

    private fun platformInCall(tc: TelecomManager): Boolean =
        try {
            tc.isInCall
        } catch (e: SecurityException) {
            false
        }

    private fun update(block: () -> CallStatus) {
        synchronized(lock) {
            block()
            publish()
        }
    }

    private fun publish() {
        val next = tracker.status
        val prev = state.value
        if (next == prev) return
        if (next.phase != prev.phase) Log.i(TAG, "phase ${next.phase} incoming=${next.incoming}")
        state.value = next
    }

    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    private inner class Listener : PhoneStateListener(executor) {
        override fun onCallStateChanged(state: Int, phoneNumber: String?) {
            update { tracker.onLegacy(state, phoneNumber) }
        }

        /** Hidden @SystemApi callback; same JVM signature as the framework method, so it overrides it. */
        fun onPreciseCallStateChanged(callState: PreciseCallState) {
            val s = PreciseReader.read(callState) ?: return
            update {
                preciseSeen = true
                tracker.onPrecise(s[0], s[1], s[2])
            }
        }
    }

    /** Reads ringing, foreground and background states from the framework PreciseCallState. */
    private object PreciseReader {
        private val getters: List<Method>? = try {
            val c = Class.forName("android.telephony.PreciseCallState")
            listOf(
                c.getMethod("getRingingCallState"),
                c.getMethod("getForegroundCallState"),
                c.getMethod("getBackgroundCallState"),
            )
        } catch (e: Exception) {
            null
        }

        val available: Boolean get() = getters != null

        fun read(callState: Any): IntArray? {
            val g = getters ?: return null
            return try {
                IntArray(3) { g[it].invoke(callState) as Int }
            } catch (e: Exception) {
                Log.w(TAG, "precise call state unreadable: ${e.javaClass.simpleName}")
                null
            }
        }
    }

    private companion object {
        const val TAG = "AegisCallLink"
        /** PhoneStateListener.LISTEN_PRECISE_CALL_STATE (@SystemApi). */
        const val LISTEN_PRECISE_CALL_STATE = 0x00000800
        const val DIAL_TIMEOUT_S = 20L
        const val PRECISE_PROBE_S = 5L
        const val ANSWER_RETRIES = 20
        const val ANSWER_RETRY_MS = 500L
    }
}
