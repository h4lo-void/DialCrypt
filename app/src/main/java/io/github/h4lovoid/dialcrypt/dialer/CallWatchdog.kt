package io.github.h4lovoid.dialcrypt.dialer

import android.os.Debug
import android.os.Handler
import android.os.Looper
import android.os.SystemClock

/**
 * Ends `:call` when its main thread stops responding during a live call, so Telecom binds the
 * in-call service again and the call can still be answered or ended. A background thread posts a
 * heartbeat to the main thread every [periodMs]; while a call is live and no debugger is attached,
 * [kill] runs once the last heartbeat is older than [timeoutMs]. The clock is uptime, so deep
 * sleep does not count as a stall.
 */
class CallWatchdog(
    private val isCallLive: () -> Boolean,
    private val timeoutMs: Long = 6_000L,
    private val kill: () -> Unit,
    private val clock: () -> Long = { SystemClock.uptimeMillis() },
    private val postToMain: (Runnable) -> Unit = mainPoster(),
    private val debuggerAttached: () -> Boolean = { Debug.isDebuggerConnected() || Debug.waitingForDebugger() },
    private val periodMs: Long = 1_000L,
) {
    @Volatile
    private var lastBeat: Long = 0L

    @Volatile
    private var killed: Boolean = false

    @Volatile
    private var thread: Thread? = null

    private val beat = Runnable { lastBeat = clock() }

    fun start() {
        if (thread != null) return
        lastBeat = clock()
        val t = Thread({ loop() }, "dialer-watchdog").apply { isDaemon = true }
        thread = t
        t.start()
    }

    fun stop() {
        val t = thread ?: return
        thread = null
        t.interrupt()
    }

    /** One heartbeat and one check; the background thread runs it every [periodMs]. */
    internal fun step() {
        postToMain(beat)
        check()
    }

    private fun check() {
        if (killed) return
        val now = clock()
        if (!isCallLive() || debuggerAttached()) {
            lastBeat = now
            return
        }
        if (now - lastBeat >= timeoutMs) {
            killed = true
            kill()
        }
    }

    private fun loop() {
        val me = Thread.currentThread()
        while (thread === me) {
            step()
            try {
                Thread.sleep(periodMs)
            } catch (_: InterruptedException) {
                return
            }
        }
    }
}

private fun mainPoster(): (Runnable) -> Unit {
    val main = Handler(Looper.getMainLooper())
    return { main.post(it) }
}
