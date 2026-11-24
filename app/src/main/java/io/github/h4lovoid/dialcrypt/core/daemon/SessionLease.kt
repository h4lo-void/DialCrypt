package io.github.h4lovoid.dialcrypt.core.daemon

import android.net.LocalSocket
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.IOException
import java.io.OutputStream
import java.util.Timer
import java.util.TimerTask
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The secure process's session with the daemon. [start] attaches with the lease from the launcher and then
 * sends a heartbeat every 500 ms; the daemon treats 2 s of silence as a dead App. Callbacks run on a
 * background thread. [onLost] fires once when the connection breaks or ATTACH is refused, and not after [end].
 */
class SessionLease(
    lease: ByteArray,
    private val onViolation: (code: Int) -> Unit,
    private val onLost: () -> Unit,
) {
    private val leaseBytes: ByteArray = lease.copyOf().also {
        require(it.size == DaemonProtocol.LEASE_SIZE) { "lease must be 16 bytes" }
    }
    private val writeLock = Any()
    private val started = AtomicBoolean(false)
    private val ending = AtomicBoolean(false)
    private val lostFired = AtomicBoolean(false)
    private val endedLatch = CountDownLatch(1)
    private val infoFlow = MutableStateFlow<AttachInfo?>(null)

    @Volatile private var socket: LocalSocket? = null
    @Volatile private var out: OutputStream? = null
    @Volatile private var attached = false
    @Volatile private var closed = false

    /** Set when the daemon has accepted the attach: mode, tier and what the daemon claims to have done. */
    val info: StateFlow<AttachInfo?> = infoFlow

    fun start() {
        if (!started.compareAndSet(false, true)) return
        Thread({ converse() }, "aegis-lease").apply { isDaemon = true; start() }
    }

    /** Tells the daemon the session is over and waits up to [waitForEndedMs] for ENDED, then closes. */
    fun end(waitForEndedMs: Long = END_WAIT_MS) {
        if (!ending.compareAndSet(false, true)) return
        val wasAttached = attached
        if (wasAttached) {
            try { send(ClientMsg.End) } catch (_: IOException) {}
            if (waitForEndedMs > 0) {
                try {
                    endedLatch.await(waitForEndedMs, TimeUnit.MILLISECONDS)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
        }
        closed = true
        DaemonSocket.closeQuietly(socket)
    }

    private fun converse() {
        val s = LocalSocket()
        socket = s
        val attachTimer = Timer("aegis-attach-timer", true)
        attachTimer.schedule(object : TimerTask() {
            override fun run() {
                if (!attached && !ending.get()) {
                    closed = true
                    DaemonSocket.closeQuietly(s)
                    lost()
                }
            }
        }, ATTACH_TIMEOUT_MS)
        try {
            DaemonSocket.connect(s)
            out = s.outputStream
            send(ClientMsg.Hello(DaemonProtocol.VERSION))
            val input = s.inputStream
            val reader = FrameReader()
            val buf = ByteArray(128)
            var attachSent = false
            loop@ while (true) {
                val n = input.read(buf)
                if (n < 0) break
                for (body in reader.push(buf, 0, n)) {
                    when (val m = DaemonCodec.decodeServer(body)) {
                        is ServerMsg.Hello -> {
                            if (m.version != DaemonProtocol.VERSION) break@loop
                            if (!attachSent) {
                                attachSent = true
                                send(ClientMsg.Attach(leaseBytes))
                            }
                        }
                        is ServerMsg.Attached -> if (!attached) {
                            attachTimer.cancel()
                            infoFlow.value = AttachInfo(m.mode, m.tier, m.claims)
                            attached = true
                            startHeartbeat()
                        }
                        is ServerMsg.Violation -> onViolation(m.code)
                        is ServerMsg.Ended -> {
                            endedLatch.countDown()
                            break@loop
                        }
                        // FAIL: ATTACH refused. The rest is not valid in this state. The daemon closes either way.
                        is ServerMsg.Fail, is ServerMsg.Progress, is ServerMsg.Ready -> break@loop
                    }
                }
            }
        } catch (_: IOException) {
            // Connect failed or the connection broke.
        } catch (_: FrameException) {
            // A malformed frame ends the session like a broken connection.
        } finally {
            attachTimer.cancel()
            closed = true
            DaemonSocket.closeQuietly(s)
        }
        lost()
    }

    private fun startHeartbeat() {
        Thread({
            var next = System.nanoTime()
            while (!closed && !ending.get()) {
                try {
                    send(ClientMsg.Heartbeat(leaseBytes))
                } catch (_: IOException) {
                    closed = true
                    DaemonSocket.closeQuietly(socket)
                    lost()
                    return@Thread
                }
                next += HEARTBEAT_NANOS
                val wait = next - System.nanoTime()
                if (wait > 0) {
                    try {
                        Thread.sleep(wait / 1_000_000, (wait % 1_000_000).toInt())
                    } catch (_: InterruptedException) {
                        return@Thread
                    }
                }
            }
        }, "aegis-heartbeat").apply { isDaemon = true; start() }
    }

    private fun send(m: ClientMsg) {
        val bytes = DaemonCodec.encodeClient(m)
        synchronized(writeLock) {
            // After END nothing else is sent.
            if (m is ClientMsg.Heartbeat && ending.get()) return
            val o = out ?: throw IOException("not connected")
            o.write(bytes)
            o.flush()
        }
    }

    private fun lost() {
        if (ending.get()) return
        if (lostFired.compareAndSet(false, true)) onLost()
    }

    companion object {
        /** Intent extra that carries the lease from the launcher to the secure process. */
        const val EXTRA_LEASE = "aegis.lease"
        const val END_WAIT_MS = 3_000L
        const val ATTACH_TIMEOUT_MS = 5_000L
        private const val HEARTBEAT_NANOS = 500_000_000L
    }
}
