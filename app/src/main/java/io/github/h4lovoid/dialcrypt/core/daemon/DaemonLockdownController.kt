package io.github.h4lovoid.dialcrypt.core.daemon

import android.content.Context
import android.net.LocalSocket
import android.util.Log
import io.github.h4lovoid.dialcrypt.core.AccessibilityCheck
import io.github.h4lovoid.dialcrypt.core.AppCheck
import io.github.h4lovoid.dialcrypt.core.HardeningLevel
import io.github.h4lovoid.dialcrypt.core.ItemStatus
import io.github.h4lovoid.dialcrypt.core.LockdownController
import io.github.h4lovoid.dialcrypt.core.LockdownFailure
import io.github.h4lovoid.dialcrypt.core.LockdownPhase
import io.github.h4lovoid.dialcrypt.core.LockdownState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import java.io.IOException
import java.util.Timer
import java.util.TimerTask
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Asks the root daemon over its abstract socket to check the device and harden it. Runs in the launcher
 * process. After READY the connection is closed: the daemon keeps the prepared session and waits for the
 * secure process to attach with the lease returned by [lease].
 *
 * Before the daemon is asked, the app checks that no accessibility service is enabled ([accessibilityOff]);
 * when one is, preparation fails at once (fail closed) and the daemon is not contacted.
 */
class DaemonLockdownController(
    context: Context,
    private val accessibilityOff: () -> Boolean = { AccessibilityCheck.noneEnabled(context) },
) : LockdownController {
    private val flow = MutableStateFlow(
        LockdownState(LockdownPhase.IDLE, PrepMapping.itemsFor(HardeningLevel.LEVEL_1, ItemStatus.PENDING)),
    )
    override val state: StateFlow<LockdownState> = flow

    @Volatile private var leaseBytes: ByteArray? = null

    /** A copy of the 16-byte lease once the phase is READY, otherwise null. */
    fun lease(): ByteArray? = leaseBytes?.copyOf()

    /** Updates lockdown state in `:secure` once `SessionLease` receives `ATTACHED` from the daemon. */
    fun applyAttach(info: AttachInfo) {
        val level = if (info.tier >= 2) HardeningLevel.LEVEL_2 else HardeningLevel.LEVEL_1
        val dry = info.mode == DaemonProtocol.MODE_DRY_RUN
        flow.update { current ->
            val items = applyReadyItems(current.items, info.tier, info.mode, info.claims)
            LockdownState(LockdownPhase.READY, items, level, dryRun = dry)
        }
    }

    override fun prepare() {
        synchronized(this) {
            if (flow.value.phase == LockdownPhase.PREPARING) return
            leaseBytes?.fill(0)
            leaseBytes = null
            val fresh = PrepMapping.itemsFor(HardeningLevel.LEVEL_1, ItemStatus.PENDING)
            if (!accessibilityOff()) {
                Log.w(TAG, "preparation refused: an accessibility service is enabled")
                flow.value = LockdownState(
                    LockdownPhase.FAILED,
                    PrepMapping.appCheckFailed(fresh, AppCheck.NO_ACCESSIBILITY_SERVICES),
                    HardeningLevel.LEVEL_1,
                )
                return
            }
            flow.value = LockdownState(
                LockdownPhase.PREPARING,
                fresh,
                HardeningLevel.LEVEL_1,
            )
        }
        Thread({
            // Right after a session ends the daemon is still restoring the phone and answers BUSY;
            // ask again a little later instead of showing a failed preparation.
            var attempt = 0
            while (converse(lastTry = attempt >= BUSY_RETRIES)) {
                attempt++
                Thread.sleep(BUSY_RETRY_MS)
            }
        }, "aegis-prepare").apply { isDaemon = true; start() }
    }

    /** One PREPARE conversation. True, with nothing published, when the daemon was only busy and [lastTry] is false. */
    private fun converse(lastTry: Boolean): Boolean {
        val socket = LocalSocket()
        val timer = Timer("aegis-prepare-timer", true)
        val timedOut = AtomicBoolean(false)
        val failures = ArrayList<PrepMapping.Mapped>()
        var onlyBusy = true
        var ready: ServerMsg.Ready? = null
        var protocolError = false
        try {
            timer.schedule(object : TimerTask() {
                override fun run() {
                    timedOut.set(true)
                    DaemonSocket.closeQuietly(socket)
                }
            }, TIMEOUT_MS)
            DaemonSocket.connect(socket)
            val out = socket.outputStream
            val input = socket.inputStream
            try {
                out.write(DaemonCodec.encodeClient(ClientMsg.Hello(DaemonProtocol.VERSION)))
                out.flush()
            } catch (_: IOException) {
                // The daemon may already have refused this caller; its FAIL can still be read below.
            }
            val reader = FrameReader()
            val buf = ByteArray(128)
            var prepareSent = false
            read@ while (true) {
                val n = input.read(buf)
                if (n < 0) break
                for (body in reader.push(buf, 0, n)) {
                    when (val m = DaemonCodec.decodeServer(body)) {
                        is ServerMsg.Hello -> {
                            if (m.version != DaemonProtocol.VERSION) {
                                protocolError = true
                                break@read
                            }
                            if (!prepareSent) {
                                prepareSent = true
                                out.write(DaemonCodec.encodeClient(ClientMsg.Prepare))
                                out.flush()
                            }
                        }
                        is ServerMsg.Progress -> flow.update { it.copy(items = PrepMapping.applyProgress(it.items, m.step)) }
                        is ServerMsg.Ready -> {
                            ready = m
                            break@read
                        }
                        is ServerMsg.Fail -> {
                            Log.w(TAG, "daemon refused: item=${m.item} code=${m.code}")
                            if (m.item != ITEM_PROTOCOL || m.code != CODE_BUSY) onlyBusy = false
                            failures.add(PrepMapping.mapFail(m.item, m.code, flow.value.items))
                            // A precheck sends every failure and then closes; do not wait for a daemon that does not.
                            if (failures.size == 1) {
                                timer.schedule(object : TimerTask() {
                                    override fun run() = DaemonSocket.closeQuietly(socket)
                                }, DRAIN_MS)
                            }
                        }
                        is ServerMsg.Attached, is ServerMsg.Violation, is ServerMsg.Ended -> {
                            protocolError = true
                            break@read
                        }
                    }
                }
            }
        } catch (_: IOException) {
            // Connect failed or the connection broke: decided below from what was received.
        } catch (_: FrameException) {
            protocolError = true
        } finally {
            timer.cancel()
            DaemonSocket.closeQuietly(socket)
        }
        val r = ready
        if (r == null && failures.isNotEmpty() && onlyBusy && !lastTry) return true
        when {
            r != null -> {
                leaseBytes = r.lease.copyOf()
                val level = if (r.tier >= 2) HardeningLevel.LEVEL_2 else HardeningLevel.LEVEL_1
                val items = flow.updateAndReturnItems(r)
                val dry = r.mode == DaemonProtocol.MODE_DRY_RUN
                flow.update { LockdownState(LockdownPhase.READY, items, level, dryRun = dry) }
            }
            failures.isNotEmpty() ->
                flow.update { it.copy(phase = LockdownPhase.FAILED, items = PrepMapping.markFailed(it.items, failures)) }
            timedOut.get() -> failWith(LockdownFailure.TIMEOUT)
            protocolError -> failWith(LockdownFailure.UNKNOWN)
            else -> failWith(LockdownFailure.DAEMON_UNREACHABLE)
        }
        return false
    }

    private fun MutableStateFlow<LockdownState>.updateAndReturnItems(r: ServerMsg.Ready): List<io.github.h4lovoid.dialcrypt.core.PrepItemState> =
        applyReadyItems(value.items, r.tier, r.mode, r.claims)

    private fun applyReadyItems(
        current: List<io.github.h4lovoid.dialcrypt.core.PrepItemState>,
        tier: Int,
        mode: Int,
        claims: Int,
    ): List<io.github.h4lovoid.dialcrypt.core.PrepItemState> {
        val base = PrepMapping.allDone(current, tier)
        if (tier < 2 || mode == DaemonProtocol.MODE_DRY_RUN) return base
        return base.map { st ->
            val missingClaim = when (st.item) {
                io.github.h4lovoid.dialcrypt.core.PrepItem.OTHER_APPS_STOPPED -> (claims and DaemonProtocol.CLAIM_APPS_STOPPED) == 0
                io.github.h4lovoid.dialcrypt.core.PrepItem.MEMORY_CLEARED -> (claims and DaemonProtocol.CLAIM_MEMORY_SCRUBBED) == 0
                else -> false
            }
            if (missingClaim) st.copy(status = ItemStatus.PENDING) else st
        }
    }

    private fun failWith(failure: LockdownFailure) {
        flow.update { it.copy(phase = LockdownPhase.FAILED, items = PrepMapping.failureOnly(it.items, failure)) }
    }

    private companion object {
        const val TAG = "AegisDaemon"
        const val TIMEOUT_MS = 30_000L
        const val DRAIN_MS = 1_000L
        // Fail item=21 (protocol) code=212 (busy): a previous session is still being torn down.
        const val ITEM_PROTOCOL = 21
        const val CODE_BUSY = 212
        const val BUSY_RETRIES = 8
        const val BUSY_RETRY_MS = 1_500L
    }
}
