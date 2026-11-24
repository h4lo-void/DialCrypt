package io.github.h4lovoid.dialcrypt.call

import android.content.ContentResolver
import android.content.Context
import android.content.pm.PackageManager
import android.database.ContentObserver
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.provider.CallLog
import android.util.Log

/**
 * Removes the system call log entry of a call the app placed or took over, best effort. The
 * system writes that entry shortly after the call ends, so each [erase] watches the call log
 * (a ContentObserver plus a short poll) for up to [TIMEOUT_MS] and deletes the one row that
 * [CallLogMatcher] ties to the call, the one dated closest to its start, then stops. A call
 * leaves a single row, so a single row is the most it ever deletes, and only by _ID.
 *
 * Without READ_CALL_LOG and WRITE_CALL_LOG it does nothing and logs one line. Logs never contain
 * a number. All work runs on [handler]'s thread (a private background thread by default).
 */
internal class CallLogEraser(context: Context, handler: Handler? = null) {
    private val appContext: Context = context.applicationContext ?: context
    private val resolver: ContentResolver = appContext.contentResolver
    private val worker: Handler = handler ?: sharedHandler

    /** Starts watching for the entry of [target]; [onDone] runs on the worker thread when the watch ends. */
    fun erase(target: CallLogTarget, onDone: () -> Unit = {}) {
        worker.post { Job(target, onDone).start() }
    }

    private fun hasPermissions(): Boolean = CallPermissions.CALL_LOG_ERASE.all {
        appContext.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
    }

    private inner class Job(private val target: CallLogTarget, private val onDone: () -> Unit) {
        private val startedAt = SystemClock.uptimeMillis()
        private var removed = 0
        private var observing = false
        private var finished = false
        private val sweepRunnable = Runnable { sweep() }
        private val observer = object : ContentObserver(worker) {
            override fun onChange(selfChange: Boolean) {
                if (finished) return
                worker.removeCallbacks(sweepRunnable)
                worker.postDelayed(sweepRunnable, OBSERVER_DELAY_MS)
            }
        }

        fun start() {
            if (!hasPermissions()) {
                Log.i(TAG, "call log erase off: READ_CALL_LOG or WRITE_CALL_LOG not granted")
                finish()
                return
            }
            try {
                resolver.registerContentObserver(CallLog.Calls.CONTENT_URI, true, observer)
                observing = true
            } catch (e: Exception) {
                Log.w(TAG, "call log observer refused: ${e.javaClass.simpleName}; polling only")
            }
            sweep()
        }

        private fun sweep() {
            if (finished) return
            worker.removeCallbacks(sweepRunnable)
            val erased = try {
                sweepOnce()
            } catch (_: SecurityException) {
                Log.i(TAG, "call log erase stopped: permission refused")
                finish()
                return
            } catch (e: Exception) {
                Log.w(TAG, "call log erase stopped: ${e.javaClass.simpleName}")
                finish()
                return
            }
            val now = SystemClock.uptimeMillis()
            when {
                erased -> {
                    Log.i(TAG, "call log erase done: removed=$removed")
                    finish()
                }
                now - startedAt >= TIMEOUT_MS -> {
                    Log.i(TAG, "call log erase timed out: removed=$removed")
                    finish()
                }
                else -> worker.postDelayed(sweepRunnable, minOf(POLL_MS, startedAt + TIMEOUT_MS - now))
            }
        }

        /**
         * One call leaves one row, so at most one row is ever deleted: the matching row dated closest
         * to the start of the call. Returns true once that row is gone.
         */
        private fun sweepOnce(): Boolean {
            var bestId = -1L
            var bestDistance = Long.MAX_VALUE
            resolver.query(
                CallLog.Calls.CONTENT_URI,
                PROJECTION,
                "${CallLog.Calls.DATE} >= ? AND ${CallLog.Calls.DATE} <= ?",
                arrayOf(target.windowStartMs.toString(), target.windowEndMs.toString()),
                null,
            )?.use { c ->
                val iId = c.getColumnIndexOrThrow(CallLog.Calls._ID)
                val iNumber = c.getColumnIndexOrThrow(CallLog.Calls.NUMBER)
                val iPresentation = c.getColumnIndexOrThrow(CallLog.Calls.NUMBER_PRESENTATION)
                val iType = c.getColumnIndexOrThrow(CallLog.Calls.TYPE)
                val iDate = c.getColumnIndexOrThrow(CallLog.Calls.DATE)
                while (c.moveToNext()) {
                    val row = CallLogRow(
                        number = if (c.isNull(iNumber)) null else c.getString(iNumber),
                        presentation = c.getInt(iPresentation),
                        type = c.getInt(iType),
                        dateMs = c.getLong(iDate),
                    )
                    if (CallLogMatcher.matches(target, row)) {
                        val distance = kotlin.math.abs(row.dateMs - target.startMs)
                        if (distance < bestDistance) {
                            bestDistance = distance
                            bestId = c.getLong(iId)
                        }
                    }
                }
            }
            if (bestId < 0) return false
            val deleted = resolver.delete(CallLog.Calls.CONTENT_URI, "${CallLog.Calls._ID} = ?", arrayOf(bestId.toString()))
            if (deleted > 0) removed += deleted
            return deleted > 0
        }

        private fun finish() {
            if (finished) return
            finished = true
            worker.removeCallbacks(sweepRunnable)
            if (observing) {
                observing = false
                runCatching { resolver.unregisterContentObserver(observer) }
            }
            onDone()
        }
    }

    companion object {
        private const val TAG = "AegisCallLogEraser"
        const val TIMEOUT_MS = 30_000L
        const val POLL_MS = 1_000L
        const val OBSERVER_DELAY_MS = 200L

        private val PROJECTION = arrayOf(
            CallLog.Calls._ID,
            CallLog.Calls.NUMBER,
            CallLog.Calls.NUMBER_PRESENTATION,
            CallLog.Calls.TYPE,
            CallLog.Calls.DATE,
        )

        private val sharedHandler: Handler by lazy {
            Handler(HandlerThread("aegis-calllog").apply { start() }.looper)
        }
    }
}
