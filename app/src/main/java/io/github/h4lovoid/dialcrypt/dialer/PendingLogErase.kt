package io.github.h4lovoid.dialcrypt.dialer

import android.app.ActivityManager
import android.content.Context
import io.github.h4lovoid.dialcrypt.core.DirectBoot
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.TreeSet

/**
 * File `noBackupFilesDir/call_log_erase_pending`: one line for every call whose call log entry the
 * secure flow is going to erase, holding only the time the call started. `:call` adds the line as
 * soon as the call is marked for erasing and removes it when the eraser has deleted the entry or given
 * up. While a line exists the recent calls in `:dialer` hold back every row dated from
 * [hiddenFrom] on, so the entry is never drawn in the moments before it is erased.
 *
 * A file nobody looks after any more must not hide new rows for good: readers drop it when `:call` is
 * not running or when it was last written more than [MAX_AGE_MS] ago, and `:call` drops what an
 * earlier process left when its services start. Before the first unlock after boot no secure call can
 * exist and the file cannot be read, so nothing is read or written.
 */
internal object PendingLogErase {
    private const val FILE_NAME = "call_log_erase_pending"

    /** A row may be dated this long before the call's start as the app saw it (CallLogMatcher.BEFORE_START_MS). */
    const val MARGIN_MS = 5_000L

    /** Longer than any call the secure flow is expected to hold. */
    const val MAX_AGE_MS = 6 * 3_600_000L

    // Starts of the calls this process is waiting on. Only `:call` adds to it.
    private val starts = TreeSet<Long>()

    fun file(context: Context): File = File(context.applicationContext.noBackupFilesDir, FILE_NAME)

    /** `:call`: the entry of the call that started at [startMs] will be erased. */
    @Synchronized
    fun begin(context: Context, startMs: Long) {
        if (starts.add(startMs)) write(context)
    }

    /** `:call`: the entry of the call that started at [startMs] is gone, or the eraser gave up. */
    @Synchronized
    fun end(context: Context, startMs: Long) {
        if (starts.remove(startMs)) write(context)
    }

    /** `:call`, when a service starts: a file left by an earlier process has no one waiting on it. */
    @Synchronized
    fun reset(context: Context) {
        if (starts.isEmpty()) write(context)
    }

    /**
     * The time from which call log rows are held back, or null when no erase is pending. A stale
     * file is deleted. [ownerAlive]: the `:call` process, which looks after the file, is running.
     */
    fun hiddenFrom(
        context: Context,
        nowMs: Long = System.currentTimeMillis(),
        ownerAlive: (Context) -> Boolean = ::callProcessAlive,
    ): Long? {
        if (!DirectBoot.isUserUnlocked(context)) return null
        val f = file(context)
        return runCatching {
            if (!f.isFile) return null
            val earliest = f.readLines().mapNotNull { it.trim().toLongOrNull() }.minOrNull()
            if (earliest == null || nowMs - f.lastModified() > MAX_AGE_MS || !ownerAlive(context)) {
                f.delete()
                return null
            }
            earliest - MARGIN_MS
        }.getOrNull()
    }

    private fun write(context: Context) {
        if (!DirectBoot.isUserUnlocked(context)) return
        runCatching {
            val f = file(context)
            if (starts.isEmpty()) {
                if (f.exists()) f.delete()
                return
            }
            f.parentFile?.mkdirs()
            val tmp = File(f.path + ".tmp")
            tmp.writeText(starts.joinToString("\n"))
            Files.move(tmp.toPath(), f.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        }
    }

    private fun callProcessAlive(context: Context): Boolean {
        val name = context.packageName + ":call"
        return runCatching {
            context.getSystemService(ActivityManager::class.java)?.runningAppProcesses?.any { it.processName == name }
        }.getOrNull() ?: true
    }

    @Synchronized
    internal fun forgetForTest() {
        starts.clear()
    }
}
