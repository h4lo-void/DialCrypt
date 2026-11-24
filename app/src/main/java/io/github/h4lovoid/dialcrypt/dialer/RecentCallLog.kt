package io.github.h4lovoid.dialcrypt.dialer

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.provider.CallLog
import androidx.core.content.ContextCompat
import io.github.h4lovoid.dialcrypt.dialer.model.CallLogAccess
import io.github.h4lovoid.dialcrypt.dialer.model.RecentEntry

/**
 * The system call log for the recent calls list in `:dialer`. Reads only id, number, type,
 * presentation, date and duration: never a cached name. The default dialer holds READ_CALL_LOG and
 * WRITE_CALL_LOG through its role, and the Magisk module grants both as well. Rows of secure calls are
 * removed by CallLogEraser in `:call`; until then the list holds them back ([PendingLogErase]).
 */
internal class RecentCallLog(context: Context) : CallLogAccess {
    private val app = context.applicationContext ?: context

    private fun granted(permission: String): Boolean =
        ContextCompat.checkSelfPermission(app, permission) == PackageManager.PERMISSION_GRANTED

    override fun load(): List<RecentEntry>? {
        if (!granted(Manifest.permission.READ_CALL_LOG)) return null
        val uri = CallLog.Calls.CONTENT_URI.buildUpon()
            .appendQueryParameter(CallLog.Calls.LIMIT_PARAM_KEY, LIMIT.toString())
            .build()
        return runCatching {
            app.contentResolver.query(uri, PROJECTION, null, null, CallLog.Calls.DATE + " DESC")?.use { c ->
                val id = c.getColumnIndexOrThrow(CallLog.Calls._ID)
                val number = c.getColumnIndexOrThrow(CallLog.Calls.NUMBER)
                val type = c.getColumnIndexOrThrow(CallLog.Calls.TYPE)
                val presentation = c.getColumnIndexOrThrow(CallLog.Calls.NUMBER_PRESENTATION)
                val date = c.getColumnIndexOrThrow(CallLog.Calls.DATE)
                val duration = c.getColumnIndexOrThrow(CallLog.Calls.DURATION)
                val rows = ArrayList<RecentEntry>(c.count)
                while (c.moveToNext()) {
                    rows += RecentEntry(
                        id = c.getLong(id),
                        number = c.getString(number),
                        type = c.getInt(type),
                        presentation = c.getInt(presentation),
                        dateMs = c.getLong(date),
                        durationSec = c.getLong(duration),
                    )
                }
                rows
            }
        }.getOrNull()
    }

    override fun delete(id: Long): Boolean {
        if (!granted(Manifest.permission.WRITE_CALL_LOG)) return false
        return runCatching {
            app.contentResolver.delete(CallLog.Calls.CONTENT_URI, CallLog.Calls._ID + " = ?", arrayOf(id.toString())) > 0
        }.getOrDefault(false)
    }

    override fun clear(): Boolean {
        if (!granted(Manifest.permission.WRITE_CALL_LOG)) return false
        return runCatching {
            app.contentResolver.delete(CallLog.Calls.CONTENT_URI, null, null)
            true
        }.getOrDefault(false)
    }

    private companion object {
        const val LIMIT = 300
        val PROJECTION = arrayOf(
            CallLog.Calls._ID,
            CallLog.Calls.NUMBER,
            CallLog.Calls.TYPE,
            CallLog.Calls.NUMBER_PRESENTATION,
            CallLog.Calls.DATE,
            CallLog.Calls.DURATION,
        )
    }
}
