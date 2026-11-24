package io.github.h4lovoid.dialcrypt.dialer

import android.Manifest
import android.app.Application
import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.provider.CallLog
import androidx.test.core.app.ApplicationProvider
import io.github.h4lovoid.dialcrypt.dialer.model.RecentEntry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/** The recent calls read only the needed columns, newest first, and delete by id or all at once. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class RecentCallLogTest {
    private val app: Application = ApplicationProvider.getApplicationContext()
    private lateinit var provider: RecentsCallLogProvider

    @Before
    fun setUp() {
        provider = Robolectric.setupContentProvider(RecentsCallLogProvider::class.java, CallLog.AUTHORITY)
        provider.rows += RecentEntry(1L, "+15550100199", CallLog.Calls.INCOMING_TYPE, CallLog.Calls.PRESENTATION_ALLOWED, 1_000L, 30L)
        provider.rows += RecentEntry(2L, "", CallLog.Calls.MISSED_TYPE, CallLog.Calls.PRESENTATION_RESTRICTED, 3_000L, 0L)
        provider.rows += RecentEntry(3L, "+447700900101", CallLog.Calls.OUTGOING_TYPE, CallLog.Calls.PRESENTATION_ALLOWED, 2_000L, 95L)
    }

    @Test
    fun withoutPermissionNothingIsReadOrDeleted() {
        val log = RecentCallLog(app)
        assertNull(log.load())
        assertFalse(log.delete(1L))
        assertFalse(log.clear())
        assertEquals(3, provider.rows.size)
        assertNull(provider.lastProjection)
    }

    @Test
    fun rowsAreReadNewestFirstWithoutAnyNameColumn() {
        shadowOf(app).grantPermissions(Manifest.permission.READ_CALL_LOG)
        val rows = RecentCallLog(app).load()!!
        assertEquals(listOf(2L, 3L, 1L), rows.map { it.id })
        assertEquals(RecentEntry(3L, "+447700900101", CallLog.Calls.OUTGOING_TYPE, CallLog.Calls.PRESENTATION_ALLOWED, 2_000L, 95L), rows[1])
        val projection = provider.lastProjection!!.toSet()
        assertFalse(projection.contains(CallLog.Calls.CACHED_NAME))
        assertEquals(
            setOf(CallLog.Calls._ID, CallLog.Calls.NUMBER, CallLog.Calls.TYPE, CallLog.Calls.NUMBER_PRESENTATION, CallLog.Calls.DATE, CallLog.Calls.DURATION),
            projection,
        )
    }

    @Test
    fun oneRowIsDeletedByIdAndClearRemovesEveryRow() {
        shadowOf(app).grantPermissions(Manifest.permission.READ_CALL_LOG, Manifest.permission.WRITE_CALL_LOG)
        val log = RecentCallLog(app)
        assertTrue(log.delete(3L))
        assertEquals(listOf(1L, 2L), provider.rows.map { it.id })
        assertFalse(log.delete(99L))
        assertTrue(log.clear())
        assertTrue(provider.rows.isEmpty())
        assertTrue(log.load()!!.isEmpty())
    }
}

/** In-memory call log that sorts by date and deletes by `_id = ?` or everything without a selection. */
class RecentsCallLogProvider : ContentProvider() {
    val rows = mutableListOf<RecentEntry>()
    var lastProjection: Array<out String>? = null

    override fun onCreate(): Boolean = true

    override fun getType(uri: Uri): String? = null

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor {
        lastProjection = projection
        val columns = projection ?: arrayOf(CallLog.Calls._ID)
        val cursor = MatrixCursor(columns)
        val sorted = if (sortOrder == CallLog.Calls.DATE + " DESC") rows.sortedByDescending { it.dateMs } else rows
        for (r in sorted) {
            cursor.addRow(
                columns.map { c ->
                    when (c) {
                        CallLog.Calls._ID -> r.id
                        CallLog.Calls.NUMBER -> r.number
                        CallLog.Calls.TYPE -> r.type
                        CallLog.Calls.NUMBER_PRESENTATION -> r.presentation
                        CallLog.Calls.DATE -> r.dateMs
                        CallLog.Calls.DURATION -> r.durationSec
                        else -> null
                    }
                }.toTypedArray(),
            )
        }
        return cursor
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int {
        val before = rows.size
        if (selection == null) {
            rows.clear()
        } else if (selection == CallLog.Calls._ID + " = ?") {
            val id = selectionArgs?.firstOrNull()?.toLongOrNull() ?: return 0
            rows.removeAll { it.id == id }
        }
        return before - rows.size
    }

    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
}
