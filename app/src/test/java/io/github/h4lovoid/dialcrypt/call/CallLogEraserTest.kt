package io.github.h4lovoid.dialcrypt.call

import android.Manifest
import android.app.Application
import android.content.ContentProvider
import android.content.ContentUris
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.provider.CallLog
import androidx.test.core.app.ApplicationProvider
import java.time.Duration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/** The eraser waits for the late system entry, removes only it, and does nothing without permission. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class CallLogEraserTest {
    private val app: Application = ApplicationProvider.getApplicationContext()
    private lateinit var provider: FakeCallLogProvider
    private val now = System.currentTimeMillis()
    private val typeIncoming = 1

    @Before
    fun setUp() {
        provider = Robolectric.setupContentProvider(FakeCallLogProvider::class.java, CallLog.AUTHORITY)
    }

    private fun idle(ms: Long) = shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(ms))

    private fun insert(number: String?, type: Int, dateMs: Long, presentation: Int = CallLogMatcher.PRESENTATION_ALLOWED) {
        val values = ContentValues().apply {
            put(CallLog.Calls.NUMBER, number)
            put(CallLog.Calls.NUMBER_PRESENTATION, presentation)
            put(CallLog.Calls.TYPE, type)
            put(CallLog.Calls.DATE, dateMs)
        }
        app.contentResolver.insert(CallLog.Calls.CONTENT_URI, values)
    }

    private fun eraser() = CallLogEraser(app, Handler(Looper.getMainLooper()))

    private fun outgoingTarget() = CallLogMatcher.target(
        listOf("+44 7700-900-123"),
        hidden = false,
        incoming = false,
        startMs = now - 20_000L,
        endMs = now,
    )!!

    @Test
    fun entryWrittenAfterTheCallIsRemovedAndUnrelatedEntriesStay() {
        shadowOf(app).grantPermissions(Manifest.permission.READ_CALL_LOG, Manifest.permission.WRITE_CALL_LOG)
        insert("+447700900123", CallLog.Calls.OUTGOING_TYPE, now - 3_600_000L)
        insert("07700900999", CallLog.Calls.OUTGOING_TYPE, now - 19_000L)
        insert("07700900123", typeIncoming, now - 19_000L)
        var done = false
        eraser().erase(outgoingTarget()) { done = true }

        idle(2_000L)
        assertEquals(3, provider.size)
        assertFalse(done)

        // The system writes the entry a moment after the call ends.
        insert("07700900123", CallLog.Calls.OUTGOING_TYPE, now - 19_000L)
        assertEquals(4, provider.size)
        idle(1_200L)
        assertEquals(3, provider.size)
        assertFalse(provider.has("07700900123", CallLog.Calls.OUTGOING_TYPE))
        assertTrue(provider.deleteSelections.isNotEmpty())
        // One row, picked by its id: never a selection by number or by time.
        assertEquals(listOf("${CallLog.Calls._ID} = ?"), provider.deleteSelections)

        idle(5_000L)
        assertTrue(done)
        assertEquals(3, provider.size)
    }

    @Test
    fun watchEndsAfterTheTimeoutWhenNoEntryAppears() {
        shadowOf(app).grantPermissions(Manifest.permission.READ_CALL_LOG, Manifest.permission.WRITE_CALL_LOG)
        insert("07700900999", CallLog.Calls.OUTGOING_TYPE, now - 19_000L)
        var done = false
        eraser().erase(outgoingTarget()) { done = true }

        idle(CallLogEraser.TIMEOUT_MS - 2_000L)
        assertFalse(done)
        idle(3_000L)
        assertTrue(done)
        assertEquals(1, provider.size)
        assertTrue(provider.deleteSelections.isEmpty())
    }

    @Test
    fun withoutWritePermissionNothingIsDeletedAndNothingCrashes() {
        shadowOf(app).grantPermissions(Manifest.permission.READ_CALL_LOG)
        shadowOf(app).denyPermissions(Manifest.permission.WRITE_CALL_LOG)
        insert("07700900123", CallLog.Calls.OUTGOING_TYPE, now - 19_000L)
        var done = false
        eraser().erase(outgoingTarget()) { done = true }

        idle(CallLogEraser.TIMEOUT_MS + 1_000L)
        assertTrue(done)
        assertEquals(1, provider.size)
        assertTrue(provider.deleteSelections.isEmpty())
    }
}

/** In-memory stand-in for the system call log provider. Honors the date range of the eraser's query. */
class FakeCallLogProvider : ContentProvider() {
    private class Row(val id: Long, val number: String?, val presentation: Int, val type: Int, val date: Long)

    private val rows = mutableListOf<Row>()
    private var nextId = 1L
    val deleteSelections = mutableListOf<String>()

    val size: Int get() = rows.size

    fun has(number: String, type: Int): Boolean = rows.any { it.number == number && it.type == type }

    override fun onCreate(): Boolean = true

    override fun getType(uri: Uri): String? = null

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor {
        val lo = selectionArgs?.getOrNull(0)?.toLong() ?: Long.MIN_VALUE
        val hi = selectionArgs?.getOrNull(1)?.toLong() ?: Long.MAX_VALUE
        val columns: Array<String> = (projection ?: ALL).map { it }.toTypedArray()
        val cursor = MatrixCursor(columns)
        for (r in rows) {
            if (r.date < lo || r.date > hi) continue
            cursor.addRow(columns.map { value(r, it) }.toTypedArray())
        }
        return cursor
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? {
        val v = values ?: return null
        val row = Row(
            id = nextId++,
            number = v.getAsString(CallLog.Calls.NUMBER),
            presentation = v.getAsInteger(CallLog.Calls.NUMBER_PRESENTATION) ?: CallLogMatcher.PRESENTATION_ALLOWED,
            type = v.getAsInteger(CallLog.Calls.TYPE) ?: 1,
            date = v.getAsLong(CallLog.Calls.DATE) ?: 0L,
        )
        rows += row
        context?.contentResolver?.notifyChange(uri, null)
        return ContentUris.withAppendedId(uri, row.id)
    }

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int {
        deleteSelections += selection.orEmpty()
        val ids = selectionArgs?.map { it.toLong() }?.toSet() ?: return 0
        val before = rows.size
        rows.removeAll { it.id in ids }
        val removed = before - rows.size
        if (removed > 0) context?.contentResolver?.notifyChange(uri, null)
        return removed
    }

    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0

    private fun value(r: Row, column: String): Any? = when (column) {
        CallLog.Calls._ID -> r.id
        CallLog.Calls.NUMBER -> r.number
        CallLog.Calls.NUMBER_PRESENTATION -> r.presentation
        CallLog.Calls.TYPE -> r.type
        CallLog.Calls.DATE -> r.date
        else -> null
    }

    private companion object {
        val ALL = arrayOf(
            CallLog.Calls._ID,
            CallLog.Calls.NUMBER,
            CallLog.Calls.NUMBER_PRESENTATION,
            CallLog.Calls.TYPE,
            CallLog.Calls.DATE,
        )
    }
}
