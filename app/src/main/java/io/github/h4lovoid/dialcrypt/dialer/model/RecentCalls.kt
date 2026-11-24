package io.github.h4lovoid.dialcrypt.dialer.model

import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Locale
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class RecentDirection { INCOMING, OUTGOING, MISSED }

/** One row of the system call log as read: no name, no cached contact data. */
data class RecentEntry(
    val id: Long,
    val number: String?,
    val type: Int,
    val presentation: Int,
    val dateMs: Long,
    val durationSec: Long,
) {
    // Keeps the number out of any accidental log line.
    override fun toString(): String = "RecentEntry(id=$id, type=$type)"
}

/** One row of the recent calls list as shown. [dialNumber] is null when the row cannot be called back. */
data class RecentItem(
    val id: Long,
    val direction: RecentDirection,
    val number: NumberText,
    val dateMs: Long,
    val durationSec: Long?,
    val dialNumber: String?,
) {
    override fun toString(): String = "RecentItem(id=$id, direction=$direction)"
}

data class RecentState(
    val items: List<RecentItem> = emptyList(),
    val loaded: Boolean = false,
    /** The call log could not be read (no permission or a query failure). */
    val unavailable: Boolean = false,
    /**
     * Rows dated from this time on were held back, because the secure flow is still erasing a call
     * log entry. Null when nothing is pending.
     */
    val hiddenFromMs: Long? = null,
)

/** Reading and deleting rows of the system call log. */
interface CallLogAccess {
    /** Newest first; null when the call log cannot be read. */
    fun load(): List<RecentEntry>?

    fun delete(id: Long): Boolean

    fun clear(): Boolean
}

object RecentCalls {
    // android.provider.CallLog.Calls values, repeated here so the model stays free of Android classes.
    const val TYPE_INCOMING = 1
    const val TYPE_OUTGOING = 2
    const val TYPE_MISSED = 3
    const val TYPE_VOICEMAIL = 4
    const val TYPE_REJECTED = 5
    const val TYPE_BLOCKED = 6
    const val TYPE_ANSWERED_EXTERNALLY = 7
    const val PRESENTATION_ALLOWED = 1
    const val PRESENTATION_RESTRICTED = 2
    const val PRESENTATION_UNKNOWN = 3
    const val PRESENTATION_PAYPHONE = 4

    /** Rejected and blocked calls count as missed; voicemail and unknown types are not listed. */
    fun direction(type: Int): RecentDirection? = when (type) {
        TYPE_INCOMING, TYPE_ANSWERED_EXTERNALLY -> RecentDirection.INCOMING
        TYPE_OUTGOING -> RecentDirection.OUTGOING
        TYPE_MISSED, TYPE_REJECTED, TYPE_BLOCKED -> RecentDirection.MISSED
        else -> null
    }

    /**
     * The row as shown. The number follows the display rule of the call screens with the screen
     * unlocked (the keypad never shows over the lock screen): a stranger's number whole, a contact's
     * number masked unless [showFull], a number the index cannot place masked.
     */
    fun item(e: RecentEntry, membership: (String) -> ContactMembership, showFull: Boolean): RecentItem? {
        val direction = direction(e.type) ?: return null
        val raw = e.number?.trim()?.takeIf { it.isNotEmpty() }
        val (presentation, payphone) = when (e.presentation) {
            PRESENTATION_RESTRICTED -> NumberPresentation.WITHHELD to false
            PRESENTATION_PAYPHONE -> NumberPresentation.WITHHELD to true
            PRESENTATION_UNKNOWN -> NumberPresentation.UNKNOWN to false
            else -> (if (raw != null) NumberPresentation.SHOWN else NumberPresentation.UNKNOWN) to false
        }
        val shown = raw.takeIf { presentation == NumberPresentation.SHOWN }
        val member = shown?.let(membership) ?: ContactMembership.UNKNOWN
        return RecentItem(
            id = e.id,
            direction = direction,
            number = NumberTexts.of(shown, presentation, member, showFull, locked = false, payphone = payphone),
            dateMs = e.dateMs,
            durationSec = e.durationSec.takeIf { direction != RecentDirection.MISSED && it > 0L },
            dialNumber = shown?.let { DialInput.clean(it) },
        )
    }

    /** m:ss, or h:mm:ss from one hour on. */
    fun duration(sec: Long): String {
        val s = sec.coerceAtLeast(0L)
        val h = s / 3600L
        val m = (s % 3600L) / 60L
        val r = s % 60L
        return if (h > 0L) String.format(Locale.ROOT, "%d:%02d:%02d", h, m, r) else String.format(Locale.ROOT, "%d:%02d", m, r)
    }

    /** The time of day for a call today, otherwise the date, both in the [locale]'s short style. */
    fun time(dateMs: Long, nowMs: Long, zone: ZoneId, locale: Locale): String {
        val at = Instant.ofEpochMilli(dateMs).atZone(zone)
        val today = Instant.ofEpochMilli(nowMs).atZone(zone).toLocalDate()
        val style = if (at.toLocalDate() == today) {
            DateTimeFormatter.ofLocalizedTime(FormatStyle.SHORT)
        } else {
            DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM)
        }
        return at.format(style.withLocale(locale))
    }
}

/**
 * State of the recent calls list in `:dialer`. [refresh], [delete] and [clearAll] block on the call
 * log and the contact index, so they run off the main thread. A refresh reads the index once
 * ([openIndex]) and asks about each number once. Deleting does not wait for a running refresh; a
 * refresh that an edit overtook loads again, so a deleted row never comes back.
 *
 * [pendingEraseFromMs] is the start of the earliest call whose entry the secure flow is still erasing;
 * rows dated from then on are left out until it answers null.
 */
class RecentCallsModel(
    private val log: CallLogAccess,
    private val openIndex: () -> (String) -> ContactMembership,
    private val showFull: () -> Boolean,
    private val pendingEraseFromMs: () -> Long? = { null },
) {
    private val _state = MutableStateFlow(RecentState())
    val state: StateFlow<RecentState> = _state.asStateFlow()
    private val refreshLock = Any()
    private val stateLock = Any()

    // Counts deletes and clears, under stateLock.
    private var edits = 0L

    fun refresh() {
        synchronized(refreshLock) {
            val index = openIndex()
            val known = HashMap<String, ContactMembership>()
            val membership: (String) -> ContactMembership = { n -> known.getOrPut(n) { index(n) } }
            val full = showFull()
            for (pass in 1..MAX_PASSES) {
                val seenEdits = synchronized(stateLock) { edits }
                // The marker is read before and after the call log: it is written before the entry appears
                // and removed after the entry is deleted, so one of the two readings covers the entry.
                val before = pendingEraseFromMs()
                val entries = log.load()
                val after = pendingEraseFromMs()
                val hiddenFrom = listOfNotNull(before, after).minOrNull()
                val next = if (entries == null) {
                    RecentState(loaded = true, unavailable = true, hiddenFromMs = hiddenFrom)
                } else {
                    val shown = if (hiddenFrom == null) entries else entries.filter { it.dateMs < hiddenFrom }
                    RecentState(items = shown.mapNotNull { e -> RecentCalls.item(e, membership, full) }, loaded = true, hiddenFromMs = hiddenFrom)
                }
                val applied = synchronized(stateLock) {
                    if (edits == seenEdits) {
                        _state.value = next
                        true
                    } else {
                        false
                    }
                }
                if (applied) return
            }
        }
    }

    /** Refreshes when the pending erase changed since the list was last loaded, for example when it finished. */
    fun refreshIfPendingEraseChanged(): Boolean {
        if (pendingEraseFromMs() == _state.value.hiddenFromMs) return false
        refresh()
        return true
    }

    /** Deletes one row from the call log; the list changes only when the call log did. */
    fun delete(id: Long): Boolean {
        if (!log.delete(id)) return false
        synchronized(stateLock) {
            edits++
            _state.value = _state.value.copy(items = _state.value.items.filterNot { it.id == id })
        }
        return true
    }

    fun clearAll(): Boolean {
        if (!log.clear()) return false
        synchronized(stateLock) {
            edits++
            _state.value = _state.value.copy(items = emptyList())
        }
        return true
    }

    private companion object {
        /** How often one refresh loads again because a delete or clear overtook it. */
        const val MAX_PASSES = 3
    }
}
