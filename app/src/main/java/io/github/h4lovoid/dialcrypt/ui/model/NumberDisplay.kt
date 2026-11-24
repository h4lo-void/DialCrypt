package io.github.h4lovoid.dialcrypt.ui.model

import androidx.compose.runtime.Composable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.staticCompositionLocalOf
import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.NumberVisibility
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Whether contact numbers show whole. Provided by AppRoot from the stored preference; off unless provided. */
val LocalShowFullNumbers = compositionLocalOf { false }

/** Asks the contact number index about a number. Provided by AppRoot; unknown (masked) unless provided. */
val LocalContactLookup = staticCompositionLocalOf<(String) -> ContactMembership> { { ContactMembership.UNKNOWN } }

/** Where [LocalContactLookup] runs: it reads a file and uses the Keystore. Tests provide their own dispatcher. */
val LocalContactLookupDispatcher = staticCompositionLocalOf<CoroutineDispatcher> { Dispatchers.IO }

/** A contact's number in lists: whole when the preference is on, otherwise only the last four digits. */
@Composable
fun listNumber(number: String?): String? =
    NumberVisibility.text(number, ContactMembership.CONTACT, LocalShowFullNumbers.current, locked = false)

/**
 * A caller or callee number that may belong to a contact. A known [contactId] means a contact;
 * otherwise the index is asked on [LocalContactLookupDispatcher], and until it answers the number shows masked.
 * The secure screens never show over the lock screen, so the screen counts as unlocked here.
 */
@Composable
fun callerNumber(number: String?, contactId: Long? = null): String? {
    val lookup = LocalContactLookup.current
    val dispatcher = LocalContactLookupDispatcher.current
    val initial = if (contactId != null) ContactMembership.CONTACT else ContactMembership.UNKNOWN
    val membership by produceState(initial, number, contactId, lookup, dispatcher) {
        value = initial
        if (contactId == null && !number.isNullOrBlank()) {
            value = withContext(dispatcher) { runCatching { lookup(number) }.getOrDefault(ContactMembership.UNKNOWN) }
        }
    }
    return NumberVisibility.text(number, membership, LocalShowFullNumbers.current, locked = false)
}
