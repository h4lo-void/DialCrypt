package io.github.h4lovoid.dialcrypt.core

/** Whether a phone number belongs to a DialCrypt contact, as far as the contact number index can tell. */
enum class ContactMembership { CONTACT, NOT_CONTACT, UNKNOWN }

/**
 * How a phone number shows outside the keypad (where the user's own digits always show):
 *
 * - not a contact: the whole number, also over the lock screen;
 * - a contact: only the last four digits, unless the user chose to see contact numbers in full and
 *   the screen is unlocked;
 * - unknown (index unreadable, key missing, before the first unlock): only the last four digits.
 */
object NumberVisibility {
    fun showsWhole(membership: ContactMembership, showFullContacts: Boolean, locked: Boolean): Boolean =
        when (membership) {
            ContactMembership.NOT_CONTACT -> true
            ContactMembership.CONTACT -> showFullContacts && !locked
            ContactMembership.UNKNOWN -> false
        }

    /** The number as it shows on screen; null when there is no number. */
    fun text(number: String?, membership: ContactMembership, showFullContacts: Boolean, locked: Boolean): String? {
        val n = number?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        return if (showsWhole(membership, showFullContacts, locked)) n else PhoneRules.mask(n)
    }
}
