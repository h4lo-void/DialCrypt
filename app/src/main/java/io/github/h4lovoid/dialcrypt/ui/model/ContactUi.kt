package io.github.h4lovoid.dialcrypt.ui.model

import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.core.Contact
import io.github.h4lovoid.dialcrypt.core.ContactTrust
import io.github.h4lovoid.dialcrypt.core.QuickConnect
import io.github.h4lovoid.dialcrypt.ui.theme.Tone
import java.util.Locale

/**
 * What a contact shows in a list: one status and, when it applies, a quick-connect hint.
 * Pairing and hardware proof belong to the detail screen.
 */
object ContactUi {
    fun status(contact: Contact): StatusBanner = when {
        contact.keyChanged -> StatusBanner(R.string.badge_key_changed, Tone.DANGER)
        contact.verified -> StatusBanner(R.string.badge_verified, Tone.OK)
        contact.paired -> pairing(contact)
        else -> StatusBanner(R.string.badge_unverified, Tone.WARN)
    }

    /** Paired only once both sides are known to have saved each other; saved by us alone waits for them. */
    fun pairing(contact: Contact): StatusBanner = when {
        contact.paired && contact.mutual -> StatusBanner(R.string.detail_paired_yes, Tone.OK)
        contact.paired -> StatusBanner(R.string.detail_paired_waiting, Tone.WARN)
        else -> StatusBanner(R.string.detail_paired_no, Tone.NEUTRAL)
    }

    fun showsQuickConnect(contact: Contact): Boolean = contact.quickConnect == QuickConnect.READY

    /** Avatar letters: first letter of the first word and of the last word. */
    fun initials(name: String): String {
        val words = name.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
        val picked = if (words.size <= 1) words else listOf(words.first(), words.last())
        return picked.mapNotNull { firstLetter(it) }.joinToString("").ifEmpty { "?" }
    }

    private fun firstLetter(word: String): String? {
        var i = 0
        while (i < word.length) {
            val cp = word.codePointAt(i)
            if (Character.isLetterOrDigit(cp)) return String(Character.toChars(cp)).uppercase(Locale.ROOT)
            i += Character.charCount(cp)
        }
        return null
    }
}
