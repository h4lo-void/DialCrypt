package io.github.h4lovoid.dialcrypt.dialer.model

import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.core.NumberVisibility

object NumberTexts {
    /**
     * The caller line for the in-call screen, by [NumberVisibility]: a number that is not a contact
     * shows whole; a contact's number, or one the index cannot place ([membership]), shows only its
     * last four digits unless the user chose to see contact numbers whole and the screen is unlocked.
     */
    fun of(
        number: String?,
        p: NumberPresentation,
        membership: ContactMembership,
        showFull: Boolean,
        locked: Boolean,
        payphone: Boolean = false,
    ): NumberText {
        if (payphone) return NumberText.Payphone
        return when (p) {
            NumberPresentation.WITHHELD -> NumberText.Hidden
            NumberPresentation.UNKNOWN -> NumberText.Unknown
            NumberPresentation.SHOWN -> {
                NumberVisibility.text(number, membership, showFull, locked)?.let { NumberText.Digits(it) } ?: NumberText.Unknown
            }
        }
    }
}
