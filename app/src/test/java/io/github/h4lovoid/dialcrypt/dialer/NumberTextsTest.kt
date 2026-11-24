package io.github.h4lovoid.dialcrypt.dialer

import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.dialer.model.NumberText
import io.github.h4lovoid.dialcrypt.dialer.model.NumberTexts
import org.junit.Assert.assertEquals
import org.junit.Test

class NumberTextsTest {
    private val shown = NumberPresentation.SHOWN
    private val contact = ContactMembership.CONTACT
    private val masked = NumberText.Digits("\u2022\u2022\u2022\u2022 0199")
    private val whole = NumberText.Digits("+15550100199")

    @Test
    fun aContactIsWholeOnlyWhenChosenAndUnlocked() {
        assertEquals(whole, NumberTexts.of("+15550100199", shown, contact, showFull = true, locked = false))
        assertEquals(masked, NumberTexts.of("+15550100199", shown, contact, showFull = false, locked = false))
        assertEquals(masked, NumberTexts.of("+15550100199", shown, contact, showFull = true, locked = true))
    }

    @Test
    fun aStrangerIsAlwaysWhole() {
        for (showFull in listOf(true, false)) {
            for (locked in listOf(true, false)) {
                assertEquals(whole, NumberTexts.of("+15550100199", shown, ContactMembership.NOT_CONTACT, showFull, locked))
            }
        }
    }

    @Test
    fun anUnplacedNumberIsAlwaysMasked() {
        for (showFull in listOf(true, false)) {
            for (locked in listOf(true, false)) {
                assertEquals(masked, NumberTexts.of("+15550100199", shown, ContactMembership.UNKNOWN, showFull, locked))
            }
        }
    }

    @Test
    fun hiddenUnknownAndPayphone() {
        for (m in ContactMembership.entries) {
            assertEquals(NumberText.Hidden, NumberTexts.of(null, NumberPresentation.WITHHELD, m, true, false))
            assertEquals(NumberText.Unknown, NumberTexts.of(null, NumberPresentation.UNKNOWN, m, true, false))
            assertEquals(NumberText.Unknown, NumberTexts.of("  ", shown, m, true, false))
            assertEquals(NumberText.Payphone, NumberTexts.of(null, NumberPresentation.WITHHELD, m, true, false, payphone = true))
        }
    }

    @Test
    fun shortNumbersStayWholeWhenAllowed() {
        assertEquals(NumberText.Digits("112"), NumberTexts.of("112", shown, contact, showFull = true, locked = false))
        assertEquals(NumberText.Digits("112"), NumberTexts.of("112", shown, ContactMembership.NOT_CONTACT, showFull = false, locked = true))
    }
}
