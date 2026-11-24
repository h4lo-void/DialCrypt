package io.github.h4lovoid.dialcrypt

import io.github.h4lovoid.dialcrypt.core.ContactMembership
import io.github.h4lovoid.dialcrypt.core.NumberVisibility
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** One test per row of the number display rule. */
class NumberVisibilityTest {
    private val number = "+34600123456"
    private val masked = "\u2022\u2022\u2022\u2022 3456"

    private fun shown(m: ContactMembership, showFull: Boolean, locked: Boolean) = NumberVisibility.text(number, m, showFull, locked)

    @Test
    fun notAContactIsWholeAlsoOverTheLockScreen() {
        assertEquals(number, shown(ContactMembership.NOT_CONTACT, showFull = false, locked = false))
        assertEquals(number, shown(ContactMembership.NOT_CONTACT, showFull = false, locked = true))
        assertEquals(number, shown(ContactMembership.NOT_CONTACT, showFull = true, locked = true))
    }

    @Test
    fun aContactWithTheSwitchOffShowsTheLastFourDigits() {
        assertEquals(masked, shown(ContactMembership.CONTACT, showFull = false, locked = false))
        assertEquals(masked, shown(ContactMembership.CONTACT, showFull = false, locked = true))
    }

    @Test
    fun aContactWithTheSwitchOnIsWholeOnlyWhileUnlocked() {
        assertEquals(number, shown(ContactMembership.CONTACT, showFull = true, locked = false))
        assertEquals(masked, shown(ContactMembership.CONTACT, showFull = true, locked = true))
    }

    @Test
    fun anUnplacedNumberShowsTheLastFourDigits() {
        assertEquals(masked, shown(ContactMembership.UNKNOWN, showFull = false, locked = false))
        assertEquals(masked, shown(ContactMembership.UNKNOWN, showFull = true, locked = false))
        assertEquals(masked, shown(ContactMembership.UNKNOWN, showFull = true, locked = true))
    }

    @Test
    fun noNumberStaysNull() {
        assertNull(NumberVisibility.text(null, ContactMembership.NOT_CONTACT, true, false))
        assertNull(NumberVisibility.text("   ", ContactMembership.NOT_CONTACT, true, false))
    }
}
