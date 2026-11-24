package io.github.h4lovoid.dialcrypt

import io.github.h4lovoid.dialcrypt.core.CountryCallingCodes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class CountryCallingCodesTest {
    @Test
    fun representativeRegionsMapToTheirCallingCodes() {
        assertEquals("1", CountryCallingCodes.forIso("us"))
        assertEquals("1", CountryCallingCodes.forIso("ca"))
        assertEquals("1", CountryCallingCodes.forIso("jm"))
        assertEquals("7", CountryCallingCodes.forIso("ru"))
        assertEquals("7", CountryCallingCodes.forIso("kz"))
        assertEquals("44", CountryCallingCodes.forIso("gb"))
        assertEquals("49", CountryCallingCodes.forIso("de"))
        assertEquals("34", CountryCallingCodes.forIso("es"))
        assertEquals("33", CountryCallingCodes.forIso("fr"))
        assertEquals("81", CountryCallingCodes.forIso("jp"))
        assertEquals("91", CountryCallingCodes.forIso("in"))
        assertEquals("852", CountryCallingCodes.forIso("hk"))
        assertEquals("886", CountryCallingCodes.forIso("tw"))
    }

    @Test
    fun lookupIgnoresLetterCaseAndSurroundingSpaces() {
        assertEquals("44", CountryCallingCodes.forIso("GB"))
        assertEquals("44", CountryCallingCodes.forIso("Gb"))
        assertEquals("49", CountryCallingCodes.forIso(" de "))
    }

    @Test
    fun unknownBlankOrMissingRegionsResolveToNull() {
        assertNull(CountryCallingCodes.forIso(null))
        assertNull(CountryCallingCodes.forIso(""))
        assertNull(CountryCallingCodes.forIso("  "))
        assertNull(CountryCallingCodes.forIso("zz"))
        assertNull(CountryCallingCodes.forIso("usa"))
    }
}
