package io.github.h4lovoid.dialcrypt.dialer

import io.github.h4lovoid.dialcrypt.dialer.model.DialInput
import io.github.h4lovoid.dialcrypt.dialer.model.DialPolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DialInputTest {
    @Test
    fun emergencyAndServiceCodesPassUnchanged() {
        assertEquals("112", DialInput.clean("112"))
        assertEquals("*#06#", DialInput.clean("*#06#"))
        assertEquals("*#*#4636#*#*", DialInput.clean("*#*#4636#*#*"))
    }

    @Test
    fun postDialDigitsAreKept() {
        assertEquals("+15550100199;1234", DialInput.clean("+1 (555) 010-0199;1234"))
        assertEquals("5550100,,12", DialInput.clean("555 0100,,12"))
    }

    @Test
    fun nothingDialableIsNull() {
        assertNull(DialInput.clean(""))
        assertNull(DialInput.clean("abc"))
    }

    @Test
    fun onlyEmergencyCallsGoOutDuringASecureCall() {
        assertTrue(DialPolicy.allow(emergency = true, busy = true))
        assertFalse(DialPolicy.allow(emergency = false, busy = true))
        assertTrue(DialPolicy.allow(emergency = false, busy = false))
        assertTrue(DialPolicy.allow(emergency = true, busy = false))
    }
}
