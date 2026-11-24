package io.github.h4lovoid.dialcrypt.incoming

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CallSourceTest {
    @Test
    fun withoutTheRoleOnlyTheNonUiServiceCounts() {
        assertTrue(CallSource.accepts(CallSource.NON_UI, roleHeld = false))
        assertFalse(CallSource.accepts(CallSource.DIALER_UI, roleHeld = false))
    }

    @Test
    fun withTheRoleOnlyTheDialerServiceCounts() {
        assertTrue(CallSource.accepts(CallSource.DIALER_UI, roleHeld = true))
        assertFalse(CallSource.accepts(CallSource.NON_UI, roleHeld = true))
    }

    @Test
    fun exactlyOneSourceIsAcceptedEitherWay() {
        for (held in listOf(false, true)) {
            assertEquals(1, CallSource.entries.count { CallSource.accepts(it, held) })
        }
    }

    @Test
    fun aCallTakenWithoutTheRoleIsStillEndedThroughTheNonUiServiceOnceTheRoleIsHeld() {
        assertTrue(CallSource.accepts(CallSource.NON_UI, roleHeld = false))
        // The role is taken during the call: new calls come from the dialer service ...
        assertFalse(CallSource.accepts(CallSource.NON_UI, roleHeld = true))
        // ... but removal and unbinding of the tracked call still come from the non-UI service.
        assertTrue(CallSource.owns(CallSource.NON_UI, trackedSource = CallSource.NON_UI))
        assertFalse(CallSource.owns(CallSource.DIALER_UI, trackedSource = CallSource.NON_UI))
    }

    @Test
    fun aCallTakenWithTheRoleIsStillEndedThroughTheDialerServiceOnceTheRoleIsGivenBack() {
        assertTrue(CallSource.accepts(CallSource.DIALER_UI, roleHeld = true))
        assertFalse(CallSource.accepts(CallSource.DIALER_UI, roleHeld = false))
        assertTrue(CallSource.owns(CallSource.DIALER_UI, trackedSource = CallSource.DIALER_UI))
        assertFalse(CallSource.owns(CallSource.NON_UI, trackedSource = CallSource.DIALER_UI))
    }

    @Test
    fun nothingIsOwnedWhileNoCallIsTracked() {
        for (source in CallSource.entries) assertFalse(CallSource.owns(source, trackedSource = null))
    }
}
