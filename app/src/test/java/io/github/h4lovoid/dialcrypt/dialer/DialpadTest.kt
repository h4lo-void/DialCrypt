package io.github.h4lovoid.dialcrypt.dialer

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** What the dial pad's call button sends to Telecom, with a fake [CallPlacer]. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DialpadTest {
    private val app: Application = ApplicationProvider.getApplicationContext()

    private class FakePlacer(private val result: Boolean = true) : CallPlacer {
        val placed = ArrayList<String>()

        override fun place(number: String): Boolean {
            placed += number
            return result
        }
    }

    private val emergencyNumbers = setOf("112", "911", "999")

    private fun dialer(
        placer: CallPlacer,
        busy: () -> Boolean = { false },
        emergency: (String) -> Boolean = { it in emergencyNumbers },
        special: (String) -> Boolean = { false },
    ) = Dialer(placer = placer, isEmergency = emergency, secureBusy = busy, specialCode = special)

    // ---- input and the number that goes out ---------------------------------------------------------

    @Test
    fun theNumberIsCleanedByDialInputBeforeItIsPlaced() {
        val placer = FakePlacer()
        val result = dialer(placer).dial("(555) 12-34 ab")
        assertEquals(DialResult.PLACED, result)
        assertEquals(listOf("5551234"), placer.placed)
    }

    @Test
    fun starsHashesPlusAndPostDialCharactersGoOutUnchanged() {
        val placer = FakePlacer()
        assertEquals(DialResult.PLACED, dialer(placer).dial("*31#+15551234,2;3"))
        assertEquals(listOf("*31#+15551234,2;3"), placer.placed)
    }

    @Test
    fun anEmergencyNumberIsSentAsTyped() {
        val placer = FakePlacer()
        assertEquals(DialResult.PLACED, dialer(placer).dial("112"))
        assertEquals(listOf("112"), placer.placed)
    }

    @Test
    fun anEmptyNumberIsNotDialed() {
        val placer = FakePlacer()
        val d = dialer(placer)
        assertEquals(DialResult.EMPTY, d.dial(""))
        assertEquals(DialResult.EMPTY, d.dial("   "))
        assertEquals(DialResult.EMPTY, d.dial("abc-()"))
        assertTrue(placer.placed.isEmpty())
    }

    @Test
    fun aRefusedPlacementIsReportedAsFailed() {
        val placer = FakePlacer(result = false)
        assertEquals(DialResult.FAILED, dialer(placer).dial("5551234"))
        assertEquals(listOf("5551234"), placer.placed)
    }

    @Test
    fun aSpecialCodeIsHandedToTheSystemAndNeverDialed() {
        val placer = FakePlacer()
        val codes = ArrayList<String>()
        val d = dialer(placer, special = { codes += it; true })
        assertEquals(DialResult.SPECIAL_CODE, d.dial("*#*#4636#*#*"))
        assertEquals(listOf("4636"), codes)
        assertTrue(placer.placed.isEmpty())
        assertEquals(DialResult.FAILED, dialer(placer, special = { false }).dial("*#*#4636#*#*"))
        assertTrue(placer.placed.isEmpty())
    }

    // ---- while a secure call is under way -------------------------------------------------------------

    @Test
    fun anOrdinaryNumberIsBlockedDuringASecureCallButAnEmergencyNumberGoesOut() {
        val placer = FakePlacer()
        val d = dialer(placer, busy = { true })
        assertEquals(DialResult.BLOCKED, d.dial("5551234"))
        assertTrue(placer.placed.isEmpty())
        assertEquals(DialResult.PLACED, d.dial("112"))
        assertEquals(DialResult.PLACED, d.dial("911"))
        assertEquals(listOf("112", "911"), placer.placed)
    }

    @Test
    fun whenTheEmergencyCheckFailsTheNumberIsTreatedAsEmergencyEvenDuringASecureCall() {
        val placer = FakePlacer()
        val d = dialer(placer, busy = { true }, emergency = { throw IllegalStateException("telephony unavailable") })
        assertEquals(DialResult.PLACED, d.dial("5551234"))
        assertEquals(listOf("5551234"), placer.placed)
    }

    @Test
    fun theMarkerWithACallUpBlocksAndWithoutTheMarkerOrWithoutACallItDoesNot() {
        // Same rule as DialpadActivity.secureBusy: the marker written by :call and a call that is up.
        var inCall = false
        val placer = FakePlacer()
        val d = dialer(placer, busy = { SecureBusyMarker.isSet(app) && inCall })

        SecureBusyMarker.set(app, true)
        inCall = true
        assertEquals(DialResult.BLOCKED, d.dial("5551234"))
        assertEquals(DialResult.PLACED, d.dial("112"))

        inCall = false
        assertEquals(DialResult.PLACED, d.dial("5551234"))

        inCall = true
        SecureBusyMarker.set(app, false)
        assertEquals(DialResult.PLACED, d.dial("5551235"))
        assertEquals(listOf("112", "5551234", "5551235"), placer.placed)
    }

    // ---- the marker file ---------------------------------------------------------------------------------

    @Test
    fun theMarkerIsAnEmptyFileInNoBackupStorage() {
        assertFalse(SecureBusyMarker.isSet(app))
        SecureBusyMarker.set(app, true)
        val file = SecureBusyMarker.file(app)
        assertTrue(SecureBusyMarker.isSet(app))
        assertEquals(app.noBackupFilesDir.canonicalPath, file.parentFile?.canonicalPath)
        assertEquals(0L, file.length())
        // Setting it twice keeps it; clearing removes it and clearing again is harmless.
        SecureBusyMarker.set(app, true)
        assertTrue(SecureBusyMarker.isSet(app))
        SecureBusyMarker.set(app, false)
        assertFalse(SecureBusyMarker.isSet(app))
        SecureBusyMarker.set(app, false)
        assertFalse(SecureBusyMarker.isSet(app))
        assertNull(file.takeIf { it.exists() })
    }
}
