package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.real.BiometricFiles
import io.github.h4lovoid.dialcrypt.core.real.BiometricStore
import io.github.h4lovoid.dialcrypt.core.real.NativeCode
import io.github.h4lovoid.dialcrypt.core.real.UnlockBioEffects
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Which unlock results stamp fingerprint freshness, delete it, or keep the PIN stretch for enrolling. */
class UnlockBioEffectsTest {
    @Rule
    @JvmField
    val tmp = TemporaryFolder()

    private val old = BiometricStore.Stamp(bootCount = 3, elapsedMs = 100L)

    private fun setup(): Pair<BiometricFiles, UnlockBioEffects> {
        val files = BiometricFiles(tmp.root)
        assertTrue(files.writeStamp(old))
        return files to UnlockBioEffects(files, bootCount = { 3 }, elapsedMs = { 5_000L })
    }

    private fun p() = ByteArray(32) { 7 }

    @Test
    fun onlyANormalPinUnlockWhileEnrollingKeepsTheStretch() {
        val (_, fx) = setup()
        assertTrue(fx.mayKeep(viaPin = true, enrolling = true))
        assertFalse("a fingerprint unlock", fx.mayKeep(viaPin = false, enrolling = true))
        assertFalse("not enrolling", fx.mayKeep(viaPin = true, enrolling = false))

        val kept = p()
        assertSame(kept, fx.afterUnlock(NativeCode.UNLOCK_NORMAL, viaPin = true, enrolling = true, featureOn = false, kept = kept))
        for ((rc, viaPin) in listOf(
            NativeCode.UNLOCK_DURESS to true,
            NativeCode.UNLOCK_WRONG to true,
            NativeCode.LOCKED to true,
            NativeCode.UNLOCK_NORMAL to false,
        )) {
            val copy = p()
            assertNull("rc=$rc viaPin=$viaPin", fx.afterUnlock(rc, viaPin, enrolling = true, featureOn = true, kept = copy))
            assertArrayEquals("wiped rc=$rc viaPin=$viaPin", ByteArray(32), copy)
        }
        assertNull(fx.afterUnlock(NativeCode.UNLOCK_NORMAL, viaPin = true, enrolling = false, featureOn = true, kept = p()))
    }

    @Test
    fun aNormalPinUnlockStampsFreshnessWhenTheFeatureIsOnOrBeingTurnedOn() {
        val (files, fx) = setup()
        fx.afterUnlock(NativeCode.UNLOCK_NORMAL, viaPin = true, enrolling = false, featureOn = true, kept = null)
        assertEquals(BiometricStore.Stamp(3, 5_000L), files.readStamp())
        assertTrue(files.writeStamp(old))
        fx.afterUnlock(NativeCode.UNLOCK_NORMAL, viaPin = true, enrolling = true, featureOn = false, kept = null)
        assertEquals(BiometricStore.Stamp(3, 5_000L), files.readStamp())
        assertTrue(files.writeStamp(old))
        fx.afterUnlock(NativeCode.UNLOCK_NORMAL, viaPin = true, enrolling = false, featureOn = false, kept = null)
        assertEquals("feature off: untouched", old, files.readStamp())
    }

    @Test
    fun aFingerprintUnlockNeverRenewsFreshness() {
        val (files, fx) = setup()
        fx.afterUnlock(NativeCode.UNLOCK_NORMAL, viaPin = false, enrolling = false, featureOn = true, kept = null)
        assertEquals(old, files.readStamp())
    }

    @Test
    fun aWrongOrEmergencyPinDeletesFreshness() {
        for (rc in listOf(NativeCode.UNLOCK_WRONG, NativeCode.UNLOCK_DURESS)) {
            val (files, fx) = setup()
            fx.afterUnlock(rc, viaPin = true, enrolling = false, featureOn = true, kept = null)
            assertNull("rc=$rc", files.readStamp())
        }
        // A wrong stretch from a fingerprint unlock counts the same.
        val (files, fx) = setup()
        fx.afterUnlock(NativeCode.UNLOCK_WRONG, viaPin = false, enrolling = false, featureOn = true, kept = null)
        assertNull(files.readStamp())
    }
}
