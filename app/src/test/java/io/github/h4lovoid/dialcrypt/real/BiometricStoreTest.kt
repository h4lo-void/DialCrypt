package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.BiometricState
import io.github.h4lovoid.dialcrypt.core.real.BiometricFiles
import io.github.h4lovoid.dialcrypt.core.real.BiometricStore
import java.io.File
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class BiometricStoreTest {
    @Rule
    @JvmField
    val tmp = TemporaryFolder()

    private val binding = ByteArray(32) { (it + 1).toByte() }
    private val iv = ByteArray(12) { (0x40 + it).toByte() }
    private val ct = ByteArray(48) { (0x80 + it).toByte() }
    private val hours = 60L * 60 * 1000

    @Test
    fun wrappedStretchRoundTripsInTheDocumentedLayout() {
        val raw = BiometricStore.encodeWrapped(BiometricStore.Wrapped(binding, iv, ct))!!
        assertEquals(97, raw.size)
        assertArrayEquals("ABIO".toByteArray(), raw.copyOfRange(0, 4))
        assertEquals(1, raw[4].toInt())
        assertArrayEquals(binding, raw.copyOfRange(5, 37))
        assertArrayEquals(iv, raw.copyOfRange(37, 49))
        assertArrayEquals(ct, raw.copyOfRange(49, 97))
        val back = BiometricStore.parseWrapped(raw)!!
        assertArrayEquals(binding, back.binding)
        assertArrayEquals(iv, back.iv)
        assertArrayEquals(ct, back.ct)
        assertArrayEquals("AegisBio-v1".toByteArray() + byteArrayOf(1) + binding, BiometricStore.aad(binding))
    }

    @Test
    fun malformedWrapsAreRefused() {
        val raw = BiometricStore.encodeWrapped(BiometricStore.Wrapped(binding, iv, ct))!!
        assertNull(BiometricStore.parseWrapped(null))
        assertNull(BiometricStore.parseWrapped(raw.copyOf(96)))
        assertNull(BiometricStore.parseWrapped(raw + byteArrayOf(0)))
        assertNull(BiometricStore.parseWrapped(raw.copyOf().also { it[0] = 'X'.code.toByte() }))
        assertNull(BiometricStore.parseWrapped(raw.copyOf().also { it[4] = 2 }))
        assertNull(BiometricStore.encodeWrapped(BiometricStore.Wrapped(binding.copyOf(31), iv, ct)))
        assertNull(BiometricStore.encodeWrapped(BiometricStore.Wrapped(binding, iv.copyOf(16), ct)))
        assertNull(BiometricStore.encodeWrapped(BiometricStore.Wrapped(binding, iv, ct.copyOf(32))))
    }

    @Test
    fun stampRoundTripsAndRejectsBadData() {
        val s = BiometricStore.Stamp(bootCount = 17, elapsedMs = 123_456_789L)
        val raw = BiometricStore.encodeStamp(s)
        assertEquals(13, raw.size)
        assertEquals(1, raw[0].toInt())
        assertEquals(s, BiometricStore.parseStamp(raw))
        assertNull(BiometricStore.parseStamp(raw.copyOf(12)))
        assertNull(BiometricStore.parseStamp(raw.copyOf().also { it[0] = 2 }))
        assertNull(BiometricStore.parseStamp(BiometricStore.encodeStamp(BiometricStore.Stamp(1, -5L))))
        assertNull(BiometricStore.parseStamp(null))
    }

    @Test
    fun freshnessHoldsForTwelveHoursInTheSameBootOnly() {
        val stamp = BiometricStore.Stamp(bootCount = 4, elapsedMs = 10 * hours)
        assertTrue(BiometricStore.isFresh(stamp, 4, 10 * hours))
        assertTrue(BiometricStore.isFresh(stamp, 4, 22 * hours - 1))
        assertFalse("12 hours after the PIN", BiometricStore.isFresh(stamp, 4, 22 * hours))
        assertFalse("after a restart", BiometricStore.isFresh(stamp, 5, 10 * hours + 1))
        assertFalse("clock before the stamp", BiometricStore.isFresh(stamp, 4, 10 * hours - 1))
        assertFalse("no stamp", BiometricStore.isFresh(null, 4, 10 * hours))
        assertFalse("unknown boot count", BiometricStore.isFresh(stamp, null, 10 * hours))
    }

    @Test
    fun stateFollowsTheFilesAndKeepsInvalidatedUntilTheNextChange() {
        assertEquals(BiometricState.READY, BiometricStore.state(wrapped = true, fresh = true, previous = BiometricState.OFF))
        assertEquals(BiometricState.NEEDS_PIN, BiometricStore.state(wrapped = true, fresh = false, previous = BiometricState.READY))
        assertEquals(BiometricState.OFF, BiometricStore.state(wrapped = false, fresh = false, previous = BiometricState.READY))
        assertEquals(BiometricState.INVALIDATED, BiometricStore.state(false, false, BiometricState.INVALIDATED))
        assertEquals(BiometricState.UNAVAILABLE, BiometricStore.state(false, false, BiometricState.UNAVAILABLE))
        assertEquals(BiometricState.READY, BiometricStore.state(true, true, BiometricState.INVALIDATED))
    }

    @Test
    fun lockoutsOfferNoRetry() {
        assertFalse(BiometricStore.retryAllowed(BiometricStore.ERROR_LOCKOUT))
        assertFalse(BiometricStore.retryAllowed(BiometricStore.ERROR_LOCKOUT_PERMANENT))
        // Canceled, timeout, hardware unavailable, dismissed.
        for (code in listOf(5, 3, 1, -1)) assertTrue(BiometricStore.retryAllowed(code))
    }

    @Test
    fun filesAreWrittenReadAndDeleted() {
        val f = BiometricFiles(tmp.root)
        assertFalse(f.hasWrapped())
        assertNull(f.readStamp())
        assertTrue(f.writeWrapped(BiometricStore.Wrapped(binding, iv, ct)))
        assertTrue(f.writeStamp(BiometricStore.Stamp(3, 99L)))
        assertTrue(f.hasWrapped())
        assertNotNull(f.readWrapped())
        assertEquals(BiometricStore.Stamp(3, 99L), f.readStamp())
        assertTrue(f.deleteStamp())
        assertNull(f.readStamp())
        assertTrue(f.hasWrapped())
        File(tmp.root, BiometricFiles.WRAP_FILE).writeBytes(ByteArray(10))
        assertFalse("a damaged file counts as no file", f.hasWrapped())
        assertTrue(f.deleteAll())
        assertFalse(File(tmp.root, BiometricFiles.WRAP_FILE).exists())
        assertFalse(File(tmp.root, BiometricFiles.STAMP_FILE).exists())
    }
}
