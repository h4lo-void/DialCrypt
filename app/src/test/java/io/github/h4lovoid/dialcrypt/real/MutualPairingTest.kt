package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.real.MutualPairing
import io.github.h4lovoid.dialcrypt.core.real.SessionHost
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** ESTABLISHED with a pairing contact id marks that contact as mutual; a failure stays out of the call. */
class MutualPairingTest {
    private class RecordingHost(private val fail: Boolean = false) : SessionHost {
        val marked = mutableListOf<Long>()
        override val appHandle: Long = 1L
        override val unlocked: Boolean = true
        override fun contactIdForKey(pub33: ByteArray): Long? = null
        override fun vaultDirty(seq: Long) {}
        override fun contactsChanged() {}
        override fun markMutual(contactId: Long) {
            if (fail) error("vault write failed")
            marked += contactId
        }
    }

    @Test
    fun aCallEstablishedWithAContactsPairingMarksThatContact() {
        val host = RecordingHost()
        assertTrue(MutualPairing.record(7L, host))
        assertEquals(listOf(7L), host.marked)
    }

    @Test
    fun aCallWithoutAPairingMarksNobody() {
        val host = RecordingHost()
        assertFalse(MutualPairing.record(0L, host))
        assertEquals(emptyList<Long>(), host.marked)
    }

    @Test
    fun aFailedMarkIsReportedWithoutThrowing() {
        assertFalse(MutualPairing.record(7L, RecordingHost(fail = true)))
    }

    @Test
    fun aFullHandshakeCountsTheContactWhosePskItUsed() {
        assertEquals(7L, MutualPairing.contactFor(pskContactId = 7L, resume = false, storedContactId = 9L))
    }

    @Test
    fun aResumeCountsTheStoredContactSoContactsPairedBeforeTheUpgradeAreMarkedToo() {
        assertEquals(9L, MutualPairing.contactFor(pskContactId = 0L, resume = true, storedContactId = 9L))
    }

    @Test
    fun aFullHandshakeWithoutAPskCountsNobodyEvenWithAStoredContact() {
        assertEquals(0L, MutualPairing.contactFor(pskContactId = 0L, resume = false, storedContactId = 9L))
        assertEquals(0L, MutualPairing.contactFor(pskContactId = 0L, resume = true, storedContactId = 0L))
    }
}
