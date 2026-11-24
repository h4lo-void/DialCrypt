package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.core.FakeScenarios
import io.github.h4lovoid.dialcrypt.core.real.ContactMetaStore
import io.github.h4lovoid.dialcrypt.core.real.VaultContact
import io.github.h4lovoid.dialcrypt.core.real.VaultFile
import io.github.h4lovoid.dialcrypt.ui.model.ContactUi
import java.io.File
import java.nio.ByteBuffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Independent acceptance checks for the "paired only after both sides added each other" change. */
class MutualPairingReviewTest {
    @Rule
    @JvmField
    val tmp = TemporaryFolder()

    private val xor: (ByteArray) -> ByteArray = { b -> b.map { (it.toInt() xor 0x5A).toByte() }.toByteArray() }
    private val seed = ByteArray(32) { (it * 5 + 3).toByte() }
    private val unlocked = { true }

    private fun file() = File(tmp.root, "contact_meta.bin")

    private fun plaintext(
        version: Int = 3,
        numbers: List<Pair<Long, String>> = listOf(9L to "07700900123"),
        declaredMutual: Int? = null,
        mutual: List<Long> = listOf(7L, 8L),
        withMutualSection: Boolean = version >= 2,
        trailing: ByteArray = ByteArray(0),
    ): ByteArray {
        val bb = java.io.ByteArrayOutputStream()
        bb.write("ACMD".toByteArray(Charsets.US_ASCII))
        bb.write(version)
        bb.write(seed)
        bb.write(ByteBuffer.allocate(2).putShort(numbers.size.toShort()).array())
        for ((id, n) in numbers) {
            val nb = n.toByteArray(Charsets.UTF_8)
            bb.write(ByteBuffer.allocate(8).putLong(id).array())
            bb.write(nb.size)
            bb.write(nb)
        }
        if (withMutualSection) {
            bb.write(ByteBuffer.allocate(2).putShort((declaredMutual ?: mutual.size).toShort()).array())
            for (id in mutual) bb.write(ByteBuffer.allocate(8).putLong(id).array())
        }
        bb.write(trailing)
        return bb.toByteArray()
    }

    private fun storeWith(pt: ByteArray): ContactMetaStore {
        file().delete()
        assertTrue(VaultFile(file()).write(xor(pt)))
        return ContactMetaStore(file(), xor, xor, unlocked)
    }

    private fun assertRejected(store: ContactMetaStore, label: String) {
        val loaded = store.loadOrInitSeed()
        assertNotNull(label, loaded)
        assertFalse("$label: seed must not come from a rejected file", loaded!!.contentEquals(seed))
        for (id in listOf(0L, 1L, 7L, 8L, 9L, 0xFFFFL)) assertFalse("$label: mutual $id", store.isMutual(id))
        assertNull("$label: number", store.numberFor(9L))
    }

    @Test
    fun versionThreeRoundTripsMoreThan255MutualIdsAndKeepsSeedAndNumbers() {
        val ids = (1L..300L).toList()
        val s = storeWith(plaintext(mutual = ids))
        assertArrayEquals(seed, s.loadOrInitSeed()!!)
        assertEquals("07700900123", s.numberFor(9L))
        ids.forEach { assertTrue(s.isMutual(it)) }
        assertFalse(s.isMutual(301L))
        assertTrue(s.setMutual(301L, true))
        val r = ContactMetaStore(file(), xor, xor, unlocked)
        assertArrayEquals(seed, r.loadOrInitSeed()!!)
        (1L..301L).forEach { assertTrue("id $it", r.isMutual(it)) }
        assertEquals("07700900123", r.numberFor(9L))
    }

    @Test
    fun versionOneFileKeepsNumberWithNoMutualAndGetsANewSeed() {
        val s = storeWith(plaintext(version = 1))
        val fresh = s.loadOrInitSeed()!!
        assertFalse(fresh.contentEquals(seed))
        assertEquals("07700900123", s.numberFor(9L))
        for (id in listOf(1L, 7L, 8L, 9L)) assertFalse(s.isMutual(id))
        assertEquals(3, xor(VaultFile(file()).read()!!)[4].toInt())
        assertArrayEquals(fresh, ContactMetaStore(file(), xor, xor, unlocked).loadOrInitSeed()!!)
    }

    @Test
    fun versionOneFileWithAppendedMutualBytesIsRejectedNotReadAsMutual() {
        val forged = ByteBuffer.allocate(2 + 8).putShort(1).putLong(7L).array()
        assertRejected(storeWith(plaintext(version = 1, trailing = forged)), "v1+mutual tail")
    }

    @Test
    fun everyTruncationIsRejectedWithoutCrash() {
        for (version in listOf(2, 3)) {
            val full = plaintext(version = version)
            for (len in 0 until full.size) {
                assertRejected(storeWith(full.copyOf(len)), "v$version truncated to $len")
            }
        }
    }

    @Test
    fun tamperedMutualCountIsRejected() {
        assertRejected(storeWith(plaintext(declaredMutual = 0xFFFF)), "count 65535")
        assertRejected(storeWith(plaintext(declaredMutual = 3)), "count 3 with 2 ids")
        assertRejected(storeWith(plaintext(declaredMutual = 1)), "count 1 with 2 ids (trailing id)")
        assertRejected(storeWith(plaintext(declaredMutual = 0, mutual = listOf(7L))), "count 0 with an id")
        assertRejected(storeWith(plaintext(trailing = byteArrayOf(1))), "one trailing byte")
    }

    @Test
    fun unknownVersionsAreRejected() {
        assertRejected(storeWith(plaintext(version = 0)), "v0")
        assertRejected(storeWith(plaintext(version = 4)), "v4")
        assertRejected(storeWith(plaintext(version = 255)), "v255")
    }

    @Test
    fun nonPositiveAndDuplicateMutualIdsAreIgnored() {
        val s = storeWith(plaintext(mutual = listOf(0L, -5L, 7L, 7L)))
        assertArrayEquals(seed, s.loadOrInitSeed()!!)
        assertFalse(s.isMutual(0L))
        assertFalse(s.isMutual(-5L))
        assertTrue(s.isMutual(7L))
        assertTrue(s.setMutual(8L, true))
        val pt = xor(VaultFile(file()).read()!!)
        val off = 4 + 1 + 32 + 2 + (8 + 1 + "07700900123".length)
        assertEquals(2, ((pt[off].toInt() and 0xFF) shl 8) or (pt[off + 1].toInt() and 0xFF))
        assertEquals(off + 2 + 16, pt.size)
    }

    @Test
    fun setMutualOnAFreshStoreSurvivesReopenAndLockUnlock() {
        var vaultOpen = true
        val s = ContactMetaStore(file(), xor, xor, { vaultOpen })
        assertTrue(s.setMutual(5L, true))
        val seed1 = s.loadOrInitSeed()!!
        vaultOpen = false
        assertFalse("locked memory holds no mutual state", s.isMutual(5L))
        vaultOpen = true
        assertArrayEquals(seed1, s.loadOrInitSeed()!!)
        assertTrue(s.isMutual(5L))
    }

    @Test
    fun retainContactsDropsMutualOfDeletedIdAndKeepsTheRest() {
        val s = storeWith(plaintext(mutual = listOf(7L, 8L)))
        s.loadOrInitSeed()
        s.retainContacts(setOf(8L, 9L))
        val r = ContactMetaStore(file(), xor, xor, unlocked)
        assertArrayEquals(seed, r.loadOrInitSeed()!!)
        assertFalse(r.isMutual(7L))
        assertTrue(r.isMutual(8L))
        assertEquals("07700900123", r.numberFor(9L))
    }

    @Test
    fun wipeClearsMutualInMemoryAndOnDisk() {
        val s = storeWith(plaintext())
        s.loadOrInitSeed()
        assertTrue(s.isMutual(7L))
        assertTrue(s.wipe())
        assertFalse(s.isMutual(7L))
        assertFalse(file().exists())
        val r = ContactMetaStore(file(), xor, xor, unlocked)
        r.loadOrInitSeed()
        assertFalse(r.isMutual(7L))
    }

    @Test
    fun setMutualFalseRemovesAndPersists() {
        val s = storeWith(plaintext())
        s.loadOrInitSeed()
        assertTrue(s.setMutual(7L, false))
        assertTrue(s.setMutual(7L, false))
        val r = ContactMetaStore(file(), xor, xor, unlocked)
        r.loadOrInitSeed()
        assertFalse(r.isMutual(7L))
        assertTrue(r.isMutual(8L))
    }

    @Test
    fun setMutualReportsAFailedSeal() {
        val s = ContactMetaStore(file(), { null }, xor, unlocked)
        assertFalse(s.setMutual(5L, true))
    }

    private fun vc(flags: Int) = VaultContact(3L, flags, ByteArray(33) { 2 }, "Ana", null, null)

    @Test
    fun mutualOnlyCountsWhenTheVaultContactHasAPsk() {
        assertTrue(vc(0x01).toContact(null, true).mutual)
        assertTrue(vc(0x01).toContact(null, true).paired)
        assertFalse(vc(0x01).toContact(null, false).mutual)
        assertFalse(vc(0x00).toContact(null, true).mutual)
        assertFalse(vc(0x00).toContact(null, true).paired)
    }

    @Test
    fun displayFollowsPairedAndMutual() {
        val base = FakeScenarios.sam.copy(keyChanged = false, verified = false)
        assertEquals(R.string.detail_paired_yes, ContactUi.pairing(base.copy(paired = true, mutual = true)).textRes)
        assertEquals(R.string.detail_paired_waiting, ContactUi.pairing(base.copy(paired = true, mutual = false)).textRes)
        assertEquals(R.string.detail_paired_no, ContactUi.pairing(base.copy(paired = false, mutual = false)).textRes)
        assertEquals(R.string.detail_paired_no, ContactUi.pairing(base.copy(paired = false, mutual = true)).textRes)
        assertEquals(R.string.detail_paired_waiting, ContactUi.status(base.copy(paired = true, mutual = false)).textRes)
        assertEquals(R.string.badge_unverified, ContactUi.status(base.copy(paired = false, mutual = true)).textRes)
        assertEquals(R.string.badge_verified, ContactUi.status(base.copy(verified = true, paired = true, mutual = false)).textRes)
        assertEquals(R.string.badge_key_changed, ContactUi.status(base.copy(keyChanged = true, verified = true, paired = true, mutual = true)).textRes)
    }
}
