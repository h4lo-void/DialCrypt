package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.real.ContactMetaStore
import io.github.h4lovoid.dialcrypt.core.real.VaultFile
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

/** contact_meta.bin is sealed by the native vault: nothing in it is readable or writable while the app is locked. */
class ContactMetaLockTest {
    @Rule
    @JvmField
    val tmp = TemporaryFolder()

    /** Stand-in for nativeMetaSeal / nativeMetaOpen: fails while locked; the first byte names the sealing key. */
    private class FakeVault {
        var unlocked = true
        var sealFails = false
        var key: Byte = 0x5A
        var opens = 0
        val seal: (ByteArray) -> ByteArray? = { pt ->
            if (!unlocked || sealFails) null else byteArrayOf(key) + xor(pt)
        }
        val open: (ByteArray) -> ByteArray? = { ct ->
            opens++
            if (!unlocked || ct.isEmpty() || ct[0] != key) null else xor(ct.copyOfRange(1, ct.size))
        }

        private fun xor(b: ByteArray) = b.map { (it.toInt() xor key.toInt()).toByte() }.toByteArray()

        fun plaintextOf(f: File): ByteArray = open(VaultFile(f).read()!!)!!
    }

    private fun file() = File(tmp.root, "contact_meta.bin")

    private fun store(v: FakeVault) = ContactMetaStore(file(), v.seal, v.open, { v.unlocked })

    /** A version 2 plaintext: seed, number 07700900101 for id 9, contact 7 marked mutual. */
    private fun versionTwo(seed: ByteArray): ByteArray {
        val number = "07700900101".toByteArray(Charsets.UTF_8)
        return ByteBuffer.allocate(4 + 1 + 32 + 2 + 8 + 1 + number.size + 2 + 8)
            .put("ACMD".toByteArray(Charsets.US_ASCII)).put(2.toByte()).put(seed)
            .putShort(1).putLong(9L).put(number.size.toByte()).put(number)
            .putShort(1).putLong(7L)
            .array()
    }

    @Test
    fun versionTwoFileKeepsNumbersAndMutualAndIsRewrittenAsVersionThreeWithANewSeed() {
        val v = FakeVault()
        val old = ByteArray(32) { (it * 3 + 1).toByte() }
        assertTrue(VaultFile(file()).write(v.seal(versionTwo(old))!!))
        val s = store(v)
        val fresh = s.loadOrInitSeed()!!
        assertFalse("the old seed was printed in every pairing code", fresh.contentEquals(old))
        assertEquals("07700900101", s.numberFor(9L))
        assertTrue(s.isMutual(7L))
        val pt = v.plaintextOf(file())
        assertEquals(3, pt[4].toInt())
        assertArrayEquals(fresh, pt.copyOfRange(5, 37))

        val reopened = store(v)
        assertArrayEquals(fresh, reopened.loadOrInitSeed()!!)
        assertEquals("07700900101", reopened.numberFor(9L))
        assertTrue(reopened.isMutual(7L))
    }

    @Test
    fun noSeedIsHandedOutUntilItIsInTheFile() {
        val v = FakeVault()
        v.sealFails = true
        val s = store(v)
        assertNull("first seed not written", s.loadOrInitSeed())
        assertFalse(file().exists())
        v.sealFails = false
        val first = s.loadOrInitSeed()!!
        assertArrayEquals(first, store(v).loadOrInitSeed()!!)

        v.sealFails = true
        assertNull("new seed not written", s.rotateSeed())
        assertArrayEquals("the old seed stays in memory", first, s.loadOrInitSeed()!!)
        assertArrayEquals("and in the file", first, store(v).loadOrInitSeed()!!)
        v.sealFails = false
        val second = s.rotateSeed()!!
        assertFalse(second.contentEquals(first))
        assertArrayEquals(second, s.loadOrInitSeed()!!)
        assertArrayEquals(second, store(v).loadOrInitSeed()!!)
    }

    @Test
    fun aNewSeedTheNativeSideRefusesIsTakenBackFromTheFile() {
        val v = FakeVault()
        val s = store(v)
        assertTrue(s.setNumber(9L, "07700900101"))
        val old = s.loadOrInitSeed()!!
        var handed: ByteArray? = null
        assertNull(s.rotateSeed { seed -> handed = seed.copyOf(); false })
        assertFalse(handed!!.contentEquals(old))
        assertArrayEquals("the old seed stays in memory", old, s.loadOrInitSeed()!!)
        assertArrayEquals("and is back in the file", old, store(v).loadOrInitSeed()!!)
        assertEquals("07700900101", store(v).numberFor(9L))
        assertNull("an exception counts as a refusal", s.rotateSeed { throw IllegalStateException("native") })
        assertArrayEquals(old, store(v).loadOrInitSeed()!!)
        val fresh = s.rotateSeed { true }!!
        assertFalse(fresh.contentEquals(old))
        assertArrayEquals(fresh, store(v).loadOrInitSeed()!!)
    }

    @Test
    fun versionTwoFileWhoseRewriteFailsGivesNoSeedButKeepsItsData() {
        val v = FakeVault()
        val old = ByteArray(32) { 9 }
        assertTrue(VaultFile(file()).write(v.seal(versionTwo(old))!!))
        v.sealFails = true
        val s = store(v)
        assertNull(s.loadOrInitSeed())
        assertEquals("07700900101", s.numberFor(9L))
        assertTrue(s.isMutual(7L))
        v.sealFails = false
        val fresh = s.loadOrInitSeed()!!
        assertFalse(fresh.contentEquals(old))
        assertEquals(3, v.plaintextOf(file())[4].toInt())
    }

    @Test
    fun lockedStoreReadsAndWritesNothingAndLeavesTheFileAlone() {
        val v = FakeVault()
        val s = store(v)
        val seed = s.loadOrInitSeed()!!
        assertTrue(s.setNumber(7L, "07700900101"))
        assertTrue(s.setMutual(7L, true))
        val onDisk = file().readBytes()
        val opensBefore = v.opens

        v.unlocked = false
        assertNull(s.loadOrInitSeed())
        assertNull(s.rotateSeed())
        assertNull(s.numberFor(7L))
        assertFalse(s.isMutual(7L))
        assertFalse(s.setNumber(8L, "07700900102"))
        assertFalse(s.setMutual(8L, true))
        s.retainContacts(emptySet())
        assertEquals("the file is not opened while locked", opensBefore, v.opens)
        assertArrayEquals("the file is untouched while locked", onDisk, file().readBytes())

        v.unlocked = true
        assertEquals("07700900101", s.numberFor(7L))
        assertEquals("locking dropped the memory, so the file is read again", opensBefore + 1, v.opens)
        assertArrayEquals(seed, s.loadOrInitSeed()!!)
        assertTrue(s.isMutual(7L))
        assertNull(s.numberFor(8L))
        assertFalse(s.isMutual(8L))
    }

    @Test
    fun oldFormatFileIsDeletedOnceUnlockedAndTheStoreStartsEmpty() {
        // Layout of the former StrongBox AES-GCM file: iv length 12, iv, ciphertext and tag.
        assertTrue(VaultFile(file()).write(byteArrayOf(12) + ByteArray(12 + 40) { 3 }))
        val v = FakeVault()
        v.unlocked = false
        val s = store(v)
        assertNull(s.loadOrInitSeed())
        assertTrue("kept while locked", file().exists())

        v.unlocked = true
        assertNull(s.numberFor(9L))
        assertFalse("deleted once the unlocked vault cannot open it", file().exists())
        val fresh = s.loadOrInitSeed()!!
        assertEquals(32, fresh.size)
        assertEquals(v.key, file().readBytes()[0])
        assertArrayEquals(fresh, store(v).loadOrInitSeed()!!)
    }

    @Test
    fun fileSealedByAnotherVaultIsDiscarded() {
        val previous = FakeVault().apply { key = 0x33 }
        assertTrue(store(previous).setNumber(7L, "07700900101"))
        val s = store(FakeVault())
        assertNull(s.numberFor(7L))
        assertFalse(file().exists())
        assertNotNull(s.loadOrInitSeed())
        assertTrue(file().exists())
    }

    @Test
    fun lockingWhileTheFileOpensKeepsTheFile() {
        val v = FakeVault()
        assertTrue(store(v).setNumber(7L, "07700900101"))
        val onDisk = file().readBytes()
        val racing = ContactMetaStore(
            file(),
            v.seal,
            { _ ->
                v.unlocked = false
                null
            },
            { v.unlocked },
        )
        assertNull(racing.numberFor(7L))
        assertArrayEquals(onDisk, file().readBytes())
        v.unlocked = true
        assertEquals("07700900101", store(v).numberFor(7L))
    }

    @Test
    fun wipeDeletesTheFileWhileLocked() {
        val v = FakeVault()
        val s = store(v)
        assertTrue(s.setNumber(7L, "07700900101"))
        v.unlocked = false
        assertTrue(s.wipe())
        assertFalse(file().exists())
        v.unlocked = true
        assertNull(s.numberFor(7L))
        assertFalse(file().exists())
    }
}
