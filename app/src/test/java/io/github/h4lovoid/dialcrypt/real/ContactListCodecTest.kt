package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.HardwareLevel
import io.github.h4lovoid.dialcrypt.core.QuickConnect
import io.github.h4lovoid.dialcrypt.core.real.ContactListCodec
import io.github.h4lovoid.dialcrypt.core.real.Fingerprint
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ContactListCodecTest {
    private fun pub(seed: Int) = ByteArray(33) { (seed * 7 + it).toByte() }

    private fun Bytes.contact(id: Long, flags: Int, pub: ByteArray, label: String, boot: Int = 0, patch: Long = 0) = apply {
        val l = label.toByteArray(Charsets.UTF_8)
        u32(id).u8(flags).raw(pub).u8(l.size).raw(l)
        if (flags and 0x10 != 0) u8(boot).u32(patch)
        if (flags and 0x20 != 0) fill(16, 0x5A)
    }

    @Test
    fun emptyList() {
        assertEquals(0, ContactListCodec.parse(bytes { u16(0) })!!.size)
    }

    @Test
    fun parsesFlagsAttestationAndNumberTag() {
        val data = bytes {
            u16(3)
            contact(1, 0x00, pub(1), "Ann")
            contact(2, 0x01 or 0x02 or 0x04 or 0x10 or 0x20, pub(2), "Bo €", boot = 1, patch = 202410)
            contact(0xFFFF_FFFEL, 0x08 or 0x10, pub(3), "", boot = 2, patch = 202301)
        }
        val list = ContactListCodec.parse(data)!!
        assertEquals(3, list.size)

        val a = list[0]
        assertEquals(1L, a.id)
        assertEquals("Ann", a.label)
        assertArrayEquals(pub(1), a.pub33)
        assertNull(a.boot)
        assertFalse(a.hasNumberTag)

        val b = list[1]
        assertEquals("Bo €", b.label)
        assertTrue(b.hasPsk && b.sasVerified && b.resumeCurrent && b.hasNumberTag)
        assertEquals(1, b.boot)
        assertEquals(202410L, b.osPatch)

        val c = list[2]
        assertEquals(0xFFFF_FFFEL, c.id)
        assertTrue(c.resumeNew)
        assertEquals(2, c.boot)
    }

    @Test
    fun mapsToUiContact() {
        val data = bytes {
            u16(4)
            contact(1, 0x00, pub(1), "A")
            contact(2, 0x01 or 0x02 or 0x04 or 0x10 or 0x20, pub(2), "B", boot = 0, patch = 1)
            contact(3, 0x02 or 0x10, pub(3), "C", boot = 1, patch = 1)
            contact(4, 0x08 or 0x10, pub(4), "D", boot = 2, patch = 1)
        }
        val ui = ContactListCodec.parse(data)!!.map { it.toContact() }

        assertEquals(1L, ui[0].id)
        assertEquals("A", ui[0].name)
        assertFalse(ui[0].verified)
        assertFalse(ui[0].paired)
        assertEquals(QuickConnect.UNAVAILABLE, ui[0].quickConnect)
        assertEquals(HardwareLevel.UNATTESTED, ui[0].hardware)
        assertEquals(Fingerprint.of(pub(1)), ui[0].fingerprint)

        assertTrue(ui[1].verified)
        assertTrue(ui[1].paired)
        assertEquals(QuickConnect.READY, ui[1].quickConnect)
        assertEquals(HardwareLevel.STRONGBOX_LOCKED, ui[1].hardware)
        // Only a tag of the number is stored.
        assertNull(ui[1].number)

        assertEquals(QuickConnect.REBUILD_PENDING, ui[2].quickConnect)
        assertEquals(HardwareLevel.STRONGBOX_SELF_SIGNED, ui[2].hardware)
        assertEquals(QuickConnect.REBUILD_PENDING, ui[3].quickConnect)
        assertEquals(HardwareLevel.STRONGBOX_UNLOCKED, ui[3].hardware)
        assertTrue(ui.none { it.keyChanged })
    }

    @Test
    fun malformedListsAreRejected() {
        val good = bytes { u16(1).contact(5, 0x10 or 0x20, pub(5), "Eve", boot = 0, patch = 1) }
        assertTrue(ContactListCodec.parse(good) != null)
        for (cut in 0 until good.size) assertNull("cut $cut", ContactListCodec.parse(good.copyOf(cut)))
        assertNull("trailing byte", ContactListCodec.parse(good + byteArrayOf(0)))
        assertNull("count too high", ContactListCodec.parse(bytes { u16(2).contact(5, 0, pub(5), "Eve") }))
        assertNull("unknown flag", ContactListCodec.parse(bytes { u16(1).contact(5, 0x40, pub(5), "Eve") }))
        assertNull("id 0", ContactListCodec.parse(bytes { u16(1).contact(0, 0, pub(5), "Eve") }))
        assertNull("boot code", ContactListCodec.parse(bytes { u16(1).contact(5, 0x10, pub(5), "Eve", boot = 3) }))
        val badUtf8 = bytes { u16(1).u32(5).u8(0).raw(pub(5)).u8(2).u8(0xC3).u8(0x28) }
        assertNull("bad UTF-8", ContactListCodec.parse(badUtf8))
    }

    @Test
    fun fingerprintIsSixteenUpperHexBytesInGroups() {
        val f = Fingerprint.of(pub(1))
        assertTrue(f, Regex("[0-9A-F]{4}( [0-9A-F]{4}){7}").matches(f))
        assertEquals(f, Fingerprint.of(pub(1)))
        assertNotEquals(f, Fingerprint.of(pub(2)))
    }
}
