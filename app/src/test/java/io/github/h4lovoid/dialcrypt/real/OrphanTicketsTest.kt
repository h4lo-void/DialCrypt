package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.real.OrphanTickets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Start-up clean-up: only tickets the vault file on disk does not reference are retired. */
class OrphanTicketsTest {
    private fun be(vararg ids: Int) = ids.flatMap { listOf(it ushr 24, it ushr 16, it ushr 8, it).map(Int::toByte) }.toByteArray()

    @Test
    fun theFileHeaderIdsAreReadBigEndian() {
        assertArrayEquals(intArrayOf(6, 7, 8, 9, 10), OrphanTickets.parseIds(be(6, 7, 8, 9, 10)))
        assertArrayEquals(intArrayOf(0x01020304, -1), OrphanTickets.parseIds(be(0x01020304, -1)))
        assertNull(OrphanTickets.parseIds(null))
        assertNull(OrphanTickets.parseIds(ByteArray(0)))
        assertNull(OrphanTickets.parseIds(ByteArray(7)))
    }

    @Test
    fun ticketsOutsideTheFileAreRetiredAndNoneOfTheFile() {
        val file = intArrayOf(6, 7, 8, 9, 10)
        // Killed after importing 11..15, before the file was replaced.
        assertArrayEquals(intArrayOf(11, 12, 13, 14, 15), OrphanTickets.toRetire(file, intArrayOf(7, 8, 9, 10, 11, 12, 13, 14, 15)))
        // Killed after the file was replaced, before 1..5 were retired.
        assertArrayEquals(intArrayOf(1, 2, 3), OrphanTickets.toRetire(file, intArrayOf(1, 2, 3, 6, 7, 8, 9, 10)))
        // Nothing extra, and spent tickets of the file are simply missing.
        assertArrayEquals(IntArray(0), OrphanTickets.toRetire(file, intArrayOf(8, 9)))
        assertArrayEquals(IntArray(0), OrphanTickets.toRetire(file, IntArray(0)))
    }

    @Test
    fun aBrokenOrUnreadableFileRetiresNothing() {
        val live = intArrayOf(1, 2, 3, 11, 12)
        assertArrayEquals(IntArray(0), OrphanTickets.toRetire(null, live))
        assertArrayEquals(IntArray(0), OrphanTickets.toRetire(IntArray(0), live))
        assertArrayEquals(IntArray(0), OrphanTickets.toRetire(OrphanTickets.parseIds(ByteArray(3)), live))
    }
}
