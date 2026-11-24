package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.PinResult
import io.github.h4lovoid.dialcrypt.core.real.ChainTlv
import io.github.h4lovoid.dialcrypt.core.real.DerSplit
import io.github.h4lovoid.dialcrypt.core.real.HexLines
import io.github.h4lovoid.dialcrypt.core.real.PinBegin
import io.github.h4lovoid.dialcrypt.core.real.PinInput
import io.github.h4lovoid.dialcrypt.core.real.RotationLayout
import io.github.h4lovoid.dialcrypt.core.real.TrustConfigBuilder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LayoutsTest {
    private fun der(contentLen: Int, fill: Int): ByteArray {
        val content = ByteArray(contentLen) { fill.toByte() }
        return bytes {
            u8(0x30)
            when {
                contentLen < 0x80 -> u8(contentLen)
                contentLen < 0x100 -> u8(0x81).u8(contentLen)
                else -> u8(0x82).u16(contentLen)
            }
            raw(content)
        }
    }

    @Test
    fun rotationLayoutParsesTicketsAndRetired() {
        val m1 = ByteArray(32) { 1 }
        val m2 = ByteArray(32) { 2 }
        val data = bytes { u8(2).u32(6).raw(m1).u32(0xFFFF_FFFFL).raw(m2).u8(3).u32(1).u32(2).u32(3) }
        val layout = RotationLayout.parse(data)!!
        assertEquals(listOf(6, -1), layout.fresh.map { it.id })
        assertArrayEquals(m1, layout.fresh[0].material)
        assertArrayEquals(intArrayOf(1, 2, 3), layout.retire)
        layout.wipeMaterial()
        assertTrue(layout.fresh.all { t -> t.material.all { it == 0.toByte() } })
    }

    @Test
    fun setupRotationHasNoRetiredTickets() {
        val data = bytes {
            u8(5)
            for (id in 1..5) u32(id.toLong()).fill(32, id)
            u8(0)
        }
        val layout = RotationLayout.parse(data)!!
        assertEquals(listOf(1, 2, 3, 4, 5), layout.fresh.map { it.id })
        assertEquals(0, layout.retire.size)
    }

    @Test
    fun malformedRotationIsRejected() {
        val good = bytes { u8(1).u32(9).fill(32, 7).u8(1).u32(4) }
        for (cut in 0 until good.size) assertNull("cut $cut", RotationLayout.parse(good.copyOf(cut)))
        assertNull(RotationLayout.parse(good + byteArrayOf(0)))
    }

    @Test
    fun pinBeginNeedsExactly36Bytes() {
        val input = ByteArray(32) { (it * 3).toByte() }
        val begin = PinBegin.parse(bytes { u32(0x8000_0002L).raw(input) })!!
        assertEquals(0x8000_0002L.toInt(), begin.ticketId)
        assertArrayEquals(input, begin.input)
        begin.wipe()
        assertTrue(begin.input.all { it == 0.toByte() })
        assertNull(PinBegin.parse(ByteArray(35)))
        assertNull(PinBegin.parse(ByteArray(37)))
    }

    @Test
    fun chainTlvDropsTheRoot() {
        val leaf = der(10, 1)
        val inter = der(300, 2)
        val root = der(5, 3)
        val tlv = ChainTlv.encode(listOf(leaf, inter, root))!!
        assertArrayEquals(bytes { u16(leaf.size).raw(leaf).u16(inter.size).raw(inter) }, tlv)
        assertNull(ChainTlv.encode(listOf(leaf)))
    }

    @Test
    fun derSplitHandlesShortAndLongLengths() {
        val a = der(3, 1)
        val b = der(200, 2)
        val c = der(1000, 3)
        val parts = DerSplit.certificates(a + b + c)!!
        assertEquals(3, parts.size)
        assertArrayEquals(b, parts[1])
        assertArrayEquals(c, parts[2])
        assertNull(DerSplit.certificates(ByteArray(0)))
        assertNull(DerSplit.certificates((a + b).copyOf(a.size + b.size - 1)))
        assertNull(DerSplit.certificates(byteArrayOf(0x31, 0x01, 0x00)))
    }

    @Test
    fun hexLinesIgnoreCommentsSeparatorsAndPadOddLengths() {
        val parsed = HexLines.parse("# header\n\nAB:cd ef  # note\r\n123\n")!!
        assertEquals(2, parsed.size)
        assertArrayEquals(byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte()), parsed[0])
        assertArrayEquals(byteArrayOf(0x01, 0x23), parsed[1])
        assertEquals(0, HexLines.parse("  # nothing\n")!!.size)
        assertNull(HexLines.parse("12zz"))
    }

    @Test
    fun trustConfigEncodesAllRecordsInOrder() {
        val r1 = der(4, 1)
        val r2 = der(150, 2)
        val signer = "00".repeat(31) + "ff"
        val tlv = TrustConfigBuilder.build(
            rootsDer = r1 + r2,
            revoked = "0a1b\n",
            avbKeys = "",
            appSigners = "# release key\n$signer\n",
            minPatch = "202401\n",
        )!!
        val expected = bytes {
            u8(1)
            u8(1).u16(r1.size).raw(r1)
            u8(1).u16(r2.size).raw(r2)
            u8(2).u16(2).u8(0x0A).u8(0x1B)
            u8(4).u16(32).fill(31, 0).u8(0xFF)
            u8(5).u16(4).u32(202401)
        }
        assertArrayEquals(expected, tlv)
    }

    @Test
    fun trustConfigRejectsMissingOrBadValues() {
        val root = der(4, 1)
        val signer = "11".repeat(32)
        assertNull(TrustConfigBuilder.build(ByteArray(0), "", "", signer, "202401"))
        assertNull(TrustConfigBuilder.build(root, "", "", "", "202401"))
        assertNull(TrustConfigBuilder.build(root, "", "", "11".repeat(31), "202401"))
        assertNull(TrustConfigBuilder.build(root, "", "", signer, ""))
        assertNull(TrustConfigBuilder.build(root, "", "", signer, "202401\n202402"))
        assertNull(TrustConfigBuilder.build(root, "", "", signer, "0"))
        assertNull(TrustConfigBuilder.build(root, "xyz", "", signer, "202401"))
    }

    @Test
    fun pinChecksFollowPinRules() {
        val good = "Tr0ub4dor&3".toCharArray()
        val other = "c0rrect-h0rse".toCharArray()
        assertNull(PinInput.check(good, other))
        assertEquals(PinResult.TOO_SHORT, PinInput.check("abc123".toCharArray(), other))
        assertEquals(PinResult.TOO_SHORT, PinInput.check(good, "x".repeat(65).toCharArray()))
        assertEquals(PinResult.TOO_SIMPLE, PinInput.check("abababababab".toCharArray(), other))
        assertEquals(PinResult.SAME_PINS, PinInput.check(good, good.copyOf()))
    }

    @Test
    fun pinUtf8EncodesWithoutStrings() {
        assertArrayEquals("pin-é-😀".toByteArray(Charsets.UTF_8), PinInput.utf8("pin-é-😀".toCharArray()))
        assertNull(PinInput.utf8(charArrayOf('a', '\uD800', 'b')))
        assertEquals(0, PinInput.utf8(CharArray(0))!!.size)
    }
}
