package io.github.h4lovoid.dialcrypt

import com.google.zxing.BinaryBitmap
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.BitMatrix
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import io.github.h4lovoid.dialcrypt.core.InviteCard
import io.github.h4lovoid.dialcrypt.core.PairingCodeCodec
import io.github.h4lovoid.dialcrypt.ui.components.QrCodeEncoder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The QR codes the add-contact page shows are read back by the same decoder the camera uses (ZXing),
 * and the card that comes out still proves which of our cards it answers.
 */
class QrRoundTripTest {
    /** Draws [matrix] the way a screen does (quiet zone, each module [scale] pixels) and decodes it. */
    private fun decode(matrix: Array<BooleanArray>, scale: Int = 4, quiet: Int = 4): String {
        val n = matrix.size
        val side = (n + 2 * quiet) * scale
        val bits = BitMatrix(side)
        for (r in 0 until n) {
            for (c in 0 until n) {
                if (matrix[r][c]) bits.setRegion((c + quiet) * scale, (r + quiet) * scale, scale, scale)
            }
        }
        val pixels = IntArray(side * side) { i -> if (bits.get(i % side, i / side)) BLACK else WHITE }
        return QRCodeReader().decode(BinaryBitmap(HybridBinarizer(RGBLuminanceSource(side, side, pixels)))).text
    }

    @Test
    fun aTaggedReplyCardSurvivesTheQrCodeAndStillAnswersOurCard() {
        val ours = InviteCard("Alice", "+447700900123", codeOf(1), InviteCard.newNonce())
        val tag = InviteCard.replyTag(ours, codeOf(2))
        assertNotNull(tag)
        val reply = InviteCard("Bob", "07700900123", codeOf(2), InviteCard.newNonce(), tag)
        val text = reply.toTextCard()!!
        assertTrue(text.startsWith("AEGISCARD1:"))

        val matrix = QrCodeEncoder.encode(text)
        assertNotNull(matrix)
        val decoded = decode(matrix!!)
        assertEquals(text, decoded)

        val parsed = InviteCard.parse(decoded)
        assertNotNull(parsed)
        assertEquals(reply.code, parsed!!.code)
        assertEquals("Bob", parsed.name)
        assertEquals("07700900123", parsed.number)
        assertEquals(tag, parsed.replyTo)
        assertTrue("the reply proves Bob saved our card", InviteCard.answers(parsed, ours))
        assertFalse("but not some other card of ours", InviteCard.answers(parsed, ours.copy(nonce = ours.nonce!! + 1)))
    }

    @Test
    fun theLongestCardStillFitsTheLargestQrVersionAndDecodes() {
        val ours = InviteCard("A", null, codeOf(3), 3L)
        // Three UTF-8 bytes per character and the longest number: the name gets cut to fit the 154-byte card.
        val longest = InviteCard(
            "€".repeat(InviteCard.MAX_NAME_CHARS),
            "1".repeat(32),
            codeOf(4),
            Long.MIN_VALUE,
            InviteCard.replyTag(ours, codeOf(4)),
        )
        assertEquals(154, longest.toCompactBytes()!!.size)
        val text = longest.toTextCard()!!

        val matrix = QrCodeEncoder.encode(text)
        assertNotNull("must fit version 12", matrix)
        assertTrue(matrix!!.size <= 17 + 4 * 12)
        val decoded = decode(matrix)
        assertEquals(text, decoded)
        val parsed = InviteCard.parse(decoded)!!
        assertEquals("1".repeat(32), parsed.number)
        assertTrue(parsed.name.isNotEmpty() && parsed.name.all { it == '€' })
        assertTrue(InviteCard.answers(parsed, ours))
    }

    private companion object {
        const val BLACK = 0xFF000000.toInt()
        const val WHITE = 0xFFFFFFFF.toInt()

        fun codeOf(seed: Int): String {
            val raw = ByteArray(PairingCodeCodec.RAW_LEN)
            raw[0] = 3
            for (i in 1 until 66) raw[i] = ((i * 37 + seed * 101 + 5) and 0xFF).toByte()
            var crc = 0xFFFF
            for (i in 0 until 66) {
                crc = crc xor ((raw[i].toInt() and 0xFF) shl 8)
                repeat(8) {
                    crc = if ((crc and 0x8000) != 0) ((crc shl 1) xor 0x1021) and 0xFFFF else (crc shl 1) and 0xFFFF
                }
            }
            raw[66] = ((crc ushr 8) and 0xFF).toByte()
            raw[67] = (crc and 0xFF).toByte()
            return PairingCodeCodec.encode(raw)!!
        }
    }
}
