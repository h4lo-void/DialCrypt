package io.github.h4lovoid.dialcrypt

import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import io.github.h4lovoid.dialcrypt.ui.components.QrCodeEncoder
import java.util.Random
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The scanner (ZXing) stops looking for finder patterns once it has three. A cross in the data that
 * looks like one, above the bottom-left finder, then takes that finder's place and the code cannot be
 * read at any size. The encoder must not hand out such a code.
 */
class QrLookAlikeTest {
    /** Each module [scale] pixels, four modules of quiet zone, read the way the camera path reads a frame. */
    private fun read(matrix: Array<BooleanArray>, scale: Int): String? {
        val quiet = 4
        val side = (matrix.size + 2 * quiet) * scale
        val pixels = IntArray(side * side) { WHITE }
        for (r in matrix.indices) for (c in matrix.indices) if (matrix[r][c]) {
            for (y in 0 until scale) for (x in 0 until scale) pixels[((r + quiet) * scale + y) * side + (c + quiet) * scale + x] = BLACK
        }
        val source = RGBLuminanceSource(side, side, pixels)
        val hints = mapOf(DecodeHintType.TRY_HARDER to true)
        for (bitmap in listOf(BinaryBitmap(HybridBinarizer(source)), BinaryBitmap(GlobalHistogramBinarizer(source)))) {
            try {
                return QRCodeReader().decode(bitmap, hints).text
            } catch (e: Exception) {
                // The next binarizer, as in the scanner.
            }
        }
        return null
    }

    @Test
    fun cardsThatOnceCarriedAFourthFinderAreReadAtEverySize() {
        // Under the mask the plain penalty rules pick, both cards have a cross at column 22 just above
        // the centre alignment pattern. ZXing took it for the third finder: the first card could not be
        // read at 4 pixels a module or more, the second not as the add-contact page draws it.
        for (text in listOf(CARD_SEEN_AT_NO_SIZE, CARD_SEEN_ONLY_SQUARE)) {
            val matrix = QrCodeEncoder.encode(text)
            assertNotNull(matrix)
            assertEquals(0, QrCodeEncoder.finderLookAlikes(matrix!!))
            for (scale in 3..10) assertEquals("at $scale px", text, read(matrix, scale))
        }
    }

    @Test
    fun aFinderPatternInTheDataIsCountedAndTheThreeRealOnesAreNot() {
        val n = 45
        val blank = Array(n) { BooleanArray(n) }
        assertEquals(0, QrCodeEncoder.finderLookAlikes(blank))

        fun finderAt(m: Array<BooleanArray>, top: Int, left: Int) {
            for (r in 0..6) for (c in 0..6) {
                m[top + r][left + c] = r == 0 || r == 6 || c == 0 || c == 6 || (r in 2..4 && c in 2..4)
            }
        }
        val corners = Array(n) { BooleanArray(n) }
        finderAt(corners, 0, 0)
        finderAt(corners, 0, n - 7)
        finderAt(corners, n - 7, 0)
        assertEquals(0, QrCodeEncoder.finderLookAlikes(corners))

        finderAt(corners, 20, 25)
        assertEquals(1, QrCodeEncoder.finderLookAlikes(corners))

        // Wider in the middle (1:1:4:1:1 down the column) is still inside ZXing's tolerance.
        val stretched = Array(n) { BooleanArray(n) }
        for (r in 0..7) for (c in 0..6) {
            stretched[20 + r][25 + c] = r == 0 || r == 7 || c == 0 || c == 6 || (r in 2..5 && c in 2..4)
        }
        assertTrue(QrCodeEncoder.finderLookAlikes(stretched) >= 1)
    }

    @Test
    fun cardsOfTheUsualLengthsHoldNoLookAlikeAndAreReadAtEverySize() {
        val random = Random(20261124L)
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        // 110 and 131 characters after the prefix: a first card and a tagged reply.
        for (length in listOf(110, 131)) {
            repeat(120) { i ->
                val text = "AEGISCARD1:" + String(CharArray(length) { alphabet[random.nextInt(alphabet.length)] })
                val matrix = QrCodeEncoder.encode(text)
                assertNotNull(matrix)
                assertEquals("card $i of length $length", 0, QrCodeEncoder.finderLookAlikes(matrix!!))
                for (scale in listOf(3, 4, 5, 7, 10)) assertEquals("card $i of length $length at $scale px", text, read(matrix, scale))
            }
        }
    }

    private companion object {
        const val BLACK = 0xFF000000.toInt()
        const val WHITE = 0xFFFFFFFF.toInt()
        const val CARD_SEEN_AT_NO_SIZE =
            "AEGISCARD1:AwLK7xQ5XoOozfIXPGGGq9D1Gj9kia7T-B1CZ4yx1vsgRWqPtNn-I0htkrfcASZLcJW63wQpTnOYveIHLFF2m8DlCtAYlGrjuQVxBFWiBFYMfPiR6D_efHG9SvI2AANib2I"
        const val CARD_SEEN_ONLY_SQUARE =
            "AEGISCARD1:AwLK7xQ5XoOozfIXPGGGq9D1Gj9kia7T-B1CZ4yx1vsgRWqPtNn-I0htkrfcASZLcJW63wQpTnOYveIHLFF2m8DlCtAY3sQH1tGdTJlOQNgdRX9aaP0SrDiOX2PPAANib2I"
    }
}
