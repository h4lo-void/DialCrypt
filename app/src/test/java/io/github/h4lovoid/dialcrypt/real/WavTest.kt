package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.real.Wav
import io.github.h4lovoid.dialcrypt.core.real.WavWriter
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class WavTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private fun wav(rate: Int = 16_000, channels: Int = 1, bits: Int = 16, format: Int = 1, vararg samples: Short): ByteArray {
        val data = ByteBuffer.allocate(samples.size * 2).order(ByteOrder.LITTLE_ENDIAN)
        samples.forEach { data.putShort(it) }
        val b = ByteBuffer.allocate(44 + data.capacity()).order(ByteOrder.LITTLE_ENDIAN)
        b.put("RIFF".toByteArray()).putInt(36 + data.capacity()).put("WAVE".toByteArray())
        b.put("fmt ".toByteArray()).putInt(16).putShort(format.toShort()).putShort(channels.toShort())
        b.putInt(rate).putInt(rate * channels * bits / 8).putShort((channels * bits / 8).toShort()).putShort(bits.toShort())
        b.put("data".toByteArray()).putInt(data.capacity()).put(data.array())
        return b.array()
    }

    @Test
    fun parsesAValidHeaderAndSamples() {
        val s = Wav.parse(wav(samples = shortArrayOf(1, -2, 32767, -32768)))
        assertNotNull(s)
        assertArrayEquals(shortArrayOf(1, -2, 32767, -32768), s)
    }

    @Test
    fun skipsExtraChunksBeforeData() {
        val plain = wav(samples = shortArrayOf(5, 6))
        val extra = ByteBuffer.allocate(8 + 3 + 1).order(ByteOrder.LITTLE_ENDIAN)
        extra.put("LIST".toByteArray()).putInt(3).put(byteArrayOf(1, 2, 3, 0))
        val joined = plain.copyOfRange(0, 36) + extra.array() + plain.copyOfRange(36, plain.size)
        assertArrayEquals(shortArrayOf(5, 6), Wav.parse(joined))
    }

    @Test
    fun rejectsOtherFormats() {
        assertNull(Wav.parse(wav(rate = 8_000, samples = shortArrayOf(1))))
        assertNull(Wav.parse(wav(rate = 48_000, samples = shortArrayOf(1))))
        assertNull(Wav.parse(wav(channels = 2, samples = shortArrayOf(1, 2))))
        assertNull(Wav.parse(wav(bits = 8, samples = shortArrayOf(1))))
        assertNull(Wav.parse(wav(format = 3, samples = shortArrayOf(1))))
        assertNull(Wav.parse(ByteArray(0)))
        assertNull(Wav.parse("RIFFxxxxWAVE".toByteArray()))
        assertNull(Wav.parse(ByteArray(64)))
    }

    @Test
    fun truncatedDataIsClampedToWhatIsThere() {
        val full = wav(samples = shortArrayOf(1, 2, 3, 4))
        assertArrayEquals(shortArrayOf(1, 2), Wav.parse(full.copyOfRange(0, full.size - 3)))
    }

    @Test
    fun writerOutputReadsBackAndFillsTheLength() {
        val f = File(tmp.root, "rx.wav")
        val a = ShortArray(320) { (it - 100).toShort() }
        val b = ShortArray(7) { (it * 3).toShort() }
        WavWriter(f).use { w ->
            w.append(a, 0, a.size)
            w.append(b, 0, b.size)
            assertEquals(327L, w.samples)
        }
        val bytes = f.readBytes()
        assertEquals(44 + 327 * 2, bytes.size)
        val head = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(36 + 327 * 2, head.getInt(4))
        assertEquals(327 * 2, head.getInt(40))
        assertArrayEquals(a + b, Wav.parse(bytes))
    }

    @Test
    fun flushedFileIsReadableBeforeClose() {
        val f = File(tmp.root, "mid.wav")
        val w = WavWriter(f)
        assertArrayEquals(ShortArray(0), Wav.parse(f.readBytes()))
        w.append(shortArrayOf(9, 8, 7), 0, 3)
        w.flushHeader()
        assertArrayEquals(shortArrayOf(9, 8, 7), Wav.parse(f.readBytes()))
        w.append(shortArrayOf(6), 0, 1)
        w.close()
        assertArrayEquals(shortArrayOf(9, 8, 7, 6), Wav.parse(f.readBytes()))
    }
}
