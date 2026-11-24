package io.github.h4lovoid.dialcrypt.call

import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.cos
import kotlin.math.roundToInt
import kotlin.math.sin
import kotlin.math.sqrt
import kotlin.random.Random
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ResamplerTest {
    private fun tone(rate: Int, hz: Double, amp: Double, count: Int) =
        ShortArray(count) { (amp * sin(2 * PI * hz * it / rate)).roundToInt().toShort() }

    /** Pushes [input] in chunks of the given sizes (cycled) and drains everything available. */
    private fun run(r: Resampler, input: ShortArray, chunks: IntArray = intArrayOf(input.size)): ShortArray {
        val out = ArrayList<Short>()
        val tmp = ShortArray(257)
        var pos = 0
        var c = 0
        while (pos < input.size) {
            val n = minOf(chunks[c++ % chunks.size], input.size - pos)
            r.push(input, pos, n)
            pos += n
            while (true) {
                val got = r.pull(tmp, 0, tmp.size)
                if (got == 0) break
                for (i in 0 until got) out.add(tmp[i])
            }
        }
        return out.toShortArray()
    }

    private fun rms(x: ShortArray, from: Int, to: Int): Double {
        var s = 0.0
        for (i in from until to) s += x[i].toDouble() * x[i]
        return sqrt(s / (to - from))
    }

    /** Amplitude of the [hz] component, by correlation. */
    private fun level(x: ShortArray, rate: Int, hz: Double, from: Int, to: Int): Double {
        var re = 0.0
        var im = 0.0
        for (i in from until to) {
            re += x[i] * cos(2 * PI * hz * i / rate)
            im += x[i] * sin(2 * PI * hz * i / rate)
        }
        return 2 * sqrt(re * re + im * im) / (to - from)
    }

    @Test
    fun equalRatesCopyExactly() {
        val rnd = Random(7)
        val input = ShortArray(5000) { rnd.nextInt(-32768, 32768).toShort() }
        val out = run(Resampler(16_000, 16_000), input)
        assertTrue(out.size > 4900)
        assertArrayEquals(input.copyOf(out.size), out)
    }

    @Test
    fun chunkingDoesNotChangeTheOutput() {
        val rnd = Random(11)
        val pairs = listOf(48_000 to 16_000, 16_000 to 48_000, 44_100 to 16_000, 8_000 to 16_000, 16_000 to 8_000)
        for ((from, to) in pairs) {
            val input = ShortArray(20_000) { rnd.nextInt(-20000, 20000).toShort() }
            val whole = run(Resampler(from, to), input)
            val pieces = run(Resampler(from, to), input, intArrayOf(1, 7, 160, 333, 2, 960))
            assertArrayEquals("$from->$to", whole, pieces)
        }
    }

    @Test
    fun outputLengthFollowsTheRateRatio() {
        for ((from, to) in listOf(48_000 to 16_000, 16_000 to 48_000, 44_100 to 16_000, 8_000 to 16_000)) {
            val input = ShortArray(from * 2)
            val out = run(Resampler(from, to), input)
            val expected = to * 2
            // Only the filter look-ahead (under 4 ms) may still be pending.
            assertTrue("$from->$to gave ${out.size}", out.size <= expected && out.size > expected - to / 250)
        }
    }

    @Test
    fun steadyLevelIsKept() {
        val input = ShortArray(48_000) { 10_000.toShort() }
        val out = run(Resampler(48_000, 16_000), input)
        for (i in 200 until out.size) assertTrue("sample $i = ${out[i]}", abs(out[i] - 10_000) <= 2)
    }

    @Test
    fun toneInBandKeepsFrequencyAndAmplitude() {
        for (from in intArrayOf(48_000, 44_100, 8_000)) {
            val out = run(Resampler(from, PCM_RATE), tone(from, 1000.0, 12_000.0, from))
            val a = level(out, PCM_RATE, 1000.0, 400, out.size - 400)
            assertEquals("$from Hz input", 12_000.0, a, 12_000.0 * 0.02)
            assertEquals("$from Hz input", 12_000.0 / sqrt(2.0), rms(out, 400, out.size - 400), 12_000.0 * 0.03)
        }
        val up = run(Resampler(PCM_RATE, 48_000), tone(PCM_RATE, 3000.0, 12_000.0, PCM_RATE))
        assertEquals(12_000.0, level(up, 48_000, 3000.0, 1000, up.size - 1000), 12_000.0 * 0.02)
    }

    @Test
    fun toneAboveTheOutputNyquistIsRemoved() {
        // 12 kHz at 48 kHz would alias to 4 kHz in a 16 kHz stream.
        val out = run(Resampler(48_000, PCM_RATE), tone(48_000, 12_000.0, 20_000.0, 48_000))
        assertTrue(rms(out, 400, out.size - 400) < 20_000 * 0.01)
        // Upsampling 8 kHz leaves no image of a 3 kHz tone at 5 kHz.
        val up = run(Resampler(8_000, PCM_RATE), tone(8_000, 3000.0, 20_000.0, 8_000))
        assertTrue(level(up, PCM_RATE, 5000.0, 400, up.size - 400) < 20_000 * 0.01)
    }
}
