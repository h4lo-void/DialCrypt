package io.github.h4lovoid.dialcrypt.call

import kotlin.math.PI
import kotlin.math.ceil
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt
import kotlin.math.sin

/**
 * Streaming windowed-sinc resampler for mono 16-bit PCM between two fixed rates.
 * Output sample n sits at input time n * inRate / outRate, tracked in integers so it never
 * drifts. Equal rates give an exact copy. Not thread safe.
 */
internal class Resampler(val inRate: Int, val outRate: Int) {
    private val step: Int
    private val phases: Int
    private val half: Int
    private val taps: Int
    private val table: FloatArray

    private var buf: FloatArray
    private var len = 0
    private var base = 0
    private var phase = 0

    init {
        require(inRate > 0 && outRate > 0)
        val g = gcd(inRate, outRate)
        step = inRate / g
        phases = outRate / g
        // 0.9: keeps the transition band below the lower Nyquist frequency.
        val cutoff = if (inRate == outRate) 1.0 else 0.9 * min(1.0, outRate.toDouble() / inRate)
        half = ceil(ZERO_CROSSINGS / cutoff).toInt()
        taps = 2 * half
        table = FloatArray(phases * taps)
        for (p in 0 until phases) {
            val frac = p.toDouble() / phases
            var sum = 0.0
            val row = DoubleArray(taps) { j ->
                val x = (j - (half - 1)) - frac
                val w = blackman(x / half)
                val h = cutoff * sinc(cutoff * x) * w
                sum += h
                h
            }
            for (j in 0 until taps) table[p * taps + j] = (row[j] / sum).toFloat()
        }
        buf = FloatArray(max(4096, taps * 4))
        reset()
    }

    /** Drops all buffered input and starts over. */
    fun reset() {
        buf.fill(0f)
        len = half - 1
        base = half - 1
        phase = 0
    }

    fun push(input: ShortArray, off: Int, count: Int) {
        if (len + count > buf.size) {
            buf = buf.copyOf(max(buf.size * 2, len + count))
        }
        for (i in 0 until count) buf[len + i] = input[off + i].toFloat()
        len += count
    }

    /** Writes up to [max] output samples that the pushed input fully determines; returns the count. */
    fun pull(out: ShortArray, off: Int, max: Int): Int {
        var n = 0
        while (n < max && base + half < len) {
            val first = base - half + 1
            val row = phase * taps
            var acc = 0f
            for (j in 0 until taps) acc += buf[first + j] * table[row + j]
            out[off + n] = acc.roundToInt().coerceIn(Short.MIN_VALUE.toInt(), Short.MAX_VALUE.toInt()).toShort()
            n++
            phase += step
            base += phase / phases
            phase %= phases
        }
        compact()
        return n
    }

    private fun compact() {
        val drop = base - half + 1
        if (drop <= 0 || drop < buf.size / 2) return
        val keep = len - drop
        System.arraycopy(buf, drop, buf, 0, keep)
        len = keep
        base -= drop
    }

    private companion object {
        const val ZERO_CROSSINGS = 16

        fun gcd(a: Int, b: Int): Int = if (b == 0) a else gcd(b, a % b)

        fun sinc(x: Double): Double = if (x == 0.0) 1.0 else sin(PI * x) / (PI * x)

        /** Blackman window over -1..1. */
        fun blackman(t: Double): Double =
            if (t <= -1.0 || t >= 1.0) 0.0 else 0.42 + 0.5 * cos(PI * t) + 0.08 * cos(2 * PI * t)
    }
}
