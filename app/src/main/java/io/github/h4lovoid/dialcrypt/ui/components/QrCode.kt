package io.github.h4lovoid.dialcrypt.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import io.github.h4lovoid.dialcrypt.ui.theme.Radius
import kotlin.math.abs

/**
 * Self-contained pure-Kotlin ISO-18004 QR Code encoder (Byte mode, ECC-L, versions 1..12)
 * with zero third-party or network dependencies.
 *
 * The mask is chosen so that the code holds no fourth "finder pattern": the scanner (ZXing) stops
 * looking as soon as it has three, so a look-alike in the data above the bottom-left finder takes
 * that finder's place and the code cannot be read at any size ([finderLookAlikes]). When every mask
 * has one, the same text is written again with its first characters as byte segments of their own
 * (each segment header moves everything after it by twelve modules), and after that in the next
 * version. Every reader joins the segments back into the same text.
 */
internal object QrCodeEncoder {
    private data class VersionSpec(
        val version: Int,
        val totalCodewords: Int,
        val dataCodewords: Int,
        val ecPerBlock: Int,
        val g1Blocks: Int,
        val g1Data: Int,
        val g2Blocks: Int,
        val g2Data: Int,
        val alignments: IntArray,
    )

    // Standard ISO-18004 Level-L tables for versions 1..12.
    private val SPECS = arrayOf(
        VersionSpec(1, 26, 19, 7, 1, 19, 0, 0, intArrayOf()),
        VersionSpec(2, 44, 34, 10, 1, 34, 0, 0, intArrayOf(6, 18)),
        VersionSpec(3, 70, 55, 15, 1, 55, 0, 0, intArrayOf(6, 22)),
        VersionSpec(4, 100, 80, 20, 1, 80, 0, 0, intArrayOf(6, 26)),
        VersionSpec(5, 134, 108, 26, 1, 108, 0, 0, intArrayOf(6, 30)),
        VersionSpec(6, 172, 136, 18, 2, 68, 0, 0, intArrayOf(6, 34)),
        VersionSpec(7, 196, 156, 20, 2, 78, 0, 0, intArrayOf(6, 22, 38)),
        VersionSpec(8, 242, 194, 24, 2, 97, 0, 0, intArrayOf(6, 24, 42)),
        VersionSpec(9, 292, 232, 30, 2, 116, 0, 0, intArrayOf(6, 26, 46)),
        VersionSpec(10, 346, 274, 18, 2, 68, 2, 69, intArrayOf(6, 28, 50)),
        VersionSpec(11, 404, 324, 20, 4, 81, 0, 0, intArrayOf(6, 30, 54)),
        VersionSpec(12, 466, 370, 24, 2, 92, 2, 93, intArrayOf(6, 32, 58)),
    )

    private val GF_EXP = IntArray(512)
    private val GF_LOG = IntArray(256)

    init {
        var x = 1
        for (i in 0 until 255) {
            GF_EXP[i] = x
            GF_LOG[x] = i
            x = x shl 1
            if (x >= 256) x = x xor 0x11D
        }
        for (i in 255 until 512) GF_EXP[i] = GF_EXP[i - 255]
    }

    private fun gfMul(a: Int, b: Int): Int =
        if (a == 0 || b == 0) 0 else GF_EXP[GF_LOG[a] + GF_LOG[b]]

    private fun rsGenerator(ecCount: Int): IntArray {
        var poly = intArrayOf(1)
        for (i in 0 until ecCount) {
            val next = IntArray(poly.size + 1)
            val root = GF_EXP[i]
            for (j in poly.indices) {
                next[j] = next[j] xor poly[j]
                next[j + 1] = next[j + 1] xor gfMul(poly[j], root)
            }
            poly = next
        }
        return poly
    }

    private fun rsCompute(data: IntArray, ecCount: Int): IntArray {
        val gen = rsGenerator(ecCount)
        val rem = IntArray(ecCount)
        for (b in data) {
            val factor = b xor rem[0]
            System.arraycopy(rem, 1, rem, 0, ecCount - 1)
            rem[ecCount - 1] = 0
            for (j in 0 until ecCount) {
                rem[j] = rem[j] xor gfMul(gen[j + 1], factor)
            }
        }
        return rem
    }

    fun encode(text: String): Array<BooleanArray>? {
        val bytes = text.toByteArray(Charsets.UTF_8)
        val first = SPECS.indexOfFirst { fits(bytes.size, 0, it) }
        if (first < 0) return null
        var best: Array<BooleanArray>? = null
        var bestLookAlikes = Int.MAX_VALUE
        for (i in first..minOf(first + EXTRA_VERSIONS, SPECS.size - 1)) {
            for (leading in 0..MAX_LEADING_SEGMENTS) {
                // Only single-byte characters may stand alone: a reader decodes each segment by itself.
                if (leading > 0 && (leading >= bytes.size || bytes[leading - 1] < 0 || !fits(bytes.size, leading, SPECS[i]))) break
                val (modules, lookAlikes) = encodeAs(bytes, SPECS[i], leading)
                if (lookAlikes == 0) return modules
                if (lookAlikes < bestLookAlikes) {
                    best = modules
                    bestLookAlikes = lookAlikes
                }
            }
        }
        return best
    }

    /** Whether [byteCount] bytes, the first [leading] of them as segments of their own, fit the version of [spec]. */
    private fun fits(byteCount: Int, leading: Int, spec: VersionSpec): Boolean {
        val headerBits = 4 + if (spec.version >= 10) 16 else 8
        return (leading + 1) * headerBits + byteCount * 8 <= spec.dataCodewords * 8
    }

    /**
     * The code for [bytes] in the version of [spec] under its best mask, and how many finder
     * look-alikes it still has. The first [leading] bytes are written as one-byte segments.
     */
    private fun encodeAs(bytes: ByteArray, spec: VersionSpec, leading: Int): Pair<Array<BooleanArray>, Int> {
        val codewords = buildCodewords(bytes, spec, leading)
        val size = 17 + 4 * spec.version
        val modules = Array(size) { BooleanArray(size) }
        val function = Array(size) { BooleanArray(size) }

        placeFunctionPatterns(spec, modules, function)
        placeDataBits(codewords, modules, function)

        var bestMask = 0
        var bestPenalty = Int.MAX_VALUE
        var bestLookAlikes = Int.MAX_VALUE
        for (mask in 0..7) {
            val candidate = Array(size) { r -> modules[r].clone() }
            applyMask(mask, candidate, function)
            placeFormatAndVersion(spec.version, mask, candidate)
            // A mask without look-alikes always wins; the usual penalty decides among equals.
            val lookAlikes = finderLookAlikes(candidate)
            val p = penalty(candidate)
            if (lookAlikes < bestLookAlikes || (lookAlikes == bestLookAlikes && p < bestPenalty)) {
                bestPenalty = p
                bestLookAlikes = lookAlikes
                bestMask = mask
            }
        }
        applyMask(bestMask, modules, function)
        placeFormatAndVersion(spec.version, bestMask, modules)
        return modules to bestLookAlikes
    }

    private fun buildCodewords(bytes: ByteArray, spec: VersionSpec, leading: Int): IntArray {
        val bits = BitBuffer()
        val countBits = if (spec.version >= 10) 16 else 8
        for (i in 0 until leading) {
            bits.append(0b0100, 4)
            bits.append(1, countBits)
            bits.append(bytes[i].toInt() and 0xFF, 8)
        }
        bits.append(0b0100, 4) // Byte mode
        bits.append(bytes.size - leading, countBits)
        for (i in leading until bytes.size) bits.append(bytes[i].toInt() and 0xFF, 8)
        val maxBits = spec.dataCodewords * 8
        bits.append(0, minOf(4, maxBits - bits.size))
        while (bits.size % 8 != 0) bits.append(0, 1)
        var pad = 0
        while (bits.size < maxBits) {
            bits.append(if (pad % 2 == 0) 0xEC else 0x11, 8)
            pad++
        }
        val rawData = bits.toBytes()
        val totalBlocks = spec.g1Blocks + spec.g2Blocks
        val dataBlocks = Array(totalBlocks) { IntArray(0) }
        val ecBlocks = Array(totalBlocks) { IntArray(0) }
        var off = 0
        for (i in 0 until totalBlocks) {
            val len = if (i < spec.g1Blocks) spec.g1Data else spec.g2Data
            val block = IntArray(len) { rawData[off + it].toInt() and 0xFF }
            off += len
            dataBlocks[i] = block
            ecBlocks[i] = rsCompute(block, spec.ecPerBlock)
        }
        val out = IntArray(spec.totalCodewords)
        var outPos = 0
        val maxData = maxOf(spec.g1Data, spec.g2Data)
        for (c in 0 until maxData) {
            for (b in 0 until totalBlocks) {
                if (c < dataBlocks[b].size) out[outPos++] = dataBlocks[b][c]
            }
        }
        for (c in 0 until spec.ecPerBlock) {
            for (b in 0 until totalBlocks) {
                out[outPos++] = ecBlocks[b][c]
            }
        }
        return out
    }

    private fun placeFunctionPatterns(spec: VersionSpec, m: Array<BooleanArray>, fn: Array<BooleanArray>) {
        val n = m.size
        fun setFn(r: Int, c: Int, v: Boolean) {
            if (r in 0 until n && c in 0 until n) {
                m[r][c] = v
                fn[r][c] = true
            }
        }

        fun finder(top: Int, left: Int) {
            for (dr in -1..7) {
                for (dc in -1..7) {
                    val dark = dr in 0..6 && dc in 0..6 && (
                        dr == 0 || dr == 6 || dc == 0 || dc == 6 || (dr in 2..4 && dc in 2..4)
                        )
                    setFn(top + dr, left + dc, dark)
                }
            }
        }
        finder(0, 0)
        finder(0, n - 7)
        finder(n - 7, 0)

        for (i in 8 until n - 8) {
            val dark = i % 2 == 0
            setFn(6, i, dark)
            setFn(i, 6, dark)
        }
        val centers = spec.alignments
        for (r in centers) {
            for (c in centers) {
                // Only the three corners overlap a finder pattern; centres on the timing lines (v7+) are drawn.
                val first = centers.first()
                val last = centers.last()
                if ((r == first && (c == first || c == last)) || (r == last && c == first)) continue
                for (dr in -2..2) {
                    for (dc in -2..2) {
                        val dark = abs(dr) == 2 || abs(dc) == 2 || (dr == 0 && dc == 0)
                        setFn(r + dr, c + dc, dark)
                    }
                }
            }
        }
        // Format information reservations & dark module
        for (i in 0..8) {
            if (i != 6) {
                fn[8][i] = true
                fn[i][8] = true
            }
        }
        for (i in 0..7) {
            fn[8][n - 1 - i] = true
            fn[n - 1 - i][8] = true
        }
        setFn(n - 8, 8, true)

        if (spec.version >= 7) {
            for (i in 0 until 6) {
                for (j in 0 until 3) {
                    fn[i][n - 11 + j] = true
                    fn[n - 11 + j][i] = true
                }
            }
        }
    }

    private fun placeDataBits(codewords: IntArray, m: Array<BooleanArray>, fn: Array<BooleanArray>) {
        val n = m.size
        var bitIdx = 0
        val totalBits = codewords.size * 8
        var up = true
        var col = n - 1
        while (col > 0) {
            if (col == 6) col--
            for (step in 0 until n) {
                val row = if (up) n - 1 - step else step
                for (dc in 0..1) {
                    val c = col - dc
                    if (!fn[row][c]) {
                        val dark = if (bitIdx < totalBits) {
                            ((codewords[bitIdx ushr 3] ushr (7 - (bitIdx and 7))) and 1) != 0
                        } else {
                            false
                        }
                        m[row][c] = dark
                        bitIdx++
                    }
                }
            }
            col -= 2
            up = !up
        }
    }

    private fun applyMask(mask: Int, m: Array<BooleanArray>, fn: Array<BooleanArray>) {
        val n = m.size
        for (r in 0 until n) {
            for (c in 0 until n) {
                if (fn[r][c]) continue
                val invert = when (mask) {
                    0 -> (r + c) % 2 == 0
                    1 -> r % 2 == 0
                    2 -> c % 3 == 0
                    3 -> (r + c) % 3 == 0
                    4 -> (r / 2 + c / 3) % 2 == 0
                    5 -> (r * c) % 2 + (r * c) % 3 == 0
                    6 -> ((r * c) % 2 + (r * c) % 3) % 2 == 0
                    else -> ((r + c) % 2 + (r * c) % 3) % 2 == 0
                }
                if (invert) m[r][c] = !m[r][c]
            }
        }
    }

    private fun placeFormatAndVersion(version: Int, mask: Int, m: Array<BooleanArray>) {
        val n = m.size
        // ECC-L = 01
        val fmtData = (0b01 shl 3) or mask
        var rem = fmtData shl 10
        for (i in 14 downTo 10) {
            if ((rem and (1 shl i)) != 0) rem = rem xor (0x537 shl (i - 10))
        }
        val fmtBits = ((fmtData shl 10) or rem) xor 0x5412
        for (i in 0..14) {
            val dark = ((fmtBits ushr i) and 1) != 0
            // Vertical
            when {
                i < 6 -> m[i][8] = dark
                i < 8 -> m[i + 1][8] = dark
                else -> m[n - 15 + i][8] = dark
            }
            // Horizontal
            when {
                i < 8 -> m[8][n - 1 - i] = dark
                i < 9 -> m[8][7] = dark
                else -> m[8][14 - i] = dark
            }
        }
        if (version >= 7) {
            var vRem = version shl 12
            for (i in 17 downTo 12) {
                if ((vRem and (1 shl i)) != 0) vRem = vRem xor (0x1F25 shl (i - 12))
            }
            val vBits = (version shl 12) or vRem
            for (i in 0 until 18) {
                val dark = ((vBits ushr i) and 1) != 0
                val a = n - 11 + (i % 3)
                val b = i / 3
                m[b][a] = dark
                m[a][b] = dark
            }
        }
    }

    private fun penalty(m: Array<BooleanArray>): Int {
        val n = m.size
        var score = 0
        for (r in 0 until n) {
            var runLen = 1
            var colRunLen = 1
            for (c in 1 until n) {
                if (m[r][c] == m[r][c - 1]) runLen++ else {
                    if (runLen >= 5) score += 3 + (runLen - 5)
                    runLen = 1
                }
                if (m[c][r] == m[c - 1][r]) colRunLen++ else {
                    if (colRunLen >= 5) score += 3 + (colRunLen - 5)
                    colRunLen = 1
                }
            }
            if (runLen >= 5) score += 3 + (runLen - 5)
            if (colRunLen >= 5) score += 3 + (colRunLen - 5)
        }
        for (r in 0 until n - 1) {
            for (c in 0 until n - 1) {
                val b = m[r][c]
                if (m[r][c + 1] == b && m[r + 1][c] == b && m[r + 1][c + 1] == b) score += 3
            }
        }
        // Runs that look like a finder pattern (1:1:3:1:1 next to four light modules) make scanners
        // lock onto the wrong place, so they cost the most.
        for (r in 0 until n) {
            for (c in 0..n - FINDER_RUN) {
                if (finderLike(c) { m[r][it] }) score += 40
                if (finderLike(c) { m[it][r] }) score += 40
            }
        }
        // The share of dark modules should stay near one half.
        var dark = 0
        for (row in m) for (b in row) if (b) dark++
        score += (kotlin.math.abs(dark * 100 / (n * n) - 50) / 5) * 10
        return score
    }

    private const val FINDER_RUN = 11
    private val FINDER_THEN_LIGHT = booleanArrayOf(true, false, true, true, true, false, true, false, false, false, false)
    private val LIGHT_THEN_FINDER = booleanArrayOf(false, false, false, false, true, false, true, true, true, false, true)

    /** How many of the first characters may become segments of their own to get rid of finder look-alikes. */
    private const val MAX_LEADING_SEGMENTS = 3

    /** How many versions above the smallest fitting one may be used for the same purpose. */
    private const val EXTRA_VERSIONS = 2

    /**
     * A camera and a screen never show modules at exactly equal widths: dark runs come out a little
     * wider or narrower than light ones. Look-alikes are searched with each of these changes, in
     * modules, added to every dark run and taken from every light run.
     */
    private val RUN_GAINS = floatArrayOf(-0.25f, -0.125f, 0f, 0.125f, 0.25f)

    /**
     * Places outside the three finder patterns that ZXing's finder search (FinderPatternFinder 3.5)
     * would take for a finder pattern: a row whose runs dark-light-dark-light-dark are in proportion
     * 1:1:3:1:1 within its tolerance, the column through the middle of that centre run likewise, and
     * the row through the middle of the column's centre run again. ZXing then looks along the diagonal
     * through its centre pixel. Where inside a module that pixel falls changes with the size of the
     * picture, so here the place counts when any diagonal within half a module of the centre passes
     * ([diagonalMayMatch]). The area outside the code counts as light.
     */
    internal fun finderLookAlikes(m: Array<BooleanArray>): Int {
        val n = m.size
        val found = HashSet<Int>()
        for (gain in RUN_GAINS) {
            for (r in 0 until n) {
                var c = 0
                while (c < n) {
                    if (!m[r][c]) {
                        c++
                        continue
                    }
                    val row = runsThrough(n, c) { m[r][it] }
                    val end = if (row != null) row[START] + row[CENTER] else c + 1
                    if (row != null && crossSection(row, gain, AXIS_TOLERANCE)) {
                        for (col in middles(row)) lookAlikeFrom(m, r, col, row, gain, found)
                    }
                    while (c < n && c < end) c++
                    while (c < n && m[r][c]) c++
                }
            }
        }
        return found.size
    }

    /** The checks ZXing runs after a row matched at [r] with the centre run's middle at [col]. */
    private fun lookAlikeFrom(m: Array<BooleanArray>, r: Int, col: Int, row: IntArray, gain: Float, found: MutableSet<Int>) {
        val n = m.size
        val column = runsThrough(n, r) { m[it][col] } ?: return
        if (!sameSize(column, row, gain, 2f) || !crossSection(column, gain, AXIS_TOLERANCE)) return
        val centerY = column[START] + column[CENTER] / 2f
        for (centerRow in middles(column)) {
            val again = runsThrough(n, col) { m[centerRow][it] } ?: continue
            if (!sameSize(again, row, gain, 1f) || !crossSection(again, gain, AXIS_TOLERANCE)) continue
            val centerX = again[START] + again[CENTER] / 2f
            for (centerCol in middles(again)) {
                if (inFinder(n, centerRow, centerCol) || centerRow * n + centerCol in found) continue
                if (diagonalMayMatch(m, centerY, centerX, gain)) found += centerRow * n + centerCol
            }
        }
    }

    /**
     * ZXing's diagonal check for a centre near ([centerY], [centerX]), in modules: the runs along the
     * line down and to the right through its centre pixel must again be 1:1:3:1:1, with a wider
     * tolerance. That pixel lies within about a pixel of the centre the two axes gave, and a line a
     * fraction of a module to the side clips other modules at their corners. So every line up to half
     * a module to either side is tried, with and without the short runs a corner clip leaves.
     */
    private fun diagonalMayMatch(m: Array<BooleanArray>, centerY: Float, centerX: Float, gain: Float): Boolean {
        val n = m.size
        for (shift in -DIAGONAL_STEPS / 2..DIAGONAL_STEPS / 2) {
            val side = shift / DIAGONAL_STEPS.toFloat()
            val y = centerY - side / 2f
            val x = centerX + side / 2f
            // Samples along the line, DIAGONAL_STEPS to a module, from where it enters the code.
            val before = (minOf(y, x) * DIAGONAL_STEPS).toInt()
            val count = before + ((n - maxOf(y, x)) * DIAGONAL_STEPS).toInt()
            if (before !in 0 until count) continue
            val dark = BooleanArray(count) { i ->
                val t = (i - before + 0.5f) / DIAGONAL_STEPS
                m[(y + t).toInt().coerceIn(0, n - 1)][(x + t).toInt().coerceIn(0, n - 1)]
            }
            for (clip in CLIP_LENGTHS) {
                val line = if (clip == 0) dark else withoutShortRuns(dark, clip)
                val runs = runsThrough(count, before) { line[it] } ?: continue
                if (crossSection(runs, gain * DIAGONAL_STEPS, DIAGONAL_TOLERANCE)) return true
            }
        }
        return false
    }

    /** [line] with every run shorter than [shortest] samples given the colour before it. */
    private fun withoutShortRuns(line: BooleanArray, shortest: Int): BooleanArray {
        val out = line.clone()
        var i = 0
        while (i < out.size) {
            var j = i
            while (j < out.size && line[j] == line[i]) j++
            if (i > 0 && j - i < shortest) for (k in i until j) out[k] = out[i - 1]
            i = j
        }
        return out
    }

    private const val A = 0
    private const val B = 1
    private const val CENTER = 2
    private const val D = 3
    private const val E = 4
    private const val START = 5

    /** ZXing lets each of the five runs differ from its ideal width by half a module (three quarters on the diagonal). */
    private const val AXIS_TOLERANCE = 2f
    private const val DIAGONAL_TOLERANCE = 1.333f

    /** Samples to a module along a diagonal, and the runs (in samples) a corner clip may leave. */
    private const val DIAGONAL_STEPS = 16
    private val CLIP_LENGTHS = intArrayOf(0, 3, 5)

    /**
     * The five runs dark-light-dark-light-dark along a line of [length] modules, with the centre run
     * holding position [p], and where that centre run starts. Null when [p] is light or a run is
     * missing; a light run that reaches the edge of the code has no dark run behind it.
     */
    private inline fun runsThrough(length: Int, p: Int, dark: (Int) -> Boolean): IntArray? {
        if (p !in 0 until length || !dark(p)) return null
        var lo = p
        while (lo > 0 && dark(lo - 1)) lo--
        var hi = p
        while (hi < length - 1 && dark(hi + 1)) hi++
        var i = lo - 1
        var b = 0
        while (i >= 0 && !dark(i)) {
            b++
            i--
        }
        var a = 0
        while (i >= 0 && dark(i)) {
            a++
            i--
        }
        var j = hi + 1
        var d = 0
        while (j < length && !dark(j)) {
            d++
            j++
        }
        var e = 0
        while (j < length && dark(j)) {
            e++
            j++
        }
        if (a == 0 || b == 0 || d == 0 || e == 0) return null
        return intArrayOf(a, b, hi - lo + 1, d, e, lo)
    }

    /** ZXing's foundPatternCross: every run within module / [tolerance] of 1:1:3:1:1, after [gain]. */
    private fun crossSection(runs: IntArray, gain: Float, tolerance: Float): Boolean {
        val a = runs[A] + gain
        val b = runs[B] - gain
        val c = runs[CENTER] + gain
        val d = runs[D] - gain
        val e = runs[E] + gain
        if (b <= 0f || d <= 0f) return false
        val module = (a + b + c + d + e) / 7f
        val max = module / tolerance
        return abs(module - a) < max && abs(module - b) < max && abs(3f * module - c) < 3f * max &&
            abs(module - d) < max && abs(module - e) < max
    }

    /**
     * ZXing's cross checks also want the whole pattern near the size first seen in the row: within
     * 40% down the column ([share] 2), within 20% along the row again ([share] 1).
     */
    private fun sameSize(runs: IntArray, first: IntArray, gain: Float, share: Float): Boolean {
        val total = runs[A] + runs[B] + runs[CENTER] + runs[D] + runs[E] + gain
        val original = first[A] + first[B] + first[CENTER] + first[D] + first[E] + gain
        return 5f * abs(total - original) < share * original
    }

    /** The module in the middle of the centre run; both neighbours of the middle when its length is even. */
    private fun middles(runs: IntArray): IntArray {
        val length = runs[CENTER]
        val mid = runs[START] + length / 2
        return if (length % 2 == 1) intArrayOf(mid) else intArrayOf(mid - 1, mid)
    }

    private fun inFinder(n: Int, r: Int, c: Int): Boolean =
        (r < 7 && c < 7) || (r < 7 && c >= n - 7) || (r >= n - 7 && c < 7)

    /** True when the eleven modules from [start] read as a finder run with its four light modules before or after. */
    private inline fun finderLike(start: Int, at: (Int) -> Boolean): Boolean {
        var after = true
        var before = true
        for (i in 0 until FINDER_RUN) {
            val module = at(start + i)
            if (module != FINDER_THEN_LIGHT[i]) after = false
            if (module != LIGHT_THEN_FINDER[i]) before = false
            if (!after && !before) return false
        }
        return true
    }

    private class BitBuffer {
        private var bytes = ByteArray(64)
        var size = 0
            private set

        fun append(value: Int, numBits: Int) {
            for (i in numBits - 1 downTo 0) {
                val bit = (value ushr i) and 1
                val byteIndex = size ushr 3
                if (byteIndex >= bytes.size) bytes = bytes.copyOf(bytes.size * 2)
                if (bit == 1) {
                    bytes[byteIndex] = (bytes[byteIndex].toInt() or (1 shl (7 - (size and 7)))).toByte()
                }
                size++
            }
        }

        fun toBytes(): ByteArray = bytes.copyOf((size + 7) / 8)
    }
}

/** High-contrast QR preview with a crisp white quiet zone so any camera scanner reads it cleanly. */
@Composable
fun QrCodeBox(data: String, modifier: Modifier = Modifier) {
    val matrix = remember(data) { QrCodeEncoder.encode(data) }
    if (matrix != null) {
        Box(
            modifier
                .aspectRatio(1f)
                .clip(RoundedCornerShape(Radius.md))
                .background(Color.White)
                .padding(14.dp),
        ) {
            Canvas(Modifier.fillMaxSize()) {
                val n = matrix.size
                val cell = size.minDimension / n
                val padX = (size.width - cell * n) / 2f
                val padY = (size.height - cell * n) / 2f
                for (r in 0 until n) {
                    for (c in 0 until n) {
                        if (matrix[r][c]) {
                            drawRect(
                                color = Color.Black,
                                topLeft = Offset(padX + c * cell, padY + r * cell),
                                size = Size(cell + 0.5f, cell + 0.5f),
                            )
                        }
                    }
                }
            }
        }
    }
}
