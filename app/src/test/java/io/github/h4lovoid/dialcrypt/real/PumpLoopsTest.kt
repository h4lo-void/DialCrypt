package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.real.PumpEnd
import io.github.h4lovoid.dialcrypt.core.real.PumpLoops
import org.junit.Assert.assertEquals
import org.junit.Test

class PumpLoopsTest {
    @Test
    fun txWritesUntilTheSessionIsOver() {
        val slots = ArrayDeque(listOf(ShortArray(4) { 1 }, ShortArray(0), ShortArray(2) { 2 }))
        val written = mutableListOf<Int>()
        var idles = 0
        val end = PumpLoops.runTx({ false }, { slots.removeFirstOrNull() }, { written += it.size; it.size }, { idles++ })
        assertEquals(PumpEnd.SESSION_OVER, end)
        assertEquals(listOf(4, 2), written)
        assertEquals(1, idles)
    }

    @Test
    fun txStopsOnAudioFailureOrStopFlag() {
        assertEquals(PumpEnd.AUDIO_FAILED, PumpLoops.runTx({ false }, { ShortArray(8) }, { -1 }, {}))
        var stop = false
        assertEquals(PumpEnd.STOPPED, PumpLoops.runTx({ stop }, { ShortArray(8) }, { stop = true; -1 }, {}))
        assertEquals(PumpEnd.STOPPED, PumpLoops.runTx({ true }, { error("not called") }, { 0 }, {}))
        var n = 0
        assertEquals(PumpEnd.STOPPED, PumpLoops.runTx({ n >= 3 }, { ShortArray(0) }, { 0 }, { n++ }))
    }

    @Test
    fun rxFeedsWhatWasReadAndEndsOnFailures() {
        val fed = mutableListOf<Int>()
        var reads = 0
        val end = PumpLoops.runRx(
            stopped = { false },
            buf = ShortArray(10),
            read = { b -> reads++; if (reads <= 2) (if (reads == 1) b.size else 4) else -1 },
            feed = { b -> fed += b.size; 0 },
        )
        assertEquals(PumpEnd.AUDIO_FAILED, end)
        assertEquals(listOf(10, 4), fed)

        assertEquals(PumpEnd.SESSION_OVER, PumpLoops.runRx({ false }, ShortArray(10), { it.size }, { -1 }))
        assertEquals(PumpEnd.SESSION_OVER, PumpLoops.runRx({ false }, ShortArray(10), { it.size }, { -6 }))
        assertEquals(PumpEnd.NATIVE_ERROR, PumpLoops.runRx({ false }, ShortArray(10), { it.size }, { -2 }))
        var stop = false
        assertEquals(PumpEnd.STOPPED, PumpLoops.runRx({ stop }, ShortArray(10), { stop = true; -1 }, { 0 }))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rxChunkIsLimited() {
        PumpLoops.runRx({ true }, ShortArray(PumpLoops.MAX_RX_CHUNK + 1), { 0 }, { 0 })
    }
}
