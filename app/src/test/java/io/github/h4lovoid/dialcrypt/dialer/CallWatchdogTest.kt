package io.github.h4lovoid.dialcrypt.dialer

import org.junit.Assert.assertEquals
import org.junit.Test

class CallWatchdogTest {
    private var now = 0L
    private var mainAlive = true
    private var live = true
    private var debugger = false
    private var kills = 0

    private val dog = CallWatchdog(
        isCallLive = { live },
        timeoutMs = 6_000L,
        kill = { kills++ },
        clock = { now },
        postToMain = { if (mainAlive) it.run() },
        debuggerAttached = { debugger },
    )

    private fun seconds(n: Int) = repeat(n) {
        now += 1_000L
        dog.step()
    }

    @Test
    fun aHealthyMainThreadIsNeverKilled() {
        seconds(60)
        assertEquals(0, kills)
    }

    @Test
    fun aStalledMainThreadDuringACallIsKilledOnce() {
        seconds(3)
        mainAlive = false
        seconds(5)
        assertEquals(0, kills)
        seconds(1)
        assertEquals(1, kills)
        seconds(10)
        assertEquals(1, kills)
    }

    @Test
    fun aStallWithoutALiveCallIsIgnored() {
        live = false
        mainAlive = false
        seconds(30)
        assertEquals(0, kills)
        live = true
        seconds(5)
        assertEquals(0, kills)
        seconds(1)
        assertEquals(1, kills)
    }

    @Test
    fun anAttachedDebuggerPreventsTheKill() {
        debugger = true
        mainAlive = false
        seconds(30)
        assertEquals(0, kills)
    }

    @Test
    fun aShortStallIsTolerated() {
        mainAlive = false
        seconds(5)
        mainAlive = true
        seconds(30)
        assertEquals(0, kills)
    }
}
