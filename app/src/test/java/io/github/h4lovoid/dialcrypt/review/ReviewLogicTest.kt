package io.github.h4lovoid.dialcrypt.review

import io.github.h4lovoid.dialcrypt.call.CallPhase
import io.github.h4lovoid.dialcrypt.call.CallTracker
import io.github.h4lovoid.dialcrypt.call.PreciseState
import io.github.h4lovoid.dialcrypt.core.HardeningLevel
import io.github.h4lovoid.dialcrypt.core.IdentityStatus
import io.github.h4lovoid.dialcrypt.core.ItemStatus
import io.github.h4lovoid.dialcrypt.core.MessageBody
import io.github.h4lovoid.dialcrypt.core.PrepItem
import io.github.h4lovoid.dialcrypt.core.SendResult
import io.github.h4lovoid.dialcrypt.core.SessionFailure
import io.github.h4lovoid.dialcrypt.core.SessionPhase
import io.github.h4lovoid.dialcrypt.core.SessionState
import io.github.h4lovoid.dialcrypt.core.daemon.PrepMapping
import io.github.h4lovoid.dialcrypt.core.real.DerSplit
import io.github.h4lovoid.dialcrypt.core.real.EndCause
import io.github.h4lovoid.dialcrypt.core.real.HardenRetry
import io.github.h4lovoid.dialcrypt.core.real.HexLines
import io.github.h4lovoid.dialcrypt.core.real.NativeEvent
import io.github.h4lovoid.dialcrypt.core.real.NativeIdentity
import io.github.h4lovoid.dialcrypt.core.real.PinInput
import io.github.h4lovoid.dialcrypt.core.real.PumpEnd
import io.github.h4lovoid.dialcrypt.core.real.PumpLoops
import io.github.h4lovoid.dialcrypt.core.real.SessionPath
import io.github.h4lovoid.dialcrypt.core.real.SessionReducer
import io.github.h4lovoid.dialcrypt.core.real.TrustConfigBuilder
import io.github.h4lovoid.dialcrypt.core.real.VaultFile
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Logic checks behind the review findings: state mapping, fail-closed ordering, PIN bytes, call tracker, vault file, coroutine hand-off. */
class ReviewLogicTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private fun established(identity: NativeIdentity, stored: Long = 0L, resume: Boolean = false) = NativeEvent.Established(
        responder = false,
        path = SessionPath(resume = resume, usedNew = false, contactId = 0),
        identity = identity,
        pskContactId = 0,
        storedContactId = stored,
        peerPub33 = ByteArray(33) { 2 },
    )

    // ---------------------------------------------------------------- criterion 4: sending stays locked

    @Test
    fun keyChangedLocksSendingUntilBothSidesConfirmed() {
        val body = MessageBody.Text("hi")
        var s = SessionReducer.established(SessionState(phase = SessionPhase.CONNECTING), established(NativeIdentity.KEY_CHANGED, stored = 4), null)
        assertEquals(SessionPhase.KEY_CHANGED, s.phase)
        assertEquals(IdentityStatus.KEY_CHANGED, s.identity)
        assertEquals(SendResult.BLOCKED_KEY_CHANGED, SessionReducer.sendCheck(s, body, false))
        s = SessionReducer.sasConfirmed(s, offerSave = false)
        assertNull(SessionReducer.sendCheck(s, body, false))
    }

    @Test
    fun keyChangedEventBeforeEstablishedAlsoLocks() {
        var s = SessionReducer.keyChanged(SessionState(phase = SessionPhase.CONNECTING))
        s = SessionReducer.established(s, established(NativeIdentity.UNVERIFIED), null)
        assertEquals(SessionPhase.KEY_CHANGED, s.phase)
        assertEquals(SendResult.BLOCKED_KEY_CHANGED, SessionReducer.sendCheck(s, MessageBody.Text("x"), false))
    }

    @Test
    fun noSendBeforeEstablished() {
        assertEquals(SendResult.BLOCKED_NOT_ESTABLISHED, SessionReducer.sendCheck(SessionState(phase = SessionPhase.CONNECTING), MessageBody.Text("x"), false))
        assertEquals(SendResult.BLOCKED_NOT_ESTABLISHED, SessionReducer.sendCheck(SessionState(phase = SessionPhase.CLEARING), MessageBody.Text("x"), false))
    }

    // ---------------------------------------------------------------- criterion 2: end states

    @Test
    fun endCauseRules() {
        val g = 3000L
        assertNull(SessionReducer.endCause(null, null, null, 0, 100, g))
        assertEquals(EndCause.Dropped, SessionReducer.endCause(PumpEnd.AUDIO_FAILED, null, null, 0, 100, g))
        assertEquals(EndCause.Ended, SessionReducer.endCause(PumpEnd.SESSION_OVER, null, EndCause.Ended, 0, 100, g))
        assertEquals(EndCause.Failed(SessionFailure.UNKNOWN), SessionReducer.endCause(PumpEnd.SESSION_OVER, null, null, 0, 100, g))
        assertNull(SessionReducer.endCause(null, null, EndCause.Ended, 1000, 3999, g))
        assertEquals(EndCause.Ended, SessionReducer.endCause(null, null, EndCause.Ended, 1000, 4000, g))
        assertNull(SessionReducer.endCause(PumpEnd.STOPPED, PumpEnd.STOPPED, null, 0, 100, g))
    }

    @Test
    fun finalStateCases() {
        val prev = SessionState(phase = SessionPhase.ESTABLISHED)
        assertEquals(SessionPhase.CLEARED, SessionReducer.finalState(prev, EndCause.Local, true).phase)
        assertEquals(SessionPhase.CLEARED, SessionReducer.finalState(prev, EndCause.Ended, false).phase)
        assertEquals(SessionFailure.CALL_DROPPED, SessionReducer.finalState(prev, EndCause.Dropped, false).abort)
        assertEquals(SessionPhase.CLEARED, SessionReducer.finalState(prev.copy(phase = SessionPhase.CLEARING), EndCause.Dropped, false).phase)
        assertEquals(SessionFailure.PEER_ABORTED, SessionReducer.finalState(prev, EndCause.Aborted(20), false).abort)
        assertEquals(SessionPhase.CLEARED, SessionReducer.finalState(prev, EndCause.Aborted(19), false).phase)
        assertEquals(SessionFailure.BEARER_VIOLATION, SessionReducer.finalState(prev, EndCause.Aborted(24), false).abort)
    }

    @Test
    fun everyAbortReasonHasAMapping() {
        for (r in 1..26) assertNotNull("reason $r", SessionReducer.failure(r)?.let { it } ?: if (r == 1 || r == 19) Unit else null)
    }

    // ---------------------------------------------------------------- criterion 5: PIN bytes

    @Test
    fun pinAcceptedByUiRulesCanExceedTheNative128ByteLimit() {
        val normal = CharArray(50) { (0x4E00 + it).toChar() }
        val duress = CharArray(50) { (0x4F00 + it).toChar() }
        assertNull("50 characters pass PinRules (10..64 code points)", PinInput.check(normal, duress))
        val bytes = PinInput.utf8(normal)!!
        assertEquals(150, bytes.size)
        assertTrue("setupNow returns FAILED for this PIN without a reason", bytes.size > PinInput.NATIVE_MAX_BYTES)
        bytes.fill(0)
    }

    @Test
    fun pinUtf8Encoding() {
        val emoji = "\uD83D\uDE00abcd".toCharArray()
        val b = PinInput.utf8(emoji)!!
        assertArrayEquals("\uD83D\uDE00abcd".toByteArray(Charsets.UTF_8), b)
        assertNull(PinInput.utf8(charArrayOf('a', '\uD83D', 'b')))
        assertNull(PinInput.utf8(charArrayOf('\uDE00')))
        assertEquals(0, PinInput.utf8(CharArray(0))!!.size)
    }

    // ---------------------------------------------------------------- criterion 4/2: call tracker

    @Test
    fun callThatAppearsAfterAnEarlyHangUpIsReportedLive() {
        val t = CallTracker()
        t.beginDial("+447700900123")
        // hangUp() found no call in telephony yet: the dial is written off.
        t.onNothingToEnd()
        assertEquals(CallPhase.ENDED, t.status.phase)
        // The placed call then shows up: nothing owns it any more.
        val s = t.onPrecise(PreciseState.IDLE, PreciseState.DIALING, PreciseState.IDLE)
        assertEquals(CallPhase.DIALING, s.phase)
    }

    // ---------------------------------------------------------------- pump loops

    @Test
    fun txStopsOnFlagAndEndsOnNullAndAudioFailure() {
        var stop = false
        var idles = 0
        var n = 0
        val end = PumpLoops.runTx(
            stopped = { stop },
            next = { if (++n < 4) shortArrayOf() else { stop = true; shortArrayOf(1) } },
            write = { 1 },
            idle = { idles++ },
        )
        assertEquals(PumpEnd.STOPPED, end)
        assertEquals(3, idles)
        assertEquals(PumpEnd.SESSION_OVER, PumpLoops.runTx({ false }, { null }, { 1 }, {}))
        assertEquals(PumpEnd.AUDIO_FAILED, PumpLoops.runTx({ false }, { shortArrayOf(1) }, { -1 }, {}))
    }

    @Test
    fun rxEndsOnNativeAbortAndAudioFailure() {
        val buf = ShortArray(8)
        assertEquals(PumpEnd.SESSION_OVER, PumpLoops.runRx({ false }, buf, { it.size }, { -6 }))
        assertEquals(PumpEnd.SESSION_OVER, PumpLoops.runRx({ false }, buf, { it.size }, { -1 }))
        assertEquals(PumpEnd.NATIVE_ERROR, PumpLoops.runRx({ false }, buf, { it.size }, { -8 }))
        assertEquals(PumpEnd.AUDIO_FAILED, PumpLoops.runRx({ false }, buf, { -1 }, { 0 }))
    }

    // ---------------------------------------------------------------- criterion 5: vault file

    @Test
    fun writeSucceedsOnceTheNewFileIsAlreadyInPlace() {
        val f = File(tmp.root, "vault.v2")
        val v = VaultFile(f) { false }
        assertTrue(v.write(byteArrayOf(1, 2, 3)))
        assertArrayEquals(byteArrayOf(1, 2, 3), f.readBytes())
        assertFalse(File(tmp.root, "vault.v2.tmp").exists())
    }

    @Test
    fun writeKeepsOldFileWhenTheTemporaryFileCannotBeCreated() {
        val f = File(tmp.root, "vault.v2")
        val ok = VaultFile(f) { true }
        assertTrue(ok.write(byteArrayOf(5)))
        assertTrue(File(tmp.root, "vault.v2.tmp").mkdir())
        assertFalse(ok.write(byteArrayOf(6)))
        assertArrayEquals(byteArrayOf(5), f.readBytes())
    }

    // ---------------------------------------------------------------- trust resources

    @Test
    fun trustResourceParsers() {
        val short = byteArrayOf(0x30, 0x02, 1, 2)
        val long = byteArrayOf(0x30, 0x82.toByte(), 0x01, 0x00) + ByteArray(256) { 3 }
        val certs = DerSplit.certificates(short + long)!!
        assertEquals(2, certs.size)
        assertEquals(4, certs[0].size)
        assertEquals(260, certs[1].size)
        assertNull(DerSplit.certificates(byteArrayOf(0x30, 0x80.toByte(), 0)))
        assertNull(DerSplit.certificates(byteArrayOf(0x30, 0x05, 1)))
        assertNull(DerSplit.certificates(ByteArray(0)))
        val hex = HexLines.parse("# c\n AB:cd ef # tail\n\n0F\n")!!
        assertEquals(2, hex.size)
        assertArrayEquals(byteArrayOf(0xAB.toByte(), 0xCD.toByte(), 0xEF.toByte()), hex[0])
        assertArrayEquals(byteArrayOf(0x0F), hex[1])
        assertNull(HexLines.parse("zz"))
        val signer = "11".repeat(32)
        assertNotNull(TrustConfigBuilder.build(short, "", "", signer, "202411 # YYYYMM\n"))
        assertNull(TrustConfigBuilder.build(short, "", "", "", "202411"))
        assertNull(TrustConfigBuilder.build(short, "", "", signer, "202411\n202412"))
        assertNull(TrustConfigBuilder.build(short, "", "", signer, "abc"))
    }

    // ---------------------------------------------------------------- criterion 2: handle hand-off across cancellation

    /** HardenRetry (start-up): only INTERNAL is retried, every 100 ms, and the wait is bounded by LIMIT_MS. */
    @Test
    fun hardenRetryStopsOnAnyOtherCodeAndGivesUpAtTheLimit() {
        var now = 0L
        var calls = 0
        assertEquals(0, HardenRetry.run({ calls++; 0 }, { now }, { now += it }))
        assertEquals(1, calls)
        calls = 0
        now = 0
        assertEquals(0, HardenRetry.run({ if (++calls <= 3) -8 else 0 }, { now }, { now += it }))
        assertEquals(4, calls)
        assertEquals(300L, now)
        calls = 0
        now = 0
        assertEquals(-1, HardenRetry.run({ calls++; -1 }, { now }, { now += it }))
        assertEquals(1, calls)
        calls = 0
        now = 0
        assertEquals(-8, HardenRetry.run({ calls++; -8 }, { now }, { now += it }))
        assertEquals(HardenRetry.LIMIT_MS, now)
        assertEquals(51, calls)
    }

    /**
     * Criterion 6: DaemonLockdownController turns READY into the checklist with PrepMapping.allDone(items, tier).
     * READY's mode (0 = dry run, nothing changed) and claims bits are no input, so every item shows as done.
     */
    @Test
    fun readyChecklistIgnoresDryRunAndClaims() {
        val shown = PrepMapping.allDone(PrepMapping.itemsFor(HardeningLevel.LEVEL_1, ItemStatus.PENDING), tier = 2)
        assertTrue(shown.all { it.status == ItemStatus.DONE })
        assertTrue(shown.any { it.item == PrepItem.FIREWALL })
        assertTrue(shown.any { it.item == PrepItem.OTHER_APPS_STOPPED })
        assertTrue(shown.any { it.item == PrepItem.MEMORY_CLEARED })
    }

    /**
     * SessionEngine.runCall creates the native session inside withContext(worker) and keeps the handle only
     * when that call returns. When finish() cancels the job during the call, the handle is lost.
     */
    @Test
    fun handleCreatedInsideWithContextIsLostWhenTheJobIsCancelled() = runBlocking {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val created = AtomicLong(0)
        val outcome = AtomicReference("none")
        val pool = Executors.newSingleThreadExecutor()
        val worker = pool.asCoroutineDispatcher()
        val job = launch(Dispatchers.IO) {
            try {
                val h = withContext(worker) {
                    started.countDown()
                    release.await()
                    created.set(42L)
                    42L
                }
                outcome.set("received " + h)
            } catch (e: CancellationException) {
                outcome.set("cancelled")
            }
        }
        withContext(Dispatchers.IO) { started.await() }
        job.cancel()
        release.countDown()
        job.join()
        pool.shutdown()
        assertEquals("native create finished", 42L, created.get())
        assertEquals("caller never saw the handle", "cancelled", outcome.get())
    }
}
