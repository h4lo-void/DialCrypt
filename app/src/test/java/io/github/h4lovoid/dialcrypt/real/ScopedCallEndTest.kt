package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.call.CallAudio
import io.github.h4lovoid.dialcrypt.call.CallLink
import io.github.h4lovoid.dialcrypt.call.CallStatus
import io.github.h4lovoid.dialcrypt.call.IncomingOffer
import io.github.h4lovoid.dialcrypt.core.Contact
import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import io.github.h4lovoid.dialcrypt.core.SessionPhase
import io.github.h4lovoid.dialcrypt.core.real.SessionEngine
import io.github.h4lovoid.dialcrypt.core.real.SessionHost
import io.github.h4lovoid.dialcrypt.security.HardwareKeyBridge
import java.lang.reflect.Proxy
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * After a fingerprint-answered call the end screen must not stay behind, and the next secure call
 * must show either here or on the :call prompt.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ScopedCallEndTest {
    private class Host(@Volatile var scoped: Boolean, @Volatile var present: Boolean) : SessionHost {
        override val appHandle: Long = 1L
        override val unlocked: Boolean = true
        override val callScoped: Boolean get() = scoped
        override val canPresentIncoming: Boolean get() = present
        val locks = AtomicInteger()

        override fun lockAfterScopedCall() {
            locks.incrementAndGet()
            scoped = false
        }

        override fun contactIdForKey(pub33: ByteArray): Long? = null

        override fun vaultDirty(seq: Long) {}

        override fun contactsChanged() {}
    }

    private class Link : CallLink {
        override val status = MutableStateFlow(CallStatus())
        override val offers = MutableStateFlow<IncomingOffer?>(null)
        val returned = CopyOnWriteArrayList<ByteArray>()

        override fun dial(number: String) = false

        override fun answer() = false

        override fun hangUp() {}

        override fun openAudio(): CallAudio? = null

        override fun returnOffer(token: ByteArray) {
            returned += token
        }
    }

    private fun engine(host: Host, link: Link): SessionEngine {
        val keys = Proxy.newProxyInstance(javaClass.classLoader, arrayOf(HardwareKeyBridge::class.java)) { _, m, _ ->
            if (m.returnType == java.lang.Boolean.TYPE) false else null
        } as HardwareKeyBridge
        return SessionEngine(link, keys, host, Dispatchers.Unconfined, MutableStateFlow<List<Contact>>(emptyList()), null)
    }

    /** A refused call (no valid number) ends on ABORTED; hanging up then leaves CLEARED. */
    private fun endedCall(engine: SessionEngine, phase: SessionPhase) {
        engine.startCallToNumber("")
        assertEquals(SessionPhase.ABORTED, engine.state.value.phase)
        if (phase == SessionPhase.CLEARED) runBlocking { engine.endAndWipe() }
        assertEquals(phase, engine.state.value.phase)
    }

    private fun waitFor(cond: () -> Boolean): Boolean {
        val end = System.currentTimeMillis() + 3_000
        while (System.currentTimeMillis() < end) {
            if (cond()) return true
            Thread.sleep(20)
        }
        return cond()
    }

    /**
     * Waits until the engine's watchers have subscribed to the link. The call watcher handles the
     * link's first (idle) status by clearing the incoming offer; an offer shown before that would be
     * cleared again.
     */
    private fun awaitWatchers(link: Link) {
        assertTrue(
            "watchers did not subscribe",
            waitFor { link.status.subscriptionCount.value > 0 && link.offers.subscriptionCount.value > 0 },
        )
    }

    @Test
    fun theScopedLockClearsTheEndScreen() {
        for (phase in listOf(SessionPhase.ABORTED, SessionPhase.CLEARED)) {
            val host = Host(scoped = false, present = true)
            val engine = engine(host, Link())
            // The engine's watchers see the first (idle) call state at start; the unlock comes later.
            Thread.sleep(300)
            endedCall(engine, phase)
            host.scoped = true
            // Nothing rang for this unlock any more: it locks, and the end screen goes with it.
            engine.onUnlocked()
            assertEquals(phase.name, SessionPhase.IDLE, engine.state.value.phase)
            assertEquals(1, host.locks.get())
        }
    }

    @Test
    fun theNextOfferShowsHereWhenThisScreenCanShowIt() {
        for (phase in listOf(SessionPhase.ABORTED, SessionPhase.CLEARED)) {
            val link = Link()
            val engine = engine(Host(scoped = false, present = true), link)
            awaitWatchers(link)
            endedCall(engine, phase)
            link.offers.value = IncomingOffer(ByteArray(16) { 1 }, "+447700900123", NumberPresentation.SHOWN)
            assertTrue(phase.name, waitFor { engine.incoming.value != null })
            assertEquals(SessionPhase.IDLE, engine.state.value.phase)
            assertTrue(link.returned.isEmpty())
        }
    }

    @Test
    fun otherwiseTheNextOfferGoesBackToTheCallPrompt() {
        for (phase in listOf(SessionPhase.IDLE, SessionPhase.ABORTED, SessionPhase.CLEARED)) {
            val link = Link()
            val engine = engine(Host(scoped = false, present = false), link)
            if (phase != SessionPhase.IDLE) endedCall(engine, phase)
            val token = ByteArray(16) { 2 }
            link.offers.value = IncomingOffer(token, "+447700900123", NumberPresentation.SHOWN)
            assertTrue(phase.name, waitFor { link.returned.isNotEmpty() })
            assertTrue(link.returned.single().contentEquals(token))
            assertNull(engine.incoming.value)
        }
    }
}
