package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.call.CallAudio
import io.github.h4lovoid.dialcrypt.call.CallLink
import io.github.h4lovoid.dialcrypt.call.CallStatus
import io.github.h4lovoid.dialcrypt.call.IncomingOffer
import io.github.h4lovoid.dialcrypt.core.Contact
import io.github.h4lovoid.dialcrypt.core.ContactResult
import io.github.h4lovoid.dialcrypt.core.real.NativeEvent
import io.github.h4lovoid.dialcrypt.core.real.SessionEngine
import io.github.h4lovoid.dialcrypt.core.real.SessionHost
import io.github.h4lovoid.dialcrypt.security.HardwareKeyBridge
import java.lang.reflect.Proxy
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Review test: while a fingerprint unlock is call-scoped, nothing may change a
 * contact's identity data. replaceChangedKey (SAS confirmed after a key change) writes the stored
 * contact through nativeSessionSaveContact; its first step is the host lookup counted here.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ScopedCallGuardTest {
    private class Host(override val callScoped: Boolean) : SessionHost {
        override val appHandle: Long = 1L
        override val unlocked: Boolean = true
        val lookups = AtomicInteger()
        val seen = CountDownLatch(1)

        override fun contactIdForKey(pub33: ByteArray): Long? {
            lookups.incrementAndGet()
            seen.countDown()
            return null
        }

        override fun vaultDirty(seq: Long) {}

        override fun contactsChanged() {}
    }

    private class Link : CallLink {
        override val status = MutableStateFlow(CallStatus())
        override val offers = MutableStateFlow<IncomingOffer?>(null)

        override fun dial(number: String) = false

        override fun answer() = false

        override fun hangUp() {}

        override fun openAudio(): CallAudio? = null
    }

    private fun engine(host: Host): SessionEngine {
        val keys = Proxy.newProxyInstance(javaClass.classLoader, arrayOf(HardwareKeyBridge::class.java)) { _, m, _ ->
            if (m.returnType == java.lang.Boolean.TYPE) false else null
        } as HardwareKeyBridge
        return SessionEngine(Link(), keys, host, Dispatchers.Unconfined, MutableStateFlow<List<Contact>>(emptyList()), null)
    }

    /** Feeds the engine a key change and then the confirmed words, like the native session does. */
    private fun keyChangeThenSasConfirmed(engine: SessionEngine) {
        val callClass = Class.forName("io.github.h4lovoid.dialcrypt.core.real.ActiveCall")
        val ctor = callClass.declaredConstructors.first { it.parameterCount == 3 }.also { it.isAccessible = true }
        val call = ctor.newInstance(false, null, null)
        val onEvent = SessionEngine::class.java.getDeclaredMethod("onEvent", callClass, NativeEvent::class.java).also { it.isAccessible = true }
        onEvent.invoke(engine, call, NativeEvent.KeyChanged(ByteArray(33) { 1 }, ByteArray(33) { 2 }))
        onEvent.invoke(engine, call, NativeEvent.SasConfirmed)
    }

    @Test
    fun harnessReachesTheKeyReplacementWhenTheUnlockIsNotCallScoped() {
        val host = Host(callScoped = false)
        keyChangeThenSasConfirmed(engine(host))
        host.seen.await(3, TimeUnit.SECONDS)
        assertEquals(1, host.lookups.get())
    }

    @Test
    fun aKeyReplacementIsRefusedWhileTheUnlockIsCallScoped() {
        val host = Host(callScoped = true)
        keyChangeThenSasConfirmed(engine(host))
        host.seen.await(1, TimeUnit.SECONDS)
        assertEquals("replaceChangedKey ran under a call-scoped fingerprint unlock", 0, host.lookups.get())
    }

    @Test
    fun savingTheCallerIsRefusedWhileTheUnlockIsCallScoped() {
        assertEquals(ContactResult.FAILED, engine(Host(callScoped = true)).saveContact("Eve", null))
    }
}
