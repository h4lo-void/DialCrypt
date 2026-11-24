package io.github.h4lovoid.dialcrypt

import io.github.h4lovoid.dialcrypt.core.CoreAvailability
import io.github.h4lovoid.dialcrypt.core.CoreState
import io.github.h4lovoid.dialcrypt.core.FakeSecureCore
import io.github.h4lovoid.dialcrypt.core.PinResult
import io.github.h4lovoid.dialcrypt.core.SecureCore
import io.github.h4lovoid.dialcrypt.core.TestNoPin
import io.github.h4lovoid.dialcrypt.core.UnlockResult
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Test builds without a PIN set up or unlock the vault once, and report a failure instead of retrying. */
class TestNoPinTest {
    private class Recording(
        private val setup: PinResult = PinResult.OK,
        private val unlock: UnlockResult = UnlockResult.SUCCESS,
    ) : SecureCore by FakeSecureCore(CoreState(CoreAvailability.READY)) {
        val calls = mutableListOf<String>()
        override suspend fun setupPins(normal: CharArray, duress: CharArray): PinResult {
            calls += "setup:" + String(normal) + "/" + String(duress)
            return setup
        }
        override suspend fun unlock(pin: CharArray): UnlockResult {
            calls += "unlock:" + String(pin)
            return unlock
        }
    }

    private val fresh = CoreState(CoreAvailability.READY, pinConfigured = false)
    private val locked = CoreState(CoreAvailability.READY, pinConfigured = true, locked = true)
    private val open = CoreState(CoreAvailability.READY, pinConfigured = true, locked = false)

    @Test
    fun aNewVaultIsSetUpWithTheBuiltInPins() = runBlocking {
        val core = Recording()
        assertTrue(TestNoPin.open(core, fresh))
        assertEquals(listOf("setup:pixeltestkey/wipeallkeysnow"), core.calls)
    }

    @Test
    fun aLockedVaultIsUnlockedWithTheBuiltInPin() = runBlocking {
        val core = Recording()
        assertTrue(TestNoPin.open(core, locked))
        assertEquals(listOf("unlock:pixeltestkey"), core.calls)
    }

    @Test
    fun nothingHappensWhenOpenNotReadyOrDestroyed() = runBlocking {
        val core = Recording()
        assertTrue(TestNoPin.open(core, open))
        assertTrue(TestNoPin.open(core, CoreState(CoreAvailability.NOT_CONNECTED, pinConfigured = true, locked = true)))
        assertTrue(TestNoPin.open(core, locked.copy(vaultDestroyed = true)))
        assertEquals(emptyList<String>(), core.calls)
        assertFalse(TestNoPin.needed(open))
    }

    @Test
    fun aWrongPinOrFailedSetupIsReported() = runBlocking {
        assertFalse(TestNoPin.open(Recording(unlock = UnlockResult.WRONG), locked))
        assertFalse(TestNoPin.open(Recording(setup = PinResult.FAILED), fresh))
    }

    @Test
    fun realBuildsKeepThePinScreens() {
        assertFalse("unit tests are built without AEGIS_TEST_NO_PIN", BuildConfig.TEST_NO_PIN)
    }
}

