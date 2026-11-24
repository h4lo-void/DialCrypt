package io.github.h4lovoid.dialcrypt.real

import io.github.h4lovoid.dialcrypt.core.CoreAvailability
import io.github.h4lovoid.dialcrypt.core.CoreState
import io.github.h4lovoid.dialcrypt.core.FakeSecureCore
import io.github.h4lovoid.dialcrypt.core.PinResult
import io.github.h4lovoid.dialcrypt.core.real.BiometricStore
import io.github.h4lovoid.dialcrypt.core.real.NativeCode
import io.github.h4lovoid.dialcrypt.core.real.PinChangeRules
import io.github.h4lovoid.dialcrypt.core.real.PinChangeRules.Outcome
import io.github.h4lovoid.dialcrypt.core.real.RotationOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlinx.coroutines.runBlocking

/** The in-app PIN change and fingerprint answer: when it is refused, what locks, what turns the feature off. */
class PinChangeRulesTest {
    private val unlocked = CoreState(CoreAvailability.READY, pinConfigured = true, locked = false)

    @Test
    fun refusedAfterAFingerprintUnlockAndWhileFingerprintAnswerIsBeingTurnedOnButOnlyAfterTheCheck() {
        // Only a missing vault stops the change before the native current-PIN check.
        assertNull(PinChangeRules.refusal(ready = true, st = unlocked))
        assertNull(PinChangeRules.refusal(true, unlocked.copy(callScoped = true)))
        assertNull(PinChangeRules.refusal(true, unlocked.copy(bioEnrollPending = true)))
        assertEquals(PinResult.FAILED, PinChangeRules.refusal(true, unlocked.copy(locked = true)))
        assertEquals(PinResult.FAILED, PinChangeRules.refusal(true, unlocked.copy(vaultDestroyed = true)))
        assertEquals(PinResult.FAILED, PinChangeRules.refusal(true, unlocked.copy(pinConfigured = false)))
        assertEquals(PinResult.NOT_CONNECTED, PinChangeRules.refusal(false, unlocked))

        assertFalse(PinChangeRules.refusedAfterCheck(unlocked, stretchHeld = false))
        assertTrue(PinChangeRules.refusedAfterCheck(unlocked.copy(callScoped = true), false))
        assertTrue(PinChangeRules.refusedAfterCheck(unlocked.copy(bioEnrollPending = true), false))
        assertTrue(PinChangeRules.refusedAfterCheck(unlocked, stretchHeld = true))
        // Refused: failed for every native answer except the emergency PIN and the lockout.
        for (rc in intArrayOf(NativeCode.PIN_CHANGE_WRONG_CURRENT, NativeCode.PIN_CHANGE_STAGED, NativeCode.BAD_STATE, NativeCode.BAD_ARG)) {
            assertEquals(Outcome(PinResult.FAILED), PinChangeRules.afterNative(rc, refused = true))
        }
        assertEquals(Outcome(PinResult.DURESS, duress = true), PinChangeRules.afterNative(NativeCode.PIN_CHANGE_DURESS, refused = true))
        assertEquals(Outcome(PinResult.WRONG_CURRENT, lock = true), PinChangeRules.afterNative(NativeCode.PIN_CHANGE_WRONG_LOCKED, refused = true))
    }

    @Test
    fun newPinProblemsAreReportedOnlyAfterTheCurrentPinCheck() {
        assertNull(PinChangeRules.newPinProblem(null, 10, 10))
        assertEquals(PinResult.TOO_SIMPLE, PinChangeRules.newPinProblem(PinResult.TOO_SIMPLE, 10, 10))
        assertEquals(PinResult.SAME_PINS, PinChangeRules.newPinProblem(PinResult.SAME_PINS, 10, 10))
        // 43 CJK characters: within the character limit, over the native byte limit.
        assertEquals(PinResult.FAILED, PinChangeRules.newPinProblem(null, 129, 10))
        assertEquals(PinResult.FAILED, PinChangeRules.newPinProblem(null, 10, 129))
        assertEquals(PinResult.FAILED, PinChangeRules.newPinProblem(null, null, 10))

        // The emergency PIN and the lockout win over a problem of the new PINs; then the problem.
        assertEquals(Outcome(PinResult.DURESS, duress = true), PinChangeRules.afterNative(NativeCode.PIN_CHANGE_DURESS, newPinProblem = PinResult.FAILED))
        assertEquals(Outcome(PinResult.WRONG_CURRENT, lock = true), PinChangeRules.afterNative(NativeCode.PIN_CHANGE_WRONG_LOCKED, newPinProblem = PinResult.TOO_SHORT))
        assertEquals(Outcome(PinResult.TOO_SHORT), PinChangeRules.afterNative(NativeCode.PIN_CHANGE_WRONG_CURRENT, newPinProblem = PinResult.TOO_SHORT))
        assertEquals(Outcome(PinResult.TOO_SIMPLE), PinChangeRules.afterNative(NativeCode.BAD_ARG, newPinProblem = PinResult.TOO_SIMPLE))
    }

    @Test
    fun theFakeCoreChecksTheEmergencyPinBeforeTheNewPins() = runBlocking {
        val core = FakeSecureCore(unlocked)
        core.presetPins("abcdefghij", "klmnopqrst")
        // Right current PIN, bad new PINs: the problem, not counted.
        repeat(3) { assertEquals(PinResult.TOO_SHORT, core.changePins("abcdefghij".toCharArray(), "ab".toCharArray(), "pqrstuvwxy".toCharArray())) }
        assertFalse(core.state.value.locked)
        // Wrong current PIN, bad new PINs: counted, the problem is shown; the third locks.
        assertEquals(PinResult.TOO_SHORT, core.changePins("zzzzzzzzzz".toCharArray(), "ab".toCharArray(), "ab".toCharArray()))
        assertEquals(PinResult.WRONG_CURRENT, core.changePins("zzzzzzzzzz".toCharArray(), "mnopqrstuv".toCharArray(), "pqrstuvwxy".toCharArray()))
        assertEquals(PinResult.WRONG_CURRENT, core.changePins("zzzzzzzzzz".toCharArray(), "ab".toCharArray(), "ab".toCharArray()))
        assertTrue(core.state.value.locked)
        // The emergency PIN with bad new PINs destroys everything.
        val other = FakeSecureCore(unlocked)
        other.presetPins("abcdefghij", "klmnopqrst")
        assertEquals(PinResult.DURESS, other.changePins("klmnopqrst".toCharArray(), "ab".toCharArray(), "ab".toCharArray()))
        assertTrue(other.keysDestroyed)
    }

    @Test
    fun theThirdWrongCurrentPinShowsWrongCurrentAndLocks() {
        assertEquals(Outcome(PinResult.WRONG_CURRENT), PinChangeRules.afterNative(NativeCode.PIN_CHANGE_WRONG_CURRENT))
        assertEquals(Outcome(PinResult.WRONG_CURRENT, lock = true), PinChangeRules.afterNative(NativeCode.PIN_CHANGE_WRONG_LOCKED))
        assertNull(PinChangeRules.afterNative(NativeCode.PIN_CHANGE_STAGED))
        // Refused in the native core (fingerprint unlock, held stretch) or locked: failed, nothing else.
        for (rc in intArrayOf(NativeCode.BAD_STATE, NativeCode.LOCKED, NativeCode.BAD_ARG)) {
            assertEquals(Outcome(PinResult.FAILED), PinChangeRules.afterNative(rc))
        }
    }

    @Test
    fun theEmergencyPinAsTheCurrentPinTakesTheDuressPathAndNothingElse() {
        val o = PinChangeRules.afterNative(NativeCode.PIN_CHANGE_DURESS)!!
        assertEquals(PinResult.DURESS, o.result)
        assertTrue(o.duress)
        // duress() itself deletes fingerprint answer and locks; nothing else runs before it.
        assertFalse(o.lock)
        assertFalse(o.dropBiometric)
        for (rc in intArrayOf(NativeCode.PIN_CHANGE_WRONG_CURRENT, NativeCode.PIN_CHANGE_WRONG_LOCKED, NativeCode.PIN_CHANGE_STAGED, NativeCode.LOCKED)) {
            assertFalse(PinChangeRules.afterNative(rc)?.duress ?: false)
        }
    }

    @Test
    fun onlyAWrittenChangeTurnsFingerprintAnswerOffAndAnUnwrittenOneLocks() {
        val written = PinChangeRules.afterRotation(RotationOutcome.WRITTEN)
        assertEquals(PinResult.OK, written.result)
        assertTrue(written.dropBiometric)
        assertFalse(written.lock)
        // Not committed: the old PINs stay in the vault and on disk, and so does fingerprint answer.
        assertEquals(Outcome(PinResult.FAILED), PinChangeRules.afterRotation(RotationOutcome.NOT_COMMITTED))
        // Committed but not written: the native vault holds PINs the file on disk does not.
        assertEquals(Outcome(PinResult.FAILED, lock = true), PinChangeRules.afterRotation(RotationOutcome.UNWRITTEN))
    }

    @Test
    fun aWrapOfTheOldPinDoesNotMatchTheBindingAfterAChange() {
        val before = ByteArray(BiometricStore.BINDING_LEN) { it.toByte() }
        val after = before.copyOf().also { it[0] = 0x7F }
        val wrapped = BiometricStore.Wrapped(before.copyOf(), ByteArray(BiometricStore.IV_LEN), ByteArray(BiometricStore.CT_LEN))
        assertTrue(BiometricStore.sameVault(wrapped, before))
        assertFalse(BiometricStore.sameVault(wrapped, after))
        assertFalse(BiometricStore.sameVault(wrapped, before.copyOf(BiometricStore.BINDING_LEN - 1)))
    }
}
