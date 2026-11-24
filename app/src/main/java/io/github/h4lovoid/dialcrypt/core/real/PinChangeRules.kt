package io.github.h4lovoid.dialcrypt.core.real

import io.github.h4lovoid.dialcrypt.core.CoreState
import io.github.h4lovoid.dialcrypt.core.PinResult

/** How one vault rotation ended in the app: ticket import, native commit, file write. */
internal enum class RotationOutcome {
    /** Imported, committed and written; the old tickets are retired. */
    WRITTEN,

    /** Not committed: the file on disk, its tickets and the native vault's PINs are unchanged. */
    NOT_COMMITTED,

    /** Committed in the native vault, but the file was not written: the file on disk is the old one. */
    UNWRITTEN,
}

/** Rules of the in-app PIN change, kept apart from the native calls so they can be tested. */
internal object PinChangeRules {
    /** What the app does after a PIN change attempt; [duress] runs the duress path of the unlock screen. */
    data class Outcome(
        val result: PinResult,
        val lock: Boolean = false,
        val dropBiometric: Boolean = false,
        val duress: Boolean = false,
    )

    /**
     * Refusal before anything reaches the native core (there is no unlocked vault to check the
     * current PIN against), or null when the current PIN goes to the native check.
     */
    fun refusal(ready: Boolean, st: CoreState): PinResult? = when {
        !ready -> PinResult.NOT_CONNECTED
        st.locked || !st.pinConfigured || st.vaultDestroyed -> PinResult.FAILED
        else -> null
    }

    /**
     * The change is refused after a fingerprint unlock (it covers one call and never the PIN) and
     * while fingerprint answer is being turned on ([stretchHeld] or bioEnrollPending: the app holds
     * the current PIN's stretch, which a change would leave stale). Decided only after the native
     * current-PIN check, so the emergency PIN still takes the duress path; the native core refuses
     * both as well, after the same check.
     */
    fun refusedAfterCheck(st: CoreState, stretchHeld: Boolean): Boolean = st.callScoped || st.bioEnrollPending || stretchHeld

    /**
     * What is wrong with the new PINs ([policy] from PinInput.check; [pinBytes], [duressBytes] their
     * UTF-8 sizes, null when they cannot be encoded), or null. Reported only after the native
     * current-PIN check, which runs whatever this says.
     */
    fun newPinProblem(policy: PinResult?, pinBytes: Int?, duressBytes: Int?): PinResult? = policy ?: when {
        pinBytes == null || duressBytes == null -> PinResult.FAILED
        pinBytes > PinInput.NATIVE_MAX_BYTES || duressBytes > PinInput.NATIVE_MAX_BYTES -> PinResult.FAILED
        else -> null
    }

    /**
     * After nativePinChange returned [rc]; null when the new PINs are staged and must be written
     * next. The emergency PIN and the lockout come first; then a [refused] change; then a
     * [newPinProblem] (the new PINs were not sent, so nothing was staged); then the current PIN.
     */
    fun afterNative(rc: Int, refused: Boolean = false, newPinProblem: PinResult? = null): Outcome? = when {
        // The emergency PIN as the current PIN: the native core has wiped the vault as a duress
        // unlock does, and the app does the rest the same way.
        rc == NativeCode.PIN_CHANGE_DURESS -> Outcome(PinResult.DURESS, duress = true)
        // The third wrong current PIN of this unlock: the native core has locked the vault, and only
        // an unlock, which spends a ticket, opens it again.
        rc == NativeCode.PIN_CHANGE_WRONG_LOCKED -> Outcome(PinResult.WRONG_CURRENT, lock = true)
        refused -> Outcome(PinResult.FAILED)
        newPinProblem != null -> Outcome(newPinProblem)
        rc == NativeCode.PIN_CHANGE_STAGED -> null
        rc == NativeCode.PIN_CHANGE_WRONG_CURRENT -> Outcome(PinResult.WRONG_CURRENT)
        else -> Outcome(PinResult.FAILED)
    }

    /**
     * After the rotation with the staged PINs. Written: fingerprint answer goes off, because its
     * wrapped stretch belongs to the old PIN. Not committed: the staged PINs are discarded and the
     * vault stays unlocked with the old ones. Unwritten: the native vault already holds the new PINs
     * while the file on disk keeps the old ones, so the app locks and only the file on disk remains.
     */
    fun afterRotation(r: RotationOutcome): Outcome = when (r) {
        RotationOutcome.WRITTEN -> Outcome(PinResult.OK, dropBiometric = true)
        RotationOutcome.NOT_COMMITTED -> Outcome(PinResult.FAILED)
        RotationOutcome.UNWRITTEN -> Outcome(PinResult.FAILED, lock = true)
    }
}
