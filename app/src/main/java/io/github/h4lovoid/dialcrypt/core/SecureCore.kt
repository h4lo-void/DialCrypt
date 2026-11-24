package io.github.h4lovoid.dialcrypt.core

import javax.crypto.Cipher
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

private val NoBiometric: StateFlow<BiometricState> = MutableStateFlow(BiometricState.OFF)

/**
 * The only door between the UI and the secure core. PIN arrays belong to the caller,
 * who zeroes them after the call returns.
 */
interface SecureCore {
    val state: StateFlow<CoreState>
    val contacts: StateFlow<List<Contact>>
    val session: StateFlow<SessionState>
    val incoming: StateFlow<IncomingUi?>
    val callHeld: StateFlow<Boolean>

    suspend fun setupPins(normal: CharArray, duress: CharArray): PinResult
    suspend fun unlock(pin: CharArray): UnlockResult
    suspend fun changePins(current: CharArray, normal: CharArray, duress: CharArray): PinResult
    fun lock()

    /** Fingerprint answer of ringing secure calls (off by default). */
    val biometric: StateFlow<BiometricState>
        get() = NoBiometric

    /**
     * Starts turning fingerprint answer on: locks the vault so the PIN is entered once more (a real
     * attempt). False while locked, during a call or a call-scoped unlock.
     */
    suspend fun beginBiometricEnable(): Boolean = false

    /** After that PIN unlock: a new fingerprint key and its cipher, to be confirmed by a fingerprint. Null cancels. */
    suspend fun biometricEnrollCipher(): Cipher? = null

    /** Wraps the kept PIN stretch with the cipher the fingerprint released. */
    suspend fun finishBiometricEnable(authed: Cipher): Boolean = false

    fun cancelBiometricEnable() {}

    /** Deletes the wrapped stretch, its freshness stamp and the key. Needs no PIN. */
    suspend fun disableBiometric() {}

    /** Cipher to release the kept stretch, only while a secure call rings for a locked vault. Null: use the PIN. */
    suspend fun biometricUnlockCipher(): Cipher? = null

    /** Unlocks for the ringing call with the stretch the fingerprint released (one single-use ticket, as a PIN would). */
    suspend fun unlockWithBiometric(authed: Cipher): UnlockResult = UnlockResult.UNAVAILABLE

    suspend fun updateContact(id: Long, name: String, number: String?): ContactResult
    suspend fun deleteContact(id: Long): ContactResult
    suspend fun submitPairingCode(id: Long, code: String): PairingResult
    /** What [addPairedContact] would do with this code (a card or a bare code); writes nothing. */
    suspend fun previewPairing(code: String): PairingPreview = PairingPreview.New
    /**
     * Saves a contact from their pairing code. [mutual]: they are known to have saved us already, so
     * the contact shows as paired; otherwise it waits until a call with this pairing is established.
     */
    suspend fun addPairedContact(name: String, number: String?, code: String, mutual: Boolean = false): PairingResult
    /** Own pairing code; null while locked. */
    suspend fun ownPairingCode(): String?
    suspend fun rotatePairingCode(): String?
    /** Own card with a fresh random nonce, so each card shown has its own confirmation code; null while locked. */
    suspend fun ownInviteCard(name: String, number: String?): InviteCard?

    fun startCallToContact(contactId: Long)
    fun startCallToNumber(number: String)
    fun beginHandoff(token: ByteArray)
    fun decideIncoming(secure: Boolean)

    fun sendText(text: String): SendResult
    fun sendQuick(command: QuickCommand): SendResult

    /** Show the verification words and open the voice comparison window. */
    fun beginSas()
    fun openVoiceWindow()
    /** match = false hangs up and clears. */
    fun decideSas(match: Boolean)

    suspend fun saveContact(name: String, number: String?): ContactResult
    fun dismissSaveOffer()
    fun dismissAbort()

    /** Safe exit cleanup: releases handoff or active call, locks vault, clears memory. */
    suspend fun prepareExit()
    /** Hang up and clear all session material. */
    suspend fun endAndWipe()
    /** Destroy all keys. The caller then ends the process. */
    suspend fun wipeAll()
}
