package io.github.h4lovoid.dialcrypt.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Used when no real core is linked in. Every state says "not connected" and every
 * operation refuses, so nothing can pretend to work.
 */
object UnavailableSecureCore : SecureCore {
    override val state: StateFlow<CoreState> = MutableStateFlow(CoreState())
    override val contacts: StateFlow<List<Contact>> = MutableStateFlow(emptyList())
    override val session: StateFlow<SessionState> = MutableStateFlow(SessionState())
    override val incoming: StateFlow<IncomingUi?> = MutableStateFlow(null)
    override val callHeld: StateFlow<Boolean> = MutableStateFlow(false)

    override suspend fun setupPins(normal: CharArray, duress: CharArray) = PinResult.NOT_CONNECTED
    override suspend fun unlock(pin: CharArray) = UnlockResult.UNAVAILABLE
    override suspend fun changePins(current: CharArray, normal: CharArray, duress: CharArray) = PinResult.NOT_CONNECTED
    override fun lock() = Unit
    override suspend fun updateContact(id: Long, name: String, number: String?) = ContactResult.FAILED
    override suspend fun deleteContact(id: Long) = ContactResult.FAILED
    override suspend fun submitPairingCode(id: Long, code: String) = PairingResult.FAILED
    override suspend fun addPairedContact(name: String, number: String?, code: String, mutual: Boolean) = PairingResult.FAILED
    override suspend fun ownPairingCode(): String? = null
    override suspend fun rotatePairingCode(): String? = null
    override suspend fun ownInviteCard(name: String, number: String?): InviteCard? = null
    override fun startCallToContact(contactId: Long) = Unit
    override fun startCallToNumber(number: String) = Unit
    override fun beginHandoff(token: ByteArray) = Unit
    override fun decideIncoming(secure: Boolean) = Unit
    override fun sendText(text: String) = SendResult.BLOCKED_NOT_ESTABLISHED
    override fun sendQuick(command: QuickCommand) = SendResult.BLOCKED_NOT_ESTABLISHED
    override fun beginSas() = Unit
    override fun openVoiceWindow() = Unit
    override fun decideSas(match: Boolean) = Unit
    override suspend fun saveContact(name: String, number: String?) = ContactResult.FAILED
    override fun dismissSaveOffer() = Unit
    override fun dismissAbort() = Unit
    override suspend fun prepareExit() = Unit
    override suspend fun endAndWipe() = Unit
    override suspend fun wipeAll() = Unit
}

object UnavailableLockdownController : LockdownController {
    override val state: StateFlow<LockdownState> = MutableStateFlow(LockdownState())
    override fun prepare() = Unit
}
