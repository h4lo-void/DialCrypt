package io.github.h4lovoid.dialcrypt.core

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * In-memory stand-in for the secure core. It can be set to any state for screenshots and unit
 * tests; when given a [scope] it also plays out a scripted call so the debug app can be clicked through.
 */
class FakeSecureCore(
    initialState: CoreState = CoreState(CoreAvailability.READY),
    initialContacts: List<Contact> = emptyList(),
    initialSession: SessionState = SessionState(),
    private val scope: CoroutineScope? = null,
) : SecureCore {
    private val coreState = MutableStateFlow(initialState)
    private val contactList = MutableStateFlow(initialContacts)
    private val sessionState = MutableStateFlow(initialSession)
    private val incomingFlow = MutableStateFlow<IncomingUi?>(null)
    private val callHeldFlow = MutableStateFlow(false)

    override val state: StateFlow<CoreState> = coreState
    override val contacts: StateFlow<List<Contact>> = contactList
    override val session: StateFlow<SessionState> = sessionState
    override val incoming: StateFlow<IncomingUi?> = incomingFlow
    override val callHeld: StateFlow<Boolean> = callHeldFlow

    var normalPin: String? = null
        private set
    var duressPin: String? = null
        private set

    /** Everything the UI asked of the core, in order, for assertions. */
    val calls = mutableListOf<String>()
    var keysDestroyed = false
        private set

    private var nextContactId = (initialContacts.maxOfOrNull { it.id } ?: 0L) + 1
    private var nextMessageId = 1L
    private var script: Job? = null
    /** Wrong current PINs given to [changePins] since the last unlock, as the native vault counts them. */
    private var wrongCurrent = 0

    // ---- scenario control -------------------------------------------------------------

    fun setCoreState(value: CoreState) { coreState.value = value }
    fun setContacts(value: List<Contact>) { contactList.value = value }
    fun setSession(value: SessionState) { sessionState.value = value }
    fun updateSession(block: (SessionState) -> SessionState) { sessionState.update(block) }

    fun presetPins(normal: String, duress: String) {
        normalPin = normal
        duressPin = duress
        coreState.update { it.copy(pinConfigured = true) }
    }

    // ---- PIN ----------------------------------------------------------------------------

    override suspend fun setupPins(normal: CharArray, duress: CharArray): PinResult {
        calls += "setupPins"
        val r = checkPins(String(normal), String(duress))
        if (r != PinResult.OK) return r
        normalPin = String(normal)
        duressPin = String(duress)
        coreState.update { it.copy(pinConfigured = true, locked = false, attemptsLeft = MAX_PIN_ATTEMPTS) }
        return PinResult.OK
    }

    private fun checkPins(normal: String, duress: String): PinResult {
        PinRules.violation(normal)?.let { return if (it == PinRules.Violation.TOO_SIMPLE) PinResult.TOO_SIMPLE else PinResult.TOO_SHORT }
        PinRules.violation(duress)?.let { return if (it == PinRules.Violation.TOO_SIMPLE) PinResult.TOO_SIMPLE else PinResult.TOO_SHORT }
        if (PinRules.pairViolation(normal, duress)) return PinResult.SAME_PINS
        return PinResult.OK
    }

    override suspend fun unlock(pin: CharArray): UnlockResult {
        calls += "unlock"
        val entered = String(pin)
        return when {
            entered == normalPin -> {
                wrongCurrent = 0
                coreState.update { it.copy(locked = false, attemptsLeft = MAX_PIN_ATTEMPTS) }
                UnlockResult.SUCCESS
            }
            entered == duressPin -> {
                destroyKeys()
                UnlockResult.DURESS
            }
            else -> {
                val left = coreState.value.attemptsLeft - 1
                if (left <= 0) {
                    destroyKeys()
                    coreState.update { it.copy(attemptsLeft = 0, vaultDestroyed = true) }
                    UnlockResult.DEAD
                } else {
                    coreState.update { it.copy(attemptsLeft = left) }
                    UnlockResult.WRONG
                }
            }
        }
    }

    /**
     * Same order as the real core: refused while locked, then the current PIN, whatever the new
     * PINs. The emergency PIN takes the duress path (keys destroyed, locked); the third wrong current
     * PIN since the last unlock locks; otherwise a problem of the new PINs comes before a wrong
     * current PIN, and a right current PIN with bad new PINs is not counted.
     */
    override suspend fun changePins(current: CharArray, normal: CharArray, duress: CharArray): PinResult {
        calls += "changePins"
        if (coreState.value.locked) return PinResult.FAILED
        val entered = String(current)
        if (entered == duressPin) {
            destroyKeys()
            coreState.update { it.copy(locked = true) }
            return PinResult.DURESS
        }
        val problem = checkPins(String(normal), String(duress)).takeIf { it != PinResult.OK }
        if (entered != normalPin) {
            wrongCurrent += 1
            if (wrongCurrent >= WRONG_CURRENT_LIMIT) {
                wrongCurrent = 0
                lock()
                return PinResult.WRONG_CURRENT
            }
            return problem ?: PinResult.WRONG_CURRENT
        }
        if (problem != null) return problem
        normalPin = String(normal)
        duressPin = String(duress)
        return PinResult.OK
    }

    override fun lock() {
        calls += "lock"
        coreState.update { it.copy(locked = true) }
    }

    private fun destroyKeys() {
        keysDestroyed = true
        normalPin = null
        duressPin = null
        contactList.value = emptyList()
    }

    // ---- contacts -----------------------------------------------------------------------

    override suspend fun updateContact(id: Long, name: String, number: String?): ContactResult {
        calls += "updateContact"
        if (name.isBlank()) return ContactResult.INVALID_NAME
        if (number != null && !PhoneRules.isValid(number)) return ContactResult.INVALID_NUMBER
        if (contactList.value.none { it.id == id }) return ContactResult.NOT_FOUND
        contactList.update { list -> list.map { if (it.id == id) it.copy(name = name, number = number) else it } }
        return ContactResult.OK
    }

    override suspend fun deleteContact(id: Long): ContactResult {
        calls += "deleteContact"
        if (contactList.value.none { it.id == id }) return ContactResult.NOT_FOUND
        contactList.update { list -> list.filter { it.id != id } }
        return ContactResult.OK
    }

    override suspend fun submitPairingCode(id: Long, code: String): PairingResult {
        calls += "submitPairingCode"
        val clean = code.filter { !it.isWhitespace() }
        return when {
            clean.length < 20 -> PairingResult.BAD_FORMAT
            clean.last() == '0' -> PairingResult.BAD_CHECKSUM
            clean.first() == 'X' -> PairingResult.WRONG_KEY
            else -> {
                contactList.update { list -> list.map { if (it.id == id) it.copy(paired = true, mutual = false) else it } }
                PairingResult.OK
            }
        }
    }

    override suspend fun ownPairingCode(): String? {
        calls += "ownPairingCode"
        return if (coreState.value.locked) null else SAMPLE_PAIRING_CODE
    }

    override suspend fun addPairedContact(name: String, number: String?, code: String, mutual: Boolean): PairingResult {
        calls += "addPairedContact"
        if (coreState.value.locked) return PairingResult.FAILED
        val clean = code.filter { !it.isWhitespace() }
        if (clean.length < 20) return PairingResult.BAD_FORMAT
        if (name.isBlank()) return PairingResult.FAILED
        if (number != null && !PhoneRules.isValid(number)) return PairingResult.FAILED
        val id = nextContactId++
        contactList.update {
            it + Contact(
                id = id,
                name = name.trim(),
                number = number?.let { n -> PhoneRules.normalize(n) },
                fingerprint = FakeScenarios.FINGERPRINT,
                verified = false,
                paired = true,
                quickConnect = QuickConnect.UNAVAILABLE,
                hardware = HardwareLevel.UNATTESTED,
                mutual = mutual,
            )
        }
        return PairingResult.OK
    }

    override suspend fun rotatePairingCode(): String? {
        calls += "rotatePairingCode"
        return if (coreState.value.locked) null else SAMPLE_PAIRING_CODE
    }

    override suspend fun ownInviteCard(name: String, number: String?): InviteCard? {
        val code = ownPairingCode() ?: return null
        return InviteCard(name.trim(), number?.let { PhoneRules.normalize(it).ifEmpty { null } }, code, InviteCard.newNonce())
    }

    override fun beginHandoff(token: ByteArray) {
        calls += "beginHandoff"
    }

    override fun decideIncoming(secure: Boolean) {
        calls += "decideIncoming:$secure"
        val inc = incomingFlow.value ?: return
        incomingFlow.value = null
        if (secure) {
            beginCall(PeerInfo(null, null, inc.number, inc.presentation), null, CallDirection.INCOMING)
        }
    }

    // ---- session ------------------------------------------------------------------------

    override fun startCallToContact(contactId: Long) {
        calls += "startCallToContact:$contactId"
        val c = contactList.value.firstOrNull { it.id == contactId } ?: return
        beginCall(PeerInfo(c.id, c.name, c.number), c)
    }

    override fun startCallToNumber(number: String) {
        calls += "startCallToNumber:$number"
        beginCall(PeerInfo(null, null, number), null)
    }

    private fun beginCall(peer: PeerInfo, contact: Contact?, direction: CallDirection = CallDirection.OUTGOING) {
        callHeldFlow.value = true
        sessionState.value = SessionState(
            phase = SessionPhase.CONNECTING,
            direction = direction,
            peer = peer,
            connect = ConnectProgress(ConnectStep.DIALING, 0, 40),
        )
        val s = scope ?: return
        script?.cancel()
        script = s.launch {
            val steps = ConnectStep.values()
            for ((i, step) in steps.withIndex()) {
                for (p in 0..4) {
                    val percent = (i * 5 + p) * 100 / (steps.size * 5)
                    sessionState.update { it.copy(connect = ConnectProgress(step, percent, ((100 - percent) * 40) / 100)) }
                    delay(150)
                }
            }
            val changed = contact?.keyChanged == true
            sessionState.update {
                it.copy(
                    phase = if (changed) SessionPhase.KEY_CHANGED else SessionPhase.ESTABLISHED,
                    connect = null,
                    identity = when {
                        changed -> IdentityStatus.KEY_CHANGED
                        contact?.verified == true -> IdentityStatus.VERIFIED_CONTACT
                        else -> IdentityStatus.UNKNOWN
                    },
                    paired = contact?.paired == true,
                    quickConnect = contact?.quickConnect ?: QuickConnect.UNAVAILABLE,
                    hardware = contact?.hardware ?: HardwareLevel.UNATTESTED,
                    fingerprint = contact?.fingerprint ?: "9F3A 51C2 0D7E B84A 66F1 2C09 E3D5 7A18",
                    pq = PqState(mixed = contact == null || changed),
                )
            }
            if (contact != null && !changed) {
                for (p in 0..100 step 10) {
                    sessionState.update { it.copy(pq = PqState(mixed = p == 100, percent = p)) }
                    delay(200)
                }
            }
        }
    }

    override fun sendText(text: String): SendResult = send(MessageBody.Text(text.trim()), text.isBlank())

    override fun sendQuick(command: QuickCommand): SendResult = send(MessageBody.Quick(command), false)

    private fun send(body: MessageBody, empty: Boolean): SendResult {
        calls += "send"
        val s = sessionState.value
        if (s.identity == IdentityStatus.KEY_CHANGED || s.phase == SessionPhase.KEY_CHANGED) return SendResult.BLOCKED_KEY_CHANGED
        if (s.phase != SessionPhase.ESTABLISHED) return SendResult.BLOCKED_NOT_ESTABLISHED
        if (empty) return SendResult.EMPTY
        if (body is MessageBody.Text && body.text.length > SessionLimits.MAX_TEXT_CHARS) return SendResult.TOO_LONG
        val id = nextMessageId++
        val startStatus = if (scope == null) MessageStatus.SENT else MessageStatus.SENDING
        sessionState.update { it.copy(messages = it.messages + ChatMessage(id, true, body, startStatus, 0)) }
        scope?.launch {
            for (p in 0..100 step 20) {
                setMessage(id, MessageStatus.SENDING, p)
                delay(120)
            }
            setMessage(id, MessageStatus.SENT, 100)
            delay(600)
            setMessage(id, MessageStatus.DELIVERED, 100)
            delay(800)
            setMessage(id, MessageStatus.READ, 100)
        }
        return SendResult.QUEUED
    }

    private fun setMessage(id: Long, status: MessageStatus, percent: Int) {
        sessionState.update { st -> st.copy(messages = st.messages.map { if (it.id == id) it.copy(status = status, sendPercent = percent) else it }) }
    }

    override fun beginSas() {
        calls += "beginSas"
        sessionState.update {
            it.copy(sas = SasState(listOf(12, 87, 143, 201, 250), voiceWindowOpen = true, voiceSecondsLeft = 30))
        }
        val s = scope ?: return
        s.launch {
            while (true) {
                delay(1000)
                val sas = sessionState.value.sas ?: break
                if (!sas.voiceWindowOpen) break
                val left = sas.voiceSecondsLeft - 1
                sessionState.update { it.copy(sas = sas.copy(voiceSecondsLeft = left.coerceAtLeast(0), voiceWindowOpen = left > 0)) }
                if (left <= 0) break
            }
        }
    }

    override fun openVoiceWindow() {
        calls += "openVoiceWindow"
        sessionState.update { st -> st.sas?.let { st.copy(sas = it.copy(voiceWindowOpen = true, voiceSecondsLeft = 30)) } ?: st }
    }

    override fun decideSas(match: Boolean) {
        calls += "decideSas:$match"
        if (!match) {
            sessionState.update { it.copy(phase = SessionPhase.CLEARED, sas = null, messages = emptyList()) }
            return
        }
        sessionState.update { st -> st.sas?.let { st.copy(sas = it.copy(localMatched = true)) } ?: st }
        val finish = {
            // Matching words settle a changed key and verify the contact.
            sessionState.value.peer?.contactId?.let { id ->
                contactList.update { list -> list.map { if (it.id == id) it.copy(verified = true, keyChanged = false) else it } }
            }
            sessionState.update { st ->
                val unknownPeer = st.peer?.contactId == null
                st.copy(
                    phase = SessionPhase.ESTABLISHED,
                    sas = null,
                    identity = if (st.identity == IdentityStatus.VERIFIED_CONTACT) st.identity else IdentityStatus.VERIFIED_THIS_CALL,
                    saveOffer = if (unknownPeer) SaveOffer(st.peer?.number) else null,
                )
            }
        }
        val s = scope
        if (s == null) finish() else s.launch { delay(1500); finish() }
    }

    override suspend fun saveContact(name: String, number: String?): ContactResult {
        calls += "saveContact"
        if (name.isBlank()) return ContactResult.INVALID_NAME
        if (number != null && !PhoneRules.isValid(number)) return ContactResult.INVALID_NUMBER
        val st = sessionState.value
        val id = nextContactId++
        contactList.update {
            it + Contact(
                id, name, number, st.fingerprint ?: "9F3A 51C2 0D7E B84A 66F1 2C09 E3D5 7A18",
                verified = true, paired = false, quickConnect = QuickConnect.REBUILD_PENDING, hardware = st.hardware,
            )
        }
        sessionState.update {
            it.copy(peer = PeerInfo(id, name, number), identity = IdentityStatus.VERIFIED_CONTACT, saveOffer = null)
        }
        return ContactResult.OK
    }

    override fun dismissSaveOffer() {
        calls += "dismissSaveOffer"
        sessionState.update { it.copy(saveOffer = null) }
    }

    override fun dismissAbort() {
        calls += "dismissAbort"
        sessionState.value = SessionState()
    }

    override suspend fun prepareExit() {
        calls += "prepareExit"
        incomingFlow.value = null
        endAndWipe()
        lock()
    }

    override suspend fun endAndWipe() {
        calls += "endAndWipe"
        script?.cancel()
        callHeldFlow.value = false
        sessionState.update { it.copy(phase = SessionPhase.CLEARING, sas = null) }
        if (scope != null) delay(900)
        sessionState.value = SessionState(phase = SessionPhase.CLEARED)
    }

    override suspend fun wipeAll() {
        calls += "wipeAll"
        callHeldFlow.value = false
        destroyKeys()
        coreState.update { it.copy(pinConfigured = false, locked = true) }
    }

    private companion object {
        const val SAMPLE_PAIRING_CODE = "AEGIS2-ABCDE-23456-FGHJK-78MNP-Q3456-7RSTV-W89XY-ZA234-56BCD-EF78G-HJKM3-4567N-PQRS8-9TVWX-Y"

        /** The native vault's limit (MAX_WRONG_CURRENT_PINS in aegiscall-trust). */
        const val WRONG_CURRENT_LIMIT = 3
    }
}
