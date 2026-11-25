package io.github.h4lovoid.dialcrypt.core

/** Hardware attestation level of a key. Only these four values may ever be shown. */
enum class HardwareLevel { UNATTESTED, STRONGBOX_LOCKED, STRONGBOX_SELF_SIGNED, STRONGBOX_UNLOCKED }

/** State of the "quick reconnect" (resume) secret shared with a contact. */
enum class QuickConnect { UNAVAILABLE, READY, REBUILD_PENDING }

/** The single status a contact shows in lists. */
enum class ContactTrust { VERIFIED, UNVERIFIED, KEY_CHANGED }

data class Contact(
    val id: Long,
    val name: String,
    /** Full number, or null when the contact was saved from a hidden number. */
    val number: String?,
    /** Public key fingerprint, upper-case hex in groups. */
    val fingerprint: String,
    val verified: Boolean,
    val paired: Boolean,
    val quickConnect: QuickConnect,
    val hardware: HardwareLevel,
    /** A later call from this number showed a different key and the words have not been compared since. */
    val keyChanged: Boolean = false,
    /**
     * Both sides are known to have saved each other with the current pairing code: the tagged reply
     * was scanned, or a call was established with this pairing. [paired] alone only means we saved them.
     */
    val mutual: Boolean = false,
) {
    /** A changed key outranks an earlier verification. */
    val trust: ContactTrust
        get() = when {
            keyChanged -> ContactTrust.KEY_CHANGED
            verified -> ContactTrust.VERIFIED
            else -> ContactTrust.UNVERIFIED
        }
}

enum class CoreAvailability { NOT_CONNECTED, READY }

const val MAX_PIN_ATTEMPTS = 5

data class CoreState(
    val availability: CoreAvailability = CoreAvailability.NOT_CONNECTED,
    val pinConfigured: Boolean = false,
    val locked: Boolean = true,
    val attemptsLeft: Int = MAX_PIN_ATTEMPTS,
    /** True once the vault is permanently unusable (all attempts used). */
    val vaultDestroyed: Boolean = false,
    /**
     * Unlocked with a fingerprint for one ringing secure call: contacts, pairing and settings stay
     * closed, and the vault locks again when that call ends or stops ringing.
     */
    val callScoped: Boolean = false,
    /** The user is turning fingerprint answer on: the next PIN unlock keeps the PIN stretch for it. */
    val bioEnrollPending: Boolean = false,
    /**
     * False when the secure hardware does not enforce single-use keys and the Android key store
     * counts the PIN tries: software with root access can reset the count.
     */
    val singleUseHardwareEnforced: Boolean = true,
)

/**
 * Fingerprint answer of ringing secure calls. OFF: not set up. READY: a fingerprint can answer.
 * NEEDS_PIN: set up, but the next unlock needs the PIN (restart, 12 hours, a wrong PIN).
 * INVALIDATED: turned off because the fingerprints changed. UNAVAILABLE: StrongBox refused the key.
 */
enum class BiometricState { OFF, READY, NEEDS_PIN, INVALIDATED, UNAVAILABLE }

enum class PinResult {
    OK, TOO_SHORT, TOO_SIMPLE, SAME_PINS, WRONG_CURRENT, DEVICE_UNSUPPORTED, NOT_CONNECTED, FAILED,

    /** The emergency PIN was entered as the current PIN: everything is destroyed; close the app. */
    DURESS,
}

/** DURESS means the core has already destroyed all keys; the UI only closes the app. */
enum class UnlockResult { SUCCESS, DURESS, WRONG, DEAD, UNAVAILABLE }

enum class ContactResult { OK, NOT_FOUND, INVALID_NAME, INVALID_NUMBER, FAILED }

enum class PairingResult { OK, BAD_FORMAT, BAD_CHECKSUM, WRONG_KEY, FAILED }

/** What saving a received pairing code would do, found out before anything is written. */
sealed interface PairingPreview {
    /** No contact holds this identity key: a new contact. */
    object New : PairingPreview

    /** [contactId] holds this identity key with this very pairing: saving changes no pairing. */
    data class Unchanged(val contactId: Long) : PairingPreview

    /**
     * [contactId] holds this identity key with another pairing: saving replaces it, and secure calls
     * with that contact stop until they import our current card too.
     */
    data class Replaces(val contactId: Long) : PairingPreview

    /** The code is refused, or the app is locked. */
    object Invalid : PairingPreview
}

enum class SendResult { QUEUED, EMPTY, TOO_LONG, BLOCKED_KEY_CHANGED, BLOCKED_NOT_ESTABLISHED }

enum class SessionPhase { IDLE, CONNECTING, ESTABLISHED, KEY_CHANGED, ABORTED, CLEARING, CLEARED }

/** How the peer number was delivered by Telecom. */
enum class NumberPresentation { SHOWN, WITHHELD, UNKNOWN }

/** Whether the local user placed or answered the current call. */
enum class CallDirection { OUTGOING, INCOMING }

/** Live incoming call offer shown either in-app or across handoff from `:call`. */
data class IncomingUi(
    val number: String?,
    val presentation: NumberPresentation,
    val handoff: Boolean,
    val ringingSinceMs: Long,
    val ended: Boolean = false,
)

enum class ConnectStep { DIALING, WAIT_PEER, KEY_EXCHANGE, IDENTITY, FINALIZING }

data class ConnectProgress(
    val step: ConnectStep,
    /** Overall progress 0..100. */
    val percent: Int,
    val etaSeconds: Int,
)

enum class IdentityStatus { UNKNOWN, VERIFIED_THIS_CALL, VERIFIED_CONTACT, KEY_CHANGED }

data class PqState(
    /** True once the post-quantum secret has been mixed in. */
    val mixed: Boolean = false,
    /** Background progress 0..100 while not mixed. */
    val percent: Int = 0,
)

data class PeerInfo(
    val contactId: Long?,
    val name: String?,
    /** Dialed number or caller ID, null if hidden. */
    val number: String?,
    val presentation: NumberPresentation = NumberPresentation.SHOWN,
)

/** Word indices are 0..255; the same index is the number shown next to the word. */
data class SasState(
    val wordIndices: List<Int>,
    val voiceWindowOpen: Boolean,
    val voiceSecondsLeft: Int,
    val localMatched: Boolean = false,
    val peerMatched: Boolean = false,
)

data class SaveOffer(val suggestedNumber: String?)

enum class QuickCommand { UNDERSTOOD, YES, NO, WAIT, REPEAT, CALL_LATER }

sealed interface MessageBody {
    data class Text(val text: String) : MessageBody
    data class Quick(val command: QuickCommand) : MessageBody
}

enum class MessageStatus { SENDING, SENT, DELIVERED, READ, FAILED, RECEIVED }

data class ChatMessage(
    val id: Long,
    val outgoing: Boolean,
    val body: MessageBody,
    val status: MessageStatus,
    /** 0..100, meaningful while SENDING. */
    val sendPercent: Int = 0,
)

/** Failure codes from the core. The UI maps each to a sentence per language. */
enum class SessionFailure {
    NO_PREAMBLE, HANDSHAKE_FAILED, PSK_REQUIRED, BEARER_VIOLATION, PEER_ABORTED, CALL_DROPPED, UNKNOWN,
}

data class SessionState(
    val phase: SessionPhase = SessionPhase.IDLE,
    val direction: CallDirection = CallDirection.OUTGOING,
    val peer: PeerInfo? = null,
    val connect: ConnectProgress? = null,
    val identity: IdentityStatus = IdentityStatus.UNKNOWN,
    val paired: Boolean = false,
    val quickConnect: QuickConnect = QuickConnect.UNAVAILABLE,
    val pq: PqState = PqState(),
    val hardware: HardwareLevel = HardwareLevel.UNATTESTED,
    val fingerprint: String? = null,
    val sas: SasState? = null,
    val messages: List<ChatMessage> = emptyList(),
    val saveOffer: SaveOffer? = null,
    val abort: SessionFailure? = null,
    /** Set on ABORTED only: the session had reached the chat phase (messages could be sent) before it ended. */
    val wasEstablished: Boolean = false,
)

object SessionLimits {
    /** Maximum characters in one text message (the call audio channel is very slow). */
    const val MAX_TEXT_CHARS = 200
}
