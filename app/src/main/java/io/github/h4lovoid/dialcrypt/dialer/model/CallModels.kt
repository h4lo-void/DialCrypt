package io.github.h4lovoid.dialcrypt.dialer.model

import io.github.h4lovoid.dialcrypt.core.NumberPresentation

/** What the in-call screen shows for one call. */
enum class UiCallState { RINGING, WAITING, SELECT_ACCOUNT, DIALING, ACTIVE, HOLDING, DISCONNECTING, ENDED }

/** Audio route kinds the in-call screen can offer. */
enum class Endpoint { EARPIECE, SPEAKER, BLUETOOTH, WIRED, OTHER }

/** Screening progress of the ringing call tracked by the secure flow. */
enum class Screening { NONE, PENDING, PLAIN, OFFER }

/** How a ringing call is presented to the user. */
enum class IncomingUi { WAIT, NOTICE_ONLY, FULL_SCREEN, FULL_SCREEN_AND_START }

/** The caller line as the in-call screen may show it. */
sealed interface NumberText {
    data class Digits(val text: String) : NumberText
    data object Hidden : NumberText
    data object Unknown : NumberText
    data object Payphone : NumberText

    /** A merged call; [participants] is 0 when the network does not list them. */
    data class Conference(val participants: Int) : NumberText
}

/** android.telecom.Call state values, repeated here so the models stay free of Android classes. */
object TelecomState {
    const val NEW = 0
    const val DIALING = 1
    const val RINGING = 2
    const val HOLDING = 3
    const val ACTIVE = 4
    const val DISCONNECTED = 7
    const val SELECT_PHONE_ACCOUNT = 8
    const val CONNECTING = 9
    const val DISCONNECTING = 10
    const val PULLING_CALL = 11
    const val AUDIO_PROCESSING = 12
    const val SIMULATED_RINGING = 13

    fun isRinging(state: Int): Boolean = state == RINGING || state == SIMULATED_RINGING

    fun isEnding(state: Int): Boolean = state == DISCONNECTED || state == DISCONNECTING
}

/** Plain copy of one Telecom call, taken in `:call`. */
data class CallSnapshot(
    val id: Int,
    val telecomState: Int,
    val incoming: Boolean,
    val number: String?,
    val presentation: NumberPresentation,
    val connectMs: Long,
    val canHold: Boolean,
    val conferenceChild: Boolean,
    val emergency: Boolean,
    val postDial: String?,
    val accounts: List<String>,
    val payphone: Boolean = false,
    /** The secure flow (CallRegistry) tracks this call. */
    val tracked: Boolean = false,
    /** Elapsed realtime at which the call was added. */
    val addedMs: Long = 0L,
    /** Telecom offers to merge this call with another (CAPABILITY_MERGE_CONFERENCE or conferenceable calls). */
    val canMerge: Boolean = false,
    /** The call is a conference (PROPERTY_CONFERENCE); its participants are its children. */
    val conference: Boolean = false,
    val participants: Int = 0,
) {
    // Keeps the number out of any accidental log line.
    override fun toString(): String = "CallSnapshot(id=$id, state=$telecomState, incoming=$incoming)"
}

data class UiCall(
    val id: Int,
    val state: UiCallState,
    val number: NumberText,
    val connectMs: Long?,
    val canHold: Boolean,
    val emergency: Boolean,
    val postDial: String?,
    val accounts: List<String>,
    /** Only for RINGING and WAITING: the answer button may be used. */
    val answerEnabled: Boolean = false,
)

data class AudioUi(
    val muted: Boolean = false,
    val endpoint: Endpoint = Endpoint.EARPIECE,
    val available: List<Endpoint> = emptyList(),
)

/** What CallRegistry publishes about the call it tracks. */
data class RegistryView(
    val screening: Screening = Screening.NONE,
    /** An offer exists and was delivered to an open `:secure`. */
    val offerToSecure: Boolean = false,
    /** The secure flow owns the tracked call: claimed, answered securely, or dialed by the app. */
    val secureOwned: Boolean = false,
)

data class InCallUiState(
    val primary: UiCall? = null,
    val secondary: UiCall? = null,
    val audio: AudioUi = AudioUi(),
    val secureOffer: Boolean = false,
    val secureOwned: Boolean = false,
    val screening: Screening = Screening.NONE,
    /** The active and the held call may be merged into one conference. */
    val canMerge: Boolean = false,
)
