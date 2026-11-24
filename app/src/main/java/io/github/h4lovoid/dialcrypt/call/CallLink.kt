package io.github.h4lovoid.dialcrypt.call

import io.github.h4lovoid.dialcrypt.core.NumberPresentation
import java.io.Closeable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull

enum class CallPhase { IDLE, DIALING, RINGING, ACTIVE, ENDED }

enum class ClaimResult { RINGING, GONE, TAKEN }

/** [incoming], [number], and [presentation] describe the current or last call; [number] is null when hidden. */
data class CallStatus(
    val phase: CallPhase = CallPhase.IDLE,
    val incoming: Boolean = false,
    val number: String? = null,
    val presentation: NumberPresentation = NumberPresentation.SHOWN,
)

class IncomingOffer(
    val token: ByteArray,
    val number: String?,
    val presentation: NumberPresentation,
) {
    override fun equals(other: Any?): Boolean =
        this === other || (
            other is IncomingOffer &&
                token.contentEquals(other.token) &&
                number == other.number &&
                presentation == other.presentation
            )

    override fun hashCode(): Int {
        var result = token.contentHashCode()
        result = 31 * result + (number?.hashCode() ?: 0)
        result = 31 * result + presentation.hashCode()
        return result
    }
}

private val NoOffersFlow: StateFlow<IncomingOffer?> = MutableStateFlow(null)

/**
 * Cellular call control and call audio for the secure process. The secure core is the only
 * user. Every method is safe to call from any thread and in any phase.
 */
interface CallLink {
    val status: StateFlow<CallStatus>

    /** Places a cellular call. False when the platform refused or a call is already up. */
    fun dial(number: String): Boolean

    /** Answers the ringing call. False when nothing is ringing or the platform refused. */
    fun answer(): Boolean

    /** Ends the current call. */
    fun hangUp()

    /**
     * Opens the PCM streams of the ACTIVE call: 16 kHz, mono, 16-bit. While they are open the
     * microphone does not reach the uplink and the downlink does not reach the earpiece.
     * Null when the platform refuses; the caller then hangs up (fail closed).
     */
    fun openAudio(): CallAudio?

    val offers: StateFlow<IncomingOffer?>
        get() = NoOffersFlow

    fun claim(token: ByteArray): ClaimResult = ClaimResult.GONE

    fun release(token: ByteArray) {}

    /** The secure screen cannot show this offer: let `:call` show its own prompt for it. */
    fun returnOffer(token: ByteArray) {}

    fun answerPlain(token: ByteArray): Boolean = false

    fun setDataRoute(dataMode: Boolean) {}

    suspend fun waitUntilDisconnected(timeoutMs: Long = 1_500L): Boolean =
        withTimeoutOrNull(timeoutMs) { status.first { it.phase != CallPhase.ACTIVE } } != null
}

interface CallAudio : Closeable {
    /** Blocks until [len] downlink samples are read. Returns [len], or -1 once closed or failed. */
    fun read(buf: ShortArray, off: Int, len: Int): Int

    /** Blocks until [len] samples are queued for the uplink. Returns [len], or -1 once closed or failed. */
    fun write(buf: ShortArray, off: Int, len: Int): Int

    /**
     * Voice comparison window. true: microphone and earpiece work as in a normal call and
     * [write] data is dropped. false: back to silent data mode.
     */
    fun setVoiceWindow(open: Boolean)
}
