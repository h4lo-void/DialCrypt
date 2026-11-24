package io.github.h4lovoid.dialcrypt.incoming

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/**
 * Answer state of the incoming prompt: one choice at a time, and a cancelled or failed unlock hands
 * the choice back so the user can answer again while the call is still ringing.
 */
internal class PromptGate {
    /** Both answer buttons are disabled while true. Compose state, so the buttons follow it. */
    var busy by mutableStateOf(false)
        private set

    /** The user picked an answer and the prompt is handing the call over. */
    var handoffStarted: Boolean = false
        private set

    /** Claims the single answer. False when an answer is already under way. */
    fun tryBegin(): Boolean {
        if (busy) return false
        busy = true
        handoffStarted = true
        return true
    }

    /** The handoff did not happen (unlock cancelled or failed): both answers are offered again. */
    fun release() {
        busy = false
        handoffStarted = false
    }
}
