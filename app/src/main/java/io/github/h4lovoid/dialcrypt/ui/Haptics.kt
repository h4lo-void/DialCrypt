package io.github.h4lovoid.dialcrypt.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.hapticfeedback.HapticFeedback
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback

/** Short touch feedback: tick for ordinary taps, strong for state changes that matter. */
class Haptics(private val feedback: HapticFeedback) {
    fun tick() = feedback.performHapticFeedback(HapticFeedbackType.TextHandleMove)
    fun strong() = feedback.performHapticFeedback(HapticFeedbackType.LongPress)
}

@Composable
fun rememberHaptics(): Haptics {
    val feedback = LocalHapticFeedback.current
    return remember(feedback) { Haptics(feedback) }
}
