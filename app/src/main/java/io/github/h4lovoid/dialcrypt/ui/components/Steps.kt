package io.github.h4lovoid.dialcrypt.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.Crossfade
import androidx.compose.animation.core.snap
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Space
import io.github.h4lovoid.dialcrypt.ui.theme.Tone
import io.github.h4lovoid.dialcrypt.ui.theme.color

enum class StepState { DONE, RUNNING, PENDING, FAILED }

/** One line of feedback with a small icon, so the tone never relies on color alone. */
@Composable
fun InlineMessage(text: String, tone: Tone, modifier: Modifier = Modifier) {
    val c = tone.color()
    Row(
        modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(Space.sm),
    ) {
        Icon(
            when (tone) {
                Tone.OK -> Icons.Filled.CheckCircle
                Tone.WARN -> Icons.Filled.Warning
                else -> Icons.Filled.Error
            },
            contentDescription = null, tint = c, modifier = Modifier.size(20.dp),
        )
        Text(text, color = c, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
    }
}

/**
 * Round marker of one step: a green check when done, a spinner while running, a hollow ring while
 * waiting, a red cross on failure. A change of state cross-fades between the two marks. Without
 * animations the change is instant and the running marker is a still ring with a dot.
 */
@Composable
fun StepMarker(state: StepState, description: String, modifier: Modifier = Modifier, size: Dp = 28.dp) {
    val motion = rememberMotionEnabled()
    val tint by animateColorAsState(
        when (state) {
            StepState.DONE -> Palette.Ok
            StepState.RUNNING -> Palette.Accent
            StepState.PENDING -> Palette.Outline
            StepState.FAILED -> Palette.Danger
        },
        label = "step-tint",
    )
    Box(modifier.size(size).semantics { contentDescription = description }, contentAlignment = Alignment.Center) {
        Crossfade(
            targetState = state,
            animationSpec = if (motion) tween(200) else snap(),
            label = "step-mark",
        ) { shown ->
            Box(Modifier.size(size), contentAlignment = Alignment.Center) {
                when (shown) {
                    StepState.DONE -> Box(Modifier.size(size).border(1.5.dp, tint, CircleShape), contentAlignment = Alignment.Center) {
                        Icon(Icons.Filled.Check, contentDescription = null, tint = tint, modifier = Modifier.size(size * 0.55f))
                    }
                    StepState.FAILED -> Box(Modifier.size(size).border(1.5.dp, tint, CircleShape), contentAlignment = Alignment.Center) {
                        Icon(Icons.Filled.Close, contentDescription = null, tint = tint, modifier = Modifier.size(size * 0.55f))
                    }
                    StepState.PENDING -> Box(Modifier.size(size * 0.8f).border(2.dp, tint, CircleShape))
                    StepState.RUNNING -> Box(
                        Modifier.size(size * 0.9f).border(3.dp, tint.copy(alpha = 0.3f), CircleShape),
                        contentAlignment = Alignment.Center,
                    ) {
                        if (motion) {
                            CircularProgressIndicator(Modifier.size(size * 0.9f), color = tint, strokeWidth = 3.dp)
                        } else {
                            Box(Modifier.size(size * 0.3f).clip(CircleShape).background(tint))
                        }
                    }
                }
            }
        }
    }
}
