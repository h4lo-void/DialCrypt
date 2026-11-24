package io.github.h4lovoid.dialcrypt.ui.components

import android.provider.Settings
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.snap
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import io.github.h4lovoid.dialcrypt.ui.theme.Space
import kotlin.math.roundToInt

/** Length of the fade and slide when a screen appears. */
const val ScreenEnterMillis = 220

/** Length of the fade when a screen leaves. */
const val ScreenExitMillis = 160

/** Length of the glide of a progress bar or percentage to its next value. */
const val ValueGlideMillis = 300

/** False when the system animation scale is 0 (the user turned animations off). */
@Composable
fun rememberMotionEnabled(): Boolean {
    val context = LocalContext.current
    return remember(context) {
        runCatching {
            Settings.Global.getFloat(context.contentResolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f)
        }.getOrDefault(1f) > 0f
    }
}

/** Fades the screen in while it slides up a few dp. Plays once per [screenKey]; skipped without animations. */
@Composable
fun ScreenEnter(screenKey: Any?, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    key(screenKey) {
        val motion = rememberMotionEnabled()
        val progress = remember { Animatable(if (motion) 0f else 1f) }
        LaunchedEffect(Unit) {
            if (motion) progress.animateTo(1f, tween(ScreenEnterMillis, easing = FastOutSlowInEasing))
        }
        val shift = with(LocalDensity.current) { Space.md.toPx() }
        Box(
            modifier.fillMaxSize().graphicsLayer {
                alpha = progress.value
                translationY = (1f - progress.value) * shift
            },
        ) { content() }
    }
}

/** A short left-right shake each time [trigger] increases. Nothing moves without animations. */
@Composable
fun Modifier.shake(trigger: Int): Modifier {
    val motion = rememberMotionEnabled()
    val offset = remember { Animatable(0f) }
    val amplitude = with(LocalDensity.current) { 8.dp.toPx() }
    LaunchedEffect(trigger) {
        if (trigger > 0 && motion) {
            repeat(3) {
                offset.animateTo(amplitude, tween(50, easing = LinearEasing))
                offset.animateTo(-amplitude, tween(50, easing = LinearEasing))
            }
            offset.animateTo(0f, tween(50, easing = LinearEasing))
        }
    }
    return graphicsLayer { translationX = offset.value }
}

/**
 * Slow breathing between 0.4 and 1; a constant 1 without animations. The value is a [State] so the caller
 * reads it in a draw or graphicsLayer block and only that phase runs on every frame, not a recomposition.
 */
@Composable
fun rememberPulse(): State<Float> {
    if (!rememberMotionEnabled()) return remember { mutableStateOf(1f) }
    val transition = rememberInfiniteTransition(label = "pulse")
    return transition.animateFloat(
        initialValue = 0.4f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(900, easing = FastOutSlowInEasing), RepeatMode.Reverse),
        label = "pulse-alpha",
    )
}

/** A percentage that counts to each new value instead of jumping; it jumps when animations are off. */
@Composable
fun rememberAnimatedPercent(percent: Int): Int {
    val motion = rememberMotionEnabled()
    val shown by animateFloatAsState(
        percent.toFloat(),
        animationSpec = if (motion) tween(ValueGlideMillis, easing = FastOutSlowInEasing) else snap(),
        label = "percent",
    )
    return shown.roundToInt()
}
