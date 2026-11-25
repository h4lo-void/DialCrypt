package io.github.h4lovoid.dialcrypt.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.core.BiometricState
import io.github.h4lovoid.dialcrypt.core.CoreState
import io.github.h4lovoid.dialcrypt.core.PinResult
import io.github.h4lovoid.dialcrypt.core.PinRules
import io.github.h4lovoid.dialcrypt.core.SecureCore
import io.github.h4lovoid.dialcrypt.core.UnlockResult
import io.github.h4lovoid.dialcrypt.core.real.BiometricStore
import io.github.h4lovoid.dialcrypt.ui.BiometricLauncher
import io.github.h4lovoid.dialcrypt.ui.components.Card
import io.github.h4lovoid.dialcrypt.ui.components.IconTile
import io.github.h4lovoid.dialcrypt.ui.components.InlineMessage
import io.github.h4lovoid.dialcrypt.ui.components.PrimaryButton
import io.github.h4lovoid.dialcrypt.ui.components.SecondaryButton
import io.github.h4lovoid.dialcrypt.ui.components.ScreenPadding
import io.github.h4lovoid.dialcrypt.ui.components.ScreenBackHandler
import io.github.h4lovoid.dialcrypt.ui.components.StatusHero
import io.github.h4lovoid.dialcrypt.ui.components.TopBar
import io.github.h4lovoid.dialcrypt.ui.components.shake
import io.github.h4lovoid.dialcrypt.ui.keyboard.LocalInputHost
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureInputState
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureTextField
import io.github.h4lovoid.dialcrypt.ui.model.TextMaps
import io.github.h4lovoid.dialcrypt.ui.rememberHaptics
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Radius
import io.github.h4lovoid.dialcrypt.ui.theme.Space
import io.github.h4lovoid.dialcrypt.ui.theme.Tone
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.ln

enum class PinMode { SETUP, CHANGE }

private enum class PinStep { CURRENT, NEW, NEW_CONFIRM, DURESS, DURESS_CONFIRM }

/** Content that sits at the bottom of the free space, next to the keyboard, and scrolls when it does not fit. */
@Composable
private fun BottomScroll(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Box(modifier.fillMaxWidth(), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(horizontal = ScreenPadding, vertical = Space.lg),
            verticalArrangement = Arrangement.spacedBy(Space.lg),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) { content() }
    }
}

/** Thin segmented bar: one segment per step, filled up to the current one. */
@Composable
private fun StepBar(current: Int, total: Int, modifier: Modifier = Modifier) {
    Row(modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(Space.xs)) {
        for (i in 0 until total) {
            Box(
                Modifier.weight(1f).height(4.dp).clip(RoundedCornerShape(2.dp))
                    .background(if (i <= current) Palette.Accent else Palette.SurfaceHigh),
            )
        }
    }
}

/**
 * First-time setup (normal + emergency PIN) or change of both. Every step uses the in-app keyboard.
 * Entering the emergency PIN later destroys all keys and closes the app.
 */
@Composable
fun PinWizardScreen(
    mode: PinMode,
    core: SecureCore,
    onFinished: () -> Unit,
    onBack: (() -> Unit)?,
    modifier: Modifier = Modifier,
    initialStep: Int = 0,
    /** Change only: the emergency PIN was entered as the current PIN; does what the unlock screen does. */
    onDuress: () -> Unit = {},
) {
    val steps = remember(mode) {
        if (mode == PinMode.CHANGE) PinStep.values().toList() else PinStep.values().filter { it != PinStep.CURRENT }
    }
    val inputs = remember { steps.associateWith { SecureInputState(PinRules.MAX_LENGTH) } }
    // Leaving the screen (back, a lock that replaces it, the activity ending) wipes every step.
    DisposableEffect(Unit) { onDispose { inputs.values.forEach { it.clear() } } }
    var index by remember { mutableIntStateOf(initialStep.coerceIn(0, steps.lastIndex)) }
    var error by remember { mutableStateOf<Int?>(null) }
    var shakes by remember { mutableIntStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    val host = LocalInputHost.current
    val scope = rememberCoroutineScope()
    val haptics = rememberHaptics()
    val coreState by core.state.collectAsState()

    val step = steps[index]
    val input = inputs.getValue(step)
    val isLast = index == steps.lastIndex

    fun pin(s: PinStep) = inputs.getValue(s)
    val reading = input.read()
    val valid = when (step) {
        PinStep.CURRENT -> !input.isEmpty
        PinStep.NEW -> reading.violation == null
        PinStep.NEW_CONFIRM -> input.contentEquals(pin(PinStep.NEW))
        PinStep.DURESS -> reading.violation == null && !input.contentEquals(pin(PinStep.NEW))
        PinStep.DURESS_CONFIRM -> input.contentEquals(pin(PinStep.DURESS))
    }

    fun goTo(target: Int) {
        for (i in target until steps.size) inputs.getValue(steps[i]).clear()
        index = target
    }

    fun advance() {
        error = null
        if (!isLast) { index += 1; return }
        scope.launch {
            busy = true
            // Not cancellable: the duress path locks the core, which can remove this screen before the
            // result arrives, and the app must still close.
            val result = withContext(NonCancellable) {
                val cur = inputs[PinStep.CURRENT]?.toCharArray() ?: CharArray(0)
                val normal = inputs.getValue(PinStep.NEW).toCharArray()
                val duress = inputs.getValue(PinStep.DURESS).toCharArray()
                val r = if (mode == PinMode.SETUP) core.setupPins(normal, duress) else core.changePins(cur, normal, duress)
                cur.fill('\u0000'); normal.fill('\u0000'); duress.fill('\u0000')
                if (r == PinResult.DURESS) {
                    inputs.values.forEach { it.clear() }
                    onDuress()
                }
                r
            }
            if (result == PinResult.DURESS) return@launch
            busy = false
            if (result == PinResult.OK) {
                inputs.values.forEach { it.clear() }
                haptics.strong()
                onFinished()
            } else {
                error = TextMaps.pinResult(result)
                shakes += 1
                haptics.strong()
                val target = when (result) {
                    PinResult.TOO_SHORT, PinResult.TOO_SIMPLE -> steps.indexOf(PinStep.NEW)
                    PinResult.SAME_PINS -> steps.indexOf(PinStep.DURESS)
                    PinResult.WRONG_CURRENT -> steps.indexOf(PinStep.CURRENT)
                    else -> index
                }
                goTo(target.coerceAtLeast(0))
            }
        }
    }

    // System back does what the arrow does: one step back. On the first step it passes on (a closed keyboard first).
    ScreenBackHandler(enabled = index > 0) { goTo(index - 1); error = null }

    LaunchedEffect(index) {
        host.focus(inputs.getValue(steps[index]))
        host.onDone = null
    }
    LaunchedEffect(input.length) { if (input.length > 0) error = null }
    LaunchedEffect(valid, busy, index) {
        host.onDone = { if (valid && !busy) advance() }
    }

    val title = stringResource(
        when (step) {
            PinStep.CURRENT -> R.string.pin_current_title
            PinStep.NEW -> R.string.pin_new_title
            PinStep.NEW_CONFIRM -> R.string.pin_confirm_title
            PinStep.DURESS -> R.string.pin_duress_title
            PinStep.DURESS_CONFIRM -> R.string.pin_duress_confirm_title
        },
    )
    val body = when (step) {
        PinStep.CURRENT -> R.string.pin_current_body
        PinStep.NEW -> R.string.pin_new_body
        PinStep.NEW_CONFIRM, PinStep.DURESS_CONFIRM -> R.string.pin_confirm_body
        PinStep.DURESS -> R.string.pin_duress_body
    }
    val emergency = step == PinStep.DURESS || step == PinStep.DURESS_CONFIRM

    Column(modifier.fillMaxSize()) {
        TopBar(
            title = stringResource(R.string.pin_step_of, index + 1, steps.size),
            onBack = when {
                index > 0 -> ({ goTo(index - 1); error = null })
                else -> onBack
            },
        )
        StepBar(index, steps.size, Modifier.padding(horizontal = ScreenPadding))
        BottomScroll(Modifier.weight(1f)) {
            Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(Space.sm)) {
                IconTile(
                    if (emergency) Icons.Filled.Warning else Icons.Filled.Password,
                    tint = if (emergency) Palette.Warn else Palette.Accent,
                    background = if (emergency) Palette.Warn.copy(alpha = 0.10f) else Palette.AccentContainer,
                    size = 48.dp,
                )
                Text(title, style = MaterialTheme.typography.headlineSmall)
                Text(stringResource(body), style = MaterialTheme.typography.bodyLarge, color = Palette.OnSurfaceMuted)
            }
            if (step == PinStep.DURESS) {
                Card(borderColor = Palette.Warn) {
                    InlineMessage(stringResource(R.string.pin_duress_warning), Tone.WARN)
                }
            }
            if (step == PinStep.NEW && !coreState.singleUseHardwareEnforced) {
                Card(borderColor = Palette.Warn) {
                    InlineMessage(stringResource(R.string.pin_tries_software_note), Tone.WARN)
                }
            }
            Card {
                SecureTextField(input, masked = true, isError = error != null, tag = "pin_input", modifier = Modifier.shake(shakes))
                when (step) {
                    PinStep.NEW, PinStep.DURESS -> StrengthMeter(reading)
                    PinStep.NEW_CONFIRM, PinStep.DURESS_CONFIRM -> {
                        val reference = if (step == PinStep.NEW_CONFIRM) pin(PinStep.NEW) else pin(PinStep.DURESS)
                        if (input.length >= reference.length && !input.contentEquals(reference)) {
                            InlineMessage(stringResource(R.string.pin_error_mismatch), Tone.DANGER)
                        }
                    }
                    PinStep.CURRENT -> Unit
                }
                if (step == PinStep.DURESS && !input.isEmpty && input.contentEquals(pin(PinStep.NEW))) {
                    InlineMessage(stringResource(R.string.pin_error_same), Tone.DANGER)
                }
                error?.let { InlineMessage(stringResource(it), Tone.DANGER) }
                PrimaryButton(
                    stringResource(if (isLast) R.string.pin_save else R.string.action_continue),
                    onClick = { advance() },
                    enabled = valid && !busy,
                    modifier = Modifier.padding(top = Space.sm),
                )
            }
        }
    }
}

/** What the setup screen needs to know about a PIN, computed on a temporary char copy so no String of it exists. */
private class PinReading(
    val length: Int,
    val codePoints: Int,
    val violation: PinRules.Violation?,
    val strength: PinRules.Strength,
)

/** Same rules as [PinRules.violation] and [PinRules.strength], applied to a zeroed-after-use char copy. */
private fun SecureInputState.read(): PinReading = withChars { c ->
    val length = c.size
    val codePoints = Character.codePointCount(c, 0, c.size)
    var lower = false
    var upper = false
    var digit = false
    var symbol = false
    var wide = false
    for (ch in c) {
        when {
            ch in 'a'..'z' -> lower = true
            ch in 'A'..'Z' -> upper = true
            ch in '0'..'9' -> digit = true
            ch.code >= 128 -> wide = true
            !ch.isLetterOrDigit() -> symbol = true
        }
    }
    c.sort()
    var distinct = 0
    for (i in c.indices) if (i == 0 || c[i] != c[i - 1]) distinct++
    val violation = when {
        codePoints < PinRules.MIN_LENGTH -> PinRules.Violation.TOO_SHORT
        codePoints > PinRules.MAX_LENGTH -> PinRules.Violation.TOO_LONG
        distinct <= 3 -> PinRules.Violation.TOO_SIMPLE
        else -> null
    }
    val strength = if (length == 0) {
        PinRules.Strength.WEAK
    } else {
        var pool = 0
        if (lower) pool += 26
        if (upper) pool += 26
        if (digit) pool += 10
        if (symbol) pool += 33
        if (wide) pool += 64
        val effective = minOf(codePoints, distinct * 2)
        val bits = effective * ln(pool.toDouble()) / ln(2.0)
        when {
            distinct <= 3 || bits < 45 -> PinRules.Strength.WEAK
            bits < 60 -> PinRules.Strength.FAIR
            bits < 80 -> PinRules.Strength.GOOD
            else -> PinRules.Strength.STRONG
        }
    }
    PinReading(length, codePoints, violation, strength)
}

@Composable
private fun StrengthMeter(pin: PinReading) {
    val violation = pin.violation
    val strength = pin.strength
    val filled = if (pin.length == 0) 0 else when (strength) {
        PinRules.Strength.WEAK -> 1
        PinRules.Strength.FAIR -> 2
        PinRules.Strength.GOOD -> 3
        PinRules.Strength.STRONG -> 4
    }
    val color = when (strength) {
        PinRules.Strength.WEAK -> Palette.Danger
        PinRules.Strength.FAIR -> Palette.Warn
        else -> Palette.Ok
    }
    Column(verticalArrangement = Arrangement.spacedBy(Space.sm)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            for (i in 1..4) {
                Box(
                    Modifier.weight(1f).height(6.dp).clip(RoundedCornerShape(3.dp))
                        .background(if (i <= filled) color else Palette.SurfaceHigh),
                )
            }
        }
        val length = pin.codePoints
        Text(
            when {
                pin.length == 0 -> stringResource(R.string.pin_length_hint, 0, PinRules.MIN_LENGTH)
                violation == PinRules.Violation.TOO_SHORT -> stringResource(R.string.pin_length_hint, length, PinRules.MIN_LENGTH)
                violation == PinRules.Violation.TOO_SIMPLE -> stringResource(R.string.pin_error_simple)
                violation == PinRules.Violation.TOO_LONG -> stringResource(R.string.pin_error_long, PinRules.MAX_LENGTH)
                else -> stringResource(R.string.pin_strength_label, stringResource(TextMaps.strength(strength)))
            },
            style = MaterialTheme.typography.bodyMedium,
            color = if (violation != null && pin.length != 0) Palette.Warn else Palette.OnSurfaceMuted,
        )
    }
}

/**
 * Neutral title on purpose: nothing here names the product. While a secure call rings
 * ([handoffActive]) and fingerprint answer is ready, the system fingerprint dialog opens once over
 * the PIN pad; the PIN always stays usable.
 */
@Composable
fun UnlockScreen(
    core: SecureCore,
    state: CoreState,
    onDuress: () -> Unit,
    modifier: Modifier = Modifier,
    handoffActive: Boolean = false,
) {
    val input = remember { SecureInputState(PinRules.MAX_LENGTH) }
    var error by remember { mutableStateOf<Int?>(null) }
    var shakes by remember { mutableIntStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    val host = LocalInputHost.current
    val scope = rememberCoroutineScope()
    val haptics = rememberHaptics()
    val context = LocalContext.current
    val bio by core.biometric.collectAsState()
    var bioOpen by remember { mutableStateOf(false) }
    var bioRetry by remember { mutableStateOf(false) }
    var bioAutoTried by remember { mutableStateOf(false) }
    var bioCancel by remember { mutableStateOf<android.os.CancellationSignal?>(null) }
    val bioTitle = stringResource(R.string.bio_prompt_answer_title)
    val bioUsePin = stringResource(R.string.bio_prompt_use_pin)

    fun submit() {
        if (busy || input.isEmpty) return
        scope.launch {
            busy = true
            val pin = input.toCharArray()
            val result = core.unlock(pin)
            pin.fill('\u0000')
            input.clear()
            busy = false
            when (result) {
                UnlockResult.SUCCESS -> haptics.tick()
                UnlockResult.DURESS -> onDuress()
                UnlockResult.WRONG -> { error = R.string.unlock_wrong; shakes += 1; haptics.strong() }
                UnlockResult.DEAD -> Unit
                UnlockResult.UNAVAILABLE -> { error = R.string.unlock_unavailable; shakes += 1 }
            }
        }
    }

    fun onBioResult(result: UnlockResult) {
        when (result) {
            UnlockResult.SUCCESS -> haptics.tick()
            UnlockResult.DURESS -> onDuress()
            UnlockResult.WRONG -> { error = R.string.unlock_wrong; shakes += 1; haptics.strong() }
            UnlockResult.DEAD, UnlockResult.UNAVAILABLE -> host.focus(input)
        }
    }

    // Fingerprint answer: any failure only closes the dialog and leaves the PIN pad focused.
    fun startBio() {
        if (busy || bioOpen) return
        bioRetry = false
        scope.launch {
            val cipher = core.biometricUnlockCipher() ?: return@launch
            val signal = android.os.CancellationSignal()
            bioCancel = signal
            bioOpen = true
            val shown = BiometricLauncher.authenticate(
                context, bioTitle, bioUsePin, cipher, signal,
                onSuccess = { authed ->
                    bioOpen = false
                    scope.launch {
                        busy = true
                        val result = core.unlockWithBiometric(authed)
                        busy = false
                        onBioResult(result)
                    }
                },
                onError = { code ->
                    bioOpen = false
                    bioRetry = BiometricStore.retryAllowed(code)
                    host.focus(input)
                },
            )
            if (!shown) {
                bioOpen = false
                bioRetry = false
            }
        }
    }

    LaunchedEffect(Unit) { host.focus(input) }
    LaunchedEffect(busy) { host.onDone = { submit() } }
    LaunchedEffect(handoffActive, bio) {
        if (handoffActive && bio == BiometricState.READY && !bioAutoTried) {
            bioAutoTried = true
            startBio()
        }
        // The call stopped ringing: take the dialog down.
        if (!handoffActive) bioCancel?.cancel()
    }
    DisposableEffect(Unit) {
        onDispose {
            bioCancel?.cancel()
            // A PIN typed but not submitted does not outlive the screen.
            input.clear()
        }
    }

    Box(modifier.fillMaxSize(), contentAlignment = Alignment.BottomCenter) {
        Column(
            Modifier.verticalScroll(rememberScrollState()).padding(horizontal = ScreenPadding, vertical = Space.lg),
            verticalArrangement = Arrangement.spacedBy(Space.lg),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(Space.sm), horizontalAlignment = Alignment.CenterHorizontally) {
                Text(stringResource(R.string.unlock_title), style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
                Text(
                    stringResource(R.string.unlock_caption),
                    style = MaterialTheme.typography.bodyLarge, color = Palette.OnSurfaceMuted, textAlign = TextAlign.Center,
                )
            }
            if (handoffActive) {
                InlineMessage(stringResource(R.string.unlock_incoming_waiting), Tone.OK)
                if (bio == BiometricState.NEEDS_PIN) InlineMessage(stringResource(R.string.unlock_bio_needs_pin), Tone.WARN)
            }
            if (state.bioEnrollPending) {
                InlineMessage(stringResource(R.string.unlock_bio_enroll), Tone.NEUTRAL)
            }
            Card {
                SecureTextField(
                    input, masked = true, isError = error != null,
                    placeholder = stringResource(R.string.unlock_hint), tag = "unlock_input",
                    modifier = Modifier.shake(shakes),
                )
                error?.let {
                    val text = if (it == R.string.unlock_wrong) stringResource(it, state.attemptsLeft) else stringResource(it)
                    InlineMessage(text, Tone.DANGER)
                }
                PrimaryButton(
                    stringResource(R.string.unlock_action), onClick = { submit() },
                    enabled = !busy && !input.isEmpty,
                    modifier = Modifier.padding(top = Space.sm),
                )
                if (handoffActive && bio == BiometricState.READY && bioRetry && !bioOpen) {
                    SecondaryButton(
                        stringResource(R.string.unlock_bio_retry), onClick = { startBio() },
                        enabled = !busy, icon = Icons.Filled.Fingerprint,
                    )
                }
            }
        }
    }
}

/** All attempts used: the phone can never be unlocked again. The back key does nothing here. */
@Composable
fun VaultDestroyedScreen(onClose: () -> Unit, modifier: Modifier = Modifier) {
    BackHandler {}
    Column(modifier.fillMaxSize()) {
        TopBar(stringResource(R.string.destroyed_title), onBack = null)
        Column(
            Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = ScreenPadding, vertical = Space.lg),
            verticalArrangement = Arrangement.spacedBy(Space.xl, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            StatusHero(Icons.Filled.Block, Palette.Danger)
            Card(borderColor = Palette.Danger, container = Palette.DangerContainer) {
                Text(stringResource(R.string.destroyed_body), style = MaterialTheme.typography.bodyLarge)
            }
        }
        Column(Modifier.padding(horizontal = ScreenPadding, vertical = Space.md)) {
            PrimaryButton(stringResource(R.string.action_close), onClose)
        }
    }
}
