package io.github.h4lovoid.dialcrypt.dialer.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.VolumeUp
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CallEnd
import androidx.compose.material.icons.filled.CallMerge
import androidx.compose.material.icons.filled.Dialpad
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.MicOff
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.SimCard
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.dialer.model.AudioUi
import io.github.h4lovoid.dialcrypt.dialer.model.Endpoint
import io.github.h4lovoid.dialcrypt.dialer.model.InCallUiState
import io.github.h4lovoid.dialcrypt.dialer.model.NumberText
import io.github.h4lovoid.dialcrypt.dialer.model.UiCall
import io.github.h4lovoid.dialcrypt.dialer.model.UiCallState
import io.github.h4lovoid.dialcrypt.dialer.model.WaitingCallPlan
import io.github.h4lovoid.dialcrypt.ui.components.Badge
import io.github.h4lovoid.dialcrypt.ui.components.Card
import io.github.h4lovoid.dialcrypt.ui.components.MinTouch
import io.github.h4lovoid.dialcrypt.ui.components.PrimaryButton
import io.github.h4lovoid.dialcrypt.ui.components.QuietButton
import io.github.h4lovoid.dialcrypt.ui.components.ScreenPadding
import io.github.h4lovoid.dialcrypt.ui.components.SecondaryButton
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Radius
import io.github.h4lovoid.dialcrypt.ui.theme.Space
import io.github.h4lovoid.dialcrypt.ui.theme.Tone
import java.util.Locale

/** What the in-call screen can ask for. The activity wires each one to the call commands. */
class InCallActions(
    val answer: (Int) -> Unit = {},
    val answerSecure: () -> Unit = {},
    val endAndAnswer: (Int) -> Unit = {},
    val decline: (Int) -> Unit = {},
    val end: (Int) -> Unit = {},
    val hold: (Int, Boolean) -> Unit = { _, _ -> },
    val swap: () -> Unit = {},
    val merge: () -> Unit = {},
    val setMuted: (Boolean) -> Unit = {},
    val route: (Endpoint) -> Unit = {},
    val dtmf: (Int, Char?) -> Unit = { _, _ -> },
    val selectAccount: (Int, Int) -> Unit = { _, _ -> },
    val postDial: (Int, Boolean) -> Unit = { _, _ -> },
)

/** Test tags of the in-call screen. */
object InCallTags {
    const val ANSWER = "incall_answer"
    const val ANSWER_SECURE = "incall_answer_secure"
    const val ANSWER_PLAIN = "incall_answer_plain"
    const val DECLINE = "incall_decline"
    const val HOLD_AND_ANSWER = "incall_hold_and_answer"
    const val END_AND_ANSWER = "incall_end_and_answer"
    const val END = "incall_end"
    const val MUTE = "incall_mute"
    const val AUDIO = "incall_audio"
    const val KEYPAD = "incall_keypad"
    const val HOLD = "incall_hold"
    const val RESUME = "incall_resume"
    const val SWAP = "incall_swap"
    const val MERGE = "incall_merge"
    const val CONFERENCE_SIZE = "incall_conference_size"
    const val POST_DIAL_SEND = "incall_post_dial_send"
    const val POST_DIAL_CANCEL = "incall_post_dial_cancel"
    const val CHECKING = "incall_checking"
    const val EMERGENCY = "incall_emergency"
    const val NUMBER = "incall_number"
    const val OTHER_CALL = "incall_other_call"

    fun sim(index: Int): String = "incall_sim_$index"

    fun route(e: Endpoint): String = "incall_route_" + e.name.lowercase(Locale.ROOT)

    fun dtmf(c: Char): String = "incall_dtmf_$c"
}

internal object InCallFormat {
    /** Connected time as m:ss or h:mm:ss; null before the call connects. Both times are wall clock. */
    fun elapsed(connectMs: Long?, nowMs: Long): String? {
        if (connectMs == null) return null
        val total = ((nowMs - connectMs) / 1000L).coerceAtLeast(0L)
        val h = total / 3600L
        val m = (total % 3600L) / 60L
        val s = total % 60L
        return if (h > 0L) String.format(Locale.ROOT, "%d:%02d:%02d", h, m, s) else String.format(Locale.ROOT, "%d:%02d", m, s)
    }
}

/**
 * The default dialer's call screen. It only draws [state] (numbers are already masked by the
 * reducer) and forwards taps to [actions]; it has no text input. [nowMs] is wall clock time for
 * the connected timer. [handoffBusy]: a secure answer is being handed over.
 */
@Composable
fun InCallScreen(
    state: InCallUiState,
    actions: InCallActions,
    nowMs: Long,
    modifier: Modifier = Modifier,
    handoffBusy: Boolean = false,
) {
    Column(
        modifier.fillMaxSize().background(Palette.Background).padding(horizontal = ScreenPadding, vertical = Space.xl),
        verticalArrangement = Arrangement.spacedBy(Space.lg),
    ) {
        val primary = state.primary
        if (primary == null) {
            Header(stringResource(R.string.incall_ended), null)
        } else {
            when (primary.state) {
                UiCallState.RINGING -> Ringing(primary, state, actions, handoffBusy)
                UiCallState.WAITING -> Waiting(primary, state, actions, nowMs)
                UiCallState.SELECT_ACCOUNT -> SelectAccount(primary, actions)
                UiCallState.ENDED -> Header(stringResource(R.string.incall_ended), primary)
                UiCallState.DIALING, UiCallState.ACTIVE, UiCallState.HOLDING, UiCallState.DISCONNECTING ->
                    Ongoing(primary, state, actions, nowMs)
            }
        }
    }
}

@Composable
private fun ColumnScope.Ringing(call: UiCall, state: InCallUiState, actions: InCallActions, handoffBusy: Boolean) {
    Header(stringResource(R.string.incall_incoming), call, checking = !call.answerEnabled)
    Spacer(Modifier.weight(1f))
    Card {
        Column(verticalArrangement = Arrangement.spacedBy(Space.md)) {
            if (state.secureOffer) {
                PrimaryButton(
                    text = stringResource(R.string.incoming_answer_secure),
                    onClick = actions.answerSecure,
                    modifier = Modifier.testTag(InCallTags.ANSWER_SECURE),
                    enabled = !handoffBusy,
                    icon = Icons.Filled.Lock,
                )
                SecondaryButton(
                    text = stringResource(R.string.incoming_answer_plain),
                    onClick = { actions.answer(call.id) },
                    modifier = Modifier.testTag(InCallTags.ANSWER_PLAIN),
                    enabled = call.answerEnabled && !handoffBusy,
                    icon = Icons.Filled.Phone,
                )
            } else {
                PrimaryButton(
                    text = stringResource(R.string.incall_answer),
                    onClick = { actions.answer(call.id) },
                    modifier = Modifier.testTag(InCallTags.ANSWER),
                    enabled = call.answerEnabled && !handoffBusy,
                    icon = Icons.Filled.Call,
                )
            }
            SecondaryButton(
                text = stringResource(R.string.incall_decline),
                onClick = { actions.decline(call.id) },
                modifier = Modifier.testTag(InCallTags.DECLINE),
                enabled = !handoffBusy,
                danger = true,
                icon = Icons.Filled.CallEnd,
            )
        }
    }
}

@Composable
private fun ColumnScope.Waiting(call: UiCall, state: InCallUiState, actions: InCallActions, nowMs: Long) {
    Header(stringResource(R.string.incall_waiting), call, checking = !call.answerEnabled)
    state.secondary?.let { OtherCall(it, nowMs, onSwap = null) }
    Spacer(Modifier.weight(1f))
    val choices = WaitingCallPlan.choices(state.secondary?.state, state.secureOwned)
    Card {
        Column(verticalArrangement = Arrangement.spacedBy(Space.md)) {
            if (WaitingCallPlan.Choice.HOLD_AND_ANSWER in choices) {
                // Telecom holds the current call itself when the waiting one is answered.
                PrimaryButton(
                    text = stringResource(R.string.incall_hold_and_answer),
                    onClick = { actions.answer(call.id) },
                    modifier = Modifier.testTag(InCallTags.HOLD_AND_ANSWER),
                    enabled = call.answerEnabled,
                    icon = Icons.Filled.Call,
                )
            }
            if (WaitingCallPlan.Choice.END_AND_ANSWER in choices) {
                SecondaryButton(
                    text = stringResource(R.string.incall_end_and_answer),
                    onClick = { actions.endAndAnswer(call.id) },
                    modifier = Modifier.testTag(InCallTags.END_AND_ANSWER),
                    enabled = call.answerEnabled,
                    icon = Icons.Filled.Call,
                )
            }
            SecondaryButton(
                text = stringResource(R.string.incall_decline),
                onClick = { actions.decline(call.id) },
                modifier = Modifier.testTag(InCallTags.DECLINE),
                danger = true,
                icon = Icons.Filled.CallEnd,
            )
        }
    }
}

@Composable
private fun ColumnScope.SelectAccount(call: UiCall, actions: InCallActions) {
    Header(stringResource(R.string.incall_dialing), call)
    Spacer(Modifier.weight(1f))
    Card {
        Text(stringResource(R.string.incall_select_sim), style = MaterialTheme.typography.titleMedium)
        Column(verticalArrangement = Arrangement.spacedBy(Space.sm)) {
            call.accounts.forEachIndexed { index, label ->
                SecondaryButton(
                    text = label,
                    onClick = { actions.selectAccount(call.id, index) },
                    modifier = Modifier.testTag(InCallTags.sim(index)),
                    icon = Icons.Filled.SimCard,
                )
            }
        }
    }
    EndButton(call, actions)
}

@Composable
private fun ColumnScope.Ongoing(call: UiCall, state: InCallUiState, actions: InCallActions, nowMs: Long) {
    var keypadOpen by rememberSaveable(call.id) { mutableStateOf(false) }
    var routesOpen by remember(call.id) { mutableStateOf(false) }
    val label = when (call.state) {
        UiCallState.DIALING -> stringResource(R.string.incall_dialing)
        UiCallState.HOLDING -> stringResource(R.string.incall_on_hold)
        UiCallState.DISCONNECTING -> stringResource(R.string.incall_ended)
        else -> InCallFormat.elapsed(call.connectMs, nowMs) ?: stringResource(R.string.dialer_notif_ongoing)
    }
    Header(label, call)
    val other = state.secondary
    if (other != null) {
        val canSwap = !state.secureOwned && call.state == UiCallState.ACTIVE && other.state == UiCallState.HOLDING
        OtherCall(other, nowMs, onSwap = if (canSwap) actions.swap else null)
    }
    if (state.canMerge && !state.secureOwned) {
        SecondaryButton(
            text = stringResource(R.string.incall_merge),
            onClick = actions.merge,
            modifier = Modifier.testTag(InCallTags.MERGE),
            icon = Icons.Filled.CallMerge,
        )
    }
    val postDial = call.postDial
    if (postDial != null && !state.secureOwned) PostDial(call.id, postDial, actions)
    Spacer(Modifier.weight(1f))
    val controls = !state.secureOwned && call.state != UiCallState.DISCONNECTING
    if (controls && keypadOpen && call.state == UiCallState.ACTIVE) {
        DtmfPad(onDown = { actions.dtmf(call.id, it) }, onUp = { actions.dtmf(call.id, null) })
    } else if (controls && routesOpen) {
        Routes(state.audio) { e ->
            actions.route(e)
            routesOpen = false
        }
    }
    if (controls) {
        Controls(
            call = call,
            audio = state.audio,
            keypadOpen = keypadOpen,
            routesOpen = routesOpen,
            actions = actions,
            onKeypad = {
                keypadOpen = !keypadOpen
                routesOpen = false
            },
            onRoutes = {
                routesOpen = !routesOpen
                keypadOpen = false
            },
        )
    }
    EndButton(call, actions)
}

@Composable
private fun EndButton(call: UiCall, actions: InCallActions) {
    SecondaryButton(
        text = stringResource(R.string.incall_end),
        onClick = { actions.end(call.id) },
        modifier = Modifier.testTag(InCallTags.END),
        enabled = call.state != UiCallState.DISCONNECTING,
        danger = true,
        icon = Icons.Filled.CallEnd,
    )
}

/** Status line, caller line and, for an emergency call, a marker above them. */
@Composable
private fun Header(label: String, call: UiCall?, checking: Boolean = false) {
    Column(
        Modifier.fillMaxWidth().padding(top = Space.xl),
        verticalArrangement = Arrangement.spacedBy(Space.sm),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        if (call?.emergency == true) {
            Badge(stringResource(R.string.incall_emergency), Tone.DANGER, Modifier.testTag(InCallTags.EMERGENCY))
        }
        Text(label, style = MaterialTheme.typography.titleMedium, color = Palette.OnSurfaceMuted, textAlign = TextAlign.Center)
        if (call != null) {
            Text(
                numberText(call.number),
                modifier = Modifier.testTag(InCallTags.NUMBER),
                style = MaterialTheme.typography.headlineMedium,
                textAlign = TextAlign.Center,
            )
            val conference = call.number as? NumberText.Conference
            if (conference != null && conference.participants > 0) {
                Text(
                    pluralStringResource(R.plurals.incall_conference_people, conference.participants, conference.participants),
                    modifier = Modifier.testTag(InCallTags.CONFERENCE_SIZE),
                    style = MaterialTheme.typography.bodyLarge,
                    color = Palette.OnSurfaceMuted,
                    textAlign = TextAlign.Center,
                )
            }
        }
        if (checking) {
            Text(
                stringResource(R.string.incall_checking),
                modifier = Modifier.testTag(InCallTags.CHECKING),
                style = MaterialTheme.typography.bodyMedium,
                color = Palette.OnSurfaceMuted,
                textAlign = TextAlign.Center,
            )
        }
    }
}

@Composable
internal fun numberText(n: NumberText): String = when (n) {
    is NumberText.Digits -> n.text
    NumberText.Hidden -> stringResource(R.string.incall_number_hidden)
    NumberText.Unknown -> stringResource(R.string.incall_number_unknown)
    NumberText.Payphone -> stringResource(R.string.incall_payphone)
    is NumberText.Conference -> stringResource(R.string.incall_conference)
}

/** The second call: its caller line, its state and, when it is on hold, the swap action. */
@Composable
private fun OtherCall(call: UiCall, nowMs: Long, onSwap: (() -> Unit)?) {
    val status = when (call.state) {
        UiCallState.HOLDING -> stringResource(R.string.incall_on_hold)
        UiCallState.ACTIVE -> InCallFormat.elapsed(call.connectMs, nowMs) ?: stringResource(R.string.dialer_notif_ongoing)
        UiCallState.DIALING, UiCallState.SELECT_ACCOUNT -> stringResource(R.string.incall_dialing)
        UiCallState.RINGING, UiCallState.WAITING -> stringResource(R.string.incall_waiting)
        UiCallState.DISCONNECTING, UiCallState.ENDED -> stringResource(R.string.incall_ended)
    }
    Card(Modifier.testTag(InCallTags.OTHER_CALL)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.md)) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(numberText(call.number), style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(status, style = MaterialTheme.typography.bodySmall, color = Palette.OnSurfaceMuted)
            }
            if (onSwap != null) {
                QuietButton(stringResource(R.string.incall_swap), onSwap, Modifier.testTag(InCallTags.SWAP))
            }
        }
    }
}

@Composable
private fun PostDial(id: Int, digits: String, actions: InCallActions) {
    Card {
        Text(stringResource(R.string.incall_post_dial, digits), style = MaterialTheme.typography.bodyLarge)
        Row(horizontalArrangement = Arrangement.spacedBy(Space.md)) {
            SecondaryButton(
                text = stringResource(R.string.action_cancel),
                onClick = { actions.postDial(id, false) },
                modifier = Modifier.weight(1f).testTag(InCallTags.POST_DIAL_CANCEL),
            )
            PrimaryButton(
                text = stringResource(R.string.incall_send),
                onClick = { actions.postDial(id, true) },
                modifier = Modifier.weight(1f).testTag(InCallTags.POST_DIAL_SEND),
            )
        }
    }
}

@Composable
private fun Controls(
    call: UiCall,
    audio: AudioUi,
    keypadOpen: Boolean,
    routesOpen: Boolean,
    actions: InCallActions,
    onKeypad: () -> Unit,
    onRoutes: () -> Unit,
) {
    val connectedOrDialing = call.state == UiCallState.ACTIVE || call.state == UiCallState.DIALING
    val routes = audio.available.filter { it != Endpoint.OTHER }
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(Space.sm)) {
        if (connectedOrDialing) {
            Control(
                icon = if (audio.muted) Icons.Filled.MicOff else Icons.Filled.Mic,
                label = stringResource(R.string.incall_mute),
                selected = audio.muted,
                tag = InCallTags.MUTE,
                modifier = Modifier.weight(1f),
            ) { actions.setMuted(!audio.muted) }
        }
        if (connectedOrDialing && routes.size > 1) {
            Control(
                icon = Icons.AutoMirrored.Filled.VolumeUp,
                label = routeLabel(audio.endpoint) ?: stringResource(R.string.incall_audio),
                selected = routesOpen,
                tag = InCallTags.AUDIO,
                modifier = Modifier.weight(1f),
                onClick = onRoutes,
            )
        }
        if (call.state == UiCallState.ACTIVE) {
            Control(
                icon = Icons.Filled.Dialpad,
                label = stringResource(R.string.incall_keypad),
                selected = keypadOpen,
                tag = InCallTags.KEYPAD,
                modifier = Modifier.weight(1f),
                onClick = onKeypad,
            )
        }
        if (call.state == UiCallState.HOLDING) {
            Control(
                icon = Icons.Filled.PlayArrow,
                label = stringResource(R.string.incall_resume),
                selected = false,
                tag = InCallTags.RESUME,
                modifier = Modifier.weight(1f),
            ) { actions.hold(call.id, false) }
        } else if (call.state == UiCallState.ACTIVE && call.canHold) {
            Control(
                icon = Icons.Filled.Pause,
                label = stringResource(R.string.incall_hold),
                selected = false,
                tag = InCallTags.HOLD,
                modifier = Modifier.weight(1f),
            ) { actions.hold(call.id, true) }
        }
    }
}

@Composable
private fun routeLabel(e: Endpoint): String? = when (e) {
    Endpoint.EARPIECE -> stringResource(R.string.incall_route_earpiece)
    Endpoint.SPEAKER -> stringResource(R.string.incall_route_speaker)
    Endpoint.BLUETOOTH -> stringResource(R.string.incall_route_bluetooth)
    Endpoint.WIRED -> stringResource(R.string.incall_route_wired)
    Endpoint.OTHER -> null
}

/** Round icon with a label under it; a selected control has the champagne fill. */
@Composable
private fun Control(
    icon: ImageVector,
    label: String,
    selected: Boolean,
    tag: String,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    Column(
        modifier
            .testTag(tag)
            .semantics(mergeDescendants = true) { this.selected = selected }
            .clickable(role = Role.Button, onClick = onClick)
            .padding(vertical = Space.xs),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(Space.xs),
    ) {
        Box(
            Modifier.size(56.dp).clip(CircleShape).background(if (selected) Palette.Accent else Palette.SurfaceHigh),
            contentAlignment = Alignment.Center,
        ) {
            Icon(icon, contentDescription = null, tint = if (selected) Palette.Background else Palette.OnSurface)
        }
        Text(
            label,
            style = MaterialTheme.typography.labelMedium,
            color = Palette.OnSurfaceMuted,
            textAlign = TextAlign.Center,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun Routes(audio: AudioUi, onPick: (Endpoint) -> Unit) {
    Card {
        Text(stringResource(R.string.incall_audio), style = MaterialTheme.typography.titleMedium)
        audio.available.forEach { e ->
            val label = routeLabel(e) ?: return@forEach
            val selected = audio.endpoint == e
            Row(
                Modifier.fillMaxWidth().heightIn(min = MinTouch).testTag(InCallTags.route(e))
                    .selectable(selected = selected, role = Role.RadioButton) { onPick(e) },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                RadioButton(
                    selected = selected,
                    onClick = null,
                    colors = RadioButtonDefaults.colors(selectedColor = Palette.Accent, unselectedColor = Palette.Outline),
                )
                Text(label, modifier = Modifier.padding(start = Space.md), style = MaterialTheme.typography.bodyLarge)
            }
        }
    }
}

/** Tone keys: a tone plays while a key is held. The digits sent so far are shown above the keys. */
@Composable
private fun DtmfPad(onDown: (Char) -> Unit, onUp: () -> Unit) {
    var sent by rememberSaveable { mutableStateOf("") }
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(Space.sm)) {
        Text(
            sent,
            modifier = Modifier.fillMaxWidth().heightIn(min = 32.dp),
            style = MaterialTheme.typography.headlineSmall,
            textAlign = TextAlign.Center,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        listOf("123", "456", "789", "*0#").forEach { row ->
            Row(horizontalArrangement = Arrangement.spacedBy(Space.sm)) {
                row.forEach { c ->
                    ToneKey(
                        c = c,
                        modifier = Modifier.weight(1f),
                        onDown = {
                            sent = (sent + c).takeLast(MAX_SHOWN_TONES)
                            onDown(c)
                        },
                        onUp = onUp,
                    )
                }
            }
        }
    }
}

private const val MAX_SHOWN_TONES = 24

@Composable
private fun ToneKey(c: Char, modifier: Modifier, onDown: () -> Unit, onUp: () -> Unit) {
    val down by rememberUpdatedState(onDown)
    val up by rememberUpdatedState(onUp)
    Box(
        modifier
            .height(52.dp)
            .clip(RoundedCornerShape(Radius.md))
            .background(Palette.Key)
            .testTag(InCallTags.dtmf(c))
            .semantics {
                role = Role.Button
                onClick {
                    down()
                    up()
                    true
                }
            }
            .pointerInput(Unit) {
                detectTapGestures(
                    onPress = {
                        down()
                        try {
                            tryAwaitRelease()
                        } finally {
                            up()
                        }
                    },
                )
            },
        contentAlignment = Alignment.Center,
    ) {
        Text(c.toString(), style = MaterialTheme.typography.headlineSmall, color = Palette.OnSurface)
    }
}

