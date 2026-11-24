package io.github.h4lovoid.dialcrypt.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.CallEnd
import androidx.compose.material.icons.automirrored.filled.Chat
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.DoneAll
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.MicOff
import androidx.compose.material.icons.filled.RecordVoiceOver
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.withFrameNanos
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.core.ChatMessage
import io.github.h4lovoid.dialcrypt.core.ConnectStep
import io.github.h4lovoid.dialcrypt.core.IdentityStatus
import io.github.h4lovoid.dialcrypt.core.MessageBody
import io.github.h4lovoid.dialcrypt.core.MessageStatus
import io.github.h4lovoid.dialcrypt.core.PeerInfo
import io.github.h4lovoid.dialcrypt.core.PhoneRules
import io.github.h4lovoid.dialcrypt.core.QuickCommand
import io.github.h4lovoid.dialcrypt.core.QuickConnect
import io.github.h4lovoid.dialcrypt.core.SecureCore
import io.github.h4lovoid.dialcrypt.core.SendResult
import io.github.h4lovoid.dialcrypt.core.SessionFailure
import io.github.h4lovoid.dialcrypt.core.SessionLimits
import io.github.h4lovoid.dialcrypt.core.SessionPhase
import io.github.h4lovoid.dialcrypt.core.SessionState
import io.github.h4lovoid.dialcrypt.ui.components.Card
import io.github.h4lovoid.dialcrypt.ui.components.DisabledContentAlpha
import io.github.h4lovoid.dialcrypt.ui.components.FingerprintGrid
import io.github.h4lovoid.dialcrypt.ui.components.HangUpDialog
import io.github.h4lovoid.dialcrypt.ui.components.HoldToConfirmButton
import io.github.h4lovoid.dialcrypt.ui.components.IconTile
import io.github.h4lovoid.dialcrypt.ui.components.InlineMessage
import io.github.h4lovoid.dialcrypt.ui.components.PrimaryButton
import io.github.h4lovoid.dialcrypt.ui.components.ProgressBar
import io.github.h4lovoid.dialcrypt.ui.components.QuietButton
import io.github.h4lovoid.dialcrypt.ui.components.ScreenPadding
import io.github.h4lovoid.dialcrypt.ui.components.SecondaryButton
import io.github.h4lovoid.dialcrypt.ui.components.SecureDialog
import io.github.h4lovoid.dialcrypt.ui.components.StatusHero
import io.github.h4lovoid.dialcrypt.ui.components.StepMarker
import io.github.h4lovoid.dialcrypt.ui.components.StepState
import io.github.h4lovoid.dialcrypt.ui.components.ScreenBackHandler
import io.github.h4lovoid.dialcrypt.ui.components.ScreenEnterMillis
import io.github.h4lovoid.dialcrypt.ui.components.rememberAnimatedPercent
import io.github.h4lovoid.dialcrypt.ui.components.rememberMotionEnabled
import io.github.h4lovoid.dialcrypt.ui.components.TopBar
import io.github.h4lovoid.dialcrypt.ui.keyboard.LocalInputHost
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureInputState
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureTextField
import io.github.h4lovoid.dialcrypt.ui.model.ConnectingUi
import io.github.h4lovoid.dialcrypt.ui.model.SasWords
import io.github.h4lovoid.dialcrypt.ui.model.SessionUi
import io.github.h4lovoid.dialcrypt.ui.model.TextMaps
import io.github.h4lovoid.dialcrypt.ui.model.callerNumber
import io.github.h4lovoid.dialcrypt.ui.rememberHaptics
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Radius
import io.github.h4lovoid.dialcrypt.ui.theme.Space
import io.github.h4lovoid.dialcrypt.ui.theme.Tone
import io.github.h4lovoid.dialcrypt.ui.theme.color
import kotlinx.coroutines.launch

@Composable
private fun peerLabel(peer: PeerInfo?, fullNumber: Boolean = false): String {
    // The call details always spell the whole number; elsewhere the display rule decides.
    val number = if (fullNumber) peer?.number?.trim()?.takeIf { it.isNotEmpty() } else callerNumber(peer?.number, peer?.contactId)
    return peer?.name ?: number ?: stringResource(R.string.number_hidden)
}

// ---- connecting --------------------------------------------------------------------------------

/** Step-by-step progress. Says nothing about being encrypted or secure until the link exists. */
@Composable
fun ConnectingScreen(state: SessionState, onCancel: () -> Unit, modifier: Modifier = Modifier) {
    val progress = state.connect
    val percent = progress?.percent?.coerceIn(0, 100) ?: 0
    val shownPercent = rememberAnimatedPercent(percent)
    val incoming = state.direction == io.github.h4lovoid.dialcrypt.core.CallDirection.INCOMING
    var confirmHangUp by remember { mutableStateOf(false) }
    // Back asks first; the call is only hung up from the dialog, like the Hang up button below.
    ScreenBackHandler { confirmHangUp = true }
    Column(modifier.fillMaxSize()) {
        TopBar(stringResource(if (incoming) ConnectingUi.incomingTitle else ConnectingUi.title), onBack = null)
        Column(
            Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = ScreenPadding, vertical = Space.sm),
            verticalArrangement = Arrangement.spacedBy(Space.lg),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.md)) {
                IconTile(Icons.Filled.Call, size = 48.dp)
                Text(
                    stringResource(if (incoming) ConnectingUi.answering else ConnectingUi.calling, peerLabel(state.peer)),
                    style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f),
                )
            }
            Card {
                Row(verticalAlignment = Alignment.Bottom) {
                    Text(
                        stringResource(ConnectingUi.percent, shownPercent),
                        style = MaterialTheme.typography.displaySmall, modifier = Modifier.weight(1f),
                    )
                    if (progress != null) {
                        Text(
                            stringResource(ConnectingUi.eta, progress.etaSeconds),
                            style = MaterialTheme.typography.bodyMedium, color = Palette.OnSurfaceMuted,
                            modifier = Modifier.padding(bottom = Space.sm),
                        )
                    }
                }
                ProgressBar(percent / 100f, Modifier.padding(top = Space.xs))
            }
            StepList(progress?.step?.ordinal ?: -1, state.direction)
            Text(stringResource(ConnectingUi.note), style = MaterialTheme.typography.bodyMedium, color = Palette.OnSurfaceMuted)
        }
        Column(Modifier.padding(horizontal = ScreenPadding, vertical = Space.md)) {
            SecondaryButton(stringResource(ConnectingUi.cancel), onCancel, danger = true, icon = Icons.Filled.CallEnd)
        }
    }
    if (confirmHangUp) HangUpDialog(onConfirm = { confirmHangUp = false; onCancel() }, onDismiss = { confirmHangUp = false })
}

/** The five set-up stages as a vertical list: done, in progress (animated), waiting. */
@Composable
private fun StepList(current: Int, direction: io.github.h4lovoid.dialcrypt.core.CallDirection = io.github.h4lovoid.dialcrypt.core.CallDirection.OUTGOING) {
    val steps = ConnectStep.values()
    val shape = RoundedCornerShape(Radius.lg)
    Column(
        Modifier.fillMaxWidth().clip(shape).background(Palette.Surface)
            .padding(horizontal = Space.lg, vertical = Space.md),
    ) {
        steps.forEachIndexed { i, step ->
            val state = when {
                i < current -> StepState.DONE
                i == current -> StepState.RUNNING
                else -> StepState.PENDING
            }
            val description = stringResource(
                when (state) {
                    StepState.DONE -> R.string.prep_state_done
                    StepState.RUNNING -> R.string.prep_state_running
                    else -> R.string.prep_state_pending
                },
            )
            Row(
                Modifier.heightIn(min = 40.dp).semantics(mergeDescendants = true) {},
                verticalAlignment = Alignment.CenterVertically,
            ) {
                StepMarker(state, description)
                val stepLabel = if (step == ConnectStep.DIALING && direction == io.github.h4lovoid.dialcrypt.core.CallDirection.INCOMING) {
                    ConnectingUi.stepAnswering
                } else {
                    ConnectingUi.stepRes(step)
                }
                Text(
                    stringResource(stepLabel),
                    modifier = Modifier.padding(start = Space.md),
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = if (state == StepState.RUNNING) FontWeight.Medium else FontWeight.Normal,
                    color = if (state == StepState.PENDING) Palette.OnSurfaceMuted else Palette.OnSurface,
                )
            }
            if (i < steps.lastIndex) {
                Box(
                    Modifier.padding(start = 13.dp).width(2.dp).height(Space.sm)
                        .background(if (i < current) Palette.Ok.copy(alpha = 0.4f) else Palette.OutlineSoft),
                )
            }
        }
    }
}

// ---- compare the words -------------------------------------------------------------------------

/** Five verification words, each with its three-digit number, plus the voice comparison window. */
@Composable
fun SasScreen(
    state: SessionState,
    keyChanged: Boolean,
    onMatch: () -> Unit,
    onMismatch: () -> Unit,
    onOpenVoice: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val sas = state.sas ?: return
    val context = LocalContext.current
    val locked = sas.localMatched
    // The core reports only the seconds left; the longest value seen while the window is open is the full length.
    var longest by remember(sas.voiceWindowOpen) { mutableIntStateOf(sas.voiceSecondsLeft) }
    LaunchedEffect(sas.voiceSecondsLeft) { if (sas.voiceSecondsLeft > longest) longest = sas.voiceSecondsLeft }
    val total = maxOf(longest, sas.voiceSecondsLeft, 1)
    var confirmLeave by remember { mutableStateOf(false) }
    // Back asks first, and does nothing once our side has confirmed, when the hang-up button is off too.
    ScreenBackHandler { if (!locked) confirmLeave = true }
    Column(modifier.fillMaxSize().background(if (keyChanged) Palette.DangerBackground else Palette.Background)) {
        TopBar(stringResource(R.string.sas_title), onBack = null)
        Column(
            Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = ScreenPadding, vertical = Space.sm),
            verticalArrangement = Arrangement.spacedBy(Space.md),
        ) {
            if (keyChanged) {
                Card(borderColor = Palette.Danger, container = Palette.DangerContainer) {
                    InlineMessage(stringResource(R.string.sas_key_changed_note), Tone.DANGER)
                }
            }
            Text(stringResource(R.string.sas_instruction), style = MaterialTheme.typography.bodyLarge, color = Palette.OnSurfaceMuted)
            sas.wordIndices.forEach { index ->
                val word = SasWords.word(context, index)
                Row(
                    Modifier.fillMaxWidth().clip(RoundedCornerShape(Radius.md)).background(Palette.Surface)
                        .heightIn(min = 64.dp).padding(horizontal = Space.lg, vertical = Space.sm),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(Space.lg),
                ) {
                    Box(
                        Modifier.widthIn(min = 64.dp).clip(CircleShape).background(Palette.AccentContainer)
                            .padding(horizontal = Space.md, vertical = 6.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            SasWords.number(index),
                            style = if (word != null) MaterialTheme.typography.titleMedium else MaterialTheme.typography.headlineSmall,
                            fontFamily = FontFamily.Monospace, color = Palette.Accent,
                        )
                    }
                    if (word != null) {
                        Text(word, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
                    }
                }
            }
            if (SasWords.word(context, 0) == null) {
                Text(stringResource(R.string.sas_numbers_only), style = MaterialTheme.typography.bodySmall, color = Palette.OnSurfaceMuted)
            }
            if (sas.voiceWindowOpen) {
                Card {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.md)) {
                        Icon(Icons.Filled.Mic, contentDescription = null, tint = Palette.Accent, modifier = Modifier.size(24.dp))
                        Text(
                            stringResource(R.string.sas_voice_open, sas.voiceSecondsLeft),
                            style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f),
                        )
                    }
                    ProgressBar(
                        sas.voiceSecondsLeft / total.toFloat(),
                        Modifier.padding(vertical = Space.xs),
                        color = when {
                            sas.voiceSecondsLeft <= 5 -> Palette.Danger
                            sas.voiceSecondsLeft <= 10 -> Palette.Warn
                            else -> Palette.Accent
                        },
                        track = Palette.SurfaceTop,
                    )
                    Text(stringResource(R.string.sas_voice_note), style = MaterialTheme.typography.bodyMedium, color = Palette.OnSurfaceMuted)
                }
            } else {
                Card {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.md)) {
                        Icon(Icons.Filled.MicOff, contentDescription = null, tint = Palette.OnSurfaceMuted, modifier = Modifier.size(24.dp))
                        Text(
                            stringResource(R.string.sas_voice_closed),
                            style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f),
                        )
                    }
                    QuietButton(stringResource(R.string.sas_voice_reopen), onOpenVoice, enabled = !locked)
                }
            }
            if (locked) {
                InlineMessage(
                    stringResource(if (sas.peerMatched) R.string.sas_both_matched else R.string.sas_waiting_peer),
                    Tone.OK,
                )
            }
        }
        Column(Modifier.padding(horizontal = ScreenPadding, vertical = Space.md), verticalArrangement = Arrangement.spacedBy(Space.sm)) {
            PrimaryButton(stringResource(R.string.sas_match), onMatch, enabled = !locked, icon = Icons.Filled.Check)
            SecondaryButton(stringResource(R.string.sas_mismatch), onMismatch, enabled = !locked, danger = true, icon = Icons.Filled.CallEnd)
        }
    }
    if (confirmLeave) HangUpDialog(onConfirm = { confirmLeave = false; onMismatch() }, onDismiss = { confirmLeave = false })
}

// ---- warning and end states --------------------------------------------------------------------

/** Full-screen red warning. The only ways out are comparing again or hanging up. */
@Composable
fun KeyChangedScreen(onRematch: () -> Unit, onHangUp: () -> Unit, modifier: Modifier = Modifier) {
    val haptics = rememberHaptics()
    LaunchedEffect(Unit) { haptics.strong() }
    var confirmHangUp by remember { mutableStateOf(false) }
    ScreenBackHandler { confirmHangUp = true }
    Column(modifier.fillMaxSize().background(Palette.DangerBackground)) {
        Column(
            Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState())
                .padding(horizontal = ScreenPadding, vertical = Space.xl),
            verticalArrangement = Arrangement.spacedBy(Space.lg, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            StatusHero(Icons.Filled.GppBad, Palette.Danger)
            Text(
                stringResource(R.string.keychange_title), style = MaterialTheme.typography.headlineMedium,
                color = Palette.OnSurface, textAlign = TextAlign.Center,
            )
            Text(stringResource(R.string.keychange_body), style = MaterialTheme.typography.bodyLarge, color = Palette.OnSurfaceMuted, textAlign = TextAlign.Center)
            Card(borderColor = Palette.Danger, container = Palette.DangerContainer) {
                Text(
                    stringResource(R.string.keychange_no_send), style = MaterialTheme.typography.titleMedium,
                    color = Palette.Danger, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth(),
                )
            }
        }
        Column(Modifier.padding(horizontal = ScreenPadding, vertical = Space.md), verticalArrangement = Arrangement.spacedBy(Space.sm)) {
            PrimaryButton(stringResource(R.string.keychange_rematch), onRematch, icon = Icons.Filled.RecordVoiceOver)
            SecondaryButton(stringResource(R.string.keychange_hangup), onHangUp, danger = true, icon = Icons.Filled.CallEnd)
        }
    }
    if (confirmHangUp) HangUpDialog(onConfirm = { confirmHangUp = false; onHangUp() }, onDismiss = { confirmHangUp = false })
}

@Composable
fun AbortedScreen(failure: SessionFailure?, onDone: () -> Unit, modifier: Modifier = Modifier, wasEstablished: Boolean = false) {
    // The way out is the button; the back key does nothing.
    BackHandler {}
    Column(modifier.fillMaxSize()) {
        TopBar(stringResource(R.string.abort_title), onBack = null)
        Column(
            Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState())
                .padding(horizontal = ScreenPadding, vertical = Space.lg),
            verticalArrangement = Arrangement.spacedBy(Space.xl, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            StatusHero(Icons.Filled.CallEnd, Palette.Warn)
            Card {
                if (wasEstablished) {
                    // The link was up and the other side went away: no handshake wording, no "nothing was sent".
                    Text(stringResource(R.string.abort_ended_title), style = MaterialTheme.typography.titleMedium)
                    Text(
                        stringResource(R.string.abort_ended_body),
                        style = MaterialTheme.typography.bodyLarge, color = Palette.OnSurfaceMuted,
                    )
                } else {
                    Text(stringResource(R.string.abort_nothing_sent), style = MaterialTheme.typography.titleMedium)
                    Text(
                        stringResource(TextMaps.sessionFailure(failure ?: SessionFailure.UNKNOWN)),
                        style = MaterialTheme.typography.bodyLarge, color = Palette.OnSurfaceMuted,
                    )
                }
            }
        }
        Column(Modifier.padding(horizontal = ScreenPadding, vertical = Space.md)) {
            PrimaryButton(stringResource(R.string.abort_done), onDone)
        }
    }
}

/** Clearing, then "done", then the app closes. */
@Composable
fun EndingScreen(phase: SessionPhase, onClosed: () -> Unit, modifier: Modifier = Modifier) {
    val cleared = phase == SessionPhase.CLEARED
    val haptics = rememberHaptics()
    // Clearing cannot be interrupted, so the back key does nothing.
    BackHandler {}
    LaunchedEffect(cleared) {
        if (cleared) {
            haptics.strong()
            kotlinx.coroutines.delay(1200)
            onClosed()
        }
    }
    Column(
        modifier.fillMaxSize().padding(ScreenPadding),
        verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        StatusHero(
            if (cleared) Icons.Filled.CheckCircle else Icons.Filled.Sync,
            if (cleared) Palette.Ok else Palette.Accent,
            breathing = !cleared,
        )
        Text(
            stringResource(if (cleared) R.string.ending_done else R.string.ending_clearing),
            style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = Space.xl),
        )
        Text(
            stringResource(if (cleared) R.string.ending_closing else R.string.ending_wait),
            style = MaterialTheme.typography.bodyLarge, color = Palette.OnSurfaceMuted, textAlign = TextAlign.Center,
            modifier = Modifier.padding(top = Space.sm),
        )
    }
}

// ---- chat --------------------------------------------------------------------------------------

@Composable
fun ChatScreen(state: SessionState, core: SecureCore, modifier: Modifier = Modifier) {
    val scope = rememberCoroutineScope()
    val host = LocalInputHost.current
    val haptics = rememberHaptics()
    val input = remember { SecureInputState(SessionLimits.MAX_TEXT_CHARS) }
    var error by remember { mutableStateOf<Int?>(null) }
    var showDetails by remember { mutableStateOf(false) }
    var confirmEnd by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()
    // Messages that were already there, or have already come in; only a later one slides and fades in.
    val shownIds = remember { state.messages.mapTo(HashSet()) { it.id } }
    val quickState = rememberLazyListState()
    val canSend = SessionUi.canSend(state)
    val keyboardOpen = host.active != null

    LaunchedEffect(state.messages.size) {
        if (state.messages.isNotEmpty()) listState.animateScrollToItem(state.messages.lastIndex)
    }
    // The list gets shorter when the in-app keyboard opens; bring the newest message back into view.
    LaunchedEffect(keyboardOpen) {
        if (state.messages.isNotEmpty()) {
            withFrameNanos { }
            listState.scrollToItem(state.messages.lastIndex)
        }
    }
    LaunchedEffect(state.identity) { haptics.tick() }

    fun send() {
        if (!canSend || input.isEmpty) return
        val result = core.sendText(input.text().trim())
        error = when (result) {
            SendResult.QUEUED -> { input.clear(); haptics.tick(); null }
            SendResult.EMPTY -> null
            SendResult.TOO_LONG -> R.string.send_too_long
            SendResult.BLOCKED_KEY_CHANGED -> R.string.send_blocked_key_changed
            SendResult.BLOCKED_NOT_ESTABLISHED -> R.string.send_blocked_not_established
        }
    }
    LaunchedEffect(canSend) { host.onDone = null }
    // Back closes the keyboard, then asks before the chat is ended, the same hold-to-confirm as End and clear.
    ScreenBackHandler { confirmEnd = true }

    Column(modifier.fillMaxSize()) {
        StatusHeader(state, onDetails = { showDetails = true })
        if (SessionUi.canVerify(state) && !keyboardOpen) {
            Card(modifier = Modifier.padding(horizontal = ScreenPadding, vertical = Space.sm)) {
                Row(horizontalArrangement = Arrangement.spacedBy(Space.sm)) {
                    Icon(Icons.Filled.Warning, contentDescription = null, tint = Palette.Warn, modifier = Modifier.size(20.dp))
                    Text(stringResource(R.string.chat_verify_body), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                }
                SecondaryButton(stringResource(R.string.chat_verify_action), { core.beginSas() }, icon = Icons.Filled.RecordVoiceOver)
            }
        }
        if (state.messages.isEmpty()) {
            Column(
                Modifier.weight(1f).fillMaxWidth().padding(ScreenPadding),
                verticalArrangement = Arrangement.spacedBy(Space.md, Alignment.CenterVertically),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Icon(Icons.AutoMirrored.Filled.Chat, contentDescription = null, tint = Palette.Outline, modifier = Modifier.size(40.dp))
                Text(
                    stringResource(R.string.chat_empty),
                    color = Palette.OnSurfaceMuted, textAlign = TextAlign.Center,
                )
            }
        } else {
            LazyColumn(
                Modifier.weight(1f), state = listState,
                contentPadding = PaddingValues(horizontal = ScreenPadding, vertical = Space.sm),
            ) {
                itemsIndexed(state.messages, key = { _, m -> m.id }) { i, m ->
                    val joinedPrev = state.messages.getOrNull(i - 1)?.outgoing == m.outgoing
                    val joinedNext = state.messages.getOrNull(i + 1)?.outgoing == m.outgoing
                    MessageBubble(
                        m, joinedPrev, joinedNext, shownIds,
                        Modifier.padding(top = if (i == 0) 0.dp else if (joinedPrev) 2.dp else Space.md),
                    )
                }
            }
        }
        Box(Modifier.fillMaxWidth()) {
            LazyRow(
                state = quickState,
                contentPadding = PaddingValues(horizontal = ScreenPadding),
                horizontalArrangement = Arrangement.spacedBy(Space.sm),
            ) {
                items(QuickCommand.values().toList()) { cmd ->
                    Button(
                        onClick = {
                            val r = core.sendQuick(cmd)
                            error = if (r == SendResult.QUEUED) null else R.string.send_blocked_key_changed
                            haptics.tick()
                        },
                        modifier = Modifier.heightIn(min = 48.dp),
                        enabled = canSend,
                        shape = RoundedCornerShape(24.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Palette.SurfaceHigh, contentColor = Palette.OnSurface,
                            disabledContainerColor = Palette.SurfaceHigh,
                            disabledContentColor = Palette.OnSurface.copy(alpha = DisabledContentAlpha),
                        ),
                    ) { Text(stringResource(TextMaps.quickCommand(cmd)), style = MaterialTheme.typography.titleSmall) }
                }
            }
            // Soft edges hint that the row scrolls sideways.
            Box(Modifier.matchParentSize()) {
                if (quickState.canScrollBackward) EdgeFade(Modifier.align(Alignment.CenterStart), towardsEnd = false)
                if (quickState.canScrollForward) EdgeFade(Modifier.align(Alignment.CenterEnd), towardsEnd = true)
            }
        }
        error?.let {
            InlineMessage(stringResource(it), Tone.DANGER, Modifier.padding(horizontal = ScreenPadding, vertical = Space.xs))
        }
        Row(
            Modifier.padding(horizontal = ScreenPadding, vertical = Space.sm),
            verticalAlignment = Alignment.Bottom, horizontalArrangement = Arrangement.spacedBy(Space.sm),
        ) {
            SecureTextField(
                input, modifier = Modifier.weight(1f), maxLines = 3, tag = "chat_input",
                placeholder = stringResource(if (state.identity == IdentityStatus.UNKNOWN) R.string.chat_hint_unverified else R.string.chat_hint),
            )
            IconButton(
                onClick = { send() }, enabled = canSend && !input.isEmpty,
                modifier = Modifier.size(56.dp),
                colors = IconButtonDefaults.filledIconButtonColors(
                    containerColor = Palette.Accent, contentColor = Palette.Background,
                    disabledContainerColor = Palette.SurfaceHigh,
                    disabledContentColor = Palette.OnSurface.copy(alpha = DisabledContentAlpha),
                ),
            ) {
                Icon(Icons.AutoMirrored.Filled.Send, contentDescription = stringResource(R.string.chat_send))
            }
        }
        if (input.length > SessionLimits.MAX_TEXT_CHARS * 3 / 4) {
            Text(
                stringResource(R.string.chat_counter, input.length, SessionLimits.MAX_TEXT_CHARS),
                style = MaterialTheme.typography.bodySmall, color = Palette.OnSurfaceMuted,
                modifier = Modifier.padding(horizontal = ScreenPadding),
            )
        }
        if (!keyboardOpen) {
            Column(Modifier.padding(horizontal = ScreenPadding, vertical = Space.sm)) {
                HoldToConfirmButton(
                    stringResource(R.string.chat_end),
                    onConfirmed = { scope.launch { core.endAndWipe() } },
                    icon = Icons.Filled.CallEnd,
                )
            }
        }
    }
    if (showDetails) ChatDetailsDialog(state) { showDetails = false }
    if (confirmEnd) {
        SecureDialog(
            title = stringResource(R.string.back_end_title),
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(Space.lg)) {
                    Text(stringResource(R.string.back_end_body))
                    HoldToConfirmButton(
                        stringResource(R.string.chat_end),
                        onConfirmed = { confirmEnd = false; scope.launch { core.endAndWipe() } },
                        icon = Icons.Filled.CallEnd,
                    )
                }
            },
            confirmButton = { QuietButton(stringResource(R.string.action_cancel), { confirmEnd = false }) },
            onDismiss = { confirmEnd = false },
        )
    }
}

@Composable
private fun EdgeFade(modifier: Modifier, towardsEnd: Boolean, width: Dp = 28.dp) {
    val colors = if (towardsEnd) listOf(Color.Transparent, Palette.Background) else listOf(Palette.Background, Color.Transparent)
    Box(modifier.fillMaxHeight().width(width).background(Brush.horizontalGradient(colors)))
}

/**
 * Banner at the top: a small shield icon in a slot of its own and the identity status in the tone color,
 * with a thin line below. The icon keeps its slot and the margin on any width; the text gives way first.
 */
@Composable
private fun StatusHeader(state: SessionState, onDetails: () -> Unit) {
    val banner = SessionUi.identityBanner(state)
    val pq = SessionUi.pqLabel(state)
    val tone = banner?.tone ?: Tone.NEUTRAL
    val tint by animateColorAsState(tone.color(), label = "banner-tint")
    val icon = when (tone) {
        Tone.OK -> Icons.Filled.VerifiedUser
        Tone.DANGER -> Icons.Filled.GppBad
        else -> Icons.Filled.GppMaybe
    }
    Column(Modifier.fillMaxWidth()) {
        Row(
            Modifier.fillMaxWidth()
                .padding(start = ScreenPadding, end = Space.xs, top = Space.sm, bottom = Space.sm),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.size(24.dp), contentAlignment = Alignment.Center) {
                Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(20.dp))
            }
            Column(Modifier.weight(1f).padding(start = Space.md)) {
                if (banner != null) {
                    Text(
                        stringResource(banner.textRes), color = tint, style = MaterialTheme.typography.titleSmall,
                        maxLines = 2, overflow = TextOverflow.Ellipsis,
                    )
                }
                if (pq != null) {
                    Text(
                        if (pq.percent != null) stringResource(pq.res, pq.percent) else stringResource(pq.res),
                        style = MaterialTheme.typography.bodySmall, color = Palette.OnSurfaceMuted,
                    )
                }
                if (state.quickConnect == QuickConnect.REBUILD_PENDING) {
                    Text(stringResource(R.string.quick_rebuild), style = MaterialTheme.typography.bodySmall, color = Palette.Warn)
                }
            }
            QuietButton(stringResource(R.string.chat_details), onDetails)
        }
        Box(Modifier.fillMaxWidth().height(1.dp).background(if (tone == Tone.NEUTRAL) Palette.OutlineSoft else tint.copy(alpha = 0.4f)))
    }
}

/**
 * One message. Neighbours from the same side are joined: the corners between them are tight and
 * the gap is small, so a run of messages reads as one block. A message that arrives while the chat is
 * open fades in and slides a few dp in from its own side; [shownIds] remembers which ones have done so.
 */
@Composable
private fun MessageBubble(
    msg: ChatMessage,
    joinedPrev: Boolean,
    joinedNext: Boolean,
    shownIds: MutableSet<Long>,
    modifier: Modifier = Modifier,
) {
    val outgoing = msg.outgoing
    val motion = rememberMotionEnabled()
    val arrive = remember { Animatable(if (motion && msg.id !in shownIds) 0f else 1f) }
    LaunchedEffect(msg.id) {
        if (arrive.value < 1f) arrive.animateTo(1f, tween(ScreenEnterMillis, easing = FastOutSlowInEasing))
        shownIds.add(msg.id)
    }
    val slide = with(LocalDensity.current) { Space.md.toPx() }
    val shownPercent = rememberAnimatedPercent(msg.sendPercent.coerceIn(0, 100))
    val big = 18.dp
    val tight = 4.dp
    val tail = 6.dp
    val shape = if (outgoing) {
        RoundedCornerShape(topStart = big, topEnd = if (joinedPrev) tight else big, bottomEnd = if (joinedNext) tight else tail, bottomStart = big)
    } else {
        RoundedCornerShape(topStart = if (joinedPrev) tight else big, topEnd = big, bottomEnd = big, bottomStart = if (joinedNext) tight else tail)
    }
    val bg = if (outgoing) Palette.OutgoingBubble else Palette.SurfaceHigh
    Row(
        modifier.fillMaxWidth().graphicsLayer {
            alpha = arrive.value
            translationX = (1f - arrive.value) * slide * (if (outgoing) 1f else -1f)
        },
        horizontalArrangement = if (outgoing) Arrangement.End else Arrangement.Start,
    ) {
        Column(
            Modifier.widthIn(max = 300.dp).clip(shape).background(bg)
                .then(if (msg.status == MessageStatus.FAILED) Modifier.border(1.dp, Palette.Danger.copy(alpha = 0.7f), shape) else Modifier)
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(Space.xs),
        ) {
            when (val body = msg.body) {
                is MessageBody.Text -> Text(body.text, style = MaterialTheme.typography.bodyLarge)
                is MessageBody.Quick -> Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Bolt, contentDescription = null, tint = Palette.Accent, modifier = Modifier.size(18.dp))
                    Text(
                        stringResource(TextMaps.quickCommand(body.command)),
                        style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium, color = Palette.Accent,
                        modifier = Modifier.padding(start = Space.xs),
                    )
                }
            }
            if (outgoing) {
                SessionUi.statusRes(msg.status)?.let { res ->
                    val failed = msg.status == MessageStatus.FAILED
                    val tint = when (msg.status) {
                        MessageStatus.FAILED -> Palette.Danger
                        MessageStatus.READ -> Palette.Accent
                        else -> Palette.OnSurfaceMuted
                    }
                    Row(
                        Modifier.align(Alignment.End),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(Space.xs),
                    ) {
                        Icon(
                            when (msg.status) {
                                MessageStatus.SENDING -> Icons.Filled.Schedule
                                MessageStatus.SENT -> Icons.Filled.Check
                                MessageStatus.FAILED -> Icons.Filled.Error
                                else -> Icons.Filled.DoneAll
                            },
                            contentDescription = null, tint = tint, modifier = Modifier.size(14.dp),
                        )
                        Text(
                            when {
                                msg.status != MessageStatus.SENDING -> stringResource(res)
                                // The engine reports no progress yet, so 0 shows no number.
                                msg.sendPercent > 0 -> stringResource(res, shownPercent)
                                else -> stringResource(R.string.msg_sending_unknown)
                            },
                            style = MaterialTheme.typography.labelSmall,
                            color = if (failed) Palette.Danger else tint,
                        )
                    }
                }
                if (msg.status == MessageStatus.SENDING) {
                    if (msg.sendPercent > 0) {
                        ProgressBar(
                            msg.sendPercent.coerceIn(0, 100) / 100f,
                            height = 4.dp, track = Color.Black.copy(alpha = 0.35f),
                        )
                    } else {
                        LinearProgressIndicator(
                            Modifier.fillMaxWidth(), color = Palette.Accent, trackColor = Color.Black.copy(alpha = 0.35f),
                        )
                    }
                }
            }
        }
    }
}

/** Technical details live here: key exchange names, hardware class, fingerprint. */
@Composable
private fun ChatDetailsDialog(state: SessionState, onDismiss: () -> Unit) {
    SecureDialog(
        title = stringResource(R.string.details_title),
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(Space.md)) {
                // The user opened this dialog on purpose, so the full number shows here.
                DetailLine(stringResource(R.string.details_peer), peerLabel(state.peer, fullNumber = true))
                SessionUi.identityBanner(state)?.let { DetailLine(stringResource(R.string.detail_identity), stringResource(it.textRes)) }
                DetailLine(stringResource(R.string.detail_hardware), stringResource(TextMaps.hardwareDetail(state.hardware)))
                state.fingerprint?.let {
                    Column(verticalArrangement = Arrangement.spacedBy(Space.xs)) {
                        Text(stringResource(R.string.detail_fingerprint), style = MaterialTheme.typography.labelMedium, color = Palette.OnSurfaceMuted)
                        FingerprintGrid(it)
                    }
                }
                DetailLine(stringResource(R.string.details_protocol), stringResource(R.string.details_protocol_value))
                DetailLine(stringResource(R.string.detail_quick), stringResource(TextMaps.quickConnect(state.quickConnect)))
                SessionUi.pqLabel(state)?.let {
                    DetailLine(
                        stringResource(R.string.details_pq),
                        if (it.percent != null) stringResource(it.res, it.percent) else stringResource(it.res),
                    )
                }
                if (state.paired) DetailLine(stringResource(R.string.detail_pairing), stringResource(R.string.detail_paired_yes))
            }
        },
        confirmButton = { QuietButton(stringResource(R.string.action_close), onDismiss) },
        onDismiss = onDismiss,
    )
}

@Composable
private fun DetailLine(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelMedium, color = Palette.OnSurfaceMuted)
        Text(value, style = MaterialTheme.typography.bodyMedium, color = Palette.OnSurface)
    }
}

/** In place of the save form after a fingerprint answered the call: saving needs the PIN. */
@Composable
fun SaveNeedsPinScreen(onLater: () -> Unit, modifier: Modifier = Modifier) {
    Column(modifier.fillMaxSize()) {
        TopBar(stringResource(R.string.save_title), onBack = null)
        Column(
            Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()).padding(horizontal = ScreenPadding, vertical = Space.lg),
            verticalArrangement = Arrangement.spacedBy(Space.lg),
        ) {
            InlineMessage(stringResource(R.string.session_save_needs_pin), Tone.WARN)
        }
        Column(Modifier.padding(horizontal = ScreenPadding, vertical = Space.md)) {
            PrimaryButton(stringResource(R.string.save_later), onLater)
        }
    }
}
