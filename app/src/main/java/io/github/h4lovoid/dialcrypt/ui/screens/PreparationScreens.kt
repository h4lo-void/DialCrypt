package io.github.h4lovoid.dialcrypt.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.LinkOff
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.core.ItemStatus
import io.github.h4lovoid.dialcrypt.core.LockdownPhase
import io.github.h4lovoid.dialcrypt.core.LockdownState
import io.github.h4lovoid.dialcrypt.core.PrepItemState
import io.github.h4lovoid.dialcrypt.ui.components.Card
import io.github.h4lovoid.dialcrypt.ui.components.GroupDivider
import io.github.h4lovoid.dialcrypt.ui.components.InfoGroup
import io.github.h4lovoid.dialcrypt.ui.components.InlineMessage
import io.github.h4lovoid.dialcrypt.ui.components.PrimaryButton
import io.github.h4lovoid.dialcrypt.ui.components.ProgressBar
import io.github.h4lovoid.dialcrypt.ui.components.ScreenPadding
import io.github.h4lovoid.dialcrypt.ui.components.StatusHero
import io.github.h4lovoid.dialcrypt.ui.components.StepMarker
import io.github.h4lovoid.dialcrypt.ui.components.StepState
import io.github.h4lovoid.dialcrypt.ui.components.TopBar
import io.github.h4lovoid.dialcrypt.ui.components.rememberAnimatedPercent
import io.github.h4lovoid.dialcrypt.ui.model.TextMaps
import io.github.h4lovoid.dialcrypt.ui.rememberHaptics
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Space
import io.github.h4lovoid.dialcrypt.ui.theme.Tone

/** Shown instead of every other screen when no secure core is linked: nothing can be done. */
@Composable
fun NotConnectedScreen(modifier: Modifier = Modifier) {
    Column(modifier.fillMaxSize()) {
        TopBar(stringResource(R.string.not_connected_title), onBack = null)
        Column(
            Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState())
                .padding(horizontal = ScreenPadding, vertical = Space.lg),
            verticalArrangement = Arrangement.spacedBy(Space.xl, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            StatusHero(Icons.Filled.LinkOff, Palette.Warn)
            Card {
                Text(stringResource(R.string.not_connected_body), style = MaterialTheme.typography.bodyLarge)
            }
        }
        Column(Modifier.padding(horizontal = ScreenPadding, vertical = Space.md)) {
            PrimaryButton(stringResource(R.string.action_continue), onClick = {}, enabled = false)
        }
    }
}

/** Neutral first screen of the default process. Nothing starts until the user taps the button. */
@Composable
fun StartScreen(onStart: () -> Unit, modifier: Modifier = Modifier) {
    Column(
        modifier.fillMaxSize().padding(horizontal = ScreenPadding, vertical = Space.xl),
        verticalArrangement = Arrangement.spacedBy(Space.xl, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            stringResource(R.string.start_hint),
            style = MaterialTheme.typography.bodyLarge, color = Palette.OnSurfaceMuted, textAlign = TextAlign.Center,
        )
        PrimaryButton(stringResource(R.string.action_start), onClick = onStart)
    }
}

/** Step 1 of the two-stage start: checks and hardening, reported by the privileged helper. */
@Composable
fun PreparationScreen(
    state: LockdownState,
    onRetry: () -> Unit,
    onContinue: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (state.phase == LockdownPhase.NOT_CONNECTED) {
        NotConnectedScreen(modifier)
        return
    }
    val haptics = rememberHaptics()
    val shownPercent = rememberAnimatedPercent(state.percent)
    LaunchedEffect(state.phase) {
        if (state.phase == LockdownPhase.READY || state.phase == LockdownPhase.FAILED) haptics.strong()
    }
    Column(modifier.fillMaxSize()) {
        TopBar(stringResource(R.string.prep_title), onBack = null)
        Column(
            Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = ScreenPadding, vertical = Space.sm),
            verticalArrangement = Arrangement.spacedBy(Space.lg),
        ) {
            Text(stringResource(R.string.prep_intro), style = MaterialTheme.typography.bodyLarge, color = Palette.OnSurfaceMuted)
            Column(verticalArrangement = Arrangement.spacedBy(Space.sm)) {
                ProgressBar(
                    state.percent / 100f,
                    color = if (state.phase == LockdownPhase.FAILED) Palette.Danger else Palette.Accent,
                )
                Text(stringResource(R.string.connect_percent, shownPercent), style = MaterialTheme.typography.labelLarge)
            }
            state.failedItem?.let { failed ->
                val code = failed.failure
                val check = failed.appCheck
                Card(borderColor = Palette.Danger, container = Palette.DangerContainer) {
                    Text(
                        stringResource(R.string.prep_failed_title, stringResource(check?.label ?: TextMaps.prepItem(failed.item))),
                        style = MaterialTheme.typography.titleMedium, color = Palette.Danger,
                    )
                    if (check != null) {
                        Text(stringResource(check.reason), style = MaterialTheme.typography.bodyLarge)
                        Text(stringResource(R.string.prep_what_to_do), style = MaterialTheme.typography.labelLarge, color = Palette.OnSurfaceMuted)
                        Text(stringResource(check.fix), style = MaterialTheme.typography.bodyLarge)
                    } else if (code != null) {
                        Text(stringResource(TextMaps.lockdownReason(code)), style = MaterialTheme.typography.bodyLarge)
                        Text(stringResource(R.string.prep_what_to_do), style = MaterialTheme.typography.labelLarge, color = Palette.OnSurfaceMuted)
                        Text(stringResource(TextMaps.lockdownFix(code)), style = MaterialTheme.typography.bodyLarge)
                    }
                }
            }
            InfoGroup {
                state.items.forEachIndexed { i, row ->
                    if (i > 0) GroupDivider(inset = 56.dp)
                    PrepRow(row)
                }
            }
            if (state.dryRun) {
                InlineMessage(stringResource(R.string.dry_run_notice), Tone.WARN)
            }
            if (state.phase == LockdownPhase.READY) {
                Text(
                    stringResource(TextMaps.hardeningLevel(state.level)),
                    style = MaterialTheme.typography.bodyMedium, color = Palette.OnSurfaceMuted,
                    textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth(),
                )
            }
        }
        Column(Modifier.padding(horizontal = ScreenPadding, vertical = Space.md)) {
            when (state.phase) {
                LockdownPhase.FAILED -> PrimaryButton(stringResource(R.string.prep_retry), onRetry)
                LockdownPhase.READY -> PrimaryButton(stringResource(R.string.prep_continue), onContinue)
                else -> PrimaryButton(stringResource(R.string.prep_working), onClick = {}, enabled = false)
            }
        }
    }
}

@Composable
private fun PrepRow(row: PrepItemState) {
    val marker = when (row.status) {
        ItemStatus.DONE -> StepState.DONE
        ItemStatus.FAILED -> StepState.FAILED
        ItemStatus.RUNNING -> StepState.RUNNING
        ItemStatus.PENDING -> StepState.PENDING
    }
    val state = stringResource(
        when (row.status) {
            ItemStatus.DONE -> R.string.prep_state_done
            ItemStatus.FAILED -> R.string.prep_state_failed
            ItemStatus.RUNNING -> R.string.prep_state_running
            ItemStatus.PENDING -> R.string.prep_state_pending
        },
    )
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).padding(horizontal = Space.lg, vertical = 10.dp)
            .semantics(mergeDescendants = true) {},
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.md),
    ) {
        StepMarker(marker, state)
        Text(
            stringResource(row.appCheck?.label ?: TextMaps.prepItem(row.item)),
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyLarge,
            color = when (row.status) {
                ItemStatus.PENDING -> Palette.OnSurfaceMuted
                ItemStatus.FAILED -> Palette.Danger
                else -> Palette.OnSurface
            },
        )
    }
}
