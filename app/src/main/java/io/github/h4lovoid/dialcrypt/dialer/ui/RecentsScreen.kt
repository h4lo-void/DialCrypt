package io.github.h4lovoid.dialcrypt.dialer.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.CallMade
import androidx.compose.material.icons.automirrored.filled.CallMissed
import androidx.compose.material.icons.automirrored.filled.CallReceived
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.dialer.model.RecentCalls
import io.github.h4lovoid.dialcrypt.dialer.model.RecentDirection
import io.github.h4lovoid.dialcrypt.dialer.model.RecentItem
import io.github.h4lovoid.dialcrypt.dialer.model.RecentState
import io.github.h4lovoid.dialcrypt.ui.components.MinTouch
import io.github.h4lovoid.dialcrypt.ui.components.QuietButton
import io.github.h4lovoid.dialcrypt.ui.components.ScreenPadding
import io.github.h4lovoid.dialcrypt.ui.components.SecureDialog
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Space
import java.time.ZoneId

/** The two pages of the phone app. */
enum class DialTab { KEYPAD, RECENTS }

/** Test tags of the tabs and the recent calls list. */
object RecentsTags {
    const val TAB_KEYPAD = "dialer_tab_keypad"
    const val TAB_RECENTS = "dialer_tab_recents"
    const val LIST = "recents_list"
    const val EMPTY = "recents_empty"
    const val UNAVAILABLE = "recents_unavailable"
    const val CLEAR_ALL = "recents_clear_all"
    const val CLEAR_CONFIRM = "recents_clear_confirm"
    const val NOTICE = "recents_notice"

    fun row(id: Long): String = "recents_row_$id"

    fun delete(id: Long): String = "recents_delete_$id"
}

/** Switches between the keypad and the recent calls. */
@Composable
fun DialerTabs(selected: DialTab, onSelect: (DialTab) -> Unit, modifier: Modifier = Modifier) {
    TabRow(
        selectedTabIndex = selected.ordinal,
        modifier = modifier.fillMaxWidth(),
        containerColor = Palette.Background,
        contentColor = Palette.OnSurface,
    ) {
        Tab(
            selected = selected == DialTab.KEYPAD,
            onClick = { onSelect(DialTab.KEYPAD) },
            modifier = Modifier.testTag(RecentsTags.TAB_KEYPAD),
            text = { Text(stringResource(R.string.dialer_tab_keypad)) },
        )
        Tab(
            selected = selected == DialTab.RECENTS,
            onClick = { onSelect(DialTab.RECENTS) },
            modifier = Modifier.testTag(RecentsTags.TAB_RECENTS),
            text = { Text(stringResource(R.string.dialer_tab_recents)) },
        )
    }
}

/**
 * Recent calls from the system call log, newest first: direction, number, time and duration. A row
 * with a number calls it back through the keypad's dial path; every row can be deleted, and the whole
 * list cleared after a confirmation. Numbers arrive already shaped by the display rule. [nowMs] is
 * wall clock time, used to show today's calls by time of day.
 */
@Composable
fun RecentsScreen(
    state: RecentState,
    nowMs: Long,
    notice: DialNotice?,
    onCall: (String) -> Unit,
    onDelete: (Long) -> Unit,
    onClearAll: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var confirmClear by remember { mutableStateOf(false) }
    Column(modifier.fillMaxSize().background(Palette.Background).padding(horizontal = ScreenPadding)) {
        if (state.items.isNotEmpty()) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                QuietButton(
                    stringResource(R.string.recents_clear_all),
                    onClick = { confirmClear = true },
                    modifier = Modifier.testTag(RecentsTags.CLEAR_ALL),
                    danger = true,
                )
            }
        }
        if (notice != null) {
            Text(
                stringResource(if (notice == DialNotice.BLOCKED) R.string.dialpad_blocked else R.string.dialpad_failed),
                modifier = Modifier.fillMaxWidth().padding(vertical = Space.sm).testTag(RecentsTags.NOTICE),
                style = MaterialTheme.typography.bodyMedium,
                color = Palette.Danger,
                textAlign = TextAlign.Center,
            )
        }
        when {
            state.unavailable -> Message(stringResource(R.string.recents_unavailable), RecentsTags.UNAVAILABLE)
            state.loaded && state.items.isEmpty() -> Message(stringResource(R.string.recents_empty), RecentsTags.EMPTY)
            else -> {
                val zone = ZoneId.systemDefault()
                val locale = LocalConfiguration.current.locales[0]
                LazyColumn(Modifier.fillMaxSize().testTag(RecentsTags.LIST)) {
                    items(state.items, key = { it.id }) { item ->
                        RecentRow(
                            item = item,
                            time = RecentCalls.time(item.dateMs, nowMs, zone, locale),
                            onCall = onCall,
                            onDelete = onDelete,
                        )
                    }
                }
            }
        }
    }
    if (confirmClear) {
        SecureDialog(
            title = stringResource(R.string.recents_clear_title),
            text = { Text(stringResource(R.string.recents_clear_body)) },
            confirmButton = {
                QuietButton(
                    stringResource(R.string.recents_clear_confirm),
                    onClick = {
                        confirmClear = false
                        onClearAll()
                    },
                    modifier = Modifier.testTag(RecentsTags.CLEAR_CONFIRM),
                    danger = true,
                )
            },
            dismissButton = { QuietButton(stringResource(R.string.action_cancel), onClick = { confirmClear = false }) },
            onDismiss = { confirmClear = false },
        )
    }
}

@Composable
private fun Message(text: String, tag: String) {
    Box(Modifier.fillMaxSize().padding(Space.xl), contentAlignment = Alignment.Center) {
        Text(
            text,
            modifier = Modifier.testTag(tag),
            style = MaterialTheme.typography.bodyLarge,
            color = Palette.OnSurfaceMuted,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun RecentRow(item: RecentItem, time: String, onCall: (String) -> Unit, onDelete: (Long) -> Unit) {
    val dial = item.dialNumber
    val missed = item.direction == RecentDirection.MISSED
    val directionLabel = stringResource(
        when (item.direction) {
            RecentDirection.INCOMING -> R.string.recents_incoming
            RecentDirection.OUTGOING -> R.string.recents_outgoing
            RecentDirection.MISSED -> R.string.recents_missed
        },
    )
    val detail = listOfNotNull(directionLabel, time, item.durationSec?.let { RecentCalls.duration(it) }).joinToString(" · ")
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .testTag(RecentsTags.row(item.id))
            .clickable(enabled = dial != null, role = Role.Button) { dial?.let(onCall) },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.md),
    ) {
        Icon(
            when (item.direction) {
                RecentDirection.INCOMING -> Icons.AutoMirrored.Filled.CallReceived
                RecentDirection.OUTGOING -> Icons.AutoMirrored.Filled.CallMade
                RecentDirection.MISSED -> Icons.AutoMirrored.Filled.CallMissed
            },
            contentDescription = null,
            tint = if (missed) Palette.Danger else Palette.OnSurfaceMuted,
            modifier = Modifier.size(20.dp),
        )
        Column(Modifier.weight(1f).padding(vertical = Space.sm)) {
            Text(
                numberText(item.number),
                style = MaterialTheme.typography.titleMedium,
                color = if (missed) Palette.Danger else Palette.OnSurface,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(detail, style = MaterialTheme.typography.bodySmall, color = Palette.OnSurfaceMuted, maxLines = 1)
        }
        IconButton(onClick = { onDelete(item.id) }, modifier = Modifier.size(MinTouch).testTag(RecentsTags.delete(item.id))) {
            Icon(Icons.Filled.Delete, contentDescription = stringResource(R.string.recents_delete), tint = Palette.OnSurfaceMuted)
        }
    }
}
