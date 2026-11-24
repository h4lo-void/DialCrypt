package io.github.h4lovoid.dialcrypt.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Contacts
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.core.Contact
import io.github.h4lovoid.dialcrypt.core.HardeningLevel
import io.github.h4lovoid.dialcrypt.core.ItemStatus
import io.github.h4lovoid.dialcrypt.core.LockdownPhase
import io.github.h4lovoid.dialcrypt.core.LockdownState
import io.github.h4lovoid.dialcrypt.core.PhoneRules
import io.github.h4lovoid.dialcrypt.ui.components.Avatar
import io.github.h4lovoid.dialcrypt.ui.components.Badge
import io.github.h4lovoid.dialcrypt.ui.components.MinTouch
import io.github.h4lovoid.dialcrypt.ui.components.PrimaryButton
import io.github.h4lovoid.dialcrypt.ui.components.ScreenPadding
import io.github.h4lovoid.dialcrypt.ui.components.SecondaryButton
import io.github.h4lovoid.dialcrypt.ui.components.StatusDot
import io.github.h4lovoid.dialcrypt.ui.components.StatusHero
import io.github.h4lovoid.dialcrypt.ui.components.TopBar
import io.github.h4lovoid.dialcrypt.ui.keyboard.InputKind
import io.github.h4lovoid.dialcrypt.ui.keyboard.LocalInputHost
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureInputState
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureTextField
import io.github.h4lovoid.dialcrypt.ui.model.ContactUi
import io.github.h4lovoid.dialcrypt.ui.model.Formatters
import io.github.h4lovoid.dialcrypt.ui.model.listNumber
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Radius
import io.github.h4lovoid.dialcrypt.ui.theme.Space

private val ContactListPadding = PaddingValues(horizontal = ScreenPadding, vertical = Space.sm)
private val ContactCardGap = Space.md

/**
 * One contact as a card on its own layer, without an edge: avatar, name with masked number, and a
 * single status on the right. The avatar color comes from the contact id; the status label says the rest.
 * The whole card is the touch target. [selected] is null in plain lists and true/false in pickers.
 */
@Composable
private fun ContactCard(contact: Contact, selected: Boolean?, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val shape = RoundedCornerShape(Radius.lg)
    val status = ContactUi.status(contact)
    val picked = selected == true
    val base = modifier
        .fillMaxWidth()
        .heightIn(min = 72.dp)
        .testTag("contact_" + contact.id)
        .clip(shape)
        .background(if (picked) Palette.SurfaceHigh else Palette.Surface)
    val touch = if (selected == null) base.clickable(onClick = onClick)
    else base.selectable(selected = selected, role = Role.RadioButton, onClick = onClick)
    Row(
        touch.padding(horizontal = Space.md, vertical = Space.md),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.md),
    ) {
        Avatar(contact.id, contact.name, picked)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(contact.name, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    listNumber(contact.number) ?: stringResource(R.string.number_hidden),
                    style = MaterialTheme.typography.bodyMedium, color = Palette.OnSurfaceMuted, maxLines = 1,
                    overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false),
                )
                if (ContactUi.showsQuickConnect(contact)) {
                    Icon(
                        Icons.Filled.Bolt, contentDescription = null, tint = Palette.Accent,
                        modifier = Modifier.padding(start = Space.sm).size(16.dp),
                    )
                    Text(
                        stringResource(R.string.badge_quick),
                        style = MaterialTheme.typography.labelMedium, color = Palette.Accent,
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(start = 2.dp).weight(1f, fill = false),
                    )
                }
            }
        }
        Badge(stringResource(status.textRes), status.tone)
    }
}

/**
 * The real state of the system hardening, as reported by the lockdown controller. Collapsed it is a status
 * dot and one short word; a tap shows the full line and another tap folds it again. A failure starts open.
 */
@Composable
private fun ProtectionBar(state: LockdownState, modifier: Modifier = Modifier) {
    val done = state.items.count { it.status == ItemStatus.DONE }
    val total = state.items.size
    val tint = when (state.phase) {
        LockdownPhase.READY -> Palette.Ok
        LockdownPhase.PREPARING -> Palette.Accent
        LockdownPhase.FAILED -> Palette.Danger
        LockdownPhase.IDLE, LockdownPhase.NOT_CONNECTED -> Palette.Warn
    }
    val title = when (state.phase) {
        LockdownPhase.READY -> R.string.protect_ready
        LockdownPhase.PREPARING -> R.string.protect_working
        LockdownPhase.FAILED -> R.string.protect_failed
        LockdownPhase.IDLE -> R.string.protect_idle
        LockdownPhase.NOT_CONNECTED -> R.string.protect_unavailable
    }
    val shortWord = when (state.phase) {
        LockdownPhase.READY -> R.string.protect_short_ready
        LockdownPhase.PREPARING -> R.string.protect_short_working
        LockdownPhase.FAILED -> R.string.protect_short_failed
        LockdownPhase.IDLE -> R.string.protect_short_idle
        LockdownPhase.NOT_CONNECTED -> R.string.protect_short_unavailable
    }
    val checksBase = if (total > 0) stringResource(title) + " · " + stringResource(R.string.protect_checks, done, total) else stringResource(title)
    val checks = if (state.dryRun) checksBase + " · " + stringResource(R.string.dry_run_short) else checksBase
    val full = if (total > 0) {
        checks + " · " + stringResource(R.string.protect_level, if (state.level == HardeningLevel.LEVEL_2) 2 else 1)
    } else checks
    // The user's choice; until there is one, only a failure shows the full line.
    var choice by remember(state.phase) { mutableStateOf<Boolean?>(null) }
    val expanded = choice ?: (state.phase == LockdownPhase.FAILED)
    // The level goes last and is dropped when a longer language would cut it off.
    var fits by remember(full) { mutableStateOf(true) }
    Row(
        modifier.fillMaxWidth().heightIn(min = MinTouch)
            .clip(RoundedCornerShape(Radius.sm))
            .clickable(role = Role.Button) { choice = !expanded }
            .padding(horizontal = Space.xs),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.sm),
    ) {
        StatusDot(tint, size = 8.dp)
        Text(
            if (!expanded) stringResource(shortWord) else if (fits) full else checks,
            style = MaterialTheme.typography.bodySmall,
            color = if (expanded || state.phase == LockdownPhase.READY) Palette.OnSurfaceMuted else tint,
            maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f),
            onTextLayout = { if (expanded && it.hasVisualOverflow) fits = false },
        )
    }
}

/** Contact list, search, and the one primary action: start a secure call. */
@Composable
fun HomeScreen(
    contacts: List<Contact>,
    onOpenContact: (Long) -> Unit,
    onStartCall: () -> Unit,
    onSettings: () -> Unit,
    modifier: Modifier = Modifier,
    lockdown: LockdownState = LockdownState(),
    onAddContact: () -> Unit = {},
    onExit: (() -> Unit)? = null,
) {
    val search = remember { SecureInputState(40) }
    val query = search.text().trim()
    // While lists hide all but the last four digits, a search must not reveal the rest by trial.
    val wholeNumbers = io.github.h4lovoid.dialcrypt.ui.model.LocalShowFullNumbers.current
    val queryDigits = query.filter { it.isDigit() }
    val shown = if (query.isEmpty()) contacts else contacts.filter { c ->
        c.name.contains(query, ignoreCase = true) ||
            (queryDigits.isNotEmpty() && c.number?.let { n ->
                if (wholeNumbers) n.contains(queryDigits) else n.filter { it.isDigit() }.takeLast(4).contains(queryDigits)
            } == true)
    }
    Column(modifier.fillMaxSize()) {
        TopBar(stringResource(R.string.home_title), onBack = null) {
            IconButton(onClick = onAddContact, modifier = Modifier.size(48.dp)) {
                Icon(Icons.Filled.PersonAdd, contentDescription = stringResource(R.string.home_add_contact))
            }
            IconButton(onClick = onSettings, modifier = Modifier.size(48.dp)) {
                Icon(Icons.Filled.Settings, contentDescription = stringResource(R.string.home_settings))
            }
            if (onExit != null) {
                IconButton(onClick = onExit, modifier = Modifier.size(48.dp)) {
                    Icon(Icons.Filled.PowerSettingsNew, contentDescription = stringResource(R.string.action_safe_exit))
                }
            }
        }
        ProtectionBar(lockdown, Modifier.padding(horizontal = ScreenPadding))
        if (contacts.isNotEmpty()) {
            SecureTextField(
                search, placeholder = stringResource(R.string.home_search_hint),
                modifier = Modifier.padding(horizontal = ScreenPadding, vertical = Space.md), tag = "search_input",
            )
        }
        if (contacts.isEmpty()) {
            Column(
                Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState()).padding(ScreenPadding),
                verticalArrangement = Arrangement.spacedBy(Space.md, Alignment.CenterVertically),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                StatusHero(Icons.Filled.Contacts, Palette.Accent)
                Text(
                    stringResource(R.string.home_empty_title),
                    style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center,
                )
                Text(
                    stringResource(R.string.home_empty_body),
                    style = MaterialTheme.typography.bodyLarge, color = Palette.OnSurfaceMuted, textAlign = TextAlign.Center,
                )
            }
        } else if (shown.isEmpty()) {
            Column(
                Modifier.weight(1f).fillMaxWidth().padding(ScreenPadding),
                verticalArrangement = Arrangement.spacedBy(Space.md, Alignment.CenterVertically),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Icon(Icons.Filled.Search, contentDescription = null, tint = Palette.Outline, modifier = Modifier.size(40.dp))
                Text(
                    stringResource(R.string.home_no_results),
                    color = Palette.OnSurfaceMuted, textAlign = TextAlign.Center,
                )
            }
        } else {
            LazyColumn(
                Modifier.weight(1f), contentPadding = ContactListPadding,
                verticalArrangement = Arrangement.spacedBy(ContactCardGap),
            ) {
                items(shown, key = { it.id }) { c -> ContactCard(c, null, Modifier.animateItem()) { onOpenContact(c.id) } }
            }
        }
        Column(
            Modifier.padding(horizontal = ScreenPadding, vertical = Space.md),
            verticalArrangement = Arrangement.spacedBy(Space.sm),
        ) {
            if (contacts.isEmpty()) {
                SecondaryButton(stringResource(R.string.home_add_contact), onAddContact, icon = Icons.Filled.PersonAdd)
            }
            PrimaryButton(stringResource(R.string.home_start_call), onStartCall, icon = Icons.Filled.Call)
        }
    }
}

/** Pick a contact or type a number. */
@Composable
fun DialScreen(
    contacts: List<Contact>,
    onCallContact: (Long) -> Unit,
    onCallNumber: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val number = remember { SecureInputState(20, InputKind.PHONE) }
    var selected by rememberSaveable { mutableStateOf<Long?>(null) }
    val host = LocalInputHost.current
    LaunchedEffect(Unit) { if (contacts.isEmpty()) host.focus(number) }
    LaunchedEffect(number.length) { if (number.length > 0) selected = null }
    val valid = selected != null || PhoneRules.isValid(number.text())
    val showError = number.length >= 5 && !PhoneRules.isValid(number.text())

    Column(modifier.fillMaxSize()) {
        TopBar(stringResource(R.string.dial_title), onBack)
        Column(Modifier.padding(horizontal = ScreenPadding), verticalArrangement = Arrangement.spacedBy(Space.sm)) {
            SecureTextField(
                number, label = stringResource(R.string.dial_number_label),
                placeholder = stringResource(R.string.dial_number_hint), isError = showError, tag = "dial_number",
            )
            if (showError) Text(stringResource(R.string.dial_invalid_number), color = Palette.Danger, style = MaterialTheme.typography.bodyMedium)
            if (contacts.isNotEmpty()) {
                Text(
                    stringResource(R.string.dial_pick_contact), style = MaterialTheme.typography.labelLarge,
                    color = Palette.OnSurfaceMuted, modifier = Modifier.padding(top = Space.sm),
                )
            }
        }
        LazyColumn(
            Modifier.weight(1f), contentPadding = ContactListPadding,
            verticalArrangement = Arrangement.spacedBy(ContactCardGap),
        ) {
            items(contacts, key = { it.id }) { c ->
                ContactCard(c, selected == c.id, Modifier.animateItem()) {
                    selected = c.id
                    number.clear()
                    host.blur()
                }
            }
        }
        Column(Modifier.padding(horizontal = ScreenPadding, vertical = Space.md), verticalArrangement = Arrangement.spacedBy(Space.sm)) {
            Text(stringResource(R.string.dial_note), style = MaterialTheme.typography.bodySmall, color = Palette.OnSurfaceMuted)
            PrimaryButton(
                stringResource(R.string.dial_call),
                onClick = {
                    val id = selected
                    if (id != null) onCallContact(id) else onCallNumber(PhoneRules.normalize(number.text()))
                },
                enabled = valid,
                icon = Icons.Filled.Call,
            )
        }
    }
}
