package io.github.h4lovoid.dialcrypt.ui.screens

import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.os.PersistableBundle
import android.view.ViewTreeObserver
import android.view.WindowManager
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.GppBad
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.QrCode2
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.findViewTreeLifecycleOwner
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.core.Contact
import io.github.h4lovoid.dialcrypt.core.ContactResult
import io.github.h4lovoid.dialcrypt.core.ContactTrust
import io.github.h4lovoid.dialcrypt.core.HardwareLevel
import io.github.h4lovoid.dialcrypt.core.InviteCard
import io.github.h4lovoid.dialcrypt.core.PairingPreview
import io.github.h4lovoid.dialcrypt.core.PairingResult
import io.github.h4lovoid.dialcrypt.core.PhoneRules
import io.github.h4lovoid.dialcrypt.core.QuickConnect
import io.github.h4lovoid.dialcrypt.core.SecureCore
import io.github.h4lovoid.dialcrypt.core.real.PairingDecisions
import io.github.h4lovoid.dialcrypt.ui.components.ActionRow
import io.github.h4lovoid.dialcrypt.ui.components.Card
import io.github.h4lovoid.dialcrypt.ui.components.DangerZone
import io.github.h4lovoid.dialcrypt.ui.components.FingerprintGrid
import io.github.h4lovoid.dialcrypt.ui.components.GroupDivider
import io.github.h4lovoid.dialcrypt.ui.components.IconTile
import io.github.h4lovoid.dialcrypt.ui.components.InfoGroup
import io.github.h4lovoid.dialcrypt.ui.components.InfoRow
import io.github.h4lovoid.dialcrypt.ui.components.InlineMessage
import io.github.h4lovoid.dialcrypt.ui.components.PrimaryButton
import io.github.h4lovoid.dialcrypt.ui.components.QrCodeBox
import io.github.h4lovoid.dialcrypt.ui.components.QrScanner
import io.github.h4lovoid.dialcrypt.ui.components.QuietButton
import io.github.h4lovoid.dialcrypt.ui.components.ScreenPadding
import io.github.h4lovoid.dialcrypt.ui.components.ScreenBackHandler
import io.github.h4lovoid.dialcrypt.ui.components.SecondaryButton
import io.github.h4lovoid.dialcrypt.ui.components.SecureDialog
import io.github.h4lovoid.dialcrypt.ui.components.TopBar
import io.github.h4lovoid.dialcrypt.ui.keyboard.InputKind
import io.github.h4lovoid.dialcrypt.ui.keyboard.LocalInputHost
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureInputState
import io.github.h4lovoid.dialcrypt.ui.keyboard.SecureTextField
import io.github.h4lovoid.dialcrypt.ui.model.ContactUi
import io.github.h4lovoid.dialcrypt.ui.model.Formatters
import io.github.h4lovoid.dialcrypt.ui.model.TextMaps
import io.github.h4lovoid.dialcrypt.ui.rememberHaptics
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Radius
import io.github.h4lovoid.dialcrypt.ui.theme.Space
import io.github.h4lovoid.dialcrypt.ui.theme.Tone
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** Section heading inside a card: icon tile and title. */
@Composable
private fun CardTitle(icon: androidx.compose.ui.graphics.vector.ImageVector, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.md)) {
        IconTile(icon)
        Text(text, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
    }
}

/** Everything about one contact. Technical names are fine here. */
@Composable
fun ContactDetailScreen(
    contact: Contact,
    core: SecureCore,
    onBack: () -> Unit,
    onEdit: () -> Unit,
    onCall: () -> Unit,
    onDeleted: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val scope = rememberCoroutineScope()
    val haptics = rememberHaptics()
    val code = remember(contact.id) { SecureInputState(140) }
    var pairingMessage by remember(contact.id) { mutableStateOf<PairingResult?>(null) }
    // A typed code that would replace this contact's pairing waits here for the user to confirm.
    var replaceCode by remember(contact.id) { mutableStateOf<String?>(null) }
    var ownCode by remember(contact.id) { mutableStateOf<String?>(null) }
    var ownCodeUnavailable by remember(contact.id) { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }

    // Back folds the revealed pairing code before it leaves the screen.
    ScreenBackHandler(enabled = ownCode != null) { ownCode = null }

    Column(modifier.fillMaxSize()) {
        TopBar(contact.name, onBack)
        Column(
            Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = ScreenPadding, vertical = Space.sm),
            verticalArrangement = Arrangement.spacedBy(Space.lg),
        ) {
            InfoGroup {
                InfoRow(Icons.Filled.Person, stringResource(R.string.detail_name), contact.name)
                GroupDivider()
                InfoRow(Icons.Filled.Phone, stringResource(R.string.detail_number), contact.number ?: stringResource(R.string.number_hidden))
                GroupDivider()
                ActionRow(Icons.Filled.Edit, stringResource(R.string.detail_edit), onEdit)
            }
            Card {
                CardTitle(Icons.Filled.Fingerprint, stringResource(R.string.detail_fingerprint))
                FingerprintGrid(contact.fingerprint, Modifier.padding(top = Space.xs))
                Text(stringResource(R.string.detail_fingerprint_hint), style = MaterialTheme.typography.bodySmall, color = Palette.OnSurfaceMuted)
            }
            InfoGroup {
                InfoRow(
                    when (contact.trust) {
                        ContactTrust.VERIFIED -> Icons.Filled.VerifiedUser
                        ContactTrust.UNVERIFIED -> Icons.Filled.GppMaybe
                        ContactTrust.KEY_CHANGED -> Icons.Filled.GppBad
                    },
                    stringResource(R.string.detail_identity),
                    stringResource(
                        when (contact.trust) {
                            ContactTrust.VERIFIED -> R.string.detail_verified_yes
                            ContactTrust.UNVERIFIED -> R.string.detail_verified_no
                            ContactTrust.KEY_CHANGED -> R.string.detail_verified_changed
                        },
                    ),
                    tone = ContactUi.status(contact).tone,
                )
                GroupDivider()
                InfoRow(
                    Icons.Filled.Memory,
                    stringResource(R.string.detail_hardware),
                    stringResource(TextMaps.hardwareTitle(contact.hardware)),
                    tone = when (contact.hardware) {
                        HardwareLevel.UNATTESTED -> Tone.WARN
                        HardwareLevel.STRONGBOX_LOCKED -> Tone.OK
                        else -> Tone.NEUTRAL
                    },
                    note = stringResource(TextMaps.hardwareExplain(contact.hardware)),
                )
                GroupDivider()
                InfoRow(
                    Icons.Filled.Bolt,
                    stringResource(R.string.detail_quick),
                    stringResource(TextMaps.quickConnect(contact.quickConnect)),
                    tone = when (contact.quickConnect) {
                        QuickConnect.READY -> Tone.OK
                        QuickConnect.REBUILD_PENDING -> Tone.WARN
                        QuickConnect.UNAVAILABLE -> Tone.NEUTRAL
                    },
                )
                GroupDivider()
                val pairing = ContactUi.pairing(contact)
                InfoRow(
                    Icons.Filled.Link,
                    stringResource(R.string.detail_pairing),
                    stringResource(pairing.textRes),
                    tone = pairing.tone,
                    note = if (pairing.textRes == R.string.detail_paired_waiting) stringResource(R.string.detail_paired_waiting_note) else null,
                )
            }
            Card {
                CardTitle(Icons.Filled.Key, stringResource(R.string.detail_enter_code_title))
                SecureTextField(code, placeholder = stringResource(R.string.detail_code_hint), maxLines = 3, tag = "pair_code_input")
                pairingMessage?.let {
                    InlineMessage(stringResource(TextMaps.pairing(it)), if (it == PairingResult.OK) Tone.OK else Tone.DANGER)
                }
                SecondaryButton(
                    stringResource(R.string.detail_pair_action),
                    onClick = {
                        val typed = code.text().trim()
                        scope.launch {
                            val preview = try {
                                core.previewPairing(typed)
                            } catch (e: Exception) {
                                PairingPreview.Invalid
                            }
                            when (val action = PairingDecisions.detailAction(preview, contact.id)) {
                                PairingDecisions.DetailAction.Submit -> {
                                    val r = core.submitPairingCode(contact.id, typed)
                                    pairingMessage = r
                                    haptics.strong()
                                    if (r == PairingResult.OK) code.clear()
                                }
                                PairingDecisions.DetailAction.ConfirmReplace -> replaceCode = typed
                                is PairingDecisions.DetailAction.Refuse -> {
                                    pairingMessage = action.result
                                    haptics.strong()
                                }
                            }
                        }
                    },
                    enabled = !code.isEmpty,
                    icon = Icons.Filled.Link,
                )
            }
            Card {
                CardTitle(Icons.Filled.Key, stringResource(R.string.detail_my_code_title))
                val shown = ownCode
                if (shown == null) {
                    if (ownCodeUnavailable) {
                        InlineMessage(stringResource(R.string.detail_my_code_unavailable), Tone.DANGER)
                    }
                    SecondaryButton(
                        stringResource(R.string.detail_my_code_show),
                        onClick = {
                            scope.launch {
                                val c = core.ownPairingCode()
                                ownCode = c
                                ownCodeUnavailable = c == null
                            }
                        },
                    )
                } else {
                    Box(
                        Modifier.fillMaxWidth().clip(RoundedCornerShape(Radius.md)).background(Palette.SurfaceHigh).padding(Space.md),
                    ) {
                        Text(
                            Formatters.groupCode(shown),
                            style = MaterialTheme.typography.titleMedium, fontFamily = FontFamily.Monospace,
                        )
                    }
                    Text(stringResource(R.string.detail_my_code_note), style = MaterialTheme.typography.bodySmall, color = Palette.OnSurfaceMuted)
                    QuietButton(stringResource(R.string.detail_my_code_hide), { ownCode = null })
                }
            }
            DangerZone(stringResource(R.string.detail_danger_zone)) {
                SecondaryButton(stringResource(R.string.detail_delete), { confirmDelete = true }, danger = true, icon = Icons.Filled.Delete)
            }
        }
        Column(Modifier.padding(horizontal = ScreenPadding, vertical = Space.md)) {
            PrimaryButton(stringResource(R.string.home_start_call), onCall, icon = Icons.Filled.Call)
        }
    }

    if (confirmDelete) {
        SecureDialog(
            title = stringResource(R.string.delete_title, contact.name),
            text = { Text(stringResource(R.string.delete_body)) },
            confirmButton = {
                QuietButton(stringResource(R.string.detail_delete), {
                    confirmDelete = false
                    scope.launch {
                        if (core.deleteContact(contact.id) == ContactResult.OK) onDeleted()
                    }
                })
            },
            dismissButton = { QuietButton(stringResource(R.string.action_cancel), { confirmDelete = false }) },
            onDismiss = { confirmDelete = false },
        )
    }
    replaceCode?.let { typed ->
        // Same choice as when adding a contact: keeping the current pairing is the main button.
        SecureDialog(
            title = stringResource(R.string.add_replace_title, contact.name),
            text = { Text(stringResource(R.string.add_replace_body, contact.name)) },
            confirmButton = { PrimaryButton(stringResource(R.string.add_replace_keep), { replaceCode = null }) },
            dismissButton = {
                QuietButton(stringResource(R.string.add_replace_confirm), {
                    replaceCode = null
                    scope.launch {
                        val r = core.submitPairingCode(contact.id, typed)
                        pairingMessage = r
                        haptics.strong()
                        if (r == PairingResult.OK) code.clear()
                    }
                })
            },
            onDismiss = { replaceCode = null },
        )
    }
}

/**
 * Name and number form, used when saving a new contact after a verified call and when
 * editing one. The number is only a label for the user, so it must be confirmed.
 */
@Composable
fun ContactFormScreen(
    title: String,
    body: String,
    initialName: String,
    initialNumber: String?,
    numberMayBeEmpty: Boolean,
    confirmLabel: String,
    cancelLabel: String,
    onSubmit: suspend (name: String, number: String?) -> ContactResult,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val name = remember { SecureInputState(40, InputKind.TEXT, initialName) }
    val number = remember { SecureInputState(20, InputKind.PHONE, initialNumber.orEmpty()) }
    var error by remember { mutableStateOf<Int?>(null) }
    var busy by remember { mutableStateOf(false) }
    val host = LocalInputHost.current
    val scope = rememberCoroutineScope()
    val haptics = rememberHaptics()

    LaunchedEffect(Unit) { host.focus(name) }

    val nameOk = name.text().isNotBlank()
    val numberText = number.text()
    val numberOk = if (numberText.isEmpty()) numberMayBeEmpty else PhoneRules.isValid(numberText)

    Column(modifier.fillMaxSize()) {
        TopBar(title, onBack = null)
        Column(
            Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = ScreenPadding, vertical = Space.sm),
            verticalArrangement = Arrangement.spacedBy(Space.lg),
        ) {
            Text(body, style = MaterialTheme.typography.bodyLarge, color = Palette.OnSurfaceMuted)
            Card {
                Column(verticalArrangement = Arrangement.spacedBy(Space.lg)) {
                    SecureTextField(name, label = stringResource(R.string.form_name), tag = "form_name")
                    SecureTextField(
                        number, label = stringResource(R.string.form_number),
                        placeholder = if (numberMayBeEmpty) stringResource(R.string.form_number_optional) else null,
                        isError = numberText.isNotEmpty() && !numberOk, tag = "form_number",
                    )
                }
                if (numberText.isNotEmpty() && !numberOk) {
                    InlineMessage(stringResource(R.string.dial_invalid_number), Tone.DANGER)
                }
                error?.let { InlineMessage(stringResource(it), Tone.DANGER) }
            }
        }
        Column(Modifier.padding(horizontal = ScreenPadding, vertical = Space.md), verticalArrangement = Arrangement.spacedBy(Space.sm)) {
            PrimaryButton(
                confirmLabel,
                onClick = {
                    scope.launch {
                        busy = true
                        val n = PhoneRules.normalize(number.text()).ifEmpty { null }
                        val r = onSubmit(name.text().trim(), n)
                        busy = false
                        error = TextMaps.contactError(r)
                        if (r != ContactResult.OK) haptics.strong()
                    }
                },
                enabled = nameOk && numberOk && !busy,
            )
            QuietButton(cancelLabel, onCancel, Modifier.fillMaxWidth())
        }
    }
}

/**
 * Adds a mutually-paired contact. Face to face, one phone shows its card as a QR code and the other
 * scans it, so nothing is sent through the air; comparing the confirmation code under the QR code is
 * optional. A QR code is taken down after a minute. After saving, the scanning phone shows its own card,
 * tagged to prove it saved theirs; when the first phone scans that, it knows both sides are done. A
 * collapsed remote section copies or pastes `AEGISCARD1:`
 * cards; those still need the confirmation codes compared.
 */
@Composable
fun AddContactScreen(
    core: SecureCore,
    onBack: () -> Unit,
    onAdded: () -> Unit,
    modifier: Modifier = Modifier,
    /** Reads QR codes from the camera; the callback returns true when the text was used. Tests pass a fake. */
    scanner: @Composable (onText: (String) -> Boolean) -> Unit = { QrScanner(it) },
) {
    val context = LocalContext.current
    val view = LocalView.current
    val clipboard = remember(context) { context.getSystemService(ClipboardManager::class.java) }
    val scope = rememberCoroutineScope()
    val haptics = rememberHaptics()

    val myName = remember { SecureInputState(InviteCard.MAX_NAME_CHARS, InputKind.TEXT) }
    val myNumber = remember { SecureInputState(20, InputKind.PHONE) }

    var step by remember { mutableStateOf(AddStep.IDLE) }
    var startNote by remember { mutableStateOf<Pair<Int, Tone>?>(null) }
    // Text of the QR code on screen: our card, made fresh every time it is shown.
    var qrText by remember { mutableStateOf<String?>(null) }
    // Confirmation code of that card exactly as their phone decodes it, shown under the QR code.
    var qrCode by remember { mutableStateOf<String?>(null) }
    // The QR code was up for a minute and has been taken down; the user can show a new one.
    var qrHidden by remember { mutableStateOf(false) }
    // Every card shown as a QR code on this page. A scanned card tagged for one of them comes from a phone that saved us.
    val shownCards = remember { mutableListOf<InviteCard>() }
    // The card saved in this exchange; our QR code shown after it carries a tag saying so.
    var savedPeerCard by remember { mutableStateOf<InviteCard?>(null) }
    var scanNote by remember { mutableStateOf<Pair<Int, Tone>?>(null) }

    // A received card waits here until the user saves or discards it.
    var pending by remember { mutableStateOf<InviteCard?>(null) }
    // A remote card still needs the confirmation codes compared; a scanned one was read straight off their screen.
    var pendingRemote by remember { mutableStateOf(false) }
    // The card carries a valid tag for a card we showed, so its phone already saved us.
    var pendingAnswersUs by remember { mutableStateOf(false) }
    // Name of the saved contact holding this card's identity key with another pairing: saving would replace it.
    var replacingName by remember { mutableStateOf<String?>(null) }
    // The core is still working out what saving this card would do; saving waits for it.
    var previewing by remember { mutableStateOf(false) }
    // What saving this card would do; only a clear answer (new, unchanged, or a confirmed replacement) can be saved.
    var previewResult by remember { mutableStateOf<PairingPreview?>(null) }
    val peerName = remember { SecureInputState(InviteCard.MAX_NAME_CHARS, InputKind.TEXT) }
    val peerNumber = remember { SecureInputState(20, InputKind.PHONE) }
    var saving by remember { mutableStateOf(false) }
    var saveError by remember { mutableStateOf<Int?>(null) }

    var remoteOpen by remember { mutableStateOf(false) }
    val peerCardInput = remember { SecureInputState(260, InputKind.TEXT) }
    var remoteNote by remember { mutableStateOf<Pair<Int, Tone>?>(null) }
    // The card we copied last, as the other phone decodes it; its confirmation code is shown for the check.
    var copiedSent by remember { mutableStateOf<InviteCard?>(null) }
    val copiedCard = remember { AtomicReference<String?>(null) }
    val clearArmed = remember { AtomicBoolean(false) }
    var copyRound by remember { mutableIntStateOf(0) }
    var copiedOnce by remember { mutableStateOf(false) }
    var confirmRotate by remember { mutableStateOf(false) }

    fun ownName(): String = InviteCard.sanitizeName(myName.text())

    fun ownNumber(): String? = myNumber.text().trim().takeIf { it.isNotEmpty() }

    /** Clears the clipboard only when it can be read and still holds our card. False: not readable yet. */
    fun clearOwnClip(): Boolean {
        val ours = copiedCard.get() ?: return true
        val cm = clipboard ?: return true
        val clip = runCatching { cm.primaryClip }.getOrNull()
        if (clip == null) {
            // Android hides the clipboard from an app without window focus; with focus it is just empty.
            if (!view.hasWindowFocus()) return false
            copiedCard.compareAndSet(ours, null)
            return true
        }
        val current = clip.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()
        if (current == ours) runCatching { cm.clearPrimaryClip() }
        copiedCard.compareAndSet(ours, null)
        return true
    }

    /** Clears now, or once the app is back in front (ON_RESUME or window focus), even after this page is gone. */
    fun clearOwnClipSoon() {
        if (clearOwnClip() || !clearArmed.compareAndSet(false, true)) return
        val lifecycle = view.findViewTreeLifecycleOwner()?.lifecycle
        val observer = view.viewTreeObserver
        lateinit var onResume: LifecycleEventObserver
        lateinit var onFocus: ViewTreeObserver.OnWindowFocusChangeListener
        fun retry() {
            if (!clearOwnClip()) return
            lifecycle?.removeObserver(onResume)
            if (observer.isAlive) observer.removeOnWindowFocusChangeListener(onFocus)
            clearArmed.set(false)
        }
        onResume = LifecycleEventObserver { _, event -> if (event == Lifecycle.Event.ON_RESUME) retry() }
        onFocus = ViewTreeObserver.OnWindowFocusChangeListener { focused -> if (focused) retry() }
        if (observer.isAlive) observer.addOnWindowFocusChangeListener(onFocus)
        lifecycle?.addObserver(onResume)
    }

    fun hideQr() {
        qrText = null
        qrCode = null
        qrHidden = false
    }

    /** Shows a fresh card of ours as a QR code; after saving their card it carries the tag for it. */
    fun showQr(next: AddStep) {
        step = next
        hideQr()
        startNote = null
        scope.launch {
            val peer = savedPeerCard
            val tag = peer?.let { p -> core.ownPairingCode()?.let { InviteCard.replyTag(p, it) } }
            val card = core.ownInviteCard(ownName(), ownNumber())?.let { if (tag != null) it.copy(replyTo = tag) else it }
            val txt = card?.toTextCard()
            val code = card?.wireCopy()?.fingerprint()
            if (step != next) return@launch
            if (card == null || txt == null || code == null) {
                startNote = R.string.add_qr_failed to Tone.DANGER
                if (next == AddStep.SHOW) step = AddStep.IDLE
                return@launch
            }
            shownCards += card
            qrText = txt
            qrCode = code
        }
    }

    fun toStart() {
        hideQr()
        scanNote = null
        step = AddStep.IDLE
    }

    fun startScan() {
        hideQr()
        scanNote = null
        startNote = null
        step = AddStep.SCAN
    }

    fun receive(card: InviteCard, remote: Boolean) {
        pending = card
        pendingRemote = remote
        pendingAnswersUs = !remote && shownCards.any { InviteCard.answers(card, it) }
        saveError = null
        startNote = null
        scanNote = null
        remoteNote = null
        hideQr()
        peerName.clear()
        peerName.replace(card.name)
        peerNumber.clear()
        card.number?.let { peerNumber.replace(it) }
        step = AddStep.CONFIRM
        replacingName = null
        previewResult = null
        previewing = true
        scope.launch {
            val preview = try {
                core.previewPairing(card.code)
            } catch (e: Exception) {
                PairingPreview.Invalid
            }
            if (pending !== card) return@launch
            val holder = when (preview) {
                is PairingPreview.Replaces -> preview.contactId
                is PairingPreview.Unchanged -> preview.contactId
                else -> null
            }?.let { id -> core.contacts.value.firstOrNull { it.id == id } }
            if (holder != null) {
                // A saved contact keeps its name and number unless the user changes them here.
                peerName.clear()
                peerName.replace(holder.name)
                peerNumber.clear()
                holder.number?.let { peerNumber.replace(it) }
            }
            if (preview is PairingPreview.Replaces) replacingName = holder?.name ?: InviteCard.sanitizeName(card.name)
            if (PairingDecisions.confirmFor(preview) == PairingDecisions.Confirm.REFUSE) {
                saveError = TextMaps.pairing(PairingResult.FAILED)
            }
            previewResult = preview
            previewing = false
        }
    }

    fun clearPending() {
        pending = null
        pendingAnswersUs = false
        replacingName = null
        previewResult = null
        previewing = false
        saveError = null
        peerName.clear()
        peerNumber.clear()
    }

    /** One decoded QR code. True: used. False: not a card of ours, keep scanning. */
    fun onScanned(text: String): Boolean {
        if (step != AddStep.SCAN) return true
        val trimmed = text.trim()
        // Only full cards from this app; a bare pairing code in some other QR code is not taken.
        val card = if (trimmed.startsWith("AEGISCARD1:", ignoreCase = true)) InviteCard.parse(trimmed) else null
        if (card == null) {
            scanNote = R.string.add_scan_not_card to Tone.WARN
            return false
        }
        haptics.tick()
        receive(card, remote = false)
        return true
    }

    fun save() {
        val card = pending ?: return
        val name = InviteCard.sanitizeName(peerName.text())
        if (name.isEmpty() || saving) return
        scope.launch {
            saving = true
            saveError = null
            val num = peerNumber.text().trim().takeIf { it.isNotEmpty() }
            // A card tagged for one we showed proves they saved us, so the pairing is mutual from the start.
            val answersUs = pendingAnswersUs
            // The bare pairing code carries no name or number, so only what is on screen is saved.
            val r = core.addPairedContact(name, num, card.code, mutual = answersUs)
            saving = false
            if (r != PairingResult.OK) {
                haptics.strong()
                saveError = TextMaps.pairing(r)
                return@launch
            }
            haptics.tick()
            val remote = pendingRemote
            clearPending()
            savedPeerCard = card
            when {
                remote -> step = AddStep.REMOTE_SAVED
                // Their card carries a valid tag for one we showed: they saved us, so both sides are done.
                answersUs -> step = AddStep.BOTH_DONE
                // They have not saved us yet: show our card, tagged so their phone knows we saved them.
                else -> showQr(AddStep.REPLY)
            }
        }
    }

    fun discard() {
        clearPending()
        toStart()
        startNote = R.string.add_discarded to Tone.WARN
    }

    fun copyCard() {
        val cm = clipboard ?: return
        scope.launch {
            val txt = core.ownInviteCard(ownName(), ownNumber())?.toTextCard()
            val sent = txt?.let { InviteCard.parse(it) }
            if (txt == null || sent == null) {
                remoteNote = TextMaps.pairing(PairingResult.FAILED) to Tone.DANGER
                return@launch
            }
            val clip = ClipData.newPlainText("card", txt)
            val sensitiveKey = if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE"
            clip.description.extras = PersistableBundle().apply { putBoolean(sensitiveKey, true) }
            cm.setPrimaryClip(clip)
            copiedCard.set(txt)
            copyRound++
            copiedOnce = true
            copiedSent = sent
            remoteNote = R.string.add_card_copied to Tone.OK
            haptics.tick()
        }
    }

    fun pasteCard() {
        val cm = clipboard ?: return
        val clip = runCatching { cm.primaryClip }.getOrNull()
        val txt = clip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString()
        val card = txt?.let { InviteCard.parse(it) }
        if (card == null) {
            remoteNote = TextMaps.pairing(PairingResult.BAD_FORMAT) to Tone.DANGER
            return
        }
        runCatching { cm.clearPrimaryClip() }
        copiedCard.set(null)
        receive(card, remote = true)
    }

    fun checkTyped() {
        val card = InviteCard.parse(peerCardInput.text())
        if (card == null) {
            remoteNote = TextMaps.pairing(PairingResult.BAD_FORMAT) to Tone.DANGER
            return
        }
        peerCardInput.clear()
        receive(card, remote = true)
    }

    fun rotate() {
        confirmRotate = false
        scope.launch {
            val made = core.rotatePairingCode() != null
            // Whether or not it worked, no card made before stays on screen or counts for tags:
            // whatever is shown from now on is made again from the code in use.
            shownCards.clear()
            copiedSent = null
            copiedOnce = false
            remoteNote = null
            clearOwnClipSoon()
            val showing = step == AddStep.SHOW || step == AddStep.REPLY
            hideQr()
            if (showing) showQr(step)
            startNote = if (made) null else TextMaps.pairing(PairingResult.FAILED) to Tone.DANGER
        }
    }

    LaunchedEffect(copyRound) {
        if (copyRound == 0) return@LaunchedEffect
        delay(60_000)
        clearOwnClipSoon()
    }
    // Back folds the open remote section first; otherwise it leaves the page like the arrow does.
    ScreenBackHandler(enabled = remoteOpen) { remoteOpen = false }
    // A QR code stays up for at most a minute, then is taken down (with full brightness) until shown again.
    LaunchedEffect(qrText) {
        if (qrText == null) return@LaunchedEffect
        delay(60_000)
        qrText = null
        qrCode = null
        qrHidden = true
    }
    DisposableEffect(Unit) {
        onDispose { clearOwnClipSoon() }
    }
    // Leaving the foreground locks the app, and the screen timing out counts, so the screen stays on on this page.
    DisposableEffect(view) {
        val keptBefore = view.keepScreenOn
        view.keepScreenOn = true
        onDispose { view.keepScreenOn = keptBefore }
    }
    // Full brightness while our QR code is on screen, so their camera reads it quickly; the old level comes back after.
    val showingQr = qrText != null && (step == AddStep.SHOW || step == AddStep.REPLY)
    DisposableEffect(showingQr) {
        // The view's context is the activity; LocalContext may be a language-specific copy that is not.
        var ctx: Context? = view.context
        while (ctx is ContextWrapper && ctx !is Activity) ctx = ctx.baseContext
        val window = if (showingQr) (ctx as? Activity)?.window else null
        val before = window?.attributes?.screenBrightness
        if (window != null) {
            val lp = window.attributes
            lp.screenBrightness = WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_FULL
            window.attributes = lp
        }
        onDispose {
            if (window != null && before != null) {
                val lp = window.attributes
                lp.screenBrightness = before
                window.attributes = lp
            }
        }
    }

    val codeBox: @Composable (String?, String) -> Unit = { code, tag ->
        Box(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(Radius.md)).background(Palette.SurfaceHigh).padding(Space.md),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                code ?: "—",
                style = MaterialTheme.typography.headlineSmall,
                fontFamily = FontFamily.Monospace,
                color = Palette.Accent,
                modifier = Modifier.testTag(tag),
            )
        }
    }
    val qrBox: @Composable (String) -> Unit = { txt ->
        // A wide white margin around the code (on top of QrCodeBox's own) helps the camera find it.
        Box(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(Radius.md)).background(Color.White).padding(Space.lg).testTag("add_my_qr"),
            contentAlignment = Alignment.Center,
        ) {
            QrCodeBox(txt, Modifier.fillMaxWidth())
        }
    }
    // Our QR code with its confirmation code underneath, or, once it timed out, a way to show a new one.
    val qrPanel: @Composable () -> Unit = {
        val txt = qrText
        val code = qrCode
        if (txt != null && code != null) {
            qrBox(txt)
            Text(stringResource(R.string.add_my_code), style = MaterialTheme.typography.titleSmall)
            codeBox(code, "add_my_qr_code")
        } else if (qrHidden) {
            InlineMessage(stringResource(R.string.add_qr_hidden), Tone.WARN)
            SecondaryButton(stringResource(R.string.add_qr_show_again), onClick = { showQr(step) }, icon = Icons.Filled.QrCode2)
        }
    }
    val myCode: @Composable () -> Unit = {
        remember(copiedSent) { copiedSent?.fingerprint() }?.let { code ->
            Text(stringResource(R.string.add_my_code), style = MaterialTheme.typography.titleSmall)
            codeBox(code, "add_my_code")
            Text(stringResource(R.string.add_my_code_hint), style = MaterialTheme.typography.bodyMedium, color = Palette.OnSurfaceMuted)
        }
    }

    Column(modifier.fillMaxSize()) {
        TopBar(stringResource(R.string.add_contact_title), onBack)
        Column(
            Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = ScreenPadding, vertical = Space.sm),
            verticalArrangement = Arrangement.spacedBy(Space.lg),
        ) {
            InlineMessage(stringResource(R.string.add_both_sides), Tone.WARN)

            when (step) {
                AddStep.IDLE -> {
                    Card {
                        CardTitle(Icons.Filled.Person, stringResource(R.string.add_my_card))
                        SecureTextField(
                            myName,
                            label = stringResource(R.string.add_my_name),
                            placeholder = stringResource(R.string.add_my_name_hint),
                            tag = "add_my_name",
                        )
                        SecureTextField(
                            myNumber,
                            label = stringResource(R.string.form_number),
                            placeholder = stringResource(R.string.form_number_optional),
                            tag = "add_my_number",
                        )
                    }
                    startNote?.let { (res, tone) -> InlineMessage(stringResource(res), tone) }
                    PrimaryButton(stringResource(R.string.add_show_qr), onClick = { showQr(AddStep.SHOW) }, icon = Icons.Filled.QrCode2)
                    SecondaryButton(stringResource(R.string.add_scan_qr), onClick = ::startScan, icon = Icons.Filled.QrCodeScanner)

                    Card {
                        Row(
                            Modifier.fillMaxWidth().clickable { remoteOpen = !remoteOpen },
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(Space.md),
                        ) {
                            IconTile(Icons.Filled.Link)
                            Text(stringResource(R.string.add_remote_title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                            Icon(
                                if (remoteOpen) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                                contentDescription = null,
                                tint = Palette.OnSurfaceMuted,
                            )
                        }
                        if (remoteOpen) {
                            InlineMessage(stringResource(R.string.add_remote_warning), Tone.WARN)
                            remoteNote?.let { (res, tone) -> InlineMessage(stringResource(res), tone) }
                            SecondaryButton(stringResource(R.string.add_card_copy), onClick = ::copyCard, icon = Icons.Filled.ContentCopy)
                            myCode()
                            SecondaryButton(stringResource(R.string.add_card_paste), onClick = ::pasteCard, icon = Icons.Filled.ContentPaste)
                            SecureTextField(peerCardInput, label = stringResource(R.string.add_peer_card_hint), tag = "add_peer_card")
                            SecondaryButton(
                                stringResource(R.string.add_card_check),
                                onClick = ::checkTyped,
                                enabled = !peerCardInput.isEmpty,
                                icon = Icons.Filled.Key,
                            )
                        }
                    }

                    QuietButton(
                        stringResource(R.string.add_code_rotate),
                        onClick = { confirmRotate = true },
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                AddStep.SHOW -> Card {
                    CardTitle(Icons.Filled.QrCode2, stringResource(R.string.add_qr_title))
                    qrPanel()
                    Text(stringResource(R.string.add_qr_show_body), style = MaterialTheme.typography.bodyMedium, color = Palette.OnSurfaceMuted)
                    PrimaryButton(stringResource(R.string.add_scan_qr), onClick = ::startScan, icon = Icons.Filled.QrCodeScanner)
                    QuietButton(stringResource(R.string.action_cancel), onClick = ::toStart, modifier = Modifier.fillMaxWidth())
                }
                AddStep.SCAN -> Card {
                    CardTitle(Icons.Filled.QrCodeScanner, stringResource(R.string.add_scan_qr))
                    Text(stringResource(R.string.add_scan_body), style = MaterialTheme.typography.bodyMedium, color = Palette.OnSurfaceMuted)
                    scanNote?.let { (res, tone) -> InlineMessage(stringResource(res), tone) }
                    scanner { onScanned(it) }
                    SecondaryButton(stringResource(R.string.add_show_qr), onClick = { showQr(AddStep.SHOW) }, icon = Icons.Filled.QrCode2)
                    QuietButton(stringResource(R.string.action_cancel), onClick = ::toStart, modifier = Modifier.fillMaxWidth())
                }
                AddStep.CONFIRM -> pending?.let { card ->
                    Card {
                        val peerCode = remember(card) { card.fingerprint() }
                        val replacing = replacingName
                        if (replacing != null) {
                            CardTitle(Icons.Filled.Warning, stringResource(R.string.add_replace_title, replacing))
                            InlineMessage(stringResource(R.string.add_replace_body, replacing), Tone.DANGER)
                        }
                        if (pendingRemote) {
                            CardTitle(Icons.Filled.Fingerprint, stringResource(R.string.add_confirm_title))
                            Text(stringResource(R.string.add_peer_code), style = MaterialTheme.typography.bodyMedium, color = Palette.OnSurfaceMuted)
                            codeBox(peerCode, "add_peer_code")
                            InlineMessage(stringResource(R.string.add_confirm_body_remote), Tone.WARN)
                        } else {
                            // A scanned card was read straight off their screen; comparing the code is optional.
                            CardTitle(Icons.Filled.Person, stringResource(R.string.add_scanned_title))
                            Text(stringResource(R.string.add_peer_code), style = MaterialTheme.typography.bodyMedium, color = Palette.OnSurfaceMuted)
                            codeBox(peerCode, "add_peer_code")
                            Text(stringResource(R.string.add_scanned_code_hint), style = MaterialTheme.typography.bodyMedium, color = Palette.OnSurfaceMuted)
                        }
                        SecureTextField(peerName, label = stringResource(R.string.form_name), tag = "add_peer_name")
                        SecureTextField(
                            peerNumber,
                            label = stringResource(R.string.form_number),
                            placeholder = stringResource(R.string.form_number_optional),
                            tag = "add_peer_number",
                        )
                        saveError?.let { InlineMessage(stringResource(it), Tone.DANGER) }
                        val confirm = PairingDecisions.confirmFor(if (previewing) null else previewResult)
                        val canSave = !saving && confirm != PairingDecisions.Confirm.REFUSE &&
                            peerCode != null && InviteCard.sanitizeName(peerName.text()).isNotEmpty()
                        if (replacing != null) {
                            // Replacing a pairing is never the default: keeping it is the main button.
                            PrimaryButton(stringResource(R.string.add_replace_keep), onClick = ::discard, enabled = !saving, icon = Icons.Filled.Close)
                            SecondaryButton(
                                stringResource(R.string.add_replace_confirm),
                                onClick = ::save,
                                enabled = canSave,
                                danger = true,
                                icon = Icons.Filled.Check,
                            )
                        } else {
                            PrimaryButton(
                                stringResource(if (pendingRemote) R.string.add_confirm_save else R.string.action_save),
                                onClick = ::save,
                                enabled = canSave,
                                icon = Icons.Filled.Check,
                            )
                            SecondaryButton(
                                stringResource(if (pendingRemote) R.string.add_confirm_discard else R.string.add_discard),
                                onClick = ::discard,
                                enabled = !saving,
                                icon = Icons.Filled.Close,
                            )
                        }
                    }
                }
                AddStep.REPLY -> Card {
                    InlineMessage(stringResource(R.string.add_saved), Tone.OK)
                    InlineMessage(stringResource(R.string.add_qr_your_turn), Tone.WARN)
                    qrPanel()
                    InlineMessage(stringResource(R.string.add_reply_paired_later), Tone.NEUTRAL)
                    startNote?.let { (res, tone) -> InlineMessage(stringResource(res), tone) }
                    PrimaryButton(stringResource(R.string.add_done), onClick = onAdded, icon = Icons.Filled.Check)
                }
                AddStep.BOTH_DONE -> Card {
                    InlineMessage(stringResource(R.string.add_both_done), Tone.OK)
                    PrimaryButton(stringResource(R.string.add_done), onClick = onAdded, icon = Icons.Filled.Check)
                }
                AddStep.REMOTE_SAVED -> Card {
                    InlineMessage(stringResource(R.string.add_saved), Tone.OK)
                    InlineMessage(stringResource(R.string.add_remote_saved), Tone.WARN)
                    remoteNote?.let { (res, tone) -> InlineMessage(stringResource(res), tone) }
                    if (!copiedOnce) {
                        SecondaryButton(stringResource(R.string.add_card_copy), onClick = ::copyCard, icon = Icons.Filled.ContentCopy)
                    }
                    myCode()
                    PrimaryButton(stringResource(R.string.add_done), onClick = onAdded, icon = Icons.Filled.Check)
                }
            }
        }
    }

    if (confirmRotate) {
        SecureDialog(
            title = stringResource(R.string.add_rotate_title),
            text = { Text(stringResource(R.string.add_rotate_body)) },
            confirmButton = { QuietButton(stringResource(R.string.add_rotate_confirm), ::rotate) },
            dismissButton = { QuietButton(stringResource(R.string.action_cancel), { confirmRotate = false }) },
            onDismiss = { confirmRotate = false },
        )
    }
}

/** Where [AddContactScreen] is in the exchange. */
private enum class AddStep {
    IDLE,
    /** Our QR code is on screen for them to scan. */
    SHOW,
    SCAN,
    /** A received card waits to be saved or discarded. */
    CONFIRM,
    /** Saved their scanned card; our tagged QR code is on screen so they can add us too. */
    REPLY,
    BOTH_DONE,
    REMOTE_SAVED,
}
