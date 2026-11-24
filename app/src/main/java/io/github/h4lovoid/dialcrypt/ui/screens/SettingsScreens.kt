package io.github.h4lovoid.dialcrypt.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Call
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.h4lovoid.dialcrypt.BuildConfig
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.core.AppLanguage
import io.github.h4lovoid.dialcrypt.core.BiometricState
import io.github.h4lovoid.dialcrypt.core.LockdownPhase
import io.github.h4lovoid.dialcrypt.core.LockdownState
import io.github.h4lovoid.dialcrypt.ui.components.ActionRow
import io.github.h4lovoid.dialcrypt.ui.components.Card
import io.github.h4lovoid.dialcrypt.ui.components.DangerZone
import io.github.h4lovoid.dialcrypt.ui.components.GroupDivider
import io.github.h4lovoid.dialcrypt.ui.components.HoldToConfirmButton
import io.github.h4lovoid.dialcrypt.ui.components.IconTile
import io.github.h4lovoid.dialcrypt.ui.components.InfoGroup
import io.github.h4lovoid.dialcrypt.ui.components.InfoRow
import io.github.h4lovoid.dialcrypt.ui.components.InlineMessage
import io.github.h4lovoid.dialcrypt.ui.components.PrimaryButton
import io.github.h4lovoid.dialcrypt.ui.components.QuietButton
import io.github.h4lovoid.dialcrypt.ui.components.ScreenPadding
import io.github.h4lovoid.dialcrypt.ui.components.SecondaryButton
import io.github.h4lovoid.dialcrypt.ui.components.SecureDialog
import io.github.h4lovoid.dialcrypt.ui.components.SectionLabel
import io.github.h4lovoid.dialcrypt.ui.components.TopBar
import io.github.h4lovoid.dialcrypt.ui.model.TextMaps
import io.github.h4lovoid.dialcrypt.incoming.screen.IncomingMode
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Space
import io.github.h4lovoid.dialcrypt.ui.theme.Tone

@Composable
fun SettingsScreen(
    language: AppLanguage,
    onLanguage: (AppLanguage) -> Unit,
    lockdown: LockdownState,
    pinChanged: Boolean,
    onBack: () -> Unit,
    onChangePin: () -> Unit,
    onAbout: () -> Unit,
    onWipeConfirmed: () -> Unit,
    modifier: Modifier = Modifier,
    incomingMode: IncomingMode = IncomingMode.CONTACTS,
    onIncomingMode: (IncomingMode) -> Unit = {},
    showFullNumbers: Boolean = false,
    onShowFullNumbers: (Boolean) -> Unit = {},
    phoneApp: PhoneAppSettings? = null,
    onExit: (() -> Unit)? = null,
    biometric: BiometricSettings? = null,
) {
    var confirmWipe by remember { mutableStateOf(false) }
    var confirmBio by remember { mutableStateOf(false) }
    var noFingerprint by remember { mutableStateOf(false) }
    Column(modifier.fillMaxSize()) {
        TopBar(stringResource(R.string.settings_title), onBack)
        Column(
            Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = ScreenPadding, vertical = Space.sm),
            verticalArrangement = Arrangement.spacedBy(Space.lg),
        ) {
            Card {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.md)) {
                    IconTile(Icons.Filled.Language)
                    Text(stringResource(R.string.settings_language), style = MaterialTheme.typography.titleMedium)
                }
                OptionRow(R.string.lang_system, language == AppLanguage.SYSTEM) { onLanguage(AppLanguage.SYSTEM) }
                OptionRow(R.string.lang_en, language == AppLanguage.EN) { onLanguage(AppLanguage.EN) }
                OptionRow(R.string.lang_es, language == AppLanguage.ES) { onLanguage(AppLanguage.ES) }
                OptionRow(R.string.lang_fr, language == AppLanguage.FR) { onLanguage(AppLanguage.FR) }
                OptionRow(R.string.lang_zh_hans, language == AppLanguage.ZH_HANS) { onLanguage(AppLanguage.ZH_HANS) }
            }
            Card {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.md)) {
                    IconTile(Icons.Filled.Call)
                    Text(stringResource(R.string.settings_incoming_title), style = MaterialTheme.typography.titleMedium)
                }
                OptionRow(R.string.incoming_mode_contacts, incomingMode == IncomingMode.CONTACTS) {
                    onIncomingMode(IncomingMode.CONTACTS)
                }
                OptionRow(R.string.incoming_mode_all, incomingMode == IncomingMode.ALL) {
                    onIncomingMode(IncomingMode.ALL)
                }
                OptionRow(R.string.incoming_mode_off, incomingMode == IncomingMode.OFF) {
                    onIncomingMode(IncomingMode.OFF)
                }
            }
            InfoGroup {
                ToggleRow(
                    Icons.Filled.Visibility,
                    stringResource(R.string.settings_full_numbers_title),
                    stringResource(R.string.settings_full_numbers_note),
                    showFullNumbers,
                    onShowFullNumbers,
                )
            }
            if (phoneApp != null) PhoneAppSection(phoneApp)
            SectionLabel(stringResource(R.string.settings_pin))
            InfoGroup(Modifier.padding(top = Space.xs)) {
                if (pinChanged) {
                    InlineMessage(
                        stringResource(R.string.settings_pin_changed), Tone.OK,
                        Modifier.padding(horizontal = Space.lg, vertical = Space.md),
                    )
                    GroupDivider()
                }
                ActionRow(Icons.Filled.Password, stringResource(R.string.settings_change_pin), onChangePin)
                if (biometric != null) {
                    GroupDivider()
                    val on = biometric.state == BiometricState.READY || biometric.state == BiometricState.NEEDS_PIN
                    ToggleRow(
                        Icons.Filled.Fingerprint,
                        stringResource(R.string.settings_bio_title),
                        stringResource(if (on) R.string.settings_bio_on else R.string.settings_bio_off),
                        on,
                        onChecked = { turnOn ->
                            noFingerprint = false
                            when {
                                !turnOn -> biometric.onTurnOff()
                                !biometric.hasFingerprint -> noFingerprint = true
                                else -> confirmBio = true
                            }
                        },
                        enabled = biometric.state != BiometricState.UNAVAILABLE,
                        tag = BiometricSettings.TOGGLE_TAG,
                    )
                    val note = when {
                        noFingerprint -> R.string.settings_bio_no_fingerprint to Tone.WARN
                        biometric.state == BiometricState.INVALIDATED -> R.string.settings_bio_invalidated to Tone.WARN
                        biometric.state == BiometricState.UNAVAILABLE || biometric.failed -> R.string.settings_bio_failed to Tone.DANGER
                        else -> null
                    }
                    note?.let { (text, tone) ->
                        InlineMessage(stringResource(text), tone, Modifier.padding(horizontal = Space.lg, vertical = Space.md))
                    }
                }
            }
            InfoGroup {
                InfoRow(
                    Icons.Filled.Shield,
                    stringResource(R.string.settings_level),
                    stringResource(TextMaps.hardeningLevel(lockdown.level)),
                    tone = when (lockdown.phase) {
                        LockdownPhase.READY -> Tone.OK
                        LockdownPhase.FAILED -> Tone.DANGER
                        LockdownPhase.PREPARING -> Tone.NEUTRAL
                        LockdownPhase.IDLE, LockdownPhase.NOT_CONNECTED -> Tone.WARN
                    },
                    note = stringResource(R.string.settings_level_note),
                )
                GroupDivider()
                ActionRow(Icons.Filled.Info, stringResource(R.string.settings_about), onAbout)
                if (onExit != null) {
                    GroupDivider()
                    ActionRow(Icons.Filled.PowerSettingsNew, stringResource(R.string.action_safe_exit), onExit)
                }
            }
            DangerZone(stringResource(R.string.danger_zone)) {
                SecondaryButton(stringResource(R.string.settings_wipe), { confirmWipe = true }, danger = true, icon = Icons.Filled.DeleteForever)
            }
        }
    }
    if (confirmWipe) {
        SecureDialog(
            title = stringResource(R.string.wipe_title),
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(Space.lg)) {
                    Text(stringResource(R.string.wipe_body))
                    HoldToConfirmButton(stringResource(R.string.wipe_action), onConfirmed = { confirmWipe = false; onWipeConfirmed() })
                }
            },
            confirmButton = { QuietButton(stringResource(R.string.action_cancel), { confirmWipe = false }) },
            onDismiss = { confirmWipe = false },
        )
    }
    if (confirmBio && biometric != null) {
        SecureDialog(
            title = stringResource(R.string.settings_bio_warning_title),
            text = { Text(stringResource(R.string.settings_bio_warning)) },
            confirmButton = {
                PrimaryButton(stringResource(R.string.settings_bio_turn_on), { confirmBio = false; biometric.onTurnOn() })
            },
            dismissButton = { QuietButton(stringResource(R.string.action_cancel), { confirmBio = false }) },
            onDismiss = { confirmBio = false },
        )
    }
}

/**
 * The "Fingerprint to answer secure calls" switch. Turning it on asks for the PIN once more
 * (the vault locks) and then for a fingerprint; turning it off needs nothing.
 */
class BiometricSettings(
    val state: BiometricState,
    val hasFingerprint: Boolean,
    val failed: Boolean,
    val onTurnOn: () -> Unit,
    val onTurnOff: () -> Unit,
) {
    companion object {
        const val TOGGLE_TAG = "settings_bio_toggle"
    }
}

/**
 * State and actions of the "Phone app" section. The role state is read from the system each time;
 * the section is only passed in builds that allow taking the default dialer role.
 */
class PhoneAppSettings(
    val held: Boolean,
    val screeningHeld: Boolean,
    val onUse: () -> Unit,
    val onRestore: () -> Unit,
    val onTakeScreening: () -> Unit,
)

/** Test tags of the "Phone app" section. */
object PhoneAppTags {
    const val SECTION = "settings_phone_app"
    const val ENABLE = "settings_dialer_enable"
    const val RESTORE = "settings_dialer_restore"
    const val SCREENING_ENABLE = "settings_screening_enable"
    const val SCREENING_ON = "settings_screening_on"
}

@Composable
private fun PhoneAppSection(s: PhoneAppSettings) {
    Card(Modifier.testTag(PhoneAppTags.SECTION)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(Space.md)) {
            IconTile(Icons.Filled.Phone)
            Text(stringResource(R.string.settings_dialer_title), style = MaterialTheme.typography.titleMedium)
        }
        Text(
            stringResource(if (s.held) R.string.settings_dialer_on else R.string.settings_dialer_off),
            style = MaterialTheme.typography.bodyLarge,
        )
        Text(stringResource(R.string.settings_dialer_note), style = MaterialTheme.typography.bodySmall, color = Palette.OnSurfaceMuted)
        if (s.held) {
            SecondaryButton(stringResource(R.string.settings_dialer_restore), s.onRestore, Modifier.testTag(PhoneAppTags.RESTORE))
            if (s.screeningHeld) {
                Text(
                    stringResource(R.string.settings_screening_on),
                    modifier = Modifier.testTag(PhoneAppTags.SCREENING_ON),
                    style = MaterialTheme.typography.bodyMedium,
                )
            } else {
                SecondaryButton(
                    stringResource(R.string.settings_screening_enable),
                    s.onTakeScreening,
                    Modifier.testTag(PhoneAppTags.SCREENING_ENABLE),
                )
                Text(
                    stringResource(R.string.settings_screening_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = Palette.OnSurfaceMuted,
                )
            }
        } else {
            SecondaryButton(
                stringResource(R.string.settings_dialer_enable),
                s.onUse,
                Modifier.testTag(PhoneAppTags.ENABLE),
                icon = Icons.Filled.Phone,
            )
        }
    }
}

@Composable
private fun OptionRow(label: Int, selected: Boolean, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).selectable(selected = selected, role = Role.RadioButton, onClick = onClick),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(
            selected = selected, onClick = null,
            colors = RadioButtonDefaults.colors(selectedColor = Palette.Accent, unselectedColor = Palette.Outline),
        )
        Text(stringResource(label), modifier = Modifier.padding(start = Space.md), style = MaterialTheme.typography.bodyLarge)
    }
}

/** Icon tile, title with a note, and a switch; the whole row toggles. */
@Composable
private fun ToggleRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    note: String,
    checked: Boolean,
    onChecked: (Boolean) -> Unit,
    enabled: Boolean = true,
    tag: String? = null,
) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 64.dp)
            .let { if (tag != null) it.testTag(tag) else it }
            .toggleable(value = checked, enabled = enabled, role = Role.Switch, onValueChange = onChecked)
            .padding(horizontal = Space.lg, vertical = Space.md),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.md),
    ) {
        IconTile(icon)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(note, style = MaterialTheme.typography.bodySmall, color = Palette.OnSurfaceMuted)
        }
        Switch(
            checked = checked, onCheckedChange = null, enabled = enabled,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Palette.Background, checkedTrackColor = Palette.Accent,
                uncheckedThumbColor = Palette.Outline, uncheckedTrackColor = Palette.SurfaceHigh,
                uncheckedBorderColor = Palette.Outline,
            ),
        )
    }
}

@Composable
fun AboutScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    Column(modifier.fillMaxSize()) {
        TopBar(stringResource(R.string.about_title), onBack)
        Column(
            Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = ScreenPadding, vertical = Space.sm),
            verticalArrangement = Arrangement.spacedBy(Space.lg),
        ) {
            Column(
                Modifier.fillMaxWidth().padding(vertical = Space.md),
                verticalArrangement = Arrangement.spacedBy(Space.sm),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(stringResource(R.string.launcher_label), style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
                Text(
                    stringResource(R.string.about_version, BuildConfig.VERSION_NAME),
                    style = MaterialTheme.typography.bodyMedium, color = Palette.OnSurfaceMuted,
                )
            }
            Card {
                Text(stringResource(R.string.about_text), style = MaterialTheme.typography.bodyLarge)
            }
            Card {
                Text(stringResource(R.string.about_license_title), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.about_license_app), style = MaterialTheme.typography.bodyMedium)
                Text(stringResource(R.string.about_license_libs), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}
