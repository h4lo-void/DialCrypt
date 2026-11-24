package io.github.h4lovoid.dialcrypt.ui.components

import android.os.Build
import android.view.View
import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.snap
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.onLongClick
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.DialogWindowProvider
import androidx.compose.ui.window.SecureFlagPolicy
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.ui.model.ContactUi
import io.github.h4lovoid.dialcrypt.ui.rememberHaptics
import io.github.h4lovoid.dialcrypt.ui.keyboard.LocalInputHost
import io.github.h4lovoid.dialcrypt.ui.theme.AvatarPalette
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Radius
import io.github.h4lovoid.dialcrypt.ui.theme.Space
import io.github.h4lovoid.dialcrypt.ui.theme.Tone
import io.github.h4lovoid.dialcrypt.ui.theme.color
import io.github.h4lovoid.dialcrypt.ui.theme.container
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** Smallest touch target anywhere in the app. */
val MinTouch: Dp = 48.dp
val ScreenPadding: Dp = Space.lg

/** Opacity of the label of a disabled button. */
const val DisabledContentAlpha = 0.38f
val ContentPadding = PaddingValues(horizontal = ScreenPadding, vertical = Space.md)

// ---- top bar and buttons -----------------------------------------------------------------------

/** Title row. With [onBack] it starts with a back arrow, otherwise the title starts at the screen margin. */
@Composable
fun TopBar(
    title: String,
    onBack: (() -> Unit)?,
    modifier: Modifier = Modifier,
    actions: @Composable () -> Unit = {},
) {
    Row(
        modifier.fillMaxWidth().heightIn(min = 64.dp).padding(horizontal = Space.xs),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (onBack != null) {
            IconButton(onClick = onBack, modifier = Modifier.size(MinTouch)) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
            }
            Spacer(Modifier.width(Space.xs))
        } else {
            Spacer(Modifier.width(Space.md))
        }
        Text(
            title,
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.weight(1f),
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        actions()
    }
}

@Composable
private fun RowScope.ButtonLabel(text: String, icon: ImageVector?, style: TextStyle) {
    if (icon != null) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(Space.sm))
    }
    Text(text, style = style, textAlign = TextAlign.Center, modifier = Modifier.weight(1f, fill = false))
}

/** The one main action of a screen: solid champagne fill with a dark label. Disabled, it fades to a neutral fill with a dim label. */
@Composable
fun PrimaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, icon: ImageVector? = null) {
    val haptics = rememberHaptics()
    Button(
        onClick = { haptics.tick(); onClick() },
        enabled = enabled,
        modifier = modifier.fillMaxWidth().heightIn(min = 56.dp),
        shape = RoundedCornerShape(Radius.md),
        colors = ButtonDefaults.buttonColors(
            containerColor = Palette.Accent,
            contentColor = Palette.Background,
            disabledContainerColor = Palette.SurfaceHigh,
            disabledContentColor = Palette.OnSurface.copy(alpha = DisabledContentAlpha),
        ),
        contentPadding = PaddingValues(horizontal = Space.lg, vertical = Space.md),
    ) { ButtonLabel(text, icon, MaterialTheme.typography.titleMedium) }
}

/**
 * A side action: a raised dark fill without an edge. [danger] gives it the rose red look (rose label and icon,
 * dark red fill, thin rose edge); it is used for ending a call, inside a [DangerZone] and on the red key-change screen.
 */
@Composable
fun SecondaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    danger: Boolean = false,
    icon: ImageVector? = null,
) {
    val tint = if (danger) Palette.Danger else Palette.OnSurface
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.fillMaxWidth().heightIn(min = 52.dp),
        shape = RoundedCornerShape(Radius.md),
        colors = ButtonDefaults.buttonColors(
            containerColor = if (danger) Palette.DangerContainer else Palette.SurfaceHigh,
            contentColor = tint,
            disabledContainerColor = if (danger) Palette.DangerContainer else Palette.SurfaceHigh,
            disabledContentColor = tint.copy(alpha = DisabledContentAlpha),
        ),
        border = if (danger) BorderStroke(1.dp, Palette.Danger.copy(alpha = 0.6f)) else null,
        contentPadding = PaddingValues(horizontal = Space.lg, vertical = Space.md),
    ) { ButtonLabel(text, icon, MaterialTheme.typography.titleMedium) }
}

@Composable
fun QuietButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, danger: Boolean = false) {
    TextButton(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.heightIn(min = MinTouch),
        colors = if (danger) ButtonDefaults.textButtonColors(contentColor = Palette.Danger) else ButtonDefaults.textButtonColors(),
    ) {
        Text(text, style = MaterialTheme.typography.titleSmall, textAlign = TextAlign.Center)
    }
}

// ---- small pieces ------------------------------------------------------------------------------

@Composable
fun StatusDot(color: Color, modifier: Modifier = Modifier, size: Dp = 8.dp) {
    Box(modifier.size(size).clip(CircleShape).background(color))
}

/** Small read-only status pill: a colored dot and a word on a faint fill. A long word is cut with an ellipsis. */
@Composable
fun Badge(text: String, tone: Tone = Tone.NEUTRAL, modifier: Modifier = Modifier) {
    val c = tone.color()
    Row(
        modifier.widthIn(max = 132.dp).clip(CircleShape).background(tone.container())
            .padding(horizontal = Space.md, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        StatusDot(c, size = 6.dp)
        Spacer(Modifier.width(6.dp))
        Text(text, color = c, style = MaterialTheme.typography.labelMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

/** Rounded square holding an icon; the leading element of list rows and banners. */
@Composable
fun IconTile(
    icon: ImageVector,
    modifier: Modifier = Modifier,
    tint: Color = Palette.Accent,
    background: Color = Palette.SurfaceHigh,
    size: Dp = 36.dp,
) {
    Box(
        modifier.size(size).clip(RoundedCornerShape(Radius.md)).background(background),
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(size * 0.55f))
    }
}

/**
 * A block on a lighter layer, without an edge. [borderColor] adds a thin edge in that color and is
 * kept for warnings about something dangerous.
 */
@Composable
fun Card(
    modifier: Modifier = Modifier,
    borderColor: Color = Color.Unspecified,
    container: Color = Palette.Surface,
    content: @Composable ColumnScope.() -> Unit,
) {
    val shape = RoundedCornerShape(Radius.lg)
    Column(
        modifier
            .fillMaxWidth()
            .clip(shape)
            .background(container)
            .then(if (borderColor == Color.Unspecified) Modifier else Modifier.border(1.dp, borderColor.copy(alpha = 0.5f), shape))
            .padding(Space.lg),
        verticalArrangement = Arrangement.spacedBy(Space.sm),
    ) { content() }
}

/** Small caption above a group of rows. */
@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text,
        modifier = modifier.fillMaxWidth().padding(start = Space.xs, top = Space.sm),
        style = MaterialTheme.typography.labelLarge,
        color = Palette.OnSurfaceMuted,
    )
}

/** A block of rows on one layer, without an edge; put [GroupDivider] between rows. */
@Composable
fun InfoGroup(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(Radius.lg)
    Column(
        modifier.fillMaxWidth().clip(shape).background(Palette.Surface),
        content = content,
    )
}

@Composable
fun GroupDivider(inset: Dp = 64.dp) {
    Box(Modifier.fillMaxWidth().padding(start = inset).height(1.dp).background(Palette.OutlineSoft))
}

/**
 * Icon, small title and value. A [tone] adds a small colored dot before the value; the value itself stays in the normal text color.
 * With [onClick] the whole row is one button with a chevron.
 */
@Composable
fun InfoRow(
    icon: ImageVector,
    title: String,
    value: String,
    modifier: Modifier = Modifier,
    tone: Tone? = null,
    note: String? = null,
    mono: Boolean = false,
    onClick: (() -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null,
) {
    val base = modifier.fillMaxWidth().heightIn(min = 64.dp)
    val touch = if (onClick != null) base.clickable(role = Role.Button, onClick = onClick)
    else base.semantics(mergeDescendants = true) {}
    Row(
        touch.padding(horizontal = Space.lg, vertical = Space.md),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.md),
    ) {
        IconTile(icon)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.labelMedium, color = Palette.OnSurfaceMuted)
            Row(verticalAlignment = Alignment.Top) {
                if (tone != null) {
                    StatusDot(tone.color(), Modifier.padding(top = 9.dp, end = Space.sm), size = 8.dp)
                }
                Text(
                    value,
                    style = MaterialTheme.typography.bodyLarge,
                    color = Palette.OnSurface,
                    fontFamily = if (mono) FontFamily.Monospace else null,
                )
            }
            if (note != null) Text(note, style = MaterialTheme.typography.bodySmall, color = Palette.OnSurfaceMuted)
        }
        when {
            trailing != null -> trailing()
            onClick != null -> Icon(
                Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null, tint = Palette.OnSurfaceMuted,
            )
        }
    }
}

/** A whole row that is one button: icon tile, label and chevron. */
@Composable
fun ActionRow(icon: ImageVector, label: String, onClick: () -> Unit, modifier: Modifier = Modifier, tint: Color = Palette.Accent) {
    Row(
        modifier.fillMaxWidth().heightIn(min = 64.dp).clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = Space.lg, vertical = Space.md),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Space.md),
    ) {
        IconTile(icon)
        Text(label, style = MaterialTheme.typography.titleSmall, color = tint, modifier = Modifier.weight(1f))
        Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null, tint = Palette.OnSurfaceMuted)
    }
}

/** A key fingerprint as monospaced groups of four characters, four groups to a line. */
@Composable
fun FingerprintGrid(fingerprint: String, modifier: Modifier = Modifier) {
    val rows = fingerprint.filter { !it.isWhitespace() }.chunked(4).chunked(4)
    Column(
        modifier.fillMaxWidth().clip(RoundedCornerShape(Radius.md)).background(Palette.SurfaceHigh).padding(Space.md),
        verticalArrangement = Arrangement.spacedBy(Space.sm),
    ) {
        rows.forEach { row ->
            Row(Modifier.fillMaxWidth()) {
                row.forEach { group ->
                    Text(
                        group, modifier = Modifier.weight(1f), maxLines = 1, softWrap = false,
                        fontFamily = FontFamily.Monospace, fontSize = 16.sp, fontWeight = FontWeight.Medium,
                    )
                }
                repeat(4 - row.size) { Box(Modifier.weight(1f)) }
            }
        }
    }
}

/** Separate block for actions that destroy something; always placed last on a screen. */
@Composable
fun DangerZone(title: String, modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(Radius.lg)
    Column(
        modifier.fillMaxWidth().clip(shape).background(Palette.DangerContainer)
            .border(1.dp, Palette.Danger.copy(alpha = 0.35f), shape).padding(Space.lg),
        verticalArrangement = Arrangement.spacedBy(Space.md),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Warning, contentDescription = null, tint = Palette.Danger, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(Space.sm))
            Text(title, style = MaterialTheme.typography.titleSmall, color = Palette.Danger)
        }
        content()
    }
}

/** Icon in a quiet round tile with a thin edge of the tone color, for full-screen states. */
@Composable
fun StatusHero(icon: ImageVector, tint: Color, modifier: Modifier = Modifier, breathing: Boolean = false) {
    val c = tint
    val pulse = if (breathing) rememberPulse() else null
    Box(
        modifier.size(88.dp).clip(CircleShape).background(Palette.SurfaceHigh)
            .drawBehind {
                // The pulse is read here, in the draw phase, so breathing does not recompose the screen.
                val stroke = 1.dp.toPx()
                val alpha = (0.35f * (pulse?.value ?: 1f)).coerceIn(0f, 1f)
                drawCircle(c.copy(alpha = alpha), radius = (size.minDimension - stroke) / 2f, style = Stroke(stroke))
            },
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, contentDescription = null, tint = c, modifier = Modifier.size(36.dp))
    }
}

/** Contact avatar: a grey step from the contact id; a champagne disc with a check mark when [selected]. */
@Composable
fun Avatar(id: Long, name: String, selected: Boolean, modifier: Modifier = Modifier) {
    Box(
        modifier.size(48.dp).clip(CircleShape)
            .background(if (selected) Palette.Accent else AvatarPalette.forId(id)),
        contentAlignment = Alignment.Center,
    ) {
        if (selected) {
            Icon(Icons.Filled.Check, contentDescription = null, tint = Palette.Background)
        } else {
            Text(
                ContactUi.initials(name), style = MaterialTheme.typography.titleSmall,
                color = Palette.OnSurface, maxLines = 1,
            )
        }
    }
}

/** Horizontal progress bar that glides to each new value in about 300 ms (jumps when animations are off). */
@Composable
fun ProgressBar(
    progress: Float,
    modifier: Modifier = Modifier,
    color: Color = Palette.Accent,
    track: Color = Palette.SurfaceHigh,
    height: Dp = 4.dp,
) {
    val target = progress.coerceIn(0f, 1f)
    val motion = rememberMotionEnabled()
    val shown by animateFloatAsState(
        target, animationSpec = if (motion) tween(ValueGlideMillis, easing = FastOutSlowInEasing) else snap(), label = "bar",
    )
    Box(
        modifier.fillMaxWidth().height(height).clip(CircleShape).background(track)
            .semantics { progressBarRangeInfo = ProgressBarRangeInfo(target, 0f..1f) },
    ) {
        Box(Modifier.fillMaxHeight().fillMaxWidth(shown).clip(CircleShape).background(color))
    }
}

// ---- hold to confirm, dialog, helpers ----------------------------------------------------------

/**
 * Needs a long press to fire, so a stray touch cannot trigger it. A fill grows while held;
 * releasing early cancels. Screen readers get a long-click action instead.
 */
@Composable
fun HoldToConfirmButton(
    label: String,
    onConfirmed: () -> Unit,
    modifier: Modifier = Modifier,
    holdMillis: Int = 1200,
    icon: ImageVector = Icons.Filled.DeleteForever,
) {
    val progress = remember { Animatable(0f) }
    val scope = rememberCoroutineScope()
    val haptics = rememberHaptics()
    val shape = RoundedCornerShape(Radius.md)
    val hint = stringResource(R.string.hold_hint)
    Box(
        modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clip(shape)
            .background(Palette.DangerBackground)
            .border(1.dp, Palette.Danger.copy(alpha = 0.6f), shape)
            .semantics {
                role = Role.Button
                contentDescription = label + ". " + hint
                onLongClick(label = label) { onConfirmed(); true }
            }
            .pointerInput(Unit) {
                detectTapGestures(onPress = {
                    val job: Job = scope.launch {
                        progress.animateTo(1f, tween(holdMillis, easing = LinearEasing))
                        haptics.strong()
                        onConfirmed()
                    }
                    tryAwaitRelease()
                    if (job.isActive) job.cancel()
                    scope.launch { progress.snapTo(0f) }
                })
            },
        contentAlignment = Alignment.Center,
    ) {
        // matchParentSize keeps the fill from influencing the button's own height.
        Box(Modifier.matchParentSize()) {
            Box(
                Modifier
                    .fillMaxHeight()
                    .fillMaxWidth(progress.value)
                    .background(Palette.Danger.copy(alpha = 0.28f)),
            )
        }
        Row(
            Modifier.padding(horizontal = Space.lg, vertical = Space.sm),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(Space.md),
        ) {
            Icon(icon, contentDescription = null, tint = Palette.Danger, modifier = Modifier.size(24.dp))
            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.weight(1f, fill = false)) {
                Text(
                    label, style = MaterialTheme.typography.titleMedium, color = Palette.OnSurface,
                    textAlign = TextAlign.Center,
                )
                Text(hint, style = MaterialTheme.typography.labelMedium, color = Palette.OnSurfaceMuted)
            }
        }
    }
}

/**
 * Every dialog window is a separate window, so it gets the same protections as the activity.
 * Dialogs never contain text inputs (those need the in-app keyboard).
 */
@Composable
fun SecureDialog(
    title: String,
    text: @Composable () -> Unit,
    confirmButton: @Composable () -> Unit,
    onDismiss: () -> Unit,
    dismissButton: (@Composable () -> Unit)? = null,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title, style = MaterialTheme.typography.titleLarge) },
        text = {
            HideOverlaysEffect()
            text()
        },
        confirmButton = confirmButton,
        dismissButton = dismissButton,
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        containerColor = Palette.SurfaceTop,
        titleContentColor = Palette.OnSurface,
        textContentColor = Palette.OnSurfaceMuted,
        shape = RoundedCornerShape(Radius.xl),
    )
}

@Composable
private fun HideOverlaysEffect() {
    val view = LocalView.current
    SideEffect {
        val window = (view.parent as? DialogWindowProvider)?.window ?: return@SideEffect
        if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
        if (Build.VERSION.SDK_INT >= 34) window.decorView.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
    }
}

/** Runs [block] once, [millis] after the composable enters the composition. */
@Composable
fun AfterDelay(millis: Long, key: Any?, block: () -> Unit) {
    LaunchedEffect(key) {
        kotlinx.coroutines.delay(millis)
        block()
    }
}

@Composable
fun FullScreen(modifier: Modifier = Modifier, background: Color = Palette.Background, content: @Composable () -> Unit) {
    Box(modifier.fillMaxSize().background(background)) { content() }
}

/**
 * System back for one screen. While the in-app keyboard is open the press only closes it; otherwise
 * [onBack] runs. With [enabled] false and no keyboard open the press goes on to the next handler.
 */
@Composable
fun ScreenBackHandler(enabled: Boolean = true, onBack: () -> Unit) {
    val host = LocalInputHost.current
    val keyboardOpen = host.active != null
    BackHandler(enabled = enabled || keyboardOpen) {
        if (host.active != null) host.blur() else onBack()
    }
}

/** Asks before a call is ended by the back key; nothing is hung up unless [onConfirm] runs. */
@Composable
fun HangUpDialog(onConfirm: () -> Unit, onDismiss: () -> Unit) {
    SecureDialog(
        title = stringResource(R.string.back_hangup_title),
        text = { Text(stringResource(R.string.back_hangup_body)) },
        confirmButton = { QuietButton(stringResource(R.string.connect_cancel), onConfirm, danger = true) },
        dismissButton = { QuietButton(stringResource(R.string.action_cancel), onDismiss) },
        onDismiss = onDismiss,
    )
}
