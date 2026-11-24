package io.github.h4lovoid.dialcrypt.ui.keyboard

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.takeOrElse
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTag
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import android.graphics.Paint
import android.graphics.Typeface
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Radius

private val CaretChars = charArrayOf('|')

/**
 * Draws the content of a revealed masked field straight from a temporary char array, so the PIN
 * never becomes a String. The array is zeroed by [SecureInputState.withChars] after each draw.
 * Font size, letter spacing, colour and baseline follow [style], matching what Text would show.
 * The node carries no semantics, so the PIN is not exposed to accessibility services.
 */
@Composable
private fun RevealedSecureText(state: SecureInputState, focused: Boolean, accent: Color, style: TextStyle) {
    val density = LocalDensity.current
    val textColor = style.color.takeOrElse { LocalContentColor.current }.toArgb()
    val accentColor = accent.toArgb()
    val fontSizePx = with(density) { style.fontSize.toPx() }
    val letterSpacingEm = with(density) { style.letterSpacing.toPx() } / fontSizePx
    val lineHeightPx = with(density) { style.lineHeight.toPx() }
    val paint = remember(textColor, fontSizePx, letterSpacingEm) {
        Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = textColor
            textSize = fontSizePx
            letterSpacing = letterSpacingEm
            typeface = Typeface.DEFAULT
        }
    }
    val caretPaint = remember(accentColor, fontSizePx, letterSpacingEm) {
        Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = accentColor
            textSize = fontSizePx
            letterSpacing = letterSpacingEm
            typeface = Typeface.DEFAULT_BOLD
        }
    }
    Box(
        Modifier
            .fillMaxWidth()
            .height(with(density) { lineHeightPx.toDp() })
            .clearAndSetSemantics { }
            .clipToBounds()
            .drawBehind {
                drawIntoCanvas { canvas ->
                    val native = canvas.nativeCanvas
                    val metrics = paint.fontMetrics
                    // Text centres its glyphs in the line height in proportion to ascent and descent.
                    val baseline = -metrics.ascent * size.height / (metrics.descent - metrics.ascent)
                    val width = state.withChars { chars ->
                        native.drawText(chars, 0, chars.size, 0f, baseline, paint)
                        paint.measureText(chars, 0, chars.size)
                    }
                    if (focused) native.drawText(CaretChars, 0, 1, width, baseline, caretPaint)
                }
            },
    )
}

/**
 * A text field that draws its own text. It is not a system text widget, so it can never
 * raise the system keyboard, and it offers no selection or clipboard.
 */
@Composable
fun SecureTextField(
    state: SecureInputState,
    modifier: Modifier = Modifier,
    label: String? = null,
    placeholder: String? = null,
    masked: Boolean = false,
    maxLines: Int = 1,
    isError: Boolean = false,
    tag: String? = null,
) {
    val host = LocalInputHost.current
    // A masked field holds a password or PIN, so the keyboard shuffles its keys for it.
    SideEffect { if (masked) state.markSecret() }
    val focused = host.active === state
    var reveal by remember { mutableStateOf(false) }
    val length = state.length
    // A revealed masked field is drawn from a char array; only the other fields may become a String.
    val drawRevealed = masked && reveal
    val shown = when {
        length == 0 || drawRevealed -> ""
        masked -> "\u2022".repeat(length)
        else -> state.text()
    }
    val shape = RoundedCornerShape(Radius.md)
    val borderColor = when {
        isError -> Palette.Danger
        focused -> MaterialTheme.colorScheme.primary
        else -> Palette.Outline
    }
    Column(modifier) {
        if (label != null) {
            Text(label, style = MaterialTheme.typography.labelLarge, color = Palette.OnSurfaceMuted, modifier = Modifier.padding(bottom = 6.dp))
        }
        Row(
            Modifier
                .fillMaxWidth()
                .heightIn(min = 56.dp)
                .clip(shape)
                .background(Palette.SurfaceHigh)
                .border(if (focused || isError) 2.dp else 1.dp, borderColor, shape)
                .clickable { host.focus(state) }
                .padding(start = 14.dp, end = 4.dp)
                .let { if (tag != null) it.semantics { testTag = tag } else it },
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.weight(1f).padding(vertical = 10.dp)) {
                if (length == 0 && placeholder != null) {
                    Text(
                        placeholder, color = Palette.Outline, style = MaterialTheme.typography.bodyLarge,
                        // Leaves room for the caret so it does not sit on top of the first letter.
                        modifier = Modifier.padding(start = if (focused) 6.dp else 0.dp),
                    )
                }
                if (drawRevealed && (length > 0 || focused)) {
                    RevealedSecureText(state, focused, MaterialTheme.colorScheme.primary, MaterialTheme.typography.bodyLarge)
                } else if (shown.isNotEmpty() || focused) {
                    val accent = MaterialTheme.colorScheme.primary
                    Text(
                        buildAnnotatedString {
                            append(shown)
                            if (focused) withStyle(SpanStyle(color = accent, fontWeight = FontWeight.Bold)) { append("|") }
                        },
                        style = MaterialTheme.typography.bodyLarge,
                        maxLines = maxLines,
                        overflow = TextOverflow.Clip,
                    )
                }
            }
            if (masked) {
                IconButton(onClick = { reveal = !reveal }, modifier = Modifier.size(48.dp)) {
                    Icon(
                        if (reveal) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                        contentDescription = stringResource(if (reveal) R.string.field_hide else R.string.field_show),
                    )
                }
            }
        }
    }
}

