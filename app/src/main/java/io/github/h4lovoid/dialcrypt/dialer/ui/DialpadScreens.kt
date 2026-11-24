package io.github.h4lovoid.dialcrypt.dialer.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Backspace
import androidx.compose.material.icons.filled.Call
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.onLongClick
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.ui.components.MinTouch
import io.github.h4lovoid.dialcrypt.ui.components.PrimaryButton
import io.github.h4lovoid.dialcrypt.ui.components.ScreenPadding
import io.github.h4lovoid.dialcrypt.ui.theme.Palette
import io.github.h4lovoid.dialcrypt.ui.theme.Radius
import io.github.h4lovoid.dialcrypt.ui.theme.Space

/** Why the last call attempt did not go out. */
enum class DialNotice { BLOCKED, FAILED }

/** Test tags of the dial pad. */
object DialpadTags {
    const val CALL = "dialpad_call"
    const val DELETE = "dialpad_delete"
    const val DIGITS = "dialpad_digits"
    const val NOTICE = "dialpad_notice"

    fun key(c: Char): String = "dialpad_key_$c"
}

private class PadKey(val main: Char, val sub: String, val hold: Char?)

private val PAD = listOf(
    listOf(PadKey('1', "", null), PadKey('2', "ABC", null), PadKey('3', "DEF", null)),
    listOf(PadKey('4', "GHI", null), PadKey('5', "JKL", null), PadKey('6', "MNO", null)),
    listOf(PadKey('7', "PQRS", null), PadKey('8', "TUV", null), PadKey('9', "WXYZ", null)),
    // Holding * adds a pause (,), holding 0 a plus sign, holding # a wait (;).
    listOf(PadKey('*', ",", ','), PadKey('0', "+", '+'), PadKey('#', ";", ';')),
)

/**
 * The dial pad: the number typed so far, twelve keys and the call button. There is no text field;
 * every key goes through [onKey], and the activity keeps only what DialInput.clean lets through.
 */
@Composable
fun DialpadScreen(
    digits: String,
    notice: DialNotice?,
    onKey: (Char) -> Unit,
    onDelete: () -> Unit,
    onClear: () -> Unit,
    onCall: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier.fillMaxSize().background(Palette.Background).padding(horizontal = ScreenPadding, vertical = Space.xl),
        verticalArrangement = Arrangement.spacedBy(Space.md),
    ) {
        Spacer(Modifier.weight(1f))
        Row(Modifier.fillMaxWidth().heightIn(min = 64.dp), verticalAlignment = Alignment.CenterVertically) {
            Spacer(Modifier.size(MinTouch))
            Text(
                digits,
                modifier = Modifier.weight(1f).testTag(DialpadTags.DIGITS),
                style = MaterialTheme.typography.headlineMedium,
                textAlign = TextAlign.Center,
                maxLines = 2,
            )
            if (digits.isNotEmpty()) {
                DeleteKey(onDelete, onClear)
            } else {
                Spacer(Modifier.size(MinTouch))
            }
        }
        if (notice != null) {
            Text(
                stringResource(if (notice == DialNotice.BLOCKED) R.string.dialpad_blocked else R.string.dialpad_failed),
                modifier = Modifier.fillMaxWidth().testTag(DialpadTags.NOTICE),
                style = MaterialTheme.typography.bodyMedium,
                color = Palette.Danger,
                textAlign = TextAlign.Center,
            )
        }
        PAD.forEach { row ->
            Row(horizontalArrangement = Arrangement.spacedBy(Space.sm)) {
                row.forEach { key ->
                    DialKey(
                        key = key,
                        modifier = Modifier.weight(1f),
                        onTap = { onKey(key.main) },
                        onHold = key.hold?.let { c -> { onKey(c) } },
                    )
                }
            }
        }
        PrimaryButton(
            text = stringResource(R.string.dialpad_call),
            onClick = onCall,
            modifier = Modifier.padding(top = Space.sm).testTag(DialpadTags.CALL),
            enabled = digits.isNotEmpty(),
            icon = Icons.Filled.Call,
        )
    }
}

@Composable
private fun DialKey(key: PadKey, modifier: Modifier, onTap: () -> Unit, onHold: (() -> Unit)?) {
    val tap by rememberUpdatedState(onTap)
    val hold by rememberUpdatedState(onHold)
    Box(
        modifier
            .height(64.dp)
            .clip(RoundedCornerShape(Radius.lg))
            .background(Palette.Key)
            .testTag(DialpadTags.key(key.main))
            .semantics {
                role = Role.Button
                onClick {
                    tap()
                    true
                }
            }
            .pointerInput(Unit) {
                detectTapGestures(
                    onTap = { tap() },
                    onLongPress = { _: Offset -> (hold ?: tap)() },
                )
            },
        contentAlignment = Alignment.Center,
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(key.main.toString(), style = MaterialTheme.typography.headlineSmall, color = Palette.OnSurface)
            Text(
                key.sub,
                style = MaterialTheme.typography.labelSmall,
                color = Palette.OnSurfaceMuted,
                modifier = Modifier.heightIn(min = 14.dp),
            )
        }
    }
}

@Composable
private fun DeleteKey(onDelete: () -> Unit, onClear: () -> Unit) {
    val delete by rememberUpdatedState(onDelete)
    val clear by rememberUpdatedState(onClear)
    val label = stringResource(R.string.dialpad_delete)
    Box(
        Modifier
            .size(MinTouch)
            .clip(CircleShape)
            .testTag(DialpadTags.DELETE)
            .semantics {
                role = Role.Button
                contentDescription = label
                onClick {
                    delete()
                    true
                }
                onLongClick {
                    clear()
                    true
                }
            }
            .pointerInput(Unit) {
                detectTapGestures(onTap = { delete() }, onLongPress = { clear() })
            },
        contentAlignment = Alignment.Center,
    ) {
        Icon(Icons.AutoMirrored.Filled.Backspace, contentDescription = null, tint = Palette.OnSurfaceMuted)
    }
}

