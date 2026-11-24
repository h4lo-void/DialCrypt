package io.github.h4lovoid.dialcrypt.ui.keyboard

import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Backspace
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.onLongClick
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.github.h4lovoid.dialcrypt.R
import io.github.h4lovoid.dialcrypt.ui.rememberHaptics
import io.github.h4lovoid.dialcrypt.ui.theme.Palette

val LocalInputHost = compositionLocalOf<InputHost> { error("InputHost not provided") }

private val KeyHeight = 52.dp

@Composable
private fun Key(
    label: String?,
    modifier: Modifier = Modifier,
    special: Boolean = false,
    highlighted: Boolean = false,
    description: String? = null,
    tag: String? = null,
    onLongPress: (() -> Unit)? = null,
    holdTypes: Boolean = false,
    onTap: () -> Unit,
    content: (@Composable () -> Unit)? = null,
) {
    val haptics = rememberHaptics()
    val tapState = rememberUpdatedState(onTap)
    val longState = rememberUpdatedState(onLongPress)
    val holdTypesState = rememberUpdatedState(holdTypes)
    val bg = when {
        highlighted -> Palette.AccentContainer
        special -> Palette.KeySpecial
        else -> Palette.Key
    }
    Box(
        modifier
            .padding(2.dp)
            .height(KeyHeight)
            .clip(RoundedCornerShape(8.dp))
            .background(bg)
            .semantics(mergeDescendants = true) {
                role = Role.Button
                if (description != null) contentDescription = description
                if (tag != null) testTag = tag
                onClick { tapState.value(); true }
                if (onLongPress != null) onLongClick { longState.value?.invoke(); true }
            }
            .pointerInput(Unit) {
                detectTapGestures(
                    onTap = { haptics.tick(); tapState.value() },
                    onLongPress = {
                        val long = longState.value
                        when {
                            long != null -> { haptics.strong(); long() }
                            // Secret input: holding a key types it like a tap, with no extra feedback.
                            holdTypesState.value -> { haptics.tick(); tapState.value() }
                        }
                    },
                )
            },
        contentAlignment = Alignment.Center,
    ) {
        if (content != null) {
            content()
        } else if (label != null) {
            Text(
                label,
                style = MaterialTheme.typography.titleLarge,
                color = if (highlighted) Palette.Accent else Color.White,
                fontWeight = FontWeight.Medium,
            )
        }
    }
}

/** The only keyboard in the app. Latin letters with accents on long press, numbers and symbols. */
@Composable
fun SecureKeyboard(host: InputHost, modifier: Modifier = Modifier) {
    val input = host.active ?: return
    val kb = host.keyboard
    val doneLabel = stringResource(R.string.kb_done)
    val shiftLabel = stringResource(R.string.kb_shift)
    val deleteLabel = stringResource(R.string.kb_backspace)
    val spaceLabel = stringResource(R.string.kb_space)
    val numbersLabel = stringResource(R.string.kb_numbers)
    val lettersLabel = stringResource(R.string.kb_letters)

    Column(
        modifier
            .fillMaxWidth()
            .background(Palette.SurfaceHigh)
            .padding(horizontal = 4.dp, vertical = 6.dp),
    ) {
        if (kb.accents.isNotEmpty()) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                kb.accents.forEach { a ->
                    Key(a, Modifier.weight(1f), highlighted = true, tag = "accent_$a", onTap = { kb.pickAccent(input, a) })
                }
            }
        }
        when (kb.page) {
            KeyboardPage.PHONE -> {
                KeyboardLayouts.phone.forEach { row ->
                    Row(Modifier.fillMaxWidth()) {
                        row.forEach { c -> Key(c.toString(), Modifier.weight(1f), tag = "key_$c", onTap = { kb.type(input, c.toString()) }) }
                    }
                }
                Row(Modifier.fillMaxWidth()) {
                    Key("+", Modifier.weight(1f), special = true, tag = "key_+", onTap = { kb.type(input, "+") })
                    Key("0", Modifier.weight(1f), tag = "key_0", onTap = { kb.type(input, "0") })
                    Key(
                        null, Modifier.weight(1f), special = true, description = deleteLabel, tag = "key_backspace",
                        onLongPress = { kb.clearAll(input) }, onTap = { kb.backspace(input) },
                    ) { Icon(Icons.AutoMirrored.Filled.Backspace, contentDescription = null, tint = Color.White) }
                }
                Row(Modifier.fillMaxWidth()) {
                    Key(doneLabel, Modifier.weight(1f), highlighted = true, tag = "key_done", onTap = { host.done() })
                }
            }
            else -> {
                // Original order, or a random one while a password or PIN has the keyboard.
                val rows = kb.rows
                // Row 1
                Row(Modifier.fillMaxWidth()) {
                    rows[0].forEach { c -> LetterKey(kb, input, c.toString(), Modifier.weight(1f)) }
                }
                // Row 2
                Row(Modifier.fillMaxWidth()) {
                    if (rows[1].length < 10) Box(Modifier.weight(0.5f))
                    rows[1].forEach { c -> LetterKey(kb, input, c.toString(), Modifier.weight(1f)) }
                    if (rows[1].length < 10) Box(Modifier.weight(0.5f))
                }
                // Row 3
                Row(Modifier.fillMaxWidth()) {
                    if (kb.page == KeyboardPage.LETTERS) {
                        Key(
                            null, Modifier.weight(1.5f), special = true,
                            highlighted = kb.shift != ShiftState.OFF, description = shiftLabel, tag = "key_shift",
                            onLongPress = { kb.longPressShift() }, onTap = { kb.tapShift() },
                        ) {
                            Icon(
                                Icons.Filled.KeyboardArrowUp, contentDescription = null,
                                tint = if (kb.shift != ShiftState.OFF) Palette.Accent else Color.White,
                            )
                        }
                    } else {
                        Box(Modifier.weight(0.75f))
                    }
                    rows[2].forEach { c -> LetterKey(kb, input, c.toString(), Modifier.weight(1f)) }
                    if (kb.page != KeyboardPage.LETTERS && rows[2].length < 7) Box(Modifier.weight(0.5f * (7 - rows[2].length)))
                    Key(
                        null, Modifier.weight(1.5f), special = true, description = deleteLabel, tag = "key_backspace",
                        onLongPress = { kb.clearAll(input) }, onTap = { kb.backspace(input) },
                    ) { Icon(Icons.AutoMirrored.Filled.Backspace, contentDescription = null, tint = Color.White) }
                }
                // Row 4
                Row(Modifier.fillMaxWidth()) {
                    Key(
                        if (kb.page == KeyboardPage.LETTERS) numbersLabel else lettersLabel,
                        Modifier.weight(1.5f), special = true, tag = "key_page", onTap = { kb.togglePage() },
                    )
                    Key(spaceLabel, Modifier.weight(5f), tag = "key_space", onTap = { kb.space(input) })
                    Key(doneLabel, Modifier.weight(2f), highlighted = true, tag = "key_done", onTap = { host.done() })
                }
            }
        }
    }
}

@Composable
private fun LetterKey(kb: KeyboardController, input: SecureInputState, key: String, modifier: Modifier) {
    // On a secret input a long press is just a tap: no accent row pops up above the keys.
    val accents = !kb.scrambled && AccentMap.options(kb.label(key)).isNotEmpty()
    Key(
        kb.label(key), modifier, tag = "key_$key",
        onLongPress = if (accents) ({ kb.longPress(key) }) else null,
        holdTypes = kb.scrambled,
        onTap = { kb.type(input, key) },
    )
}
