package io.github.h4lovoid.dialcrypt.ui.keyboard

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.security.SecureRandom
import java.util.Random

enum class KeyboardPage { LETTERS, SYMBOLS, PHONE }
enum class ShiftState { OFF, ONCE, LOCKED }

/** Accented characters offered on long press: Spanish and French. */
object AccentMap {
    private val lower: Map<String, List<String>> = mapOf(
        "a" to listOf("\u00E0", "\u00E1", "\u00E2", "\u00E4", "\u00E6", "\u00E3"),
        "e" to listOf("\u00E9", "\u00E8", "\u00EA", "\u00EB"),
        "i" to listOf("\u00ED", "\u00EC", "\u00EE", "\u00EF"),
        "o" to listOf("\u00F3", "\u00F2", "\u00F4", "\u00F6", "\u0153", "\u00F5"),
        "u" to listOf("\u00FA", "\u00F9", "\u00FB", "\u00FC"),
        "y" to listOf("\u00FD", "\u00FF"),
        "n" to listOf("\u00F1"),
        "c" to listOf("\u00E7"),
        "?" to listOf("\u00BF"),
        "!" to listOf("\u00A1"),
        "\"" to listOf("\u00AB", "\u00BB"),
        "'" to listOf("\u2019"),
        "$" to listOf("\u20AC", "\u00A3"),
        "-" to listOf("\u2013"),
        "." to listOf("\u2026"),
    )

    fun options(label: String): List<String> {
        val base = label.lowercase()
        val found = lower[base] ?: return emptyList()
        val upper = label != base
        return if (upper) found.map { it.uppercase() } else found
    }
}

object KeyboardLayouts {
    val letters = listOf("qwertyuiop", "asdfghjkl", "zxcvbnm")
    val symbols = listOf("1234567890", "-/:;()$&@\"", ".,?!'#+=")
    val phone = listOf("123", "456", "789")

    /**
     * Same characters as [rows] in a random order, cut back into rows of the original lengths
     * so the keyboard keeps its shape. Never returns the original order.
     */
    internal fun scrambled(rows: List<String>, random: Random): List<String> {
        val chars = rows.joinToString("").toMutableList()
        do {
            for (i in chars.lastIndex downTo 1) {
                val j = random.nextInt(i + 1)
                val t = chars[i]; chars[i] = chars[j]; chars[j] = t
            }
            val out = ArrayList<String>(rows.size)
            var start = 0
            for (row in rows) {
                out += chars.subList(start, start + row.length).joinToString("")
                start += row.length
            }
            if (out != rows) return out
        } while (true)
    }
}

/**
 * Pure keyboard logic; the composable only draws and forwards touches.
 * [random] picks the key order for secret inputs; outside tests it is always a [SecureRandom].
 */
class KeyboardController internal constructor(private val random: Random) {
    constructor() : this(SecureRandom())

    var page by mutableStateOf(KeyboardPage.LETTERS)
        private set
    var shift by mutableStateOf(ShiftState.OFF)
        private set
    var accents by mutableStateOf<List<String>>(emptyList())
        private set

    /** True while the keys of the letter and symbol pages are in a random order (secret input). */
    var scrambled by mutableStateOf(false)
        private set
    private var letterRows by mutableStateOf(KeyboardLayouts.letters)
    private var symbolRows by mutableStateOf(KeyboardLayouts.symbols)

    /** Character rows of the current page, in the order they are drawn. */
    val rows: List<String>
        get() = when (page) {
            KeyboardPage.LETTERS -> letterRows
            KeyboardPage.SYMBOLS -> symbolRows
            KeyboardPage.PHONE -> KeyboardLayouts.phone
        }

    fun reset(kind: InputKind) {
        page = if (kind == InputKind.PHONE) KeyboardPage.PHONE else KeyboardPage.LETTERS
        shift = ShiftState.OFF
        accents = emptyList()
        plain()
    }

    /** Picks the key order for [input]: a fresh random one when it is secret, the normal one otherwise. */
    internal fun arrangeFor(input: SecureInputState) {
        if (input.secret && input.kind == InputKind.TEXT) scramble() else plain()
    }

    /** Letters and symbols each get their own new random order. */
    private fun scramble() {
        accents = emptyList()
        letterRows = KeyboardLayouts.scrambled(KeyboardLayouts.letters, random)
        symbolRows = KeyboardLayouts.scrambled(KeyboardLayouts.symbols, random)
        scrambled = true
    }

    private fun plain() {
        letterRows = KeyboardLayouts.letters
        symbolRows = KeyboardLayouts.symbols
        scrambled = false
    }

    /** Label as drawn, with the shift state applied to letters. */
    fun label(key: String): String =
        if (page == KeyboardPage.LETTERS && shift != ShiftState.OFF) key.uppercase() else key

    fun type(input: SecureInputState, key: String) {
        input.append(label(key))
        releaseShift()
        accents = emptyList()
    }

    /** Returns true when accent options are now shown. Secret inputs never show them. */
    fun longPress(key: String): Boolean {
        if (scrambled) return false
        val options = AccentMap.options(label(key))
        if (options.isEmpty()) return false
        accents = options
        return true
    }

    fun pickAccent(input: SecureInputState, accent: String) {
        input.append(accent)
        accents = emptyList()
        releaseShift()
    }

    fun dismissAccents() { accents = emptyList() }

    fun backspace(input: SecureInputState) {
        input.backspace()
        accents = emptyList()
    }

    fun clearAll(input: SecureInputState) {
        input.clear()
        accents = emptyList()
    }

    fun space(input: SecureInputState) {
        input.append(" ")
        accents = emptyList()
        releaseShift()
    }

    fun tapShift() {
        shift = if (shift == ShiftState.OFF) ShiftState.ONCE else ShiftState.OFF
    }

    fun longPressShift() { shift = ShiftState.LOCKED }

    fun togglePage() {
        accents = emptyList()
        page = when (page) {
            KeyboardPage.LETTERS -> KeyboardPage.SYMBOLS
            KeyboardPage.SYMBOLS -> KeyboardPage.LETTERS
            KeyboardPage.PHONE -> KeyboardPage.PHONE
        }
    }

    private fun releaseShift() {
        if (shift == ShiftState.ONCE) shift = ShiftState.OFF
    }
}
