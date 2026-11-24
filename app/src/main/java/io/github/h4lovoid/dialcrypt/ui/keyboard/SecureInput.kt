package io.github.h4lovoid.dialcrypt.ui.keyboard

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.security.SecureRandom
import java.util.Random

enum class InputKind { TEXT, PHONE }

/**
 * Text buffer behind every input in the app. It is filled only by the in-app keyboard,
 * never by the system IME or the clipboard, and it is overwritten when cleared.
 */
class SecureInputState(
    val maxLength: Int = 64,
    val kind: InputKind = InputKind.TEXT,
    initial: String = "",
) {
    private val buffer = StringBuilder(initial)
    private var version by mutableIntStateOf(0)

    /** True for a password or PIN; the keyboard then shuffles its keys for this input. */
    var secret: Boolean = false
        private set

    /** Set by [InputHost] while this input owns the keyboard; told when the keys should be shuffled again. */
    internal var onReshuffle: (() -> Unit)? = null

    /** Marks this input as a password or PIN. Called by [SecureTextField] when it is masked. */
    internal fun markSecret() {
        if (secret) return
        secret = true
        onReshuffle?.invoke()
    }

    val length: Int get() { version; return buffer.length }
    val isEmpty: Boolean get() = length == 0

    /** Counts [text] calls; lets tests prove a revealed PIN is never turned into a String. */
    internal var textReadCount: Int = 0
        private set

    fun text(): String { version; textReadCount++; return buffer.toString() }

    /** Returns false when the text would exceed the limit or contains a character this input refuses. */
    fun append(s: String): Boolean {
        if (s.isEmpty()) return false
        if (kind == InputKind.PHONE && !s.all { it in '0'..'9' || it == '+' }) return false
        if (buffer.length + s.length > maxLength) return false
        buffer.append(s)
        version++
        return true
    }

    /** Replaces text for non-secret inputs (e.g. pasting a public invite card). */
    fun replace(s: String): Boolean {
        if (secret) return false
        val filtered = if (kind == InputKind.PHONE) s.filter { it in '0'..'9' || it == '+' } else s
        if (filtered.length > maxLength) return false
        buffer.setLength(0)
        buffer.append(filtered)
        version++
        return true
    }

    fun backspace() {
        if (buffer.isEmpty()) return
        val n = buffer.length
        val cut = if (n >= 2 && Character.isLowSurrogate(buffer[n - 1]) && Character.isHighSurrogate(buffer[n - 2])) 2 else 1
        for (i in n - cut until n) buffer.setCharAt(i, '\u0000')
        buffer.setLength(n - cut)
        version++
    }

    fun clear() {
        for (i in 0 until buffer.length) buffer.setCharAt(i, '\u0000')
        buffer.setLength(0)
        version++
        onReshuffle?.invoke()
    }

    /** Copy for handing to the core; the caller zeroes it afterwards. */
    fun toCharArray(): CharArray {
        version
        val out = CharArray(buffer.length)
        buffer.getChars(0, buffer.length, out, 0)
        return out
    }

    /**
     * Runs [block] on a temporary copy of the content and zeroes the copy afterwards, so a PIN can be
     * inspected without ever becoming a String. The block must not keep a reference to the array.
     */
    fun <T> withChars(block: (CharArray) -> T): T {
        val copy = toCharArray()
        try {
            return block(copy)
        } finally {
            copy.fill('\u0000')
        }
    }

    /** Compares the content with [other] without creating a String; the loop length does not depend on where the texts differ. */
    fun contentEquals(other: SecureInputState): Boolean {
        version
        other.version
        val a = buffer
        val b = other.buffer
        val n = maxOf(maxOf(a.length, b.length), maxOf(maxLength, other.maxLength))
        var diff = a.length xor b.length
        for (i in 0 until n) {
            val x = if (i < a.length) a[i].code else 0
            val y = if (i < b.length) b[i].code else 0
            diff = diff or (x xor y)
        }
        return diff == 0
    }
}

/** Holds which input currently owns the in-app keyboard. */
class InputHost internal constructor(random: Random) {
    constructor() : this(SecureRandom())

    var active: SecureInputState? by mutableStateOf(null)
        private set
    val keyboard = KeyboardController(random)

    /** What the Done key does; null just hides the keyboard. */
    var onDone: (() -> Unit)? = null

    fun focus(input: SecureInputState) {
        // Tapping a secret field that already owns the keyboard must not move the keys mid-entry.
        if (active === input && input.secret) return
        active?.onReshuffle = null
        active = input
        keyboard.reset(input.kind)
        // A secret input gets a new key order each time it gains focus and each time it is cleared.
        keyboard.arrangeFor(input)
        input.onReshuffle = { if (active === input) keyboard.arrangeFor(input) }
    }

    fun blur() {
        active?.onReshuffle = null
        active = null
        keyboard.dismissAccents()
    }

    fun done() {
        val action = onDone
        if (action != null) action() else blur()
    }
}
