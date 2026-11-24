package io.github.h4lovoid.dialcrypt.ui.model

object Formatters {
    /** Groups a pairing code in blocks so two people can read it to each other. */
    fun groupCode(code: String, size: Int = 5): String =
        code.filter { !it.isWhitespace() }.chunked(size).joinToString(" ")
}
